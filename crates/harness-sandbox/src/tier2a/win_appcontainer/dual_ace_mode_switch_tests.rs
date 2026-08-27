//! **T-1: モード切替の「払い直し」を、両モードのACEを最初に同時配布して消せるか**
//! （分流 `plans/handoff/fs-boundary-cost/T-1.md`、本流は
//! `plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`）。
//!
//! # 何が困っているのか
//!
//! Tier2a のファイルシステム境界は「許可したい各ノードのDACLへ、サンドボックス主体宛のACEを
//! 事前に書く」方式で、その主体（capability SID）は
//! **(ワークスペースのパス, 書込モード)** から導出される（[`super::workspace_capability_sid`]）。
//! モードは2つある（[`crate::tier2a::workspace_ledger::KNOWN_MODES`] ＝ `rwx` / `ro`）。
//! **モードを切り替えるとcapability SIDが変わるので、既に配った26万件のACEが全部無効になり、全額を
//! もう一度払う**（26万ノードで一巡61.4秒、`plans/mac-spike/RESULTS.md` §S12）。
//!
//! 逃げ道は2つで、片方（CoWに絞ってモードを1つにする）は別の分流が持つ。ここで測るのは
//! **もう片方——両モードのcapability SID宛ACEを、最初の1回で同時に配る**である。
//!
//! # 費用ではなく安全性を測る
//!
//! **同時配布の費用は既に「無料」だと実測されている**（§S15-1: 同一ノードのACEを3本まで
//! 1回の書込にまとめれば時間は1.0倍±3%）。したがって残っている問いは1つだけ:
//!
//! > **`ro` のcapability SIDしか持たない子から、同じツリーへ書けてしまわないか。**
//!
//! 書けてしまうならCoWの境界が消えるので、この案はその場で閉じる。書けなければ
//! **費用ゼロでモード切替の払い直しが消える**。
//!
//! # 3腕で測る理由（片側だけのテストにしない）
//!
//! | 腕 | トークンに積むcapability SID | 期待 | 何のために在るか |
//! |---|---|---|---|
//! | `none` | 通過用のcapabilityだけ | **何もできない** | 陰性対照。ここで書けたら、それは`ALL APPLICATION PACKAGES`等の**別の理由**で書けているので、以降の判定は読めない |
//! | `ro` | `ro`のcapability SID | 読める・辿れる・**書けない** | **本題** |
//! | `rwx` | `rwx`のcapability SID | 全部できる | 陽性対照。ここで書けないなら計器が壊れている（「書けなかった」を`ro`の手柄と読めない） |
//!
//! **3腕とも、ACEが2本とも載った同一のツリーを見る。** 腕ごとに別のツリーを作ると、
//! 「同居しているACEが漏れるか」という当の問いを測っていないことになる。
//!
//! # 実行（**昇格しないこと**）
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- \
//!     --ignored --test-threads=1 --nocapture dual_ace
//! ```
//!
//! 昇格するとAppContainer子の親トークンが管理者のものになり、測っている世界が実運用と
//! ずれる（`d79_exec_split_tests`と同じ理由、B-08）。ACEを書くのは**テスト自身が作った
//! ツリー**だけなので所有者権限で足りる。主体は[`super::capability_sid_from_name`]（純粋な
//! 導出）で、**台帳にもAppContainerプロファイルにも何も残さない**——
//! [`super::workspace_capability_sid`]は`%APPDATA%`の台帳へ実際に書くので**使わない**。
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::{Path, PathBuf};
use std::time::Instant;

use super::acl_dacl_write::{grant_aces_propagating, InheritableGrant};
use super::mac_spike_tests::{SpikeConsole, SpikeSpawn};
use super::test_support::{build_wide_tree, describe_dacl_aces, TestDirGuard};
use super::*;

/// `build_wide_tree`のfanout。**§S9・§S10・§S15と同じ値**にする——形が違うと
/// それらの数字と並べられない（`acl_baseline_cost_tests`が同じ理由で32を置いている）。
const FANOUT: usize = 32;

/// 撒くファイル数。**この測定は費用ではなく真偽を測る**ので、既定は小さくてよい
/// （§S15が費用側を26万ノード近傍まで押さえている）。`HARNESS_DUAL_ACE_NODES`で振れる。
const DEFAULT_FILE_COUNT: usize = 256;

fn file_count() -> usize {
    std::env::var("HARNESS_DUAL_ACE_NODES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FILE_COUNT)
}

/// 測定用のcapability SIDを**名前から導出**する。`workspace_capability_sid`は使わない
/// （モジュールdocの「実行」節）。
fn measure_cap_sid(mode: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-t1-dualcapsid-{}-{mode}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// 各腕がツリーに対して試すこと。`token`が出力に現れたら「できた」。
///
/// **トークンは互いに部分文字列にならないようにしてある**——`CREATEOK`が`CREATEOKX`に
/// 含まれると、片方しか成立していなくても両方できたことになる
/// （`d79_exec_split_tests::PROBE_ITEMS`と同じ配慮）。
const PROBE_ITEMS: &[(&str, &str)] = &[
    ("traverse-and-read-in-subdir", "TRAVREADOK"),
    ("read-root-file", "READOK"),
    ("create-new-file", "CREATEOK"),
    ("modify-existing-file", "MODIFYOK"),
    ("delete-existing-file", "DELETEOK"),
    ("execute-a-file-in-the-tree", "EXECOK"),
    ("rewrite-the-dacl", "SETACLOK"),
    ("read-the-capability-ledger", "LEDGEROK"),
];

/// 腕の識別子。ツリー上のプローブ用ファイル名にも使う（腕どうしが互いの後始末に
/// 依存しないようにするため——`rwx`腕が消したファイルを`ro`腕が消そうとすると、
/// 「消せなかった」が「もう無かった」と混ざる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// workspaceのcapability SID無し（通過用capabilityのみ）。陰性対照。
    None_,
    /// `ro`のcapability SIDのみ。**本題**。
    Ro,
    /// `rwx`のcapability SIDのみ。陽性対照。
    Rwx,
}

impl Arm {
    fn label(self) -> &'static str {
        match self {
            Self::None_ => "none",
            Self::Ro => "ro",
            Self::Rwx => "rwx",
        }
    }
}

const ARMS: &[Arm] = &[Arm::None_, Arm::Ro, Arm::Rwx];

/// ツリーへプローブ用の的を置く。**ACEを配る前に置くこと**——後から置くと、
/// 継承で付いたのか伝播で付いたのかが混ざる。
fn seed_probe_targets(root: &Path) {
    std::fs::write(root.join("note.txt"), "NOTEBODY").expect("write note.txt");
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cmd_exe = PathBuf::from(format!("{system_root}\\System32\\cmd.exe"));
    std::fs::copy(&cmd_exe, root.join("payload.exe")).expect("copy cmd.exe -> payload.exe");
    for arm in ARMS {
        std::fs::write(root.join(format!("victim-{}.txt", arm.label())), "VICTIM")
            .expect("write the per-arm delete target");
    }
}

/// 1腕ぶんのプローブ本体。**腕が変わっても同じ文字列**を撃つ（違う操作を撃つと、
/// 差が「腕の権限」なのか「撃った操作」なのか分からなくなる）。
///
/// 失敗側は`*ERR=0x........;<例外の型名>`として出す——「できなかった」だけでは
/// **拒否されたのか届かなかったのか**を区別できない（`0x80070005`＝ACCESS_DENIED、
/// `0x80070002`／`0x80070003`＝パスに届いていない）。**この区別が無いと、`ro`腕の
/// 「書けなかった」を「ACLが止めた」と言い切れない。**
///
/// PowerShellは`[IO.File]`の例外を`MethodInvocationException`で包むので、
/// **素の`$_.Exception.HResult`は常に`0x80131501`**（.NETランタイム例外の総称）になり
/// 何も区別できない。[`ERR_FORMAT`]が内側の例外まで降りるのはそのためである。
fn probe_script(root: &Path, arm: Arm, ledger: &Path) -> String {
    let r = root.display().to_string();
    let a = arm.label();
    let l = ledger.display().to_string();
    let e = ERR_FORMAT;
    format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         function Fail($p) {{ {e} }}; \
         try {{ if ([IO.File]::ReadAllText('{r}\\d000\\f000000.txt') -match 'x') \
           {{ Write-Output 'TRAVREADOK' }} }} catch {{ Fail 'TRAVREAD' }}; \
         try {{ if ([IO.File]::ReadAllText('{r}\\note.txt') -match 'NOTEBODY') \
           {{ Write-Output 'READOK' }} }} catch {{ Fail 'READ' }}; \
         try {{ [IO.File]::WriteAllText('{r}\\d000\\new-{a}.txt','y'); Write-Output 'CREATEOK' }} \
           catch {{ Fail 'CREATE' }}; \
         try {{ [IO.File]::AppendAllText('{r}\\note.txt','Z'); Write-Output 'MODIFYOK' }} \
           catch {{ Fail 'MODIFY' }}; \
         try {{ [IO.File]::Delete('{r}\\victim-{a}.txt'); \
           if (-not (Test-Path -LiteralPath '{r}\\victim-{a}.txt')) {{ Write-Output 'DELETEOK' }} }} \
           catch {{ Fail 'DELETE' }}; \
         try {{ & '{r}\\payload.exe' /c echo EXECOK }} catch {{ Fail 'EXEC' }}; \
         try {{ $acl=Get-Acl -LiteralPath '{r}\\note.txt' -ErrorAction Stop; \
           Set-Acl -LiteralPath '{r}\\note.txt' -AclObject $acl -ErrorAction Stop; \
           Write-Output 'SETACLOK' }} catch {{ Fail 'SETACL' }}; \
         try {{ $null=[IO.File]::ReadAllText('{l}'); Write-Output 'LEDGEROK' }} \
           catch {{ Fail 'LEDGER' }}; \
         Write-Output 'PROBEFINISHED'"
    )
}

/// 例外を`<PREFIX>ERR=0x........;<型名>`の1行にする PowerShell 断片。
///
/// **内側の例外まで降りる**——PowerShellが`[IO.File]`の例外を`MethodInvocationException`で
/// 包むので、外側だけを見ると全部`0x80131501`になって拒否と不在を区別できない。
/// 型名も一緒に出すのは、`UnauthorizedAccessException`（＝ACLが止めた）と
/// `DirectoryNotFoundException`（＝そもそも届いていない）を人が読んで確かめられるようにするため。
const ERR_FORMAT: &str = "$x=$_.Exception; while ($x.InnerException) { $x=$x.InnerException }; \
     Write-Output ('{0}ERR=0x{1:X8};{2}' -f $p, $x.HResult, $x.GetType().Name)";

/// AppContainer子（PowerShell）を起こしてプローブを1回撃ち、生の出力を返す。
///
/// `d79_exec_split_tests::run_in_sandbox`と同じ形である（cwdをSystem32にするのも同じ理由で、
/// 測定対象のツリーをcwdにすると「cwdへ入れないから何もできなかった」と
/// 「書込だけができない」が混ざる）。**写しを作っているのは、あちらがD-79の実装が入った
/// 時点で消える使い捨てモジュールだからである**（`docs/CODE-STRUCTURE-RULES.md`規則2が
/// 消すと定めているものへ、別のスパイクから依存を張らない）。
fn run_in_sandbox(container_sid: PSID, capabilities: &[PSID], command: &str) -> String {
    let (shell, _) = resolve_shell();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cwd = PathBuf::from(format!("{system_root}\\System32"));
    let mut child = SpikeSpawn {
        exe: &shell,
        args: &["-NoProfile", "-NonInteractive", "-Command", command],
        cwd: &cwd,
        container_sid,
        capabilities,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the probe child");
    let (out, err, _code) = child.wait_and_read();
    format!("{out}{err}")
}

/// 成立した項目の名前と、生の出力を返す。
///
/// `PROBEFINISHED`が無ければ**判定しない**——途中で死んでいれば以降は全部「できなかった」に
/// 見え、それをACEの手柄と読んでしまう（B-12と同型）。
fn probe(
    container_sid: PSID,
    capabilities: &[PSID],
    root: &Path,
    arm: Arm,
    ledger: &Path,
) -> (Vec<String>, String) {
    let out = run_in_sandbox(container_sid, capabilities, &probe_script(root, arm, ledger));
    eprintln!(
        "[dual-ace] --- arm {} raw ---\n{out}\n[dual-ace] --- end ---",
        arm.label()
    );
    assert!(
        out.contains("PROBEFINISHED"),
        "[{}] プローブが最後まで走っていない。以降の判定は読めない: {out}",
        arm.label()
    );
    let ran = PROBE_ITEMS
        .iter()
        .filter(|(_, token)| out.contains(token))
        .map(|(name, _)| (*name).to_string())
        .collect();
    (ran, out)
}

/// 出力から`<PREFIX>ERR=0x........;<型名>`を1つ拾う（拒否の**理由**をJSONへ残すため。
/// 「できなかった」だけでは、ACLが止めたのか届いていないのかを後から確かめられない）。
fn error_code(out: &str, prefix: &str) -> Option<String> {
    let needle = format!("{prefix}ERR=");
    let at = out.find(&needle)? + needle.len();
    let rest = &out[at..];
    let end = rest
        .find(['\r', '\n'])
        .unwrap_or_else(|| rest.chars().take(64).map(char::len_utf8).sum());
    Some(rest[..end].trim().to_string())
}

/// capability台帳の実パス。**サンドボックスの中から読めるか**を測るために子へ渡す
/// （副題: capability SIDの名前を知った者は誰でも[`super::capability_sid_from_name`]を呼べるので、
/// 名前が漏れる経路そのものが境界の一部になる）。
///
/// AppContainer子の`%APPDATA%`はパッケージ側へ向き得るので、**親側で解決した絶対パスを
/// 埋め込む**（子に`$env:APPDATA`を解かせると、読めなかったのが権限のせいなのか
/// 別の場所を見たせいなのか分からない）。
fn capability_ledger_path() -> PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_else(|_| "C:\\".to_string());
    PathBuf::from(appdata)
        .join("harness")
        .join("config")
        .join("workspace-capability-ledger.json")
}

/// **本題**: `ro`と`rwx`の2つのcapability SID宛ACEを1回の書込で同時に配ったとき、
/// `ro`のcapability SIDしか持たない子はそのツリーへ書けないか。
///
/// # 判定線
///
/// - `ro`の子から**書けたら②は閉じる**（CoWの境界が消える）
/// - 書けなければ、**費用ゼロでモード切替の払い直しが消える**（費用側は§S15-1が実測済み）
///
/// # assertの組み方
///
/// 拒否側だけをassertしない（`test-logic-rules`）。`none`（何もできない）と
/// `rwx`（全部できる）を同じツリー・同じプローブで挟み、**3腕の差だけ**を結論に使う。
#[test]
#[ignore = "spawns real AppContainer children and writes real DACLs; run NON-elevated with --test-threads=1"]
fn dual_ace_ro_child_cannot_write_a_tree_that_also_carries_the_rwx_ace() {
    let traverse = traverse_capability_sid().expect("traverse capability");
    let container = session_sid();
    let ledger = capability_ledger_path();
    let count = file_count();

    let dir = TestDirGuard::create("t1-dual-ace");
    let root = dir.path();
    let nodes = build_wide_tree(root, count, FANOUT);
    seed_probe_targets(root);

    let ro_cap_sid = measure_cap_sid("ro");
    let rwx_cap_sid = measure_cap_sid("rwx");
    let ro_mask = fs_access_mask(FsAccess::ReadExec);
    let rwx_mask = workspace_rwx_mask();
    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

    // --- 2本を1回の書込で配る（§S15-1が「1回にまとめれば無料」と測った当の部品） ---
    let grants = [
        InheritableGrant {
            sid: ro_cap_sid.as_psid(),
            mask: ro_mask,
            inheritance: both,
        },
        InheritableGrant {
            sid: rwx_cap_sid.as_psid(),
            mask: rwx_mask,
            inheritance: both,
        },
    ];
    let started = Instant::now();
    grant_aces_propagating(root, &grants, IdempotentCheck::Always)
        .expect("one propagating write carrying both ACEs");
    let grant_ms = started.elapsed().as_millis();

    // --- 「付けた」と「効いている」は別の事実なので、子を起こす前に読み返す（B-25） ---
    //
    // rootの明示ACEだけでなく、**最深部の葉の実効マスク**まで見る。rootに載っただけでは
    // 既存の子孫へ届いたことにならない（残課題#32がまさにその形だった）。
    let mut readback = Vec::new();
    for (label, sid, want) in [
        ("ro", ro_cap_sid.as_psid(), ro_mask),
        ("rwx", rwx_cap_sid.as_psid(), rwx_mask),
    ] {
        let folded = sid_explicit_ace(root, sid)
            .expect("read back the root ACE")
            .unwrap_or_else(|| {
                panic!("{label}: the root carries no explicit ACE for this capability SID")
            });
        let leaf_file = root.join("d000").join("f000000.txt");
        let leaf_dir = root.join("d000");
        let effective_file = sid_effective_ace_mask(&leaf_file, sid).expect("read leaf file mask");
        let effective_dir = sid_effective_ace_mask(&leaf_dir, sid).expect("read leaf dir mask");
        let note = sid_effective_ace_mask(&root.join("note.txt"), sid).expect("read note.txt mask");
        readback.push(serde_json::json!({
            "cap_sid": label,
            "sid": crate::win_common::sid_to_string(sid).unwrap_or_default(),
            "requested_mask": format!("0x{want:08x}"),
            "root_folded_mask": format!("0x{:08x}", folded.mask),
            "root_inherit_flags": folded.inherit,
            "leaf_file_effective_mask": effective_file.map(|m| format!("0x{m:08x}")),
            "leaf_dir_effective_mask": effective_dir.map(|m| format!("0x{m:08x}")),
            "note_txt_effective_mask": note.map(|m| format!("0x{m:08x}")),
        }));
        assert_eq!(
            effective_file,
            Some(want),
            "{label}: the deepest leaf must carry exactly the mask that was written — if this is \
             None the write reached nothing and the child probes below measure nothing"
        );
        assert_eq!(
            effective_dir,
            Some(want),
            "{label}: the leaf directory must carry exactly the mask that was written"
        );
        assert_eq!(
            note, Some(want),
            "{label}: note.txt (the modify target) must carry exactly the mask that was written"
        );
    }
    let root_aces = describe_dacl_aces(root).expect("list the root DACL");

    // --- 3腕を同じツリーへ撃つ ---
    let mut rows = Vec::new();
    let mut observed: Vec<(Arm, Vec<String>)> = Vec::new();
    for &arm in ARMS {
        let caps: Vec<PSID> = match arm {
            Arm::None_ => vec![traverse.as_psid()],
            Arm::Ro => vec![traverse.as_psid(), ro_cap_sid.as_psid()],
            Arm::Rwx => vec![traverse.as_psid(), rwx_cap_sid.as_psid()],
        };
        let (ran, raw) = probe(container.as_psid(), &caps, root, arm, &ledger);
        rows.push(serde_json::json!({
            "arm": arm.label(),
            "can": PROBE_ITEMS
                .iter()
                .map(|(name, _)| {
                    (
                        (*name).to_string(),
                        serde_json::json!(ran.iter().any(|n| n == name)),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>(),
            "denied_with": {
                "create": error_code(&raw, "CREATE"),
                "modify": error_code(&raw, "MODIFY"),
                "delete": error_code(&raw, "DELETE"),
                "traverse_read": error_code(&raw, "TRAVREAD"),
                "read": error_code(&raw, "READ"),
                "exec": error_code(&raw, "EXEC"),
                "set_acl": error_code(&raw, "SETACL"),
                "ledger": error_code(&raw, "LEDGER"),
            },
        }));
        observed.push((arm, ran));
    }

    // --- 撤収（付与と撤収は対、B-01）。**戻り値ではなく読み直しで**確かめる（BUG-101） ---
    let psids = [ro_cap_sid.as_psid(), rwx_cap_sid.as_psid()];
    let started = Instant::now();
    let revoke_report = revoke_workspace_sids_recursive(root, &psids, &|_, _| {})
        .expect("revoke both measurement capability SIDs");
    let revoke_ms = started.elapsed().as_millis();
    let mut leftovers_seen = Vec::new();
    for (label, sid) in [("ro", ro_cap_sid.as_psid()), ("rwx", rwx_cap_sid.as_psid())] {
        if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid) {
            leftovers_seen.push(format!(
                "{label}: {} node(s) still carry the ACE; first few: {:?}",
                leftovers.len(),
                leftovers.iter().take(5).collect::<Vec<_>>()
            ));
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "T-1 does a ro-only child leak write access when the rwx ACE sits on \
                            the same DACL",
            "nodes": nodes,
            "file_count": count,
            "fanout": FANOUT,
            "one_write_carrying_both_aces_ms": grant_ms,
            "revoke_both_ms": revoke_ms,
            "revoke_checked": revoke_report.checked,
            "revoke_rewritten": revoke_report.rewritten,
            "readback": readback,
            "root_dacl_after_the_single_write": root_aces,
            "arms": rows,
        })
    );

    assert!(
        leftovers_seen.is_empty(),
        "the revoke left ACEs behind:\n{}",
        leftovers_seen.join("\n")
    );

    // --- 期待値 ---
    //
    // `read-the-capability-ledger`は**副題の観測項目**で、境界の判定には使わない
    // （台帳が読めることは②の可否を決めない。決めるのは書込である）。したがって
    // ここでは期待値を置かず、JSONに残すだけにする。
    //
    // `rewrite-the-dacl`は**両方のcapability SIDで拒否**が期待値である。`workspace_rwx_mask`は
    // `WRITE_DAC`/`WRITE_OWNER`を意図的に外しており（`acl_grant.rs`のdoc）、
    // ここが通ると**`rwx`側の子が自分でACEを足せる**＝モードごとにcapability SIDを分けたこと
    // そのものが無意味になる。
    let expect: &[(Arm, &[(&str, bool)])] = &[
        (
            Arm::None_,
            &[
                ("traverse-and-read-in-subdir", false),
                ("read-root-file", false),
                ("create-new-file", false),
                ("modify-existing-file", false),
                ("delete-existing-file", false),
                ("execute-a-file-in-the-tree", false),
                ("rewrite-the-dacl", false),
            ],
        ),
        (
            Arm::Ro,
            &[
                ("traverse-and-read-in-subdir", true),
                ("read-root-file", true),
                ("create-new-file", false),
                ("modify-existing-file", false),
                ("delete-existing-file", false),
                ("execute-a-file-in-the-tree", true),
                ("rewrite-the-dacl", false),
            ],
        ),
        (
            Arm::Rwx,
            &[
                ("traverse-and-read-in-subdir", true),
                ("read-root-file", true),
                ("create-new-file", true),
                ("modify-existing-file", true),
                ("delete-existing-file", true),
                ("execute-a-file-in-the-tree", true),
                ("rewrite-the-dacl", false),
            ],
        ),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (arm, wants) in expect {
        let ran = &observed
            .iter()
            .find(|(a, _)| a == arm)
            .expect("every arm was probed")
            .1;
        for (item, want) in *wants {
            let got = ran.iter().any(|n| n == item);
            if got != *want {
                failures.push(format!(
                    "[{}] {item}: 期待は{}だが実際は{}",
                    arm.label(),
                    if *want { "できる" } else { "できない" },
                    if got { "できた" } else { "できなかった" }
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "同時配布の安全性:\n{}\n\
         ・`none`腕が何かできた → ツリーが別の理由（AAP等）で開いている。以降は読めない\n\
         ・`rwx`腕ができない → 計器が壊れている。`ro`腕の「できない」を境界の手柄と読めない\n\
         ・`ro`腕が書けた → **②は閉じる**（両モードのACEを同時に配るとCoWの境界が消える）",
        failures.join("\n")
    );
}
