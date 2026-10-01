//! [#30・D-112] **`harness.exe`が`policy.json`のファイル宣言へ許可を付ける経路の実機E2E**
//! （`docs/STATUS.md`サンドボックス周辺 #71）。
//!
//! # 何を確かめるのか
//!
//! `harness.exe`は起動時に`.harness/policy.json`のファイル宣言を読み、**このマシンで承認した宣言だけ**
//! （承認台帳`policy-approval-ledger.json`）に許可（ACE）を付ける。入口ドメイン`workspace-shell`の宣言は
//! 入口の子（モデルのシェル）へ、遷移先ドメインの宣言は「遷移先である・通信を宣言していない・
//! `--enforce-transitions`」のときそのドメインの子へだけ渡る（`startup::policy_fs`）。単体試験は
//! 振り分けの規則までを固定しており、**実ACL・実トークン・実台帳を通した姿は1度も見ていない**。
//!
//! | 試験 | 確かめること | 禁止側 | 許可側 |
//! |---|---|---|---|
//! | [`grant_an_entry_declaration_only_after_approval`] | 入口の宣言は承認して初めて付く | 未承認の回: 読めない・警告が出る・ACE 0本 | 承認後の回: 読める・宣言の宛先SIDのACEがちょうど1本 |
//! | [`grant_a_target_domain_declaration_only_to_that_domain`] | 遷移先の宣言は`--fs-allow`無しで遷移先だけに付く | 強制なしの回: 付かない（ACE 0本）／強制ありの回: 入口のシェルは読めない | 強制ありの回: 遷移先の子が読める |
//! | [`revoke_an_entry_declaration_whose_approval_was_removed`]・[`revoke_a_target_domain_declaration_whose_approval_was_removed`] | 承認を外して起動し直すと、自動撤収（D-27）でACEが消える | 撤収後: ACE 0本・台帳の行も宛先の索引も消える・読めない | 撤収前: 付与のキーが残したACEが在ることを前提として確かめる |
//!
//! **4点目（ポリシーエディタの試験実行を同じワークスペースで回しても`harness.exe`の許可が残る）は
//! ここに無い**——エディタ側の試験（`crates/harness-policy-editor/tests/`）の担当である。
//!
//! # 付与と撤収を別のキーにしてある（撃つ順序が要る）
//!
//! 付与の2本（`grant_`）は**付けたACEと承認を残して終わる**。撤収の2本（`revoke_`）は、その状態を
//! **製品の取り消し**（承認台帳の`revoke`と、次の起動の自動撤収）で消し、消えたことを確かめる
//! ——3点目そのものが付与の後始末になる（`bug-pattern-rules`の`B-27`: 後始末を試験が代行しない）。
//!
//! ```text
//! dev-elevated-run.exe e2e-policy-fs-grant     # 1・2点目。ACEと承認を残す
//! (Get-Acl C:\harness-e2e-policydecl-entry).Access   # 確認（任意）: S-1-15-3-* のACEが残っている
//! dev-elevated-run.exe e2e-policy-fs-revoke    # 3点目。残したものを製品の取り消しで消す
//! ```
//!
//! 分けたのは`CLAUDE.md`「開発コマンド」節の規則（付与と撤収は別のテスト関数・別のキー）に従うためで、
//! あわせて**ACEがharnessの終了後も残る**（§22.2.1の寿命）ことを、人が2つのキーの間で見られる。
//!
//! **だから`e2e-all`には入れていない**（`KNOWN_TARGETS`の`e2e-all`が`--skip policy_declarations::`
//! を持つ）。全件を並行に回すと撤収が付与より先に走り得て、前提が無いので赤になる。
//!
//! # 置き場所を固定してある
//!
//! 付与のキーと撤収のキーは**別のプロセス**で走るので、撤収側が付与側の置き場を引き当てられるよう
//! ワークスペース（`C:\harness-e2e\policy-decl-*`）も外のディレクトリ（`C:\harness-e2e-policydecl-*`）も
//! 名前を固定している（`fs_allow_case_dir`のようにPIDを付けると、撤収側から見つからない）。
//! 外のディレクトリを`C:\`直下に置く理由は`fs_allow_case_dir`と同じ（既に付与済みの祖先traverseに
//! 相乗りしないため）。
//!
//! 付与の試験は、**前の回の残り（承認・付与）を製品の取り消しで消してから**始める——承認台帳に
//! 前の回の承認が残っていると「未承認の回」が未承認でなくなる。
//!
//! # 共有資源の排他
//!
//! - **fs passthrough台帳**（`fs-passthrough-ledger.json`）: harnessが付与と自動撤収で書き、ここは
//!   [`FsLedgerExclusive`]のメソッドで読むので、**テスト関数の全体で**[`super::fs_ledger_exclusive`]を持つ
//!   （親ファイルの「共有資源の排他」節の4番。`a_transition_target_domain_is_narrower_than_the_caller`と同じ）。
//! - **承認台帳**（`policy-approval-ledger.json`）: **試験側の排他は取らない。** 読み書きは製品の
//!   `PolicyApprovalStore`だけを通り、その`Ledger::update`が名前付きミューテックス
//!   （`Local\harness-policy-approval-ledger`）で読み書きを直列化する。そのうえで各試験が触る鍵は
//!   **自分のワークスペースの分だけ**なので、並行する他の試験の承認とは鍵が重ならない。
//!   既存の反転の対照（`a_transition_target_domain_is_narrower_than_the_caller`）も同じ判断をしている。
//! - CoWセッションは作らない（`--sandbox tier2a`）ので[`super::CowExclusive`]は要らない。
//!
//! # 突き合わせる3つの値（`measurement-review`の検問10）
//!
//! 子の到達性（読めたか）・実DACL（`Get-Acl`で読むcapability SID宛のACE）・**台帳**（fs passthrough台帳の
//! 行と、capability台帳の宣言の索引）。前2つは宛先SIDの導出が共通なので、導出そのものの取り違えでは
//! 一緒にずれる（[`super::capability_sid_text`]のdocの限界）。台帳は記録の経路が別である。
//!
//! # 測っていないもの（外挿しないこと）
//!
//! - **CoW（`--sandbox tier2a-cow`）**。遷移先の書込宣言が読取として付く件（D-112の限界(e)）も含む
//! - **`read_write`の宣言**（ここは`read_exec`だけ）と、同じパスを`--fs-allow`や`settings.json`でも
//!   開いた場合の重なり
//! - **複数のワークスペースが同じパスを宣言したときの参照カウント**（`tier2a_fs_ledger_lifecycle`が
//!   `settings.json`の側で測っている）
//! - **この試験自体の歯**: 書いた時点では1度も走らせていない（`B-27`）。緑を1回見るまでは
//!   回帰網の一部として数えないこと
//!
//! # 実行
//!
//! 管理者権限で走らせる（Tier2aの準備が祖先traverseを付け、宣言のACEを書く）。昇格していなければ
//! 何もせずに落ちる——非昇格のまま撃つと、harnessが付与のたびにUACを出す。

use std::path::{Path, PathBuf};
use std::process::Command;

use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_sandbox::tier2a::policy_approval::{DeclarationRef, PolicyApprovalStore};
use harness_sandbox::tier2a::policy_grants::SkipReason;

use super::FsLedgerExclusive;

/// 付与の2本を撃つ`KNOWN_TARGETS`のキー（`crates/dev-elevated-runner/src/lib.rs`）。
const GRANT_KEY: &str = "e2e-policy-fs-grant";
/// 撤収の2本を撃つキー。
const REVOKE_KEY: &str = "e2e-policy-fs-revoke";

/// 遷移先ドメインの名前。入れ物の名前の上限（64文字）に掛からないよう短くする
/// （`declare_chain`のdoc「名前を短くしてある理由」）。
const TARGET_DOMAIN: &str = "d0";

/// 子が読めたかを判定する印。ラベルではなく**中身そのもの**を探す。
const MARKER: &str = "POLICYDECLMARKER";

/// 1つの経路（入口ドメイン／遷移先ドメイン）の置き場と、どのドメインの宣言を承認するか。
/// **付与の試験と撤収の試験が同じ値を読む**（置き場の綴りを2箇所に書かない、`B-05`）。
struct Case {
    /// ワークスペース（`C:\harness-e2e\<ws>`）。
    ws: &'static str,
    /// ワークスペースの外の、宣言するディレクトリ。
    outside: &'static str,
    /// 承認する宣言のドメイン。入口の経路は入口、遷移先の経路は[`TARGET_DOMAIN`]。
    approved_domain: &'static str,
    /// 付与の試験の腕の名前（スクラッチのファイル名と、撤収後の後始末に使う）。
    grant_arms: [&'static str; 2],
}

const ENTRY_CASE: Case = Case {
    ws: "policy-decl-entry",
    outside: r"C:\harness-e2e-policydecl-entry",
    approved_domain: ENTRY_DOMAIN,
    grant_arms: ["unapproved", "approved"],
};

const DOMAIN_CASE: Case = Case {
    ws: "policy-decl-domain",
    outside: r"C:\harness-e2e-policydecl-domain",
    approved_domain: TARGET_DOMAIN,
    grant_arms: ["unenforced", "enforced"],
};

/// 撤収の試験の腕の名前。
const REVOKED_ARM: &str = "revoked";

impl Case {
    fn workspace(&self) -> PathBuf {
        Path::new(super::CASE_ROOT).join(self.ws)
    }

    fn outside(&self) -> PathBuf {
        PathBuf::from(self.outside)
    }

    /// 遷移先ドメインの経路か。
    fn crosses_domains(&self) -> bool {
        self.approved_domain != ENTRY_DOMAIN
    }

    /// `policy.json`に書く値。**ポリシーエディタが書く綴り**（`normalize_path`の`/`区切り）にそろえる。
    /// 承認台帳は値を書いてあるとおりの文字列で照合するので、承認するときもこの値を渡す。
    fn declared_value(&self) -> String {
        format!(
            "{}/**",
            harness_policy::normalize::normalize_path(self.outside)
        )
    }

    /// 腕1本ぶんのスクラッチの名前（`run_arm_collecting_denials`の`case_name`）。
    fn arm_name(&self, arm: &str) -> String {
        format!("{}-{arm}", self.ws)
    }

    /// `policy.json`に書く宣言のうち、**承認するもの**。
    fn approved_declaration<'a>(&self, value: &'a str) -> DeclarationRef<'a> {
        DeclarationRef {
            domain: self.approved_domain,
            value,
            access: harness_config::FsAccess::ReadExec,
        }
    }

    /// `policy.json`に書く宣言の全部（前の回の残りを消すときに使う）。遷移先の経路は入口にも
    /// 同じ値を書くので2件になる（[`write_policy`]のdoc）。
    fn all_declarations<'a>(&self, value: &'a str) -> Vec<DeclarationRef<'a>> {
        let mut out = vec![DeclarationRef {
            domain: ENTRY_DOMAIN,
            value,
            access: harness_config::FsAccess::ReadExec,
        }];
        if self.crosses_domains() {
            out.push(self.approved_declaration(value));
        }
        out
    }
}

impl FsLedgerExclusive {
    /// fs passthrough台帳から`root`の行を、**製品と同じ比べ方**（`same_ledger_path`）で引く。
    ///
    /// 親の`entry_for`は綴りの完全一致で比べる。`policy.json`の宣言から付いた行は付与ルートの綴り
    /// （`C:/x`）で記録されるので、`C:\x`で探すと**在るのに無いと答える**——撤収の試験で
    /// 「行が消えた」を読み違える向きの誤りになる。
    fn entry_for_root(&self, root: &Path) -> Result<Option<(bool, Vec<String>)>, String> {
        let key = root.to_string_lossy();
        Ok(super::read_fs_ledger_entries()?
            .into_iter()
            .find(|(path, _, _)| harness_grant_ledger::same_ledger_path(path, &key))
            .map(|(_, managed, workspaces)| (managed, workspaces)))
    }

    /// その行が「`ws`がファイルで宣言している」印（自動撤収の対象である印）を持つか。
    /// ワークスペースの綴りは`--cwd`のまま記録されるので、両方を`canonicalize`して比べる。
    fn is_tagged_with(&self, root: &Path, ws: &Path) -> Result<bool, String> {
        let canonical = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        Ok(match self.entry_for_root(root)? {
            Some((managed, workspaces)) => {
                managed
                    && workspaces
                        .iter()
                        .any(|w| canonical(Path::new(w)) == canonical(ws))
            }
            None => false,
        })
    }
}

/// 昇格していなければ、何もせずに落とす（`B-33`: 走らなかったことを緑にしない）。
fn require_elevated(key: &str) {
    assert!(
        harness_sandbox::tier2a::privhelper::is_elevated(),
        "この試験は管理者権限で走らせること（Tier2aの準備と宣言のACEの書込が昇格を要る）。\
         素の`cargo test`ではなく`dev-elevated-run.exe {key}`から撃つ"
    );
}

/// 入口のシェルと（遷移先の経路では）`findstr`に、外と中のファイルを読ませる台本。
///
/// - シェルの読みは**例外を捕まえて型の名前を出す**。「読めなかった」が空のファイルや
///   台本の途中終了と同じ顔にならないようにするため（`B-35`）
/// - `findstr`へ渡すパスは`\`区切りにする（`/`で始まるトークンをオプションとして食う。
///   `a_transition_target_domain_is_narrower_than_the_caller`が2026-09-20に踏んだ）
fn probe_script(ws: &Path, outside: &Path, with_child: bool) -> String {
    let out = outside.display();
    let inn = ws.display();
    let mut script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         try {{ $a = Get-Content -LiteralPath '{out}\\secret.txt' -Raw -ErrorAction Stop; \
           Write-Output ('SHELL_OUTSIDE=' + $(if ($a -match '{MARKER}') {{'OK'}} else {{'NO_MARKER'}})) }} \
         catch {{ Write-Output ('SHELL_OUTSIDE=DENIED:' + $_.Exception.GetType().Name) }}; \
         try {{ $b = Get-Content -LiteralPath '{inn}\\inside.txt' -Raw -ErrorAction Stop; \
           Write-Output ('SHELL_INSIDE=' + $(if ($b -match '{MARKER}') {{'OK'}} else {{'NO_MARKER'}})) }} \
         catch {{ Write-Output ('SHELL_INSIDE=DENIED:' + $_.Exception.GetType().Name) }}"
    );
    if with_child {
        script.push_str(&format!(
            "; findstr /c:{MARKER} '{out}\\secret.txt' | Out-Null; \
             Write-Output ('CHILD_OUTSIDE_RC=' + $LASTEXITCODE); \
             findstr /c:{MARKER} '{inn}\\inside.txt' | Out-Null; \
             Write-Output ('CHILD_INSIDE_RC=' + $LASTEXITCODE)"
        ));
    }
    script
}

/// `policy.json`を書く。
///
/// - 入口の経路: 入口ドメインに外のディレクトリを`read_exec`で宣言するだけ（遷移の宣言は無い）
/// - 遷移先の経路: 入口→[`TARGET_DOMAIN`]の`findstr`の辺を1本と、**両方のドメインに同じ宣言**を書く。
///   遷移先にだけ書くと、編集時検査が「権限が広がる辺」として宣言ごと拒否し、harnessが起動しない
///   （検査が見るのは宣言だけで、承認は見ない。既存の反転の対照が2026-09-20に踏んだ）。
///   **入口の分は承認しない**——承認の鍵にはドメインが入っている（D-112）ので、入口の宣言は
///   未承認のまま入口の子には付かない。入口の子が読めないのは「遷移先の許可が入口へ漏れていない」
///   ことの証拠になる（宛先SIDは`(ワークスペース, パス, 種類)`で決まりドメインを含まないので、
///   止めているのはどのトークンへ積むかの振り分けだけである）。
fn write_policy(case: &Case, ws: &Path, value: &str) -> Result<(), String> {
    let mut file = PolicyFile::default();
    if case.crosses_domains() {
        super::add_edge(
            &mut file,
            ENTRY_DOMAIN,
            &super::system_findstr_exe(),
            TARGET_DOMAIN,
        )?;
        for name in [ENTRY_DOMAIN, TARGET_DOMAIN] {
            file.domains
                .iter_mut()
                .find(|d| d.name == name)
                .ok_or_else(|| format!("ドメイン{name}が宣言に無い"))?
                .fs
                .read_exec
                .push(value.to_string());
        }
    } else {
        let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
        entry.fs.read_exec.push(value.to_string());
        file.domains.push(entry);
    }
    harness_policy::policy_file::save(ws, &file)
        .map_err(|e| format!("policy.jsonを書けない: {e}"))?;
    // **読み返して編集時検査を通ることを確かめる。** 通らないとharnessが起動を断り、
    // 「付かなかった」ではなく「起動しなかった」を測ることになる。
    harness_policy::policy_file::load(ws)
        .map(|_| ())
        .map_err(|e| format!("書いたpolicy.jsonが読み込みで拒否された: {e}"))
}

/// 付与の試験の準備。**前の回の残りを製品の取り消しで消し**、ワークスペースと外のディレクトリを
/// 作り直して`policy.json`を書く。戻り値はワークスペース。
fn prepare_grant(ledger: &FsLedgerExclusive, case: &Case) -> PathBuf {
    let ws = super::case_dir(case.ws);
    let outside = case.outside();
    let value = case.declared_value();

    // 承認: 残っていると「未承認の回」が未承認でなくなる。
    let left = PolicyApprovalStore::in_config_dir().revoke(&ws, &case.all_declarations(&value));
    assert!(
        left.is_empty(),
        "前の回の承認を承認台帳から消せなかった（残っていると未承認の回が測れない）: {left:?}"
    );
    // 付与: 台帳に行が残っていれば、名前の付いた扉（`harness fs revoke`）で消す。
    let stale = ledger
        .entry_for_root(&outside)
        .unwrap_or_else(|e| panic!("fs passthrough台帳を読めない: {e}"));
    if stale.is_some() {
        let out = Command::new(super::harness_exe())
            .args(["fs", "revoke"])
            .arg(&outside)
            .output()
            .unwrap_or_else(|e| panic!("`harness fs revoke`を起動できない: {e}"));
        eprintln!(
            "[{}] 前の回の付与が台帳に残っていたので`harness fs revoke {}`で消した -> {}\n{}{}",
            case.ws,
            outside.display(),
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "前の回の付与を`harness fs revoke {}`で消せなかった（上の出力）",
            outside.display()
        );
    }

    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside)
        .unwrap_or_else(|e| panic!("外のディレクトリを作れない（{}）: {e}", outside.display()));
    std::fs::write(outside.join("secret.txt"), format!("{MARKER}\n"))
        .unwrap_or_else(|e| panic!("外のファイルを置けない: {e}"));
    std::fs::write(ws.join("inside.txt"), format!("{MARKER}\n"))
        .unwrap_or_else(|e| panic!("中のファイルを置けない: {e}"));
    write_policy(case, &ws, &value).unwrap_or_else(|e| panic!("[{}] {e}", case.ws));
    if case.crosses_domains() {
        super::assert_chain_crosses_domains(&ws, case.ws, 1);
    }
    ws
}

/// 1腕撃って読み取ったもの。
struct Observation {
    arm: super::DeniedArm,
    /// `OK`／`NO_MARKER`／`DENIED:<例外の型>`。
    shell_outside: String,
    shell_inside: String,
    /// 撃った**後**に外のディレクトリへ載っているcapability SID宛のACEの綴り（harnessの終了後に読む）。
    capability_aces: Vec<String>,
}

impl Observation {
    /// `findstr`の終了コード（外, 中）。遷移先の経路だけが持つ。
    fn child_rc(&self) -> (String, String) {
        (
            super::script_cell(&self.arm.text, "CHILD_OUTSIDE_RC="),
            super::script_cell(&self.arm.text, "CHILD_INSIDE_RC="),
        )
    }

    /// harnessの標準エラーに、`needles`を全部含む行があるか。
    fn stderr_has_line(&self, needles: &[&str]) -> bool {
        self.arm
            .harness_stderr
            .lines()
            .any(|line| needles.iter().all(|n| line.contains(n)))
    }

    /// `findstr`が遷移MACに断られたか（待ち行列から読む）。
    fn findstr_refused(&self) -> bool {
        let findstr = super::system_findstr_exe();
        self.arm
            .denied_by_daemon
            .iter()
            .any(|exe| exe.eq_ignore_ascii_case(&findstr))
    }
}

fn observe(case: &Case, ws: &Path, arm: &str, enforce: bool) -> Observation {
    let outside = case.outside();
    let script = probe_script(ws, &outside, case.crosses_domains());
    let denied =
        super::run_arm_collecting_denials(ws, &case.arm_name(arm), enforce, &script, case.ws, &[])
            .unwrap_or_else(|e| panic!("[{}] 腕`{arm}`が測れなかった: {e}", case.ws));
    let shell_outside = super::script_cell(&denied.text, "SHELL_OUTSIDE=");
    let shell_inside = super::script_cell(&denied.text, "SHELL_INSIDE=");
    // **読めなかったことを0本と読ませない**（`sid_aces`が`Get-Acl`の失敗を`Err`で返す、`B-10`）。
    let capability_aces = super::sid_aces(&outside, "S-1-15-3-")
        .unwrap_or_else(|e| panic!("[{}] 外のディレクトリのDACLを読めない: {e}", case.ws));
    eprintln!(
        "[{}] 腕`{arm}`（enforce={enforce}）: シェル 外={shell_outside} 中={shell_inside}／\
         capability ACE={capability_aces:?}",
        case.ws
    );
    Observation {
        arm: denied,
        shell_outside,
        shell_inside,
        capability_aces,
    }
}

/// この経路の宣言の宛先SIDの綴り。**台帳の索引を見るassertより後に呼ぶこと**
/// （未発行なら発行してしまう。[`super::capability_sid_text`]の「呼ぶ順序の拘束」）。
fn expected_subject(case: &Case, ws: &Path) -> Result<String, String> {
    let ws_canon = ws.canonicalize().unwrap_or_else(|_| ws.to_path_buf());
    super::capability_sid_text(
        &ws_canon,
        &case.outside(),
        harness_sandbox::FsAccess::ReadExec,
        &format!("{}-cal", case.ws),
    )
}

/// capability台帳に載っている、この経路の宣言の宛先の件数（台帳の索引）。
fn minted_subjects(case: &Case, ws: &Path) -> usize {
    let ws_canon = ws.canonicalize().unwrap_or_else(|_| ws.to_path_buf());
    super::declaration_capability_count(&case.outside(), &ws_canon)
}

/// 付いた側の確かめ（付与の試験の許可側と、撤収の試験の前提が同じものを見る）。
///
/// 3つの値——実DACL（宣言の宛先SIDのACEが**ちょうど1本**）・capability台帳の索引・fs passthrough台帳の
/// 「`ws`がファイルで宣言している」印（自動撤収の対象である印）。
fn check_granted(
    ledger: &FsLedgerExclusive,
    case: &Case,
    ws: &Path,
    observed: &[String],
    failures: &mut Vec<String>,
) {
    let outside = case.outside();
    if minted_subjects(case, ws) == 0 {
        // **ここで綴りを作りに行かない**——作る関数は未発行なら発行するので、索引が無いという
        // この失敗そのものを、試験が埋めてしまう。
        failures.push(format!(
            "capability台帳に{}宛の宣言の宛先が1件も無い——付与の経路が宛先を発行していない\
             （発行していなければ、後から取り消す索引も無い）。載っているACE: {observed:?}",
            outside.display()
        ));
    } else {
        match expected_subject(case, ws) {
            Ok(expected) => {
                if observed != std::slice::from_ref(&expected) {
                    failures.push(format!(
                        "{}に載っているcapability SID宛のACEが、宣言の宛先（read_exec）の1本ではない: \
                         載っている={observed:?} 期待={expected}",
                        outside.display()
                    ));
                }
            }
            Err(e) => failures.push(format!("宣言の宛先SIDの綴りを作れない: {e}")),
        }
    }
    match ledger.is_tagged_with(&outside, ws) {
        Ok(true) => {}
        Ok(false) => failures.push(format!(
            "fs passthrough台帳の{}の行に「{}がファイルで宣言している」印が無い。\
             **この印が無いと、承認を外しても自動撤収の対象にならない**（3点目が成り立たない）: {:?}",
            outside.display(),
            ws.display(),
            ledger.entry_for_root(&outside)
        )),
        Err(e) => failures.push(format!("fs passthrough台帳を読めない: {e}")),
    }
}

/// 未承認の警告（`SkipReason::NotApprovedOnThisMachine`）が、この値について出ているか。
/// 文言は製品の網羅`match`から引く（綴りを写さない、`B-05`）。
fn warned_not_approved(observed: &Observation, value: &str) -> bool {
    observed.stderr_has_line(&[
        "warning:",
        value,
        SkipReason::NotApprovedOnThisMachine.describe(),
    ])
}

/// 遷移先ドメインの宣言が付いたという注記（`run_agent.rs`）。
fn granted_to_target_domain(observed: &Observation) -> bool {
    let note = format!("note: granted 1 file declaration(s) of the domain {TARGET_DOMAIN:?}");
    observed.stderr_has_line(&[note.as_str()])
}

/// 遷移先ドメインを用意しなかったという警告（`run_agent.rs`）。理由の語を`reason`で絞る。
fn target_domain_refused_because(observed: &Observation, reason: &str) -> bool {
    let warning = format!("transitions into the domain {TARGET_DOMAIN:?} will be refused");
    observed.stderr_has_line(&[warning.as_str(), reason])
}

/// 自動撤収（D-27）の注記の**直後の一覧**に、`root`の名前が載っているか。
///
/// 注記は1行で、取り消したパスはその下に字下げして並ぶ（`fs_grants::revoke`の
/// `reconcile_fs_ledger_for_workspace`）。標準エラー全体で名前を探すと、同じ名前が
/// 未承認の警告などにも出るので、**取り消した一覧に載ったか**を言えない。
fn auto_revoke_listed(observed: &Observation, root: &Path) -> bool {
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let mut lines = observed.arm.harness_stderr.lines();
    while let Some(line) = lines.next() {
        if !line.contains("no longer declared by any workspace") {
            continue;
        }
        if lines
            .by_ref()
            .take_while(|l| l.starts_with("  "))
            .any(|l| l.contains(name))
        {
            return true;
        }
    }
    false
}

fn finish(case: &Case, failures: &[String], observations: &[&Observation]) {
    let texts: Vec<String> = observations
        .iter()
        .map(|o| {
            format!(
                "--- 本文 ---\n{}\n--- harnessの標準エラー ---\n{}",
                o.arm.text, o.arm.harness_stderr
            )
        })
        .collect();
    assert!(
        failures.is_empty(),
        "[{}] {}件の問題:\n- {}\n{}",
        case.ws,
        failures.len(),
        failures.join("\n- "),
        texts.join("\n")
    );
}

/// 付与の試験が状態を残したことと、確かめ方・消し方を出す。
fn announce_left_state(case: &Case, ws: &Path) {
    eprintln!(
        "[{}] **状態を残した**（撤収のキーが製品の取り消しで消す）: {}のcapability SID宛のACE・\
         承認台帳の承認・fs passthrough台帳の行・ワークスペース{}。\
         確認: (Get-Acl '{}').Access | ? IdentityReference -like 'S-1-15-3-*'／\
         消す: dev-elevated-run.exe {REVOKE_KEY}",
        case.ws,
        case.outside,
        ws.display(),
        case.outside
    );
}

/// [1点目] **入口ドメインの宣言は、このマシンで承認して初めて付く。**
///
/// | 腕 | 承認 | 入口のシェルが外を読む | 未承認の警告 | 外のcapability ACE |
/// |---|---|---|---|---|
/// | `unapproved` | 無し | **読めない**（禁止側） | 出る | 0本 |
/// | `approved` | 有り | **読める**（許可側） | 出ない | 宣言の宛先の1本 |
///
/// **2つの腕は承認の有無の1ビットだけが違う**（台本・宣言・旗は同じ）。読めなかった理由が
/// 承認であることは、この反転でしか言い切れない。中のファイル（`SHELL_INSIDE`）は両方の腕で
/// 読めること——読めなければセッションそのものが壊れていて、外の「読めない」は何の証拠にもならない。
#[test]
#[ignore = "grants a real ACE from a policy.json declaration and leaves it for the revoke key; run through dev-elevated-run e2e-policy-fs-grant"]
fn grant_an_entry_declaration_only_after_approval() {
    require_elevated(GRANT_KEY);
    let ledger = super::fs_ledger_exclusive();
    let case = &ENTRY_CASE;
    let ws = prepare_grant(&ledger, case);
    let value = case.declared_value();
    let mut failures: Vec<String> = Vec::new();

    // --- 未承認の腕（禁止側） ---
    let before = observe(case, &ws, case.grant_arms[0], false);
    if before.shell_inside != "OK" {
        failures.push(format!(
            "未承認の腕: 入口のシェルがワークスペースの中も読めていない（{}）。セッションが壊れているので、\
             外が読めないことは承認の証拠にならない",
            before.shell_inside
        ));
    }
    if !before.shell_outside.starts_with("DENIED") {
        failures.push(format!(
            "未承認の腕: **承認していない宣言で外のファイルが読めた**（{}）。D-112の本体が効いていない\
             ——同梱された`policy.json`がそのまま許可になる",
            before.shell_outside
        ));
    }
    if !warned_not_approved(&before, &value) {
        failures.push(format!(
            "未承認の腕: 未承認で付けなかったことの警告が出ていない（`B-10`。値={value}）"
        ));
    }
    if !before.capability_aces.is_empty() {
        failures.push(format!(
            "未承認の腕: 外のディレクトリにcapability SID宛のACEが載った: {:?}",
            before.capability_aces
        ));
    }
    match ledger.entry_for_root(&case.outside()) {
        Ok(None) => {}
        Ok(Some(row)) => failures.push(format!(
            "未承認の腕: fs passthrough台帳に行ができた（付けていないのに記録がある）: {row:?}"
        )),
        Err(e) => failures.push(format!("fs passthrough台帳を読めない: {e}")),
    }

    // --- 承認する（製品の承認台帳。エディタの宣言画面の`y`と同じ書き先） ---
    let not_recorded =
        PolicyApprovalStore::in_config_dir().approve(&ws, &[case.approved_declaration(&value)]);
    assert!(
        not_recorded.is_empty(),
        "宣言の承認を承認台帳へ記録できなかった: {not_recorded:?}"
    );

    // --- 承認済みの腕（許可側） ---
    let after = observe(case, &ws, case.grant_arms[1], false);
    if after.shell_inside != "OK" {
        failures.push(format!(
            "承認済みの腕: 入口のシェルがワークスペースの中も読めていない（{}）",
            after.shell_inside
        ));
    }
    if after.shell_outside != "OK" {
        failures.push(format!(
            "承認済みの腕: **承認した宣言で外のファイルが読めない**（{}）。付与・振り分け・入口のトークンへの\
             積み込みのどこかで落ちている",
            after.shell_outside
        ));
    }
    if warned_not_approved(&after, &value) {
        failures.push(
            "承認済みの腕: 承認したのに「未承認」の警告が出ている（承認台帳の鍵が読む側と書く側で\
             食い違っている）"
                .to_string(),
        );
    }
    let outside_name = case
        .outside()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    if !after.stderr_has_line(&[
        "note: fs-allow granted:",
        outside_name.as_deref().unwrap_or(""),
    ]) {
        failures
            .push("承認済みの腕: 付与の注記（`note: fs-allow granted:`）が出ていない".to_string());
    }
    check_granted(&ledger, case, &ws, &after.capability_aces, &mut failures);

    finish(case, &failures, &[&before, &after]);
    announce_left_state(case, &ws);
}

/// [2点目] **遷移先ドメインの宣言は、`--fs-allow`無しでそのドメインだけに付く。**
///
/// | 腕 | 旗 | 遷移先の宣言 | 入口のシェルが外を読む | 遷移先の子（`findstr`）が外を読む | 外のcapability ACE |
/// |---|---|---|---|---|---|
/// | `unenforced` | 無し | 付かない（用意しない警告が出る） | 読めない | 読めない（入口のまま走る） | 0本 ←「付かない」の実効 |
/// | `enforced` | `--enforce-transitions` | 付く（注記が出る） | **読めない** ← 漏れていない | **読める** ← 付いた | 宣言の宛先の1本 |
///
/// **強制なしの腕を先に撃つ**——ACEはharnessの終了後も残るので、後に撃つと「付かない」を
/// 実DACLで見られない。
///
/// 対照: 中のファイルは、どの腕でもシェルと`findstr`の両方が読めること。遷移先の子が中も読めないなら、
/// 外が読めないのは「狭い」ではなく「壊れている」である（`a_transition_target_domain_is_narrower_than_the_caller`
/// と同じ理由）。
#[test]
#[ignore = "grants a real ACE from a policy.json declaration and leaves it for the revoke key; run through dev-elevated-run e2e-policy-fs-grant"]
fn grant_a_target_domain_declaration_only_to_that_domain() {
    require_elevated(GRANT_KEY);
    let ledger = super::fs_ledger_exclusive();
    let case = &DOMAIN_CASE;
    let ws = prepare_grant(&ledger, case);
    let value = case.declared_value();
    let outside_file = format!("{}\\secret.txt", case.outside);
    let inside_file = format!("{}\\inside.txt", ws.display());

    // 遷移先の宣言だけを承認する（入口の同じ値は承認しない。`write_policy`のdoc）。
    let not_recorded =
        PolicyApprovalStore::in_config_dir().approve(&ws, &[case.approved_declaration(&value)]);
    assert!(
        not_recorded.is_empty(),
        "宣言の承認を承認台帳へ記録できなかった: {not_recorded:?}"
    );
    let mut failures: Vec<String> = Vec::new();

    // --- 強制なしの腕（遷移先の宣言は付かない） ---
    let off = observe(case, &ws, case.grant_arms[0], false);
    if off.shell_inside != "OK" {
        failures.push(format!(
            "強制なしの腕: 入口のシェルがワークスペースの中も読めていない（{}）",
            off.shell_inside
        ));
    }
    if !target_domain_refused_because(&off, "transitions are not enforced") {
        failures.push(
            "強制なしの腕: 遷移先ドメインを「強制が無効なので付けない」理由で用意しなかった、という警告が無い"
                .to_string(),
        );
    }
    if granted_to_target_domain(&off) {
        failures.push("強制なしの腕: 遷移先ドメインの宣言が付いたという注記が出ている".to_string());
    }
    if !off.capability_aces.is_empty() {
        failures.push(format!(
            "強制なしの腕: **強制が無効なのに遷移先の宣言のACEが付いた**: {:?}（使われないドメインへの付与は\
             起動の費用とUACだけを増やす。D-112の付与する範囲）",
            off.capability_aces
        ));
    }
    match ledger.entry_for_root(&case.outside()) {
        Ok(None) => {}
        Ok(Some(row)) => failures.push(format!(
            "強制なしの腕: fs passthrough台帳に行ができた（付けていないのに記録がある）: {row:?}"
        )),
        Err(e) => failures.push(format!("fs passthrough台帳を読めない: {e}")),
    }
    if !off.shell_outside.starts_with("DENIED") {
        failures.push(format!(
            "強制なしの腕: 入口のシェルが外のファイルを読めた（{}）",
            off.shell_outside
        ));
    }
    let (off_out_rc, off_in_rc) = off.child_rc();
    if off_in_rc != "0" || super::findstr_could_not_open(&off.arm.text, &inside_file) {
        failures.push(format!(
            "強制なしの腕: `findstr`がワークスペースの中も読めていない（終了コード{off_in_rc}）"
        ));
    }
    if !super::findstr_could_not_open(&off.arm.text, &outside_file) {
        failures.push(format!(
            "強制なしの腕: `findstr`が外のファイルを開けなかったと言っていない（終了コード{off_out_rc}）\
             ——誰も持っていないはずの許可で読めている"
        ));
    }

    // --- 強制ありの腕（遷移先の子にだけ付く） ---
    let on = observe(case, &ws, case.grant_arms[1], true);
    if on.findstr_refused() {
        failures.push(format!(
            "強制ありの腕: `findstr`が遷移MACに断られている。この腕は遷移先の権限を測っていない: {:?}",
            on.arm.denied_detail
        ));
    }
    if !granted_to_target_domain(&on) {
        failures.push(
            "強制ありの腕: 遷移先ドメインの宣言が付いたという注記（`note: granted 1 file declaration(s)`）が無い"
                .to_string(),
        );
    }
    if target_domain_refused_because(&on, "") {
        failures
            .push("強制ありの腕: 遷移先ドメインを用意しなかった（理由は標準エラー）".to_string());
    }
    if on.shell_inside != "OK" {
        failures.push(format!(
            "強制ありの腕: 入口のシェルがワークスペースの中も読めていない（{}）",
            on.shell_inside
        ));
    }
    if !on.shell_outside.starts_with("DENIED") {
        failures.push(format!(
            "強制ありの腕: **入口のシェルが、遷移先ドメインだけに付けたはずの許可で外を読めた**（{}）。\
             付与の結果の振り分け（`policy_fs::granted_for`）が入口のトークンへ遷移先の宛先を積んでいる",
            on.shell_outside
        ));
    }
    if !warned_not_approved(&on, &value) {
        failures.push(
            "強制ありの腕: 入口ドメインの同じ値（承認していない）について未承認の警告が無い\
             ——承認の鍵がドメインを区別していない疑い"
                .to_string(),
        );
    }
    let (on_out_rc, on_in_rc) = on.child_rc();
    if on_in_rc != "0" || super::findstr_could_not_open(&on.arm.text, &inside_file) {
        failures.push(format!(
            "強制ありの腕: 遷移先の子がワークスペースの中も読めていない（終了コード{on_in_rc}）。\
             外が読めるかどうかは測れていない"
        ));
    }
    if on_out_rc != "0" || super::findstr_could_not_open(&on.arm.text, &outside_file) {
        failures.push(format!(
            "強制ありの腕: **遷移先の子が、自分のドメインの承認済みの宣言で外を読めない**（終了コード{on_out_rc}）。\
             付与の結果がドメインの用意（`domain_provision`）へ渡っていない"
        ));
    }
    check_granted(&ledger, case, &ws, &on.capability_aces, &mut failures);

    finish(case, &failures, &[&off, &on]);
    announce_left_state(case, &ws);
}

/// [3点目] 承認を外して起動し直すと、自動撤収（D-27）で付与のキーが残したACEが消える。
///
/// # 前提を先に確かめる
///
/// この試験は付与のキーが残した状態を消す側である。**消す前に「在る」を確かめない**と、
/// 付与のキーを撃っていない回も「ACEが0本」で緑になる（`B-09`: 0件と成功を同じ値にしない）。
///
/// # 消えたことは3つの値で見る
///
/// 実DACL（capability SID宛のACEが0本）・fs passthrough台帳の行・capability台帳の宣言の索引
/// （`forget_revoked_declarations`が、実体が消えた宛先だけを落とす）。あわせて起動時の注記
/// （`no longer declared by any workspace`）と、承認を外した宣言が再び「未承認」として扱われること。
fn revoke_case(case: &Case) {
    require_elevated(REVOKE_KEY);
    let ledger = super::fs_ledger_exclusive();
    let ws = case.workspace();
    let outside = case.outside();
    let value = case.declared_value();
    let store = PolicyApprovalStore::in_config_dir();

    // --- 前提: 付与のキーが残したもの ---
    let mut missing: Vec<String> = Vec::new();
    if let Err(e) = harness_policy::policy_file::load(&ws) {
        missing.push(format!("ワークスペースの`policy.json`が読めない: {e}"));
    }
    if !store
        .load()
        .is_approved(&ws, case.approved_declaration(&value))
    {
        missing.push(format!(
            "承認台帳に({}, {value}, read_exec)の承認が無い",
            case.approved_domain
        ));
    }
    let mut present: Vec<String> = Vec::new();
    match super::sid_aces(&outside, "S-1-15-3-") {
        Ok(aces) => present = aces,
        Err(e) => missing.push(format!("外のディレクトリのDACLを読めない: {e}")),
    }
    let mut before: Vec<String> = Vec::new();
    check_granted(&ledger, case, &ws, &present, &mut before);
    missing.extend(before);
    assert!(
        missing.is_empty(),
        "[{}] 撤収する前提が無い——**先に`dev-elevated-run.exe {GRANT_KEY}`を撃ち、緑を確かめてから**\
         この試験を撃つこと（付与の試験が残した状態を消す側である）:\n- {}",
        case.ws,
        missing.join("\n- ")
    );

    // --- 承認を外す（製品の取り消し。エディタの`unapprove`と同じ書き先） ---
    let left = store.revoke(&ws, &[case.approved_declaration(&value)]);
    assert!(left.is_empty(), "承認を承認台帳から消せなかった: {left:?}");

    // --- 起動し直す ---
    let revoked = observe(case, &ws, REVOKED_ARM, case.crosses_domains());
    let mut failures: Vec<String> = Vec::new();
    if !auto_revoke_listed(&revoked, &outside) {
        failures.push(format!(
            "自動撤収の注記（`no longer declared by any workspace`）の一覧に{}が載っていない\
             ——承認を外した宣言が「もう宣言されていない」と数えられていない",
            outside.display()
        ));
    }
    if revoked.stderr_has_line(&["auto-revoke failed"]) {
        failures.push("自動撤収が失敗を報告した（標準エラー）".to_string());
    }
    if !revoked.capability_aces.is_empty() {
        failures.push(format!(
            "**承認を外して起動し直しても、{}にcapability SID宛のACEが残っている**: {:?}",
            outside.display(),
            revoked.capability_aces
        ));
    }
    match ledger.entry_for_root(&outside) {
        Ok(None) => {}
        Ok(Some(row)) => failures.push(format!(
            "fs passthrough台帳の行が残っている（ACEを剥がしても記録が残ると、台帳が実体からずれる）: {row:?}"
        )),
        Err(e) => failures.push(format!("fs passthrough台帳を読めない: {e}")),
    }
    let still_minted = minted_subjects(case, &ws);
    if still_minted != 0 {
        failures.push(format!(
            "capability台帳に宣言の宛先が{still_minted}件残っている（BUG-148と同型: ACEは消えたのに索引が残る）"
        ));
    }
    if !revoked.shell_outside.starts_with("DENIED") {
        failures.push(format!(
            "承認を外した後も入口のシェルが外のファイルを読めた（{}）",
            revoked.shell_outside
        ));
    }
    if case.crosses_domains() {
        if !target_domain_refused_because(&revoked, SkipReason::NotApprovedOnThisMachine.describe())
        {
            failures.push(
                "承認を外した遷移先ドメインが「未承認なので用意しない」として断られていない"
                    .to_string(),
            );
        }
        let refused_as_unprovisioned = revoked.arm.denied_detail.iter().any(|(exe, why)| {
            exe.eq_ignore_ascii_case(&super::system_findstr_exe())
                && why.contains("TargetDomainNotProvisioned")
        });
        if !refused_as_unprovisioned {
            failures.push(format!(
                "`findstr`が「遷移先ドメインが用意されていない」で断られていない: {:?}",
                revoked.arm.denied_detail
            ));
        }
    } else if !warned_not_approved(&revoked, &value) {
        failures.push("承認を外した宣言について未承認の警告が出ていない".to_string());
    }

    if failures.is_empty() {
        // 成功したときだけ片付ける（失敗した回は調査のため残す。親ファイルの方針）。
        // 消すのは試験が作った入れ物だけで、ACE・承認・台帳の行は製品が消したことを上で確かめた。
        let _ = std::fs::remove_dir_all(&outside);
        let scratch = super::scratch_dir();
        for arm in case.grant_arms.iter().chain([REVOKED_ARM].iter()) {
            let name = case.arm_name(arm);
            super::cleanup_on_success(&ws, &[], &name);
            let _ = std::fs::remove_file(scratch.join(format!("{name}-spawnd.log")));
        }
    } else {
        eprintln!(
            "[{}] 失敗したので状態を残した。手で消すなら（昇格して）`harness fs revoke {}`、\
             それから{}と{}を消す",
            case.ws,
            outside.display(),
            outside.display(),
            ws.display()
        );
    }
    finish(case, &failures, &[&revoked]);
}

/// [3点目・入口] 承認を外した入口ドメインの宣言は、次の起動で取り消される。
/// 付与側は[`grant_an_entry_declaration_only_after_approval`]。
#[test]
#[ignore = "removes the approval left by e2e-policy-fs-grant and checks the auto-revoke; run through dev-elevated-run e2e-policy-fs-revoke"]
fn revoke_an_entry_declaration_whose_approval_was_removed() {
    revoke_case(&ENTRY_CASE);
}

/// [3点目・遷移先] 承認を外した遷移先ドメインの宣言は、次の起動で取り消され、そのドメインは用意されない。
/// 付与側は[`grant_a_target_domain_declaration_only_to_that_domain`]。
#[test]
#[ignore = "removes the approval left by e2e-policy-fs-grant and checks the auto-revoke; run through dev-elevated-run e2e-policy-fs-revoke"]
fn revoke_a_target_domain_declaration_whose_approval_was_removed() {
    revoke_case(&DOMAIN_CASE);
}
