//! [BUG-160] **Daemon経由で起こした子の環境が、AppContainerの置き換えを二重に受ける**。
//!
//! # 何を測っているのか
//!
//! Windowsは、AppContainerの属性を付けて起こしたプロセスの環境ブロックの中で、
//! パッケージ専用の場所を指す変数（`TEMP`等）を書き換える。**harnessのコードは
//! これらの変数を1文字も書いていない**——書き換えているのはOSである。
//!
//! 属性を付けるのは「AppContainerの外から起こす」ときだけなので、
//!
//! ```text
//!   シェル自身が起こす子     : 属性なし → 置き換え0回（シェルの値をそのまま継ぐ）
//!   Daemonが代理で起こす子   : 属性あり → 置き換え1回（**シェルの値は置き換え済み**）
//! ```
//!
//! となり、後者だけが**同じ置き換えを2回**受ける。
//!
//! # 変える軸は1つだけである（生成経路）
//!
//! | 腕 | 生成禁止 | 宣言 | 誰が`cmd.exe`を起こすか |
//! |---|---|---|---|
//! | `shell-spawned` | 積まない | 無し | **プローブ自身**（フックは横取りしない） |
//! | `daemon-spawned` | 積む | `cmd.exe` | **Spawn Daemon**（フックが頼む） |
//!
//! プロファイル（＝パッケージ）はテストプロセスに1つなので、両腕とも同じ
//! `…\Packages\<pkg>\AC\…`を根に持つ。**だから値の差は生成経路の差だけを表す。**
//!
//! # 計器の限界（**判定に使っていないもの**）
//!
//! - **`cmd.exe`自身が足す変数**（`PROMPT`・`=C:`等）は両腕に等しく載るので、
//!   差分を取ると消える。**片腕だけを読んだら消えない**ので、必ず差分で読むこと
//! - **ワークスペースは腕ごとに別**である（`setup_*`が毎回作る）。
//!   ワークスペースのパスを値に持つ変数は、この測定では比べられない
//! - **親の環境そのもの**ではなく、**親が直接起こした子**の環境を親の代表として使っている。
//!   `cmd.exe`は`lpEnvironment`を`NULL`で起こされる（フックが横取りしないので逐語の継承）

use std::collections::{BTreeMap, BTreeSet};

use super::transition_acceptance_tests::{cmd_exe, policy_with_edges};
use super::transparent_hook_tests::run_probe_with_hooks;
use super::*;

/// **二重置き換えの印**。パッケージ配下を表す区切りが、**1つのパスの中に**2回以上あれば、
/// 同じ置き換えが重ねて掛かっている。
///
/// 正しい値は`…\AppData\Local\Packages\<pkg>\AC\…`で**1回**である。
///
/// > **`;`で割ってから数える。** `PATH`のように複数のパスを並べる変数は、
/// > 別々の要素がそれぞれ1回ずつ持つことがある（この機の`PATH`が実際にそうで、
/// > 割らずに数えると**壊れていない`PATH`が二重に見える**）。
const PACKAGES_SEGMENT: &str = r"\Packages\";

/// 生成経路と**関係なく**腕ごとに違う変数。
///
/// `setup_*`は腕ごとに新しいワークスペースとDaemonを作るので、その名前を値に持つ変数は
/// 必ず違う。**差分の判定から外すのはこの3つだけ**で、それ以外に差があれば
/// 生成経路が環境を変えたということである。
///
/// **名指しで外す**——「HARNESS_で始まるものを外す」のような括り方にすると、
/// 新しく増えた変数が黙って判定から落ちる。
const DIFFERS_BY_ARM_NOT_BY_PATH: &[&str] = &[
    // ワークスペースそのもの。
    "HARNESS_COW_WORKSPACE",
    // ワークスペースの中に置く診断の受け皿（`run_probe_with_hooks`が張る）。
    "HARNESS_REDIRECTOR_DEBUG_LOG",
    // Daemonの窓口。腕ごとに別のDaemonが起きるので名前が違う。
    "HARNESS_SPAWN_REQUEST_PIPE",
];

/// 子の`stdout`へ落とした`set`の出力を、名前→値の表にする。
///
/// **大小を畳んでキーにする。** Windowsの環境変数名は大小を区別しないので、
/// 綴りが揺れた回に「別の変数」として並んでしまうと差分が嘘になる。
fn parse_set_output(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        // `=C:=C:\...`のような、cmdが持つ「隠し変数」も**そのまま入れる**
        // （両腕に等しく載るので差分で消える。落とすと落とし方のほうを疑うことになる）。
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        map.insert(name.to_ascii_uppercase(), value.to_string());
    }
    map
}

/// `cmd.exe`へ1本のコマンドラインを渡して起こし、**その子が書いた標準出力**を返す。
///
/// `lpApplicationName`は渡さない（`--spawn-image`を指定しない）——実行ファイルの解決まで
/// フックの仕事にするのが、透過の本体である（段階6f-2と同じ形）。
fn run_cmd_line(
    case: &Case,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    label: &str,
    tail: &str,
) -> String {
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let out_file = workspace.join(format!("{label}.txt"));
    let command_line = format!("\"{}\" /c {tail}", cmd_exe());

    let (report, err) = run_probe_with_hooks(
        case,
        profile,
        caps,
        &[
            "--spawn-transparently",
            "none",
            "--spawn-command-line",
            &command_line,
            "--spawn-stdout",
            &out_file.to_string_lossy(),
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[BUG-160 {label}] report={report}\nstderr={err}");

    // **UTF-8として読まない。** `set`の出力はコンソールのコードページ（この機では932）で
    // 落ちるので、`read_to_string`は非ASCIIの値が1つあるだけで丸ごと失敗する。
    // 比べたいのはパスの綴り（ASCII）なので、読めない部分は置換文字のままでよい。
    let raw = std::fs::read(&out_file).unwrap_or_default();
    String::from_utf8_lossy(&raw).into_owned()
}

/// 1つの腕を最後まで回して、**その腕が見た環境**を返す。
///
/// `restricted`が生成経路を決める唯一の軸である——積めばフックがDaemonへ頼み、
/// 積まなければプローブ自身が起こす。
fn env_seen_by_the_child(label: &str, restricted: bool) -> BTreeMap<String, String> {
    let policy = if restricted {
        ChildProcessPolicy::Restricted
    } else {
        ChildProcessPolicy::Unrestricted
    };
    let (case, profile, caps) =
        setup_with_policy_and_transitions(&format!("spawnd-bug160-{label}"), policy, |_workspace| {
            if restricted {
                policy_with_edges(E2E_POLICY_DOMAIN, &[&cmd_exe()])
            } else {
                harness_policy::policy_file::PolicyFile::default()
            }
        });
    let text = run_cmd_line(&case, &profile, &caps, label, "set");
    let env = parse_set_output(&text);
    assert!(
        // **計器を疑う。** `set`が1行も落ちていない回は、比べるものが無い
        // ——「差が無い」と「測れていない」を取り違えないために、ここで落とす。
        env.contains_key("PATH"),
        "`{label}`の腕で`set`の出力が取れていない。子が起きていないか、\
         標準出力が呼び出し元のハンドルへ落ちていない（＝BUG-160より手前の壊れ方である）: \
         {text:?}"
    );
    drop(case);
    env
}

/// パッケージ配下の区切りが**1つのパスの中に**2回以上現れる値を拾う
/// （＝置き換えが重なっている）。
fn doubly_substituted(env: &BTreeMap<String, String>) -> BTreeSet<String> {
    env.iter()
        .filter(|(_, value)| {
            value
                .split(';')
                .any(|element| element.matches(PACKAGES_SEGMENT).count() >= 2)
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// **BUG-160の対の1本目**: Daemon経由で起きた子の環境が、シェルが直接起こした子と一致する。
///
/// # なぜ`TEMP`だけを見ないのか
///
/// OSが書き換えるのは`TEMP`1つとは限らない。**1つだけ直すと、残りが「別の症状」として
/// 後から出る**ので、丸ごと突き合わせて**二重になっているものを数える**。
///
/// # これだけでは足りない（対の2本目が要る理由）
///
/// 一致だけを見ると、**剥がしすぎて両腕とも同じ誤った場所を指した**ときにも緑になる。
/// 実際に一時ファイルを作れることは
/// [`the_daemon_spawned_child_can_create_a_temp_file`]が見る。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_daemon_spawned_child_sees_the_same_environment_as_the_shell() {
    // **対照を先に取る**（型: 計器を疑う）。こちらが壊れていたら、比べる相手が無い。
    let shell_spawned = env_seen_by_the_child("shell-spawned", false);
    let daemon_spawned = env_seen_by_the_child("daemon-spawned", true);

    // **差分を全部出してから判定する。** 落ちたときに「どれが二重か」を数え直せる唯一の場所である。
    //
    // **片側にしか無い名前も差として数える。** 値の食い違いだけを見ると、
    // 「子から消えた」が差0件として通ってしまう。
    let mut differing_names: Vec<String> = Vec::new();
    let mut differing: Vec<String> = Vec::new();
    let names: BTreeSet<&String> = shell_spawned.keys().chain(daemon_spawned.keys()).collect();
    for name in names {
        let shell_value = shell_spawned.get(name);
        let daemon_value = daemon_spawned.get(name);
        if shell_value == daemon_value {
            continue;
        }
        differing_names.push(name.clone());
        differing.push(format!(
            "  {name}\n    shell : {}\n    daemon: {}",
            shell_value.map(String::as_str).unwrap_or("(無し)"),
            daemon_value.map(String::as_str).unwrap_or("(無し)")
        ));
    }
    eprintln!(
        "[BUG-160] shell-spawned={}件 daemon-spawned={}件 差={}件\n{}",
        shell_spawned.len(),
        daemon_spawned.len(),
        differing.len(),
        differing.join("\n")
    );

    let doubled = doubly_substituted(&daemon_spawned);
    let doubled_in_shell = doubly_substituted(&shell_spawned);
    eprintln!(
        "[BUG-160] 二重置き換え: daemon-spawned={doubled:?} / shell-spawned={doubled_in_shell:?}"
    );

    // **対照の側にも同じ表明を置く。** こちらが二重なら、二重にしているのは
    // 生成経路ではなく`preflight`かharnessが組んだ環境である（＝原因の場所が違う）。
    assert!(
        doubled_in_shell.is_empty(),
        "シェルが直接起こした子の環境が既に二重になっている。\
         **原因はDaemonの経路ではない**——harnessが組んだ環境か、\
         トップレベルの生成が2回置き換えを受けている: {doubled_in_shell:?}"
    );
    assert!(
        doubled.is_empty(),
        "Daemon経由で起きた子の環境が、AppContainerの置き換えを二重に受けている（BUG-160）。\
         二重になった変数: {doubled:?}"
    );

    // **本命はこちらである。** 上の2つは「二重の形」しか見ておらず、
    //
    // 1. 剥がし方を間違えて**まったく別の場所**を指した回
    // 2. OSが**別の名前**を書き換え始めた回（`os_rewritten_env_names`の一覧が古くなる）
    //
    // のどちらも素通りする。**説明できない差が1件でもあれば赤**にすれば、両方で止まる。
    let unexplained: Vec<&String> = differing_names
        .iter()
        .filter(|name| {
            !DIFFERS_BY_ARM_NOT_BY_PATH
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .collect();
    assert!(
        unexplained.is_empty(),
        "**生成経路しか変えていないのに、環境に説明の付かない差がある**（BUG-160）。\
         差の付いた変数: {unexplained:?}\n\
         `TEMP`・`TMP`・`LOCALAPPDATA`ならAppContainerの置き換えが二重に掛かっている。\
         **それ以外の名前が出たなら、OSが書き換える名前が増えた**\
         ——`os_rewritten_env_names`へ足すこと。\n{}",
        differing.join("\n")
    );
}

/// **BUG-160の対の2本目**: Daemon経由で起きた子が、**実際に一時ファイルを作れる**。
///
/// # 1本目だけでは足りない
///
/// 値が一致していても、その値が**存在しない場所**を指していれば一時ファイルは作れない。
/// 「剥がす」直し方は剥がしすぎる形の失敗を持つので、**書けることを別に見る**。
///
/// # 対で撃つ（`B-35`）
///
/// シェルが直接起こした子でも同じことをする。**そちらが書けないなら、
/// 測っているのはBUG-160ではなくワークスペースやACLの事故である。**
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_daemon_spawned_child_can_create_a_temp_file() {
    const MARKER: &str = "BUG160-TEMP-WRITABLE";

    // `%TEMP%`は**子の中で**展開させる（ここで解決すると、測るのは親の値になる）。
    //
    // 末尾の`cd`は**作業ディレクトリを一緒に出すため**である（判定はしない）。
    // 2026-09-19の`e2e-git-config-transition`で、Daemon経由の子に渡った相対パスが
    // ワークスペースではない場所へ解決された形跡があり、**同じ「許可されたのに動かない」の
    // 仲間に見える**。値を出しておかないと、次に疑う人がまた1往復することになる。
    let tail =
        format!(r#"echo {MARKER} 1>"%TEMP%\bug160-probe.txt" & type "%TEMP%\bug160-probe.txt" & cd"#);

    let mut seen: Vec<(&'static str, String)> = Vec::new();
    for (label, restricted) in [("shell-spawned", false), ("daemon-spawned", true)] {
        let policy = if restricted {
            ChildProcessPolicy::Restricted
        } else {
            ChildProcessPolicy::Unrestricted
        };
        let (case, profile, caps) = setup_with_policy_and_transitions(
            &format!("spawnd-bug160-temp-{label}"),
            policy,
            |_workspace| {
                if restricted {
                    policy_with_edges(E2E_POLICY_DOMAIN, &[&cmd_exe()])
                } else {
                    harness_policy::policy_file::PolicyFile::default()
                }
            },
        );
        let written = run_cmd_line(&case, &profile, &caps, &format!("temp-{label}"), &tail);
        eprintln!("[BUG-160 temp {label}] child stdout={written:?}");
        seen.push((label, written));
        drop(case);
    }

    let output_of = |label: &str| -> String {
        seen.iter()
            .find(|(l, _)| *l == label)
            .map(|(_, o)| o.clone())
            .unwrap_or_default()
    };

    // **対照が先である。** こちらが書けないなら、`%TEMP%`そのものが使えない機なので
    // Daemon側の結果は何も意味しない。
    let shell = output_of("shell-spawned");
    assert!(
        shell.contains(MARKER),
        "シェルが直接起こした子が`%TEMP%`へ書けていない。\
         **測っているのはBUG-160ではない**（AppContainerのTempそのものが使えない）: {shell:?}"
    );

    let daemon = output_of("daemon-spawned");
    assert!(
        daemon.contains(MARKER),
        "Daemon経由で起きた子が`%TEMP%`へ書けていない（BUG-160）。\
         `TEMP`が存在しないパスを指しているので、一時ファイルを作るプログラムが\
         **許可されたのに動かない**: {daemon:?}（シェル経由では書けている: {shell:?}）"
    );
}
