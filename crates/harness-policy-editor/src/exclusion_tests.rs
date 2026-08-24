//! [`crate::exclusion`]の単体テスト。
//!
//! **禁止側と許可側を必ず対で置く**（B-35）。除外の判定が過剰に効くと、症状は「候補が空」と
//! いう静かな形で出る——禁止側だけのテストは、規則が効きすぎているときも通ってしまう。

use super::*;

const WS: &str = "C:/Users/segfo/Documents/AI/harness";
const TEMP: &str = "C:/Users/segfo/AppData/Local/Temp";
/// `with_temp_root`が入れる固定値（実マシンの環境に依存させないため）。
const HARNESS_USER_DIR: &str = "C:/Users/test/AppData/Roaming/harness";
const PACKAGES: &str = "C:/Users/test/AppData/Local/Packages";

fn rules() -> ExclusionRules {
    ExclusionRules::with_temp_root(Path::new(WS), Some(Path::new(TEMP)))
}

// ---------------------------------------------------------------------------
// 禁止側（候補にしない）
// ---------------------------------------------------------------------------

/// `%TEMP%`配下の刹那パス。実マシンの`policy.json`に実際に入っていた綴りを使う。
#[test]
fn ephemeral_temp_paths_are_excluded() {
    let rules = rules();
    for path in [
        "C:/Users/segfo/AppData/Local/Temp/.tmpX3JiLI/ledger.json",
        "C:/Users/segfo/AppData/Local/Temp/__PSScriptPolicyTest_putqt4hm.545.ps1",
        // `upper`のままなのは、これが**そのとき実際に観測された綴り**だからである
        // （差分層の呼び名はD-83で`diff_layer`へ改めたが、記録済みの実データは書き換えない）。
        r"C:\Users\segfo\AppData\Local\Temp\.tmpzs5yPG\upper\.git",
        // `%TEMP%`そのもの（fs.read_writeで宣言され、`(OI)(CI)(R,W,D)`の出所になっていた）
        "C:/Users/segfo/AppData/Local/Temp",
        "C:/Users/segfo/AppData/Local/Temp/",
    ] {
        assert_eq!(
            rules.excluded(path),
            Some(Excluded::EphemeralTemp),
            "must not be offered as a candidate: {path}"
        );
    }
}

/// harness自身のサンドボックスプロファイル（`.harness`と同じ制御物、P-08）。
#[test]
fn sandbox_profile_paths_are_excluded() {
    let rules = rules();
    for path in [
        "C:/Users/segfo/AppData/Local/Packages/harness.shell.sandbox.40892-1786361881/AC/Temp/x",
        r"C:\Users\segfo\AppData\Local\Packages\harness.shell.sandbox.1234-5678",
        // MCPサーバ用プロファイルも同じ規則で外れる（綴りは`token_of_profile`が持つ）。
        "C:/Users/segfo/AppData/Local/Packages/harness.mcp.1234-5678.docs/AC/x",
    ] {
        assert_eq!(
            rules.excluded(path),
            Some(Excluded::SandboxProfile),
            "harness's own sandbox profile must not be a candidate: {path}"
        );
    }
}

/// [BUG-103追記] **`%LOCALAPPDATA%\Packages`そのものと、他アプリのパッケージデータ。**
///
/// プロファイル名の除外だけでは足りません——`--generalize dir`が
/// `Packages/harness.shell.sandbox.<token>/AC/...`を**親の`Packages`へ丸める**ので、
/// 実際に承認されて実マシンに`(OI)(CI)(R,W,D)`を残していたのは
/// **プロファイル名を含まない値**（`…/AppData/Local/Packages`）でした。
#[test]
fn the_msix_package_data_root_is_excluded_even_without_a_profile_name() {
    let rules = rules();
    for path in [
        PACKAGES,
        "C:/Users/test/AppData/Local/Packages/",
        // 他アプリの専用データ（pwsh自身もStoreパッケージ＝射程内）。
        "C:/Users/test/AppData/Local/Packages/SomeOtherApp_8wekyb3d8bbwe/LocalState/x",
    ] {
        assert_eq!(
            rules.excluded(path),
            Some(Excluded::MsixPackageData),
            "every MSIX app's private data must stay out of the candidate list: {path}"
        );
    }
}

/// [BUG-103追記] **harnessの制御面は綴りが2つある。**
///
/// `<workspace>/.harness`（パス要素で判定）と、ユーザースコープの`%APPDATA%\harness`
/// （台帳の置き場）。後者は前者の判定では**絶対に拾えません**——実マシンでは
/// `%APPDATA%\harness\config`に`(OI)(CI)(R,W,D)`が4件載っており、そこには
/// 付与済みACEの台帳とMCPの承認台帳（D-39）がありました。
#[test]
fn the_user_scope_harness_control_directory_is_excluded_too() {
    let rules = rules();
    for path in [
        HARNESS_USER_DIR,
        "C:/Users/test/AppData/Roaming/harness/config",
        "C:/Users/test/AppData/Roaming/harness/config/fs-passthrough-ledger.json",
        r"C:\Users\test\AppData\Roaming\harness\config\mcp-approval-ledger.json",
    ] {
        assert_eq!(
            rules.excluded(path),
            Some(Excluded::HarnessControlDir),
            "harness's own ledgers must never be offered as a candidate: {path}"
        );
    }
    // 対（B-35）: 名前が似ているだけの別物は巻き込まない。
    assert_eq!(
        rules.excluded("C:/Users/test/AppData/Roaming/harness-notes/x.md"),
        None
    );
}

/// このセッションのworkspace配下（D-54で既にRWX付与済み）。
#[test]
fn paths_under_this_sessions_workspace_are_excluded() {
    let rules = rules();
    for path in [
        "C:/Users/segfo/Documents/AI/harness/src/lib.rs",
        r"C:\Users\segfo\Documents\AI\harness\target\debug\harness.exe",
        // workspace root自身。
        "C:/Users/segfo/Documents/AI/harness",
    ] {
        assert_eq!(
            rules.excluded(path),
            Some(Excluded::SessionWorkspace),
            "the session workspace is already granted RWX: {path}"
        );
    }
}

/// 既存の2規則（`.harness`・マシン全体のインストール先）も同じ関数を通る。
#[test]
fn the_existing_two_rules_still_apply_through_the_same_function() {
    let rules = rules();
    assert_eq!(
        rules.excluded("C:/other-repo/.harness/settings.json"),
        Some(Excluded::HarnessControlDir),
        "P-08: any workspace's .harness"
    );
    assert_eq!(
        rules.excluded("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/x.txt"),
        Some(Excluded::MachineWideRoot),
        "BUG-099"
    );
}

// ---------------------------------------------------------------------------
// 許可側（候補に残る）——ここが落ちると「除外が効きすぎ」を検出できない（B-35）
// ---------------------------------------------------------------------------

/// **別のリポジトリ配下は正当な承認対象。** workspaceの除外は「このセッションのもの」限定で、
/// `.harness`の扱い（どのworkspaceでも外す）とは違う。
#[test]
fn another_repository_stays_a_candidate() {
    let rules = rules();
    assert_eq!(rules.excluded("C:/other-repo/src/lib.rs"), None);
    assert_eq!(rules.excluded("D:/work/project/Cargo.toml"), None);
}

/// workspace外の実行ファイル・依存ディレクトリ（承認の主対象）。
#[test]
fn ordinary_paths_outside_the_workspace_stay_candidates() {
    let rules = rules();
    for path in [
        "C:/Users/segfo/.cargo/bin/cargo.exe",
        "C:/Users/segfo/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe",
        "C:/tools/ninja.exe",
        "C:/Users/segfo/AppData/Local/Programs/Microsoft VS Code/Code.exe",
    ] {
        assert_eq!(rules.excluded(path), None, "must stay a candidate: {path}");
    }
}

/// **前方一致するだけの兄弟を巻き込まない。** `C:/ws2`は`C:/ws`の配下ではない。
#[test]
fn sibling_paths_that_merely_share_a_prefix_stay_candidates() {
    let rules = rules();
    assert_eq!(
        rules.excluded("C:/Users/segfo/Documents/AI/harness-notes/memo.md"),
        None,
        "a sibling directory whose name starts with the workspace name is not inside it"
    );
    assert_eq!(
        rules.excluded("C:/Users/segfo/AppData/Local/Temp2/keep-me.txt"),
        None,
        "Temp2 is not under Temp"
    );
    assert_eq!(
        rules.excluded("C:/Users/segfo/AppData/Local/Packages/harness.shell.sandboxes/x"),
        None,
        "a directory that merely starts with the profile prefix is not a profile"
    );
}

/// `%TEMP%`を解決できないときは`%TEMP%`規則を適用しない（「分からない」を「該当しない」と
/// 混ぜない。誤って候補を消すより、出して見せる側へ倒す）。
#[test]
fn without_a_known_temp_root_the_temp_rule_does_not_fire() {
    let rules = ExclusionRules::with_temp_root(Path::new(WS), None);
    assert_eq!(
        rules.excluded("C:/Users/segfo/AppData/Local/Temp/.tmpX3JiLI/ledger.json"),
        None
    );
}

// ---------------------------------------------------------------------------
// 判定関数そのもの
// ---------------------------------------------------------------------------

#[test]
fn harness_control_paths_are_matched_by_component_not_by_prefix() {
    assert!(is_harness_control_path("C:/work/.harness/settings.json"));
    assert!(is_harness_control_path(r"C:\work\.HARNESS\settings.json"));
    assert!(is_harness_control_path("C:/other-repo/.harness/x"));
    assert!(!is_harness_control_path("C:/work/.harnessrc"));
    assert!(!is_harness_control_path("C:/work/harness/settings.json"));
    assert!(!is_harness_control_path("C:/work/src/lib.rs"));
}

/// プロファイル名の綴りは`harness_sandbox`側と**同じ関数**で判定する（B-05）。
#[test]
fn sandbox_profile_components_come_from_the_sandbox_crate() {
    assert!(is_sandbox_profile_path(
        "C:/x/Packages/harness.shell.sandbox.1-2/AC"
    ));
    assert!(is_sandbox_profile_path(
        "C:/x/Packages/harness.mcp.1-2.docs"
    ));
    assert!(!is_sandbox_profile_path(
        "C:/x/Packages/harness.shell.sandbox"
    ));
    assert!(!is_sandbox_profile_path("C:/x/Packages/other.app_8wekyb"));
}
