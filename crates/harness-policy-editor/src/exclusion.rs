//! **候補にしてはいけないパスの判定を1箇所に集める**（[BUG-103](../../../docs/bugs/BUG-103.md)）。
//!
//! # なぜ1関数へ集めるのか
//!
//! 候補を作る経路は2つある——観測イベント（[`crate::aggregate::Aggregate::add_event`]）と、
//! 実行像・実行前診断（`add_exec_candidate`）。かつては除外がこの2つに別々に書かれており、
//! **片方にしか無い規則**が実害を出した（[BUG-099](../../../docs/bugs/BUG-099.md):
//! 「既定で実行できる場所は候補にしない」が実行像側にしか無く、読み取り候補が素通しになって
//! `cargo`ドメインのパス2が恒久的に落ちた）。規則を1つの型へ集め、両経路がそれを通る。
//!
//! # 判定は「観測時に在ったか」ではなく「次回も同じ名前で在るか」で書く
//!
//! BUG-103の根はここにある。既存の除外「探しに行ったが存在しなかったパス」
//! （[`crate::aggregate::Aggregate::excluded_missing_target`]）は**観測時の状態**を見るので、
//! `%TEMP%\.tmpX3JiLI\...`や`Packages\harness.shell.sandbox.<pid>-<時刻>\...`のような
//! **その実行限りの名前**は素通りする（記録中は実在するため）。実測では承認済み宣言2,425件のうち
//! 1,637件が「二度と存在しないパス」で、パス2のたびに`path does not exist, skipped`を
//! 1,320件出して⚠欄を埋めていた。
//!
//! # workspaceは「このセッションのもの」だけを外す
//!
//! `.harness`は**どのworkspaceのものでも**外す（P-08。harnessの制御ディレクトリへの許可を
//! 提案してよい理由がどこにも無い）が、workspace本体は違う——記録対象が**別のリポジトリ**を
//! 走査したときの候補は正当に承認対象である。外してよいのは「いま走らせているセッションの
//! workspace」だけで、その根拠は「パス2が起動時にツリー全体へRWXを付与済み」という事実
//! （D-54）にしかない。だから[`ExclusionRules`]はセッションごとに作る。

use std::path::{Path, PathBuf};

/// 候補にしなかった理由。**数え分けるためにあるので、混ぜない**（B-09/B-32:
/// どの理由で候補が消えたのかを説明できない文言にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Excluded {
    /// harnessの制御面（P-08）。**2つの綴りがある**——workspace内の`.harness`（どのworkspaceの
    /// ものでも）と、ユーザースコープの`%APPDATA%\harness`（台帳の置き場）。
    HarnessControlDir,
    /// `%LOCALAPPDATA%\Packages`配下＝**全MSIXアプリの専用データ置き場**。
    MsixPackageData,
    /// harness自身のAppContainerプロファイル配下
    /// （`%LOCALAPPDATA%\Packages\harness.shell.sandbox.<token>` /`harness.mcp.<token>.<id>`）。
    SandboxProfile,
    /// `C:/Windows`・`C:/Program Files`配下（D-58・BUG-099）。
    MachineWideRoot,
    /// **このセッションの**workspace配下（D-54で既にRWX付与済み）。
    SessionWorkspace,
    /// `%TEMP%`配下（実行ごとの刹那パス）。
    EphemeralTemp,
}

/// 1つの記録セッションぶんの除外規則。
///
/// **[`crate::aggregate::Aggregate`]はこれ無しでは作れない**（`Aggregate::new`の引数）。
/// 「このセッションのworkspaceはどこか」を全生成経路に必ず答えさせるためで、
/// 選ぶ自由を奪うのが目的である（B-06: 配線漏れをコンパイラに数えさせる）。
#[derive(Debug, Clone)]
pub struct ExclusionRules {
    /// このセッションのworkspace root（マニフェスト由来）。
    workspace_root: PathBuf,
    /// このマシンの`%TEMP%`。**解決できないことがあり得る**ので`Option`で持ち、
    /// 解決できないときは`%TEMP%`規則を適用しない（「分からない」を「該当しない」と
    /// 混ぜないため。誤って候補を消すより、出して見せる側へ倒す）。
    temp_root: Option<PathBuf>,
    /// harnessのユーザースコープ制御ディレクトリ（`%APPDATA%\harness`）。
    /// 綴りは[`harness_grant_ledger::config_dir`]から導く（B-05）。
    harness_user_dir: Option<PathBuf>,
    /// `%LOCALAPPDATA%\Packages`＝全MSIXアプリの専用データ置き場。
    msix_packages_root: Option<PathBuf>,
}

impl ExclusionRules {
    /// 記録セッション1件ぶんの規則を作る（`%TEMP%`等はこのプロセスの環境から取る）。
    pub fn for_session(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            temp_root: Some(std::env::temp_dir()),
            // 台帳の置き場は`<config_dir>`だが、除外は**その親**（`%APPDATA%\harness`）で掛ける
            // ——harnessが将来ここへ別のサブディレクトリを作っても、制御面である事実は同じ。
            harness_user_dir: harness_grant_ledger::config_dir()
                .and_then(|dir| dir.parent().map(Path::to_path_buf)),
            msix_packages_root: std::env::var_os("LOCALAPPDATA")
                .map(|local| PathBuf::from(local).join("Packages")),
        }
    }

    /// テスト用。**実マシンの環境に依存させない**ために明示で受ける。
    pub fn with_temp_root(workspace_root: &Path, temp_root: Option<&Path>) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            temp_root: temp_root.map(Path::to_path_buf),
            harness_user_dir: Some(PathBuf::from("C:/Users/test/AppData/Roaming/harness")),
            msix_packages_root: Some(PathBuf::from("C:/Users/test/AppData/Local/Packages")),
        }
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// このパスを候補にしてよいか。候補にしないなら理由を返す。
    ///
    /// **アクセス由来の候補（`fs.read`/`fs.read_write`）と実行像由来の候補（`fs.read_exec`）の
    /// 両方がここを通る。** access種別で判定を変えないのは、`preflight`が宣言されたパスの祖先へ
    /// traverseを付けに行く条件がaccessに依らないためである（BUG-099）。
    pub fn excluded(&self, path: &str) -> Option<Excluded> {
        // 1. harnessの制御面（P-08）。**綴りが2つある**。
        //    (a) workspace内の`.harness`（どのworkspaceのものでも外す）
        //    (b) ユーザースコープの`%APPDATA%\harness`——付与済みACEの台帳とMCPの承認台帳
        //        （D-39）の置き場。**サンドボックスから書けると自分の許可を書き換えられる。**
        //        実マシンではここに`(OI)(CI)(R,W,D)`が4件載っていた（BUG-103の追記）。
        //        (a)の判定はパス要素`.harness`しか見ないので、こちらは**別に書く必要がある**。
        if is_harness_control_path(path) {
            return Some(Excluded::HarnessControlDir);
        }
        if let Some(harness_dir) = self.harness_user_dir.as_deref() {
            if crate::approve::is_under(path, harness_dir) {
                return Some(Excluded::HarnessControlDir);
            }
        }
        // 2. harness自身のサンドボックスプロファイル。**`.harness`と同じ理由**（harnessの
        //    制御物）で外す。実測30件が承認され、候補の畳み込みで親の
        //    `AppData\Local\Packages`へ丸められて全MSIXアプリのデータ置き場へ
        //    `(OI)(CI)(R,W,D)`が付いた（P-01違反）。
        if is_sandbox_profile_path(path) {
            return Some(Excluded::SandboxProfile);
        }
        // 2.5. `%LOCALAPPDATA%\Packages`**そのものと配下全部**。ここは全MSIXアプリの専用データ
        //      置き場で、`pwsh`自身もStoreパッケージである。BUG-103の実害はまさにここへ
        //      `(OI)(CI)(R,W,D)`が付いたことだった（P-01）。
        //
        //      **上の2（プロファイル名の判定）だけでは足りない。** 候補の畳み込みは
        //      `Packages/harness.shell.sandbox.<token>/AC/...`を**親の`Packages`へ丸める**ので、
        //      候補として現れる値にはプロファイル名が含まれない——実マシンの`policy.json`には
        //      `C:/Users/segfo/AppData/Local/Packages`が`fs.read`と`fs.read_write`で宣言されており、
        //      最初の掃除でも残っていた（一般化後の値は元の値と別物、という当たり前の見落とし）。
        if let Some(packages) = self.msix_packages_root.as_deref() {
            if crate::approve::is_under(path, packages) {
                return Some(Excluded::MsixPackageData);
            }
        }
        // 3. マシン全体のインストール先（D-58・BUG-099）。判定は`breadth`と共有する（B-05）。
        if harness_policy::breadth::is_default_exec_root_path(path) {
            return Some(Excluded::MachineWideRoot);
        }
        // 4. このセッションのworkspace配下（D-54でツリー全体へRWX付与済み）。承認しても
        //    得るものが無く、逆にセッション台帳へ載って`end_session`が
        //    `revoke_ace_recursive`（実測30.8秒）を回すことになる。
        if crate::approve::is_under(path, &self.workspace_root) {
            return Some(Excluded::SessionWorkspace);
        }
        // 5. `%TEMP%`配下。名前にPID・時刻・乱数を含む刹那的なパスの巣で、**次回は存在しない**。
        //    `%TEMP%`そのものも外す——ユーザーの一時ディレクトリ全体への継承つきRWDは
        //    他アプリの一時ファイルへの読み書き削除を渡すことであり（P-01）、しかも
        //    撤収はツリー全walkなので剥がしきれない（BUG-103の実測）。
        if let Some(temp_root) = self.temp_root.as_deref() {
            if crate::approve::is_under(path, temp_root) {
                return Some(Excluded::EphemeralTemp);
            }
        }
        None
    }
}

/// `.harness`（harnessの制御ディレクトリ）配下のパスか。
///
/// パス**要素**として`.harness`を持つかで判定する。前方一致で
/// `<このworkspace>/.harness`だけを見ると、記録対象が別のリポジトリを走査したときに
/// そちらの`.harness`を拾ってしまう——どのworkspaceのものであれ、harnessの制御
/// ディレクトリへの許可を提案してよい理由は無い。
pub fn is_harness_control_path(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|component| component.eq_ignore_ascii_case(".harness"))
}

/// harness自身のAppContainerプロファイル（`%LOCALAPPDATA%\Packages\<プロファイル名>`）配下か。
///
/// **綴りの正本は`harness_sandbox`側**（`session_profile::token_of_profile`）で、
/// `harness.shell.sandbox.<token>`と`harness.mcp.<token>.<server-id>`の両方を1関数で見分ける。
/// ここで`"harness.shell.sandbox"`と書き写すと、プロファイル名の形が変わったときに
/// 静かにずれる（B-05: 型で守れない複製は実行時にずれる）。
pub fn is_sandbox_profile_path(path: &str) -> bool {
    path.split(['/', '\\']).any(|component| {
        harness_sandbox::tier2a::session_profile::token_of_profile(component).is_some()
    })
}

#[cfg(test)]
#[path = "exclusion_tests.rs"]
mod exclusion_tests;
