//! セッションID → オーバーレイの置き場、の写像（**この写像の唯一の宣言点**）。
//!
//! 1つのセッションが持つオーバーレイは、モードによって置き場が違う。
//!
//! | モード | オーバーレイの位置 |
//! |---|---|
//! | `--live`（既定） | 無し（オーバーレイを使わない） |
//! | `--staged` / `--workspace-commit` | workspace内 `.harness/sandbox/<session-id>/` |
//! | `--sandbox tier2a-cow`（D-30、Windows） | workspace外 `%LOCALAPPDATA%\harness\data\cow\<session-id>\` |
//!
//! この対応は起動時（`harness-cli`の`startup::sandbox`）だけでなく、**セッション切替
//! （`/sessions`・`/fork`）のたびにTUIからも引かれる**。以前は`harness-cli`の中にあったため
//! `harness-tui`（`harness-cli`へは依存できない）から引けず、同じ`ProjectDirs::…join("cow")`が
//! 2箇所へ複製されていた——型で守れない複製は静かにずれる（`bug-pattern-rules` B-05）ので、
//! 両方が依存できるこのクレートへ降ろして1本にした。
//!
//! ## `ScopeTemplate`が「モードはプロセス寿命で不変」を型で表す
//!
//! セッションを切り替えてもステージングモードは変わらない。Tier2aのアクセス形状（workspaceが
//! RWXかROか）は起動時の`preflight`が確定し、capability・ACE・モードmutex
//! （`tier2a::workspace_ledger::begin_workspace_mode`）がそれに紐付いているためである。
//! [`ScopeTemplate`]を一度作って使い回す形にしてあるのは、切替のたびにモードを渡し直す
//! 呼び出し側が「ここでモードも変えられる」と誤解しないようにするためでもある。

use std::path::{Path, PathBuf};

use harness_core::{StagingConfig, StagingMode};

/// ワークスペースパスの綴りを揃える（**起動時も`/workspace`もこの1関数を通す**）。
///
/// `\\?\`（verbatim）前置を落とし、`.`/`..`を字句的に畳んで絶対化する。
///
/// **`canonicalize`は使わない。** あれはシンボリックリンク/ジャンクションを辿るため、ACEを
/// 付ける対象がリンク自身からリンク先へすり替わる（境界の意味が変わる）。ここで欲しいのは
/// 綴りを揃えることだけなので、FSを一切触らない`std::path::absolute`（`GetFullPathNameW`相当）
/// を使う。verbatim前置は`absolute`が素通しする仕様なので、共有ヘルパで先に落とす。
///
/// 規則を2つ持つと「`.`で入ったときだけ台帳のキーがずれる」形の穴になる（BUG-066・BUG-068は
/// どちらもこの綴り揺れが原因だった。`bug-pattern-rules` B-19）。
pub fn normalize_workspace_root(raw: &Path) -> PathBuf {
    let stripped =
        harness_change_ledger::path_rules::normalize_root_spelling(&raw.to_string_lossy());
    let stripped = PathBuf::from(stripped);
    // 失敗するのは空パス等の異常時のみ。**元の値を黙って捨てない**（後段のエラーメッセージが
    // ユーザーの打った綴りを指せるように）。
    std::path::absolute(&stripped).unwrap_or(stripped)
}

/// `--staged`/`--workspace-commit`のオーバーレイを置くworkspace内ディレクトリ（workspace相対）。
pub fn sandbox_dir_for_session(session_id: &str) -> PathBuf {
    PathBuf::from(".harness").join("sandbox").join(session_id)
}

/// CoW upper群の共通の親（`%LOCALAPPDATA%\harness\data\cow`）。
///
/// workspace外に置くのは、再帰的なパスマッピングを防ぎ、`.harness`のPROTECTED DACL
/// （`protect_harness_control_dir_from_appcontainer`）と衝突させないためである
/// （`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §9）。
/// `data_local_dir()`は`%LOCALAPPDATA%\harness\data`で、台帳群が使う`config_dir()`
/// （`%APPDATA%\harness\config`）とは別系統。
pub fn cow_upper_root() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.data_local_dir().join("cow"))
}

/// `--sandbox tier2a-cow`（D-30）のCoW upper実体を置く場所。
pub fn cow_upper_dir_for_session(session_id: &str) -> Option<PathBuf> {
    cow_upper_root().map(|root| root.join(session_id))
}

/// このプロセスがどのオーバーレイ機構で動いているか。**プロセス寿命で不変**（モジュールdoc参照）。
///
/// # なぜ列挙なのか（`cow: bool`と`staging_mode`の2フィールドではない）
///
/// マニフェスト方式（`--staged`/`--workspace-commit`）とCoW方式（`--sandbox tier2a-cow`）は
/// **別々の書込捕捉機構**で、同時には立たない。以前は`{ staging_mode, cow: bool }`という
/// 積の形で持ち、「両方立つことはない」根拠を**clapの`conflicts_with_all`**に置いていた。
/// その根拠はもう無い——`--sandbox`は値フラグなので「特定の値のときだけ排他」をclapで
/// 宣言できず、拒否は実行時（`harness-cli`の`resolve_staging_and_write_mode`）へ移った。
///
/// 遠くの実行時判定に不変条件を預けるのをやめ、**そもそも書けない形**にしてある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeTemplate {
    /// マニフェスト方式。[`StagingMode::Live`]（オーバーレイ無し）もここに含む。
    Staging(StagingMode),
    /// CoW方式（D-30）。**`StagingMode`を持たない**——CoWのときステージングモードは必ず
    /// `Live`だからで、持たせないことが「CoWかつ`--staged`」を書けなくしている。
    Cow,
}

/// あるセッションのオーバーレイの置き場。`ToolCtx`の該当2フィールドと1:1に対応する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionScope {
    /// **オーバーレイの持ち主**のセッションID。会話のセッションID（`SessionStore::id()`）とは
    /// 一致しないことがある——`/clear`は会話だけを捨ててオーバーレイを引き継ぐため。
    /// UIはこの値を表示して食い違いを見せる責務を持つ。
    pub session_id: String,
    pub staging: StagingConfig,
    pub cow_upper_dir: Option<PathBuf>,
}

impl SessionScope {
    /// オーバーレイを使わない（`--live`）か。切替を要求されても何もすることが無い。
    pub fn is_live(&self) -> bool {
        self.staging.sandbox_dir.is_none() && self.cow_upper_dir.is_none()
    }

    /// オーバーレイ実体の絶対パス（`--live`なら`None`）。`--staged`はworkspace相対で持つので、
    /// 表示・コピー・存在確認のために`workspace_root`と結合する必要がある。
    pub fn overlay_dir(&self, workspace_root: &Path) -> Option<PathBuf> {
        if let Some(cow) = &self.cow_upper_dir {
            return Some(cow.clone());
        }
        self.staging
            .sandbox_dir
            .as_ref()
            .map(|rel| workspace_root.join(rel))
    }
}

impl ScopeTemplate {
    /// `harness-cli`の起動パイプラインが確定した2値から作る。
    ///
    /// **`WorkspaceWriteMode`を先に見る。** `Cow`ならステージングモードは`Live`のはずで、
    /// そのことは`resolve_staging_and_write_mode`が保証している（`--staged`との併用を拒否する）。
    pub fn new(
        write_mode: &crate::shell_tier::WorkspaceWriteMode,
        staging_mode: StagingMode,
    ) -> Self {
        match write_mode {
            crate::shell_tier::WorkspaceWriteMode::Cow { .. } => ScopeTemplate::Cow,
            crate::shell_tier::WorkspaceWriteMode::DirectRw => ScopeTemplate::Staging(staging_mode),
        }
    }

    /// セッションIDからそのセッションのオーバーレイ位置を引く。
    ///
    /// CoWで`%LOCALAPPDATA%`が解決できない異常環境では`cow_upper_dir`が`None`になるが、
    /// **起動時に`resolve_staging_and_write_mode`が同じ条件で起動を拒否している**ので、
    /// ここへ到達する時点では解決できることが保証されている（できなければ`is_live()`が真になり、
    /// 切替は「オーバーレイを使わない」として断られる＝安全側）。
    pub fn scope_for(&self, session_id: &str) -> SessionScope {
        let (staging, cow_upper_dir) = match self {
            ScopeTemplate::Cow => (
                StagingConfig {
                    // CoWのステージングモードは常に`Live`（マニフェスト方式との併用は拒否済み）。
                    mode: StagingMode::Live,
                    sandbox_dir: None,
                },
                cow_upper_dir_for_session(session_id),
            ),
            ScopeTemplate::Staging(mode) => {
                let sandbox_dir = match mode {
                    StagingMode::Live => None,
                    StagingMode::Staged | StagingMode::WorkspaceCommit => {
                        Some(sandbox_dir_for_session(session_id))
                    }
                };
                (
                    StagingConfig {
                        mode: *mode,
                        sandbox_dir,
                    },
                    None,
                )
            }
        };
        SessionScope {
            session_id: session_id.to_string(),
            staging,
            cow_upper_dir,
        }
    }
}

// ------------------------------------------------- 置き場を用意する／中身を持っていく

/// オーバーレイのコピー（fork）で**持っていってはいけない**ファイル名。
///
/// - `net-audit.jsonl` / `fs-audit.jsonl`: 昇格ヘルパー（`harness-netfilterd`・
///   `harness-policy-learnd`）が起動時に`canonicalize`して掴んだままのシンクである。
///   **プロセスの持ち物であって、変更の持ち物ではない。** 複製すると「このセッションの
///   通信/FS監査」のつもりで読んだものが、実際には別セッションの記録の写しになる。
/// - `.harness-cow-session.json`: upper_dirの由来（セッションID・workspace）。コピー先では
///   [`prepare_scope`]が新しいIDで書き直しており、それを上書きしてはならない。
///
/// **ここに載っていないものは全部コピーする**（`tree/`・`_ext/`・`manifest.jsonl`・
/// `.harness-cow-ops.jsonl`・`.harness-cow-baseline/`…）。除外を列挙する側にしてあるのは、
/// オーバーレイへ新しいファイルが増えたとき、既定が「持っていく」＝変更が失われない側に
/// 倒れるようにするためである。
fn is_excluded_from_overlay_copy(file_name: &str) -> bool {
    matches!(
        file_name,
        "net-audit.jsonl" | "fs-audit.jsonl" | ".harness-cow-session.json"
    )
}

/// `scope`のオーバーレイをこのプロセスが使える状態にする。**切替の唯一の副作用点**。
///
/// 呼ぶのは2箇所——起動時のfork（`harness-cli`の`--fork-session`・ピッカーのfork）と、
/// セッション中の切替（`harness-tui`の`/sessions`・`/fork`）。同じ状態を作り得る経路が
/// 複数あるので、置き場の用意は**この1関数に集める**（`bug-pattern-rules` B-06/BUG-085）。
///
/// `--live`（オーバーレイ無し）では何もせず`Ok(0)`。戻り値は「用意したもの」の件数で、
/// 呼び出し側が何が起きたかを報告できるようにしてある（B-09: 多段の副作用を
/// `Result<(), _>`へ潰さない）。
///
/// **失敗したら切り替えない。** 呼び出し側は`Err`を受けたら会話も切り替えず、理由を出して
/// 現状維持する（fail-closed）。中途半端に用意されたオーバーレイへ会話だけ移すと、
/// 「書けないオーバーレイに書き続ける」という最悪の形になる。
pub fn prepare_scope(workspace_root: &Path, scope: &SessionScope) -> Result<usize, String> {
    if scope.is_live() {
        return Ok(0);
    }
    let Some(dir) = scope.overlay_dir(workspace_root) else {
        return Ok(0);
    };
    std::fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "could not create the overlay directory {}: {e}",
            dir.display()
        )
    })?;

    // `--staged`（workspace内`.harness/sandbox/<id>`）はここで終わり。**ACLは触らない**——
    // このオーバーレイを読み書きするのはharness自身のプロセスだけで、サンドボックスの子から
    // 見せる必要が無い（むしろ`.harness/`はD-05/D-09で子から隔離してある）。新しく作った
    // ディレクトリは保護済みの`.harness/`から継承するのでAppContainer宛ACEを持たない。
    #[cfg(windows)]
    if scope.cow_upper_dir.is_some() {
        return prepare_cow_upper(workspace_root, scope, &dir);
    }
    Ok(1)
}

/// `--sandbox tier2a-cow`のupper_dirを、このセッションのAppContainerから書ける状態にする（Windows専用）。
///
/// # なぜ`grant_job::wait_until_done`を通さないのか
///
/// `grant_job`のモジュールdocは「セッション中に**workspaceツリーのどこかへDACLを書きうる
/// 経路**は先に`wait_until_done`を通す」ことを約束4として要求する（BUG-085）。ここが
/// 該当しないのは、upper_dirが`%LOCALAPPDATA%\harness\data\cow\`配下＝**workspaceツリーの外**
/// だからである。`grant_job`のフェーズ0（伝播）・0.5（`.harness/`再保護）・1（救済walk）は
/// いずれもworkspaceツリーだけを対象にしており、このACE書込とノードが1つも重ならない。
///
/// # なぜUACが出ないのか
///
/// 親（[`cow_upper_root`]）までの祖先traverseチェーンは起動時の`preflight`が既に解決している。
/// 新しいleafに増えるのはこのセッションのpackage SID宛の継承ACE1件だけで、所有者は自分
/// （同一ユーザー）なのでprivhelper（昇格）を通らない。
#[cfg(windows)]
fn prepare_cow_upper(
    workspace_root: &Path,
    scope: &SessionScope,
    upper_dir: &Path,
) -> Result<usize, String> {
    use crate::tier2a::{session_profile, win_appcontainer, workspace_ledger};

    let sid = win_appcontainer::ensure_profile(&session_profile::current_profile_name())
        .map_err(|e| format!("could not resolve this session's AppContainer profile: {e}"))?;

    // 順序が本質: 実体を作る → ACEを付ける → **台帳へ記録する**（B-01/B-15）。記録を落とすと
    // `end_session`/`gc_dead_sessions`がこのACEを引けず、切替のたびに撤収経路の無い孤立ACEが
    // 1件ずつ実マシンへ残る（BUG-038・BUG-059で実際に8件残留した形）。`record_granted_path`は
    // ACE付与が成功した後にだけ呼ぶ——先に記録すると「台帳にあるのに実体が無い」逆向きの
    // 孤立になる。
    win_appcontainer::grant_ace_inheritable_rw(upper_dir, sid.as_psid()).map_err(|e| {
        format!(
            "could not grant this session access to {}: {e}",
            upper_dir.display()
        )
    })?;
    session_profile::record_granted_path(upper_dir);

    // `harness cow status`/`apply`/`list`がupper_dirから元のworkspaceを引けるようにする
    // （`preflight`が起動時に書くのと同じもの。切替後のupperにも要る）。
    workspace_ledger::write_cow_session_meta(upper_dir, workspace_root, &scope.session_id);

    // 生存マーカー。切替**前**のセッションのマーカーはプロセス終了まで保持したままにする
    // ——`harness cow discard`等が「まだ使われているか」を判定する材料であり、切り戻す
    // 可能性のあるオーバーレイを回収可能に見せない方が安全側（B-16）。
    workspace_ledger::hold_cow_session_marker(&scope.session_id)
        .map_err(|e| format!("could not create the CoW session marker: {e}"))?;
    Ok(1)
}

/// オーバーレイの中身を`from`から`to`へ再帰コピーし、**コピーしたファイル数**を返す（fork）。
///
/// 操作台帳（`.harness-cow-ops.jsonl`）の`path`はworkspace相対なので（`harness_change_ledger`）、
/// 置き場が変わってもバイトコピーのまま整合する。baselineミラーも同様。
///
/// `from`が存在しない（そのセッションがまだ何も書いていない）場合は`Ok(0)`。
///
/// **`Result<(), _>`にしない**（B-09）。部分コピーを成功へ潰すと「変更が半分だけ入った
/// オーバーレイ」が黙って生まれ、片方をapplyした時点で気付くことになる。
pub fn copy_overlay(from: &Path, to: &Path) -> Result<usize, String> {
    if !from.exists() {
        return Ok(0);
    }
    let mut copied = 0usize;
    copy_dir_recursive(from, to, &mut copied)?;
    Ok(copied)
}

fn copy_dir_recursive(from: &Path, to: &Path, copied: &mut usize) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("could not create {}: {e}", to.display()))?;
    let entries =
        std::fs::read_dir(from).map_err(|e| format!("could not read {}: {e}", from.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("could not read {}: {e}", from.display()))?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            // 名前がUTF-8でない実体は**黙って飛ばさず**エラーにする。オーバーレイの中身は
            // 変更そのものなので、「何かをコピーしなかった」を成功として返せない。
            return Err(format!(
                "overlay entry with a non-UTF-8 name under {}; refusing to copy silently",
                from.display()
            ));
        };
        if is_excluded_from_overlay_copy(name_str) {
            continue;
        }
        let src = entry.path();
        let dst = to.join(&name);
        let file_type = entry
            .file_type()
            .map_err(|e| format!("could not stat {}: {e}", src.display()))?;
        if file_type.is_dir() {
            copy_dir_recursive(&src, &dst, copied)?;
        } else {
            std::fs::copy(&src, &dst).map_err(|e| {
                format!("could not copy {} -> {}: {e}", src.display(), dst.display())
            })?;
            *copied += 1;
        }
    }
    Ok(())
}

/// forkしたセッションへ、元セッションのオーバーレイをそのまま引き継がせる。
///
/// **forkは「会話を分岐する」だけでなく「変更も分岐する」。** コピーしないと、分岐した瞬間に
/// それまでの未適用変更がレビュー対象から消える（実体は元セッション側に残るので失われはしない
/// が、画面からは消える）。用意（[`prepare_scope`]）→コピー（[`copy_overlay`]）の順で行う。
///
/// 戻り値はコピーしたファイル数。`--live`や元セッションが何も書いていない場合は`Ok(0)`。
pub fn fork_overlay(
    workspace_root: &Path,
    from: &SessionScope,
    to: &SessionScope,
) -> Result<usize, String> {
    if to.is_live() {
        return Ok(0);
    }
    prepare_scope(workspace_root, to)?;
    let (Some(from_dir), Some(to_dir)) = (
        from.overlay_dir(workspace_root),
        to.overlay_dir(workspace_root),
    ) else {
        return Ok(0);
    };
    copy_overlay(&from_dir, &to_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 監査シンクとセッションメタは持っていかない。ここが緩むと、fork先の
    /// `.harness-cow-session.json`が元セッションのIDで上書きされる。
    #[test]
    fn audit_sinks_and_session_meta_are_never_copied() {
        assert!(is_excluded_from_overlay_copy("net-audit.jsonl"));
        assert!(is_excluded_from_overlay_copy("fs-audit.jsonl"));
        assert!(is_excluded_from_overlay_copy(".harness-cow-session.json"));
    }

    /// 変更の実体・台帳・baselineミラーは必ず持っていく（既定が「持っていく」側）。
    #[test]
    fn the_changes_themselves_are_always_copied() {
        for name in [
            "tree",
            "_ext",
            "manifest.jsonl",
            ".harness-cow-ops.jsonl",
            ".harness-cow-baseline",
            ".harness-cow-denied.jsonl",
        ] {
            assert!(!is_excluded_from_overlay_copy(name), "{name}");
        }
    }

    #[test]
    fn copying_a_missing_overlay_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            copy_overlay(&tmp.path().join("nope"), &tmp.path().join("to")).unwrap(),
            0
        );
    }

    #[test]
    fn copy_walks_subdirectories_and_reports_the_file_count() {
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("from");
        std::fs::create_dir_all(from.join("tree").join("src")).unwrap();
        std::fs::write(from.join("manifest.jsonl"), "{}\n").unwrap();
        std::fs::write(from.join("tree").join("src").join("a.rs"), "fn a() {}").unwrap();
        std::fs::write(from.join(".harness-cow-ops.jsonl"), "{}\n").unwrap();
        // 除外対象も置いておく（数にもコピー先にも現れないこと）。
        std::fs::write(from.join("net-audit.jsonl"), "x\n").unwrap();

        let to = tmp.path().join("to");
        assert_eq!(copy_overlay(&from, &to).unwrap(), 3);
        assert_eq!(
            std::fs::read_to_string(to.join("tree").join("src").join("a.rs")).unwrap(),
            "fn a() {}"
        );
        assert!(to.join(".harness-cow-ops.jsonl").exists());
        assert!(!to.join("net-audit.jsonl").exists());
    }

    /// `--live`は用意するものが無い（切替を要求されても副作用ゼロ）。
    #[test]
    fn preparing_a_live_scope_does_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let scope = ScopeTemplate::Staging(StagingMode::Live).scope_for("session-x");
        assert_eq!(prepare_scope(tmp.path(), &scope).unwrap(), 0);
        assert!(!tmp.path().join(".harness").exists());
    }

    /// `--staged`はworkspace内にディレクトリを作るだけ（ACLを触らない）。
    #[test]
    fn preparing_a_staged_scope_creates_the_overlay_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let scope = ScopeTemplate::Staging(StagingMode::Staged).scope_for("session-x");
        assert_eq!(prepare_scope(tmp.path(), &scope).unwrap(), 1);
        assert!(tmp.path().join(".harness/sandbox/session-x").is_dir());
    }

    /// forkは「用意→コピー」を1回で行う（順序を逆にする間違いを呼び出し側に作らせない）。
    #[test]
    fn forking_prepares_the_destination_then_copies_into_it() {
        let tmp = tempfile::tempdir().unwrap();
        let t = ScopeTemplate::Staging(StagingMode::Staged);
        let (src, dst) = (t.scope_for("session-src"), t.scope_for("session-dst"));
        prepare_scope(tmp.path(), &src).unwrap();
        std::fs::write(
            src.overlay_dir(tmp.path()).unwrap().join("manifest.jsonl"),
            "{}\n",
        )
        .unwrap();

        assert_eq!(fork_overlay(tmp.path(), &src, &dst).unwrap(), 1);
        assert!(dst
            .overlay_dir(tmp.path())
            .unwrap()
            .join("manifest.jsonl")
            .exists());
    }

    #[test]
    fn staged_puts_the_overlay_under_the_workspace() {
        let scope = ScopeTemplate::Staging(StagingMode::Staged).scope_for("session-abc");
        assert_eq!(
            scope.staging.sandbox_dir,
            Some(
                PathBuf::from(".harness")
                    .join("sandbox")
                    .join("session-abc")
            )
        );
        assert_eq!(scope.cow_upper_dir, None);
        assert!(!scope.is_live());
        assert_eq!(
            scope.overlay_dir(Path::new("C:/ws")),
            Some(PathBuf::from("C:/ws/.harness/sandbox/session-abc"))
        );
    }

    #[test]
    fn workspace_commit_uses_the_same_layout_as_staged() {
        let scope = ScopeTemplate::Staging(StagingMode::WorkspaceCommit).scope_for("session-abc");
        assert_eq!(
            scope.staging.sandbox_dir,
            Some(sandbox_dir_for_session("session-abc"))
        );
    }

    /// `--live`はオーバーレイを持たない。切替を要求されても何もすることが無い、を
    /// 呼び出し側が`is_live()`1つで判定できること。
    #[test]
    fn live_has_no_overlay_at_all() {
        let scope = ScopeTemplate::Staging(StagingMode::Live).scope_for("session-abc");
        assert_eq!(scope.staging.sandbox_dir, None);
        assert_eq!(scope.cow_upper_dir, None);
        assert!(scope.is_live());
        assert_eq!(scope.overlay_dir(Path::new("C:/ws")), None);
    }

    /// `--sandbox tier2a-cow`はworkspace**外**へ置く。ここがworkspace内へ戻ると、再帰的なパスマッピングと
    /// `.harness`のPROTECTED DACLとの衝突が復活する。
    #[test]
    fn cow_puts_the_overlay_outside_the_workspace() {
        let scope = ScopeTemplate::Cow.scope_for("session-abc");
        assert_eq!(scope.staging.sandbox_dir, None);
        let Some(upper) = &scope.cow_upper_dir else {
            // `%LOCALAPPDATA%`が解決できない環境ではNone（起動時に弾かれている）。
            return;
        };
        assert!(upper.ends_with("session-abc"), "{}", upper.display());
        assert!(upper.starts_with(cow_upper_root().unwrap()));
        assert!(!scope.is_live());
        assert_eq!(scope.overlay_dir(Path::new("C:/ws")).as_ref(), Some(upper));
    }

    /// セッションが違えば置き場も違う（切替が意味を持つための前提）。
    #[test]
    fn different_sessions_get_different_overlays() {
        let t = ScopeTemplate::Staging(StagingMode::Staged);
        assert_ne!(
            t.scope_for("session-a").staging,
            t.scope_for("session-b").staging
        );
    }
}
