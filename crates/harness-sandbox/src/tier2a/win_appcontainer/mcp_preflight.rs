//! MCPサーバ用のpreflight（D-38、`plans/DESIGN-MCP.md` §3.2）。
//!
//! `run_shell`用の[`super::preflight`]とは**与えるものが根本的に違う**ので、共通化せず別に持つ。
//!
//! | | `run_shell`（D-37） | MCPサーバ（D-38） |
//! |---|---|---|
//! | workspace | 常にACEを付ける（RWまたはCoWのRO） | **既定で一切付けない**。宣言が明示要求したときだけ |
//! | 付与対象 | workspace・CoW 差分層・`--fs-allow`の穴 | サーバの実行ファイル周辺のみ |
//! | network | セッション共通のポリシー | サーバごとに別（専用プロキシ＋WFP） |
//!
//! workspaceへのACEを既定で付けないのは、**MCPサーバの大半はワークスペースを必要としない**
//! （社内仕様検索・課題管理・カレンダー等、サーバ自身が別のデータ源を持つ）ためである。
//! 必要とするサーバのために既定を緩めると、必要としないサーバまで巻き添えで読めるようになる。
//!
//! ## ACE付与の失敗は起動を止めない
//!
//! 付与は**加える**方向の操作なので、失敗しても境界が緩むことはない（起動できないだけ）。
//! しかも実際には、`C:\Program Files`配下の多くは既に`ALL APPLICATION PACKAGES`へ読取+実行を
//! 与えており、**そもそも付与が要らない**ことが多い。したがって失敗は警告として積み、起動は
//! 続行する——ここで止めると「本来動いたはずのサーバ」を落とすことになる。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;

/// [`preflight_mcp_server`]への要求。
#[derive(Debug)]
pub struct McpPreflightRequest<'a> {
    /// 宣言のid（`[a-z0-9-]`に制限済みであることは`harness-mcp`側が保証する）。
    pub server_id: &'a str,
    /// 起動する実行ファイル。
    pub command: &'a Path,
    /// 宣言の引数のうち、実在するパス（スクリプト本体等）。呼び出し側が抽出して渡す。
    pub arg_paths: &'a [PathBuf],
    /// 宣言が**明示要求した**場合のみ`Some`。`None`ならworkspaceへのACEを一切付けない（既定）。
    pub workspace: Option<(&'a Path, FsAccess)>,
}

#[derive(Debug)]
pub struct McpPreflightOutcome {
    /// このサーバ専用のAppContainerプロファイル名（`harness.mcp.<token>.<server-id>`）。
    pub profile_name: String,
    /// 付与できなかったルート等の診断。**起動は続行する**（モジュールdoc参照）。
    pub warnings: Vec<String>,
}

/// MCPサーバ専用のAppContainerプロファイルを用意し、起動に必要な最小のACEだけを付ける。
pub fn preflight_mcp_server(
    req: &McpPreflightRequest<'_>,
) -> Result<McpPreflightOutcome, AppContainerError> {
    // 台帳へ先に登録してからプロファイルを作る（作成直後に落ちても撤収対象が分かるように）。
    let profile_name = crate::tier2a::session_profile::record_mcp_profile(req.server_id);
    let sid = ensure_profile(&profile_name)?;

    let mut warnings = Vec::new();

    // D-54 / `grant_job`モジュールdocの「約束」4: workspaceツリーへDACLを書く経路は、背景の
    // 伝播＋救済walkと交差させない。`grant_ace_mask`は「読む→ACEを足す→書き戻す」なので、
    // 同じノードで並行すると片方のACEが消える。走っていなければ即座に返る。
    //
    // **[BUG-085] `req.workspace`の有無に関わらず、全てのACL書込より前に待つ。** 待ちを
    // workspace付与の直前だけに置いていた頃は、下の`read_exec_roots`のACE付与が背景ジョブと
    // 競合し得た——実行ファイルやスクリプトがworkspace配下にあるMCPサーバ宣言
    // （`node C:\...\<workspace>\tools\mcp\server.js`のような、プロジェクト同梱のサーバ）では
    // 付与先がworkspaceツリーの内側になるためである。「workspaceへのACEを付けるとき」ではなく
    // 「workspaceツリーへDACLを書き得るとき」が待つ条件になる。
    grant_job::wait_until_done().map_err(AppContainerError::Preflight)?;

    for root in read_exec_roots(req) {
        match is_force_grant_forbidden(&root) {
            Some(reason) => warnings.push(format!(
                "mcp {}: not granting read+execute on {} ({reason}). If the server fails to \
                 start, move it out of that location rather than widening the grant",
                req.server_id,
                root.display()
            )),
            None => match grant_ace_inheritable_access(&root, sid.as_psid(), FsAccess::ReadExec) {
                Ok(()) => {
                    crate::tier2a::session_profile::record_mcp_granted_path(&profile_name, &root)
                }
                Err(e) => warnings.push(format!(
                    "mcp {}: could not grant read+execute on {} ({e}). The server may still \
                     start if that path already allows ALL APPLICATION PACKAGES",
                    req.server_id,
                    root.display()
                )),
            },
        }
    }

    if let Some((workspace_root, access)) = req.workspace {
        grant_ace_inheritable_access(workspace_root, sid.as_psid(), access)?;
        crate::tier2a::session_profile::record_mcp_granted_path(&profile_name, workspace_root);
        // P-08: `.harness`はどのMCPサーバからも開けない。workspaceへACEを付けた場合、
        // 継承でこの制御ディレクトリまで届いてしまうので、`run_shell`側と同じ経路で
        // package SIDのACEを除去しDACLをPROTECTED化する（承認台帳の自己書換を防ぐ、D-39）。
        //
        // 剥がすのは**このMCPサーバのpackage SIDだけ**でよい。MCPサーバはworkspace
        // capability（D-54）をトークンへ積まない（`spawn`は既定で積まない、D-38 §3.2で
        // workspaceは既定の許可対象ではない）ので、capability宛のACEはここでは対象にならない。
        let harness_dir_exists = workspace_root.join(".harness").exists();
        let protected =
            protect_harness_control_dir_from_appcontainer(workspace_root, &[sid.as_psid()])?;
        // [BUG-084] 保護が1件も掛からなかったことを、このサーバの起動前に見せる。
        // ここは**第三者コードへworkspaceのACEを渡した直後**なので、制御面（D-05/D-09の層3、
        // 承認台帳の自己書換防止＝D-39）が実際に閉じたかどうかが最も効く場所である。
        if harness_dir_exists && protected.protected == 0 {
            warnings.push(format!(
                "mcp {}: granted workspace access but the .harness control directory was not \
                 protected on any node; this server may be able to reach the approval ledger. \
                 Check the workspace for concurrent deletion under .harness",
                req.server_id
            ));
        }
    }

    Ok(McpPreflightOutcome {
        profile_name,
        warnings,
    })
}

/// 読取+実行を与えるべきルートを決める。
///
/// 実行ファイル**そのもの**ではなく親ディレクトリを対象にするのは、実行に必要なものが1ファイルで
/// 完結しないため（`node.exe`は同じディレクトリのDLLを、スクリプトは隣の`node_modules`や
/// `package.json`を読む）。対象はいずれも**承認済み宣言に書かれたパス**であり、ユーザーが
/// `harness mcp approve`で内容を確認したものだけがここへ来る（D-39）。
fn read_exec_roots(req: &McpPreflightRequest<'_>) -> Vec<PathBuf> {
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    if let Some(parent) = req.command.parent() {
        if !parent.as_os_str().is_empty() {
            roots.insert(parent.to_path_buf());
        }
    }
    for path in req.arg_paths {
        // ディレクトリはそれ自体、ファイルは親（同梱物を読めるようにするため）。
        let root = if path.is_dir() {
            Some(path.clone())
        } else {
            path.parent().map(Path::to_path_buf)
        };
        if let Some(root) = root {
            if !root.as_os_str().is_empty() {
                roots.insert(root);
            }
        }
    }
    // **デバイス名前空間は付与先にならない**（2026-09-07、T2の測定中に発覚）。
    //
    // `\\.\pipe\...`のような名前は`Path::exists`が真になるので、宣言の引数から
    // 実在する絶対パスとして拾われ、その親＝**パイプ名前空間の根`\\.\pipe\`**が
    // ここへ候補として現れる。`command`側はさらに緩く、**実在の検査すら通らずに**
    // `parent()`が入る——だから落とすのは`existing_arg_paths`（引数側だけ）ではなく、
    // **2つの入口が合流するここ**である（`B-06`: N経路のうちN経路で数える）。
    //
    // **いま実害が出ていないのは偶然である。** 付与側（`is_force_grant_forbidden`）が
    // 断ってはいるが、断る理由は「デバイス名前空間だから」ではなく`canonicalize`に
    // 失敗したからで、**偶然で塞がっている**。MCPの宣言は「ユーザーが宣言した第三者コード」
    // （D-38）なので、そこから付与候補が決まる経路は意図で塞ぐ。
    let roots: BTreeSet<PathBuf> = roots
        .into_iter()
        .filter(|root| !is_device_namespace(root))
        .collect();

    // 祖先が既に入っているなら子孫は要らない（継承ACEが覆う）。付与回数＝ACL書込を減らす。
    let all: Vec<PathBuf> = roots.into_iter().collect();
    all.iter()
        .filter(|candidate| {
            !all.iter()
                .any(|other| other != *candidate && candidate.starts_with(other))
        })
        .cloned()
        .collect()
}

/// Win32のデバイス名前空間（`\\.\…` と `\\?\…`）か。
///
/// **どちらも「ファイルシステム上の場所」ではない。** 前者は名前付きパイプ・シリアルポート等の
/// デバイスを指し、後者はパス解析を飛ばす前置き（verbatim）で、`\\?\C:\x`のように
/// **実在のパスを指すこともある**。それでも**両方落とす**——ここは付与先を決める場所で、
/// 宣言がどちらの綴りで書いてきても、通常の`C:\…`へ正規化された形で受け取るべきだからである
/// （verbatim形のまま付与すると、同じ場所を2つの綴りで別々に扱う形になる）。
fn is_device_namespace(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    text.starts_with(r"\\.\") || text.starts_with(r"\\?\")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(command: &'a Path, arg_paths: &'a [PathBuf]) -> McpPreflightRequest<'a> {
        McpPreflightRequest {
            server_id: "docs",
            command,
            arg_paths,
            workspace: None,
        }
    }

    #[test]
    fn the_executables_directory_is_granted_not_the_executable_itself() {
        let command = PathBuf::from(r"C:\tools\nodejs\node.exe");
        let roots = read_exec_roots(&req(&command, &[]));
        assert_eq!(roots, vec![PathBuf::from(r"C:\tools\nodejs")]);
    }

    /// 引数のスクリプトは、その親ディレクトリごと読めるようにする（`node_modules`等）。
    #[test]
    fn a_script_argument_grants_its_containing_directory() {
        let command = PathBuf::from(r"C:\tools\nodejs\node.exe");
        let args = vec![PathBuf::from(r"C:\mcp\docs\index.js")];
        let roots = read_exec_roots(&req(&command, &args));
        assert!(roots.contains(&PathBuf::from(r"C:\mcp\docs")), "{roots:?}");
    }

    /// **引数側の入口**: デバイス名前空間は付与候補にならない（2026-09-07、T2で発覚）。
    ///
    /// 名前付きパイプは`Path::exists`が真になるので、引数から実在の絶対パスとして拾われる。
    /// 落とさないと**パイプ名前空間の根**が付与先の候補になる。
    #[test]
    fn a_device_namespace_argument_is_not_a_grant_candidate() {
        let command = PathBuf::from(r"C:\tools\nodejs\node.exe");
        let args = vec![PathBuf::from(r"\\.\pipe\harness-spawnd-request-1-0-2")];
        let roots = read_exec_roots(&req(&command, &args));
        assert_eq!(
            roots,
            vec![PathBuf::from(r"C:\tools\nodejs")],
            "デバイス名前空間が付与候補に残っている: {roots:?}"
        );
    }

    /// **コマンド側の入口**（`B-06`: N経路のうちN経路で数える）。
    ///
    /// **こちらは実在の検査すら通らない**——`req.command.parent()`が無条件で入るので、
    /// 引数側だけを塞いでも素通りする。**この対が無いと、覆えていない入口が緑のまま残る。**
    #[test]
    fn a_device_namespace_command_is_not_a_grant_candidate_either() {
        let command = PathBuf::from(r"\\.\pipe\harness-spawnd-request-1-0-2");
        let roots = read_exec_roots(&req(&command, &[]));
        assert!(
            roots.is_empty(),
            "commandがデバイス名前空間でも親が付与候補になっている: {roots:?}"
        );
    }

    /// **対の側**（`B-35`）: 通常の絶対パスは落ちない。
    ///
    /// 片方だけだと、**候補を常に空にする実装**でも上の2本は通る。
    #[test]
    fn ordinary_absolute_paths_still_become_grant_candidates() {
        let command = PathBuf::from(r"C:\tools\nodejs\node.exe");
        let args = vec![PathBuf::from(r"C:\mcp\docs\index.js")];
        let roots = read_exec_roots(&req(&command, &args));
        assert_eq!(
            roots,
            vec![
                PathBuf::from(r"C:\mcp\docs"),
                PathBuf::from(r"C:\tools\nodejs"),
            ],
            "通常のパスまで落ちている（MCPサーバが自分の同梱物を読めなくなる）: {roots:?}"
        );
    }

    /// 祖先が対象に含まれるなら子孫は落とす（継承ACEが覆うので二重付与は無駄）。
    #[test]
    fn descendants_of_an_already_granted_root_are_dropped() {
        let command = PathBuf::from(r"C:\mcp\bin\server.exe");
        let args = vec![
            PathBuf::from(r"C:\mcp\bin\plugins\a.js"),
            PathBuf::from(r"C:\other\b.js"),
        ];
        let roots = read_exec_roots(&req(&command, &args));
        assert_eq!(
            roots,
            vec![PathBuf::from(r"C:\mcp\bin"), PathBuf::from(r"C:\other")]
        );
    }

    /// PATH上の名前だけを書いた宣言（親ディレクトリが無い）でも壊れない。
    #[test]
    fn a_bare_command_name_produces_no_roots() {
        let command = PathBuf::from("node.exe");
        assert!(read_exec_roots(&req(&command, &[])).is_empty());
    }

    /// ドライブルート・`%SystemRoot%`配下は付与対象から外れる（影響範囲が大きすぎる）。
    /// 判定そのものは`is_force_grant_forbidden`が持ち、`preflight_mcp_server`はそれに従う。
    #[test]
    fn drive_roots_are_refused_by_the_shared_blast_radius_gate() {
        assert!(is_force_grant_forbidden(Path::new("C:\\")).is_some());
    }
}
