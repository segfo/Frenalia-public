//! パス2を走らせる**前に**「そのコマンドの実行ファイルへ届くか」を測る（純粋関数）。
//!
//! # なぜ起動してから判断しないのか
//!
//! 実際に起きた事故はこうだった——`cargo test`をパス2で走らせたら
//! `プログラム 'cargo.exe' の実行に失敗しました: Access is denied`で落ち、**画面には
//! 「何が拒否されたのか」も「次に何をすればよいのか」も出なかった**。原因は
//! `C:/Users/segfo/.cargo/bin`が`fs.read`として承認されていたことで、実行権が付くのは
//! `fs.read_exec`だけである（`acl_grant::fs_access_mask`）。
//!
//! 子プロセスを起こしてから失敗の文言を解釈する形にはしない。**失敗メッセージはロケール
//! 依存**であり、`Access is denied`という文字列に依存した判定はBUG-086が「やってはいけない」と
//! 結論した形そのものである。宣言（`policy.json`）と付与の結果（`preflight`）は起動前に
//! 手元にあるので、そこから言える。
//!
//! # 止めない（警告だけ）
//!
//! 判定は`which`の解決に依存し、シェル関数・エイリアス・シェル組み込みでは外れ得る。
//! **外れる可能性のある判定でfail-closedにすると、動くはずのコマンドを止める。**
//! パス2のfail-closed（強制が立たないときは中止する）は「強制が無い観測を強制がある顔で
//! 出さない」ためのもので、「このコマンドは失敗しそうだ」は別の話である。
//!
//! # 「覆うか」の規則は自前で持たない
//!
//! [`harness_policy::insufficient::covers`]を通す（コンポーネント境界を見る前方一致）。
//! 提案側が言う覆い方と診断が言う覆い方がずれると、画面の指示どおりに承認しても直らない。

use std::path::{Path, PathBuf};

use harness_config::FsAccess;

/// コマンドの実行ファイルがサンドボックスから起動できるか。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecReach {
    /// 実行権のある宣言に覆われている。
    Ok {
        exe: PathBuf,
        /// 覆っている宣言の値（`policy.json`に書かれている綴り）。
        declared: String,
    },
    /// workspace配下。Tier2aのworkspace grantが読み書き実行すべてを覆う。
    InsideWorkspace { exe: PathBuf },
    /// **AppContainerに既定で実行権がある場所**（`C:/Windows`・`C:/Program Files`配下）。
    ///
    /// 宣言が無くても起動できるので警告を出してはいけない。判定はD-58と**同じ関数**
    /// （`breadth::is_default_exec_root_path`）を通す——ここで別の規則を持つと、
    /// 「候補には出さないのに、無いと言って承認を促す」という自己矛盾になる。
    /// 実際にそうなっていた: `curl.exe`（`C:/windows/system32`）で
    /// 「1件も許可されていません→read_execで承認してください」と出るのに、コマンドは動いていた。
    /// 承認されれば`preflight`がTrustedInstaller所有ツリーへACEを付けに行く（BUG-015）。
    DefaultExecutable { exe: PathBuf },
    /// このドメインの宣言が1件も覆っていない。
    NotDeclared { exe: PathBuf },
    /// 宣言はあるが実行権が無い（`fs.read`・`fs.read_write`止まり）。**今回の事故はこれ。**
    NoExecRight {
        exe: PathBuf,
        declared: String,
        access: FsAccess,
    },
    /// 宣言はあり実行権もあるが、**そのルートへACEを付けられなかった**。
    /// 宣言を直しても解決しないので、文言を分ける必要がある。
    GrantFailed {
        exe: PathBuf,
        root: PathBuf,
        reason: String,
    },
    /// 実行ファイルを特定できなかった（PATH上に無い・シェル関数・組み込みコマンド）。
    /// **これは「起動できない」ではない**——測れなかっただけである。
    Unresolved { token: String },
}

impl ExecReach {
    /// 起動できると言えるか。`Unresolved`は**判定していない**ので偽ではなく`None`にする
    /// ——「測れなかった」を「駄目だった」に倒すと、警告が信用されなくなる。
    pub fn is_reachable(&self) -> Option<bool> {
        match self {
            ExecReach::Ok { .. }
            | ExecReach::InsideWorkspace { .. }
            | ExecReach::DefaultExecutable { .. } => Some(true),
            ExecReach::NotDeclared { .. }
            | ExecReach::NoExecRight { .. }
            | ExecReach::GrantFailed { .. } => Some(false),
            ExecReach::Unresolved { .. } => None,
        }
    }

    /// **このままでは起動できないと名指しできた実行ファイル**（`fs.read_exec`の候補にすべきもの）。
    /// 綴りは設定へそのまま書ける形。問題が無ければ`None`。
    ///
    /// # なぜこれが要るのか
    ///
    /// `fs.read_exec`の候補はD-57が`ProcessStart`の実行像から作るが、**起動を拒否された
    /// exeは`ProcessStart`を出さない**。つまりパス2で実際に詰まった当の実行ファイルだけが、
    /// 構造的に候補へ出てこない（実データでは`.cargo/bin/cargo.exe`の拒否行は`access: "read"`で、
    /// `image_path`は開いた側の`powershell.exe`だった）。ここが**もう1つの情報源**になる
    /// ——拡張子からの推測ではなく、PATH解決という観測と宣言との突き合わせの結果である。
    ///
    /// # 出さないもの
    ///
    /// - [`ExecReach::GrantFailed`][]: 宣言は既に`read_exec`である。候補を足しても直らない
    ///   （直すべきなのは付与の失敗の方）。
    /// - [`ExecReach::DefaultExecutable`][]: 既定で実行できる（D-58）。承認させると`preflight`が
    ///   システム保護ノードへACEを付けに行く。
    /// - [`ExecReach::Unresolved`][]: 測れなかっただけで、起動できないとは言っていない。
    ///
    /// **ワイルドカードを使わない`match`**にしてある——variantを足した人のビルドがここで落ち、
    /// 「候補にするかどうか」を必ず1回決めることになる。
    pub fn unreachable_exec_value(&self) -> Option<String> {
        match self {
            ExecReach::NotDeclared { exe } | ExecReach::NoExecRight { exe, .. } => {
                Some(settings_spelling(exe))
            }
            ExecReach::Ok { .. }
            | ExecReach::InsideWorkspace { .. }
            | ExecReach::DefaultExecutable { .. }
            | ExecReach::GrantFailed { .. }
            | ExecReach::Unresolved { .. } => None,
        }
    }

    /// ユーザーへ出す文言。**問題が無ければ`None`**（毎回出る警告は読まれなくなる）。
    ///
    /// 「拒否されました」では足りない。**次の操作をそのまま書く**（B-32: 文言はユーザーが
    /// その瞬間に取る行動を決める唯一の入力）。
    pub fn message(&self) -> Option<String> {
        match self {
            ExecReach::Ok { .. }
            | ExecReach::InsideWorkspace { .. }
            | ExecReach::DefaultExecutable { .. } => None,
            ExecReach::NotDeclared { exe } => Some(format!(
                "コマンドの実行ファイル {} は、このドメインでは1件も許可されていません。\n\
                 サンドボックスからは起動できないため、コマンドは失敗します。\n\
                 → 編集画面で {} を read_exec として承認してください",
                exe.display(),
                settings_spelling(exe),
            )),
            ExecReach::NoExecRight {
                exe,
                declared,
                access,
            } => Some(format!(
                "コマンドの実行ファイル {} は、このドメインでは {} として許可されていますが\n\
                 （宣言: {declared}）、実行には fs.read_exec が要ります。\n\
                 サンドボックスからは起動できないため、コマンドは失敗します。\n\
                 → 編集画面で {} を read_exec として承認してください",
                exe.display(),
                fs_key(*access),
                settings_spelling(exe),
            )),
            ExecReach::GrantFailed { exe, root, reason } => Some(format!(
                "コマンドの実行ファイル {} は read_exec として宣言されていますが、\n\
                 そのルート（{}）へACEを付けられませんでした: {reason}\n\
                 宣言を直しても解決しません（付与そのものが失敗しています）。",
                exe.display(),
                root.display(),
            )),
            ExecReach::Unresolved { token } => Some(format!(
                "コマンドの実行ファイルを特定できませんでした（PATH上に `{token}` が\n\
                 見つかりません）。シェル関数・エイリアス・組み込みコマンドなら問題ありません。\n\
                 そうでなければ、この実行は起動時に失敗します。"
            )),
        }
    }
}

/// `fs.read` / `fs.read_write` / `fs.read_exec`（設定キーの綴り。表示に使う）。
fn fs_key(access: FsAccess) -> String {
    format!("fs.{}", access.settings_key())
}

/// 承認画面へそのまま貼れる綴り（`/`区切り）。
fn settings_spelling(exe: &Path) -> String {
    harness_policy::normalize::normalize_path(&exe.to_string_lossy())
}

/// コマンド行の先頭トークンから実行ファイルの絶対パスを解決する。
///
/// **`path_env`は子へ渡すenvの`PATH`をそのまま受け取る**——プロセスのenvを別途読むと、
/// 渡す値と測る値が将来ずれる（B-05）。解決できないものは`None`（＝判定しない）。
pub fn resolve_command_exe(command: &str, path_env: &str, cwd: &Path) -> Option<PathBuf> {
    let token = first_token(command)?;
    // 絶対パス・相対パス指定はPATH探索を経ない（シェルと同じ）。
    if token.contains('/') || token.contains('\\') {
        let direct = cwd.join(&token);
        return which::which_in(&direct, Some(path_env), cwd)
            .ok()
            .or(Some(direct));
    }
    which::which_in(&token, Some(path_env), cwd).ok()
}

/// コマンド行の先頭トークン（引用符を1段だけ剥がす）。
///
/// パイプ・リダイレクト・複文は**先頭のコマンドだけ**見る。measured するのは
/// 「最初に起動されるもの」であり、それが起動できなければ後続も走らない。
fn first_token(command: &str) -> Option<String> {
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let mut chars = trimmed.chars();
    let first = chars.next()?;
    if first == '"' || first == '\'' {
        let rest: String = chars.collect();
        let end = rest.find(first)?;
        let token = rest[..end].trim().to_string();
        return (!token.is_empty()).then_some(token);
    }
    let token: String = trimmed.chars().take_while(|c| !c.is_whitespace()).collect();
    (!token.is_empty()).then_some(token)
}

/// 実行ファイルへ届くかを、**宣言と付与の結果**から判定する。
///
/// - `entries`はこのドメインの`fs`宣言（`policy.json`の綴りのまま）。
/// - `denied_roots`は`preflight`が付与に失敗したルート（`record_net`の`denied_passthrough`）。
pub fn diagnose(
    exe: &Path,
    entries: &[(&str, FsAccess)],
    workspace_root: &Path,
    denied_roots: &[(PathBuf, String, String)],
) -> ExecReach {
    let exe_value = settings_spelling(exe);
    let root_value = harness_policy::normalize::normalize_path(&workspace_root.to_string_lossy());

    // workspace配下はTier2aのworkspace grant（read/write/execute/delete）が覆う。
    if harness_policy::insufficient::covers(&root_value, &exe_value) {
        return ExecReach::InsideWorkspace {
            exe: exe.to_path_buf(),
        };
    }
    // **既定で実行できる場所は、宣言が無くても起動できる**（D-58と同じ判定を通す）。
    // ここを見落とすと、候補に出さないと決めたものを「無いから承認せよ」と促すことになる。
    if harness_policy::breadth::is_default_exec_root_path(&exe_value) {
        return ExecReach::DefaultExecutable {
            exe: exe.to_path_buf(),
        };
    }

    // **覆っている宣言のうち、実行権のあるものを優先して探す。** 「最も広いものを1つ」に
    // 畳んでから見ると、`read_write`が`read_exec`を隠す（両者は互いに包含しないため）。
    let mut covering: Option<(&str, FsAccess)> = None;
    for (declared, access) in entries {
        // ワイルドカードを含む宣言は、最初の`*`より前の確定部分で見る（`approve::classify`と同じ）。
        let literal = harness_policy::normalize::normalize_path(declared);
        let literal = literal
            .split('*')
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        if literal.is_empty() || !harness_policy::insufficient::covers(literal, &exe_value) {
            continue;
        }
        if *access == FsAccess::ReadExec {
            covering = Some((declared, *access));
            break;
        }
        if covering.is_none() {
            covering = Some((declared, *access));
        }
    }

    let Some((declared, access)) = covering else {
        return ExecReach::NotDeclared {
            exe: exe.to_path_buf(),
        };
    };
    if access != FsAccess::ReadExec {
        return ExecReach::NoExecRight {
            exe: exe.to_path_buf(),
            declared: declared.to_string(),
            access,
        };
    }
    // 宣言はあるが、そのルートへACEを付けられていないことがある（システム保護パス等）。
    // **これは宣言を直しても解決しない**ので、別の状態として出す。
    for (root, _access, reason) in denied_roots {
        let root_value = harness_policy::normalize::normalize_path(&root.to_string_lossy());
        if harness_policy::insufficient::covers(&root_value, &exe_value) {
            return ExecReach::GrantFailed {
                exe: exe.to_path_buf(),
                root: root.clone(),
                reason: reason.clone(),
            };
        }
    }
    ExecReach::Ok {
        exe: exe.to_path_buf(),
        declared: declared.to_string(),
    }
}

#[cfg(test)]
#[path = "exec_reach_tests.rs"]
mod exec_reach_tests;
