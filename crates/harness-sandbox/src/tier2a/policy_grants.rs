//! [#30] `policy.json`のファイル宣言から、**実際に許可（ACE）を付ける一覧**を作る（D-63）。
//!
//! # なぜ1つだけ置くのか
//!
//! この一覧を作る側は2つある——ポリシーエディタの試験実行（パス2）と`harness.exe`の起動である。
//! 「エディタで確かめた挙動を`harness.exe`で再現する」（`plans/HANDOFF-POLICY-EDITOR.md`の
//! ゴール）は、**2つが同じ関数を通る**ことでしか構造で保証できない。以前はエディタだけが
//! 持っていた（`approve::grant_roots`）ので、`harness.exe`が読み始めると変換が2つになるところだった。
//!
//! # 付けない値は理由ごと返す（`B-10`）
//!
//! 宣言には書いてあるのに許可が付かない値がある。黙って落とすと「宣言したのに読めない」の原因が
//! どこにも出ないので、[`SkippedDeclaration`]として返し、呼び出し側が必ず見せる。
//! 理由の文言は[`SkipReason::describe`]の網羅`match`1つが持つ（理由を足すとそこでビルドが落ちる。
//! BUG-111の型）。
//!
//! # ワークスペースの中は理由ではなく対象外
//!
//! Tier2aはワークスペース全体へ既に許可を付けているので、中の値へ別の宛先のACEを重ねる意味が無い
//! （`cargo`の宣言は実測668件で、重ねると26万ノードのツリーへ撒くことになる）。
//! これは「付けられなかった」ではないので[`DomainGrants::skipped`]には入れない。
//!
//! # この関数が守らないもの
//!
//! - **幅の判定はしない。** `C:/Users/<誰か>`のような広すぎる値を止めるのは承認時の
//!   `harness_policy::breadth`である。ここはドライブ直下まで戻る値だけを受け取らない。
//! - **候補の除外規則（`%TEMP%`・MSIXのデータ置き場等）は持たない。** それはエディタが候補を
//!   出すときの規則で、ここが拒むのは制御ディレクトリだけである——制御ディレクトリだけは
//!   開くと**自分の許可を書き換えられる**（P-08）ので、承認済みでも付けない。

use std::path::{Path, PathBuf};

use harness_policy::policy_file::PolicyDomain;

use crate::shell_tier::{FsAccess, FsPassthrough};

/// 宣言にあるのに許可を付けない理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// harnessの制御ディレクトリ（どのワークスペースのものでも`.harness`、または
    /// ユーザースコープの`%APPDATA%\harness`）。開くとサンドボックスから自分の許可を書き換えられる
    /// （P-08。BUG-103の追記で実際に`%APPDATA%\harness\config`へ`(OI)(CI)(R,W,D)`が付いた）。
    ControlDirectory,
    /// 相対パス。`policy.json`の値は絶対パスで書く（エディタは観測した絶対パスを書く）。
    /// 相対のまま付与処理へ渡すと、付与する側の作業ディレクトリ基準で別の場所を開く。
    RelativePath,
    /// `<path>/**`でも素のパスでもないワイルドカード（`C:/x/*/bin`）。確定部分が`C:/x`まで戻るので、
    /// オブジェクト単体にすれば何も開かず、再帰にすれば宣言よりはるかに広く開く（D-63）。
    MiddleWildcard,
    /// 確定部分がドライブ直下まで戻る値（`C:/*`）。事実上ドライブ全体への付与になる。
    DriveRoot,
    /// このマシンで承認されていない（D-112、`policy_approval`）。リポジトリに同梱された
    /// `policy.json`の宣言は、ユーザーがこのマシンで承認するまで許可を付けない。
    NotApprovedOnThisMachine,
}

impl SkipReason {
    /// 人へ見せる理由。**理由を足したらここでビルドが落ちる**（網羅`match`）。
    pub fn describe(self) -> &'static str {
        match self {
            SkipReason::ControlDirectory => {
                "harness's own control directory (.harness or %APPDATA%\\harness) is never opened \
                 to the sandbox, even when declared"
            }
            SkipReason::RelativePath => {
                "relative paths are not accepted in policy.json; write the absolute path"
            }
            SkipReason::MiddleWildcard => {
                "only a trailing `/**` is supported as a wildcard; a wildcard in the middle would \
                 either open nothing or open everything under the literal prefix"
            }
            SkipReason::DriveRoot => {
                "the literal part reduces to a drive root, which would open the whole drive"
            }
            SkipReason::NotApprovedOnThisMachine => {
                "not approved on this machine (a policy.json shipped with a repository is not \
                 trusted until you approve each declaration in harness-policy-editor: the \
                 declarations screen (F3), or `harness-policy-editor approve-declared`)"
            }
        }
    }
}

/// 許可を付けなかった宣言1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedDeclaration {
    /// `policy.json`に書いてあるとおりの値。
    pub value: String,
    pub access: harness_config::FsAccess,
    pub reason: SkipReason,
}

/// 1ドメインの宣言から作った、許可を付ける一覧と、付けなかった宣言。
#[derive(Debug, Clone, Default)]
pub struct DomainGrants {
    /// 付与処理（`preflight`）へ渡す一覧。**ルートごとに1件**（同じルートの宣言は和に畳んである）。
    pub passthrough: Vec<FsPassthrough>,
    pub skipped: Vec<SkippedDeclaration>,
}

/// 宣言を一覧へ変えるときの文脈（どのワークスペースか・ユーザースコープの制御ディレクトリはどこか）。
#[derive(Debug, Clone)]
pub struct GrantContext {
    workspace_root: PathBuf,
    harness_user_dir: Option<PathBuf>,
}

impl GrantContext {
    /// このマシンの`%APPDATA%\harness`を使う。
    pub fn for_workspace(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            harness_user_dir: harness_user_dir(),
        }
    }

    /// テスト用。**実マシンの環境に依存させない**ために明示で受ける。
    pub fn with_harness_user_dir(workspace_root: &Path, harness_user_dir: Option<&Path>) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            harness_user_dir: harness_user_dir.map(Path::to_path_buf),
        }
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// 宣言値1件を、**ACEを付けるオブジェクト**へ変える。
    ///
    /// - `Ok(Some(root))`: このルートへ付ける（ワイルドカードを含まない。`C:/x/**`なら`C:/x`）
    /// - `Ok(None)`: ワークスペースの中なので付けない（理由ではなく対象外。モジュールdoc）
    /// - `Err(reason)`: 宣言にあるが付けない
    ///
    /// 判定の順序は「制御ディレクトリ → 相対パス → ワークスペースの中 → ワイルドカード → ドライブ直下」。
    /// 制御ディレクトリを先に見るのは、ワークスペースの中の`.harness`も**付けなかった理由として見せる**
    /// ため（承認済みの宣言に制御ディレクトリがあること自体が、知らせるべき異常である）。
    pub fn grant_root(&self, value: &str) -> Result<Option<PathBuf>, SkipReason> {
        if is_harness_control_path(value)
            || self
                .harness_user_dir
                .as_deref()
                .is_some_and(|dir| is_under(value, dir))
        {
            return Err(SkipReason::ControlDirectory);
        }
        let normalized = harness_policy::normalize::normalize_path(value);
        if !is_absolute_windows_path(&normalized) {
            return Err(SkipReason::RelativePath);
        }
        if is_under(&normalized, &self.workspace_root) {
            return Ok(None);
        }
        if harness_policy::normalize::has_unsupported_wildcard(&normalized) {
            return Err(SkipReason::MiddleWildcard);
        }
        // [D-63] 切る位置は`normalize::literal_prefix`が1つだけ持つ。**幅の判定（`breadth`）と
        // 同じ関数を通す**——別々に切ると、承認してよいと判定した値と、実際にACEを付ける値が
        // 食い違う（B-05）。
        let literal = harness_policy::normalize::literal_prefix(&normalized);
        // ドライブ文字だけ（`C:` / `C:/`）しか残らないなら、事実上ドライブ全体への付与になる。
        // **空要素は数えない**——`C:/`は`["C:", ""]`に割れるので、要素数だけ見ると通ってしまう。
        // UNC（`//host/share/...`）は先頭の空要素2つを数えないので、`host`と`share`で2になる。
        if literal.split('/').filter(|s| !s.is_empty()).count() < 2 {
            return Err(SkipReason::DriveRoot);
        }
        let root = literal.trim_end_matches('/');
        Ok(Some(PathBuf::from(root)))
    }

    /// ドメインのファイル宣言を、付与処理が1件ずつ処理する**ワークスペース外のルート**へ畳む。
    ///
    /// **この関数が「件数」の唯一の定義である。** 付与の準備時間はこの件数にほぼ比例するので、
    /// 承認時の警告と実際に処理される集合が別々に数えていると、警告した数と待たされる数が
    /// 食い違う（B-05）。
    ///
    /// # 同じルートに複数のaccessが宣言されていたら「和」を取る
    ///
    /// 1つのオブジェクトのDACLへ同じ宛先SIDのACEを2本張ることはできないので、`fs.read_write`と
    /// `fs.read_exec`が同じルートに立ったら**両方を含む1本**（`ReadWriteExec`）にする。
    /// 「どちらかを選ぶ」規則では、どう選んでも片方の権限が黙って消える
    /// （`ReadWrite`に`FILE_GENERIC_EXECUTE`は入っていない）。合成の規則は[`FsAccess::wider`]が持つ。
    ///
    /// # [D-63] 範囲も一緒に畳む
    ///
    /// 同じルートに素の宣言と`<path>/**`が同居したら**再帰を採る**。逆向きにすると、
    /// ユーザーが`R`で明示的に広げた宣言が**別の行のせいで黙って効かなくなる**。
    ///
    /// # ドメインをまたいでは畳まない
    ///
    /// 引数は1ドメインである。2つのドメインの宣言を1本に畳むと、狭い側のドメインが
    /// 広い側の種類の許可を持つことになる。
    ///
    /// # [D-112] このマシンで承認した宣言だけ
    ///
    /// `approved`は宣言1件（ドメイン・値・種類）が承認済みかを答える。製品の呼び出しは
    /// `policy_approval::PolicyApprovalLedger::is_approved_for_key`をそのまま渡す。
    /// 引数にしてあるのは、承認する**前**の画面（件数の警告）が「今回承認する値も承認済みと
    /// みなした件数」を同じ関数で数えるためである——件数の定義をここ1つに保つ（B-05）。
    /// 照合はワークスペースの外かどうかの判定の**後**に行う（ワークスペースの中と制御ディレクトリは、
    /// 承認の有無に関係なく同じ扱いになる）。
    pub fn domain_grants(
        &self,
        domain: &PolicyDomain,
        approved: &dyn Fn(crate::tier2a::policy_approval::DeclarationRef<'_>) -> bool,
    ) -> DomainGrants {
        let mut out = DomainGrants::default();
        for (value, access) in domain.fs.entries() {
            let skip = |out: &mut DomainGrants, reason| {
                out.skipped.push(SkippedDeclaration {
                    value: value.to_string(),
                    access,
                    reason,
                })
            };
            let root = match self.grant_root(value) {
                Ok(Some(root)) => root,
                Ok(None) => continue,
                Err(reason) => {
                    skip(&mut out, reason);
                    continue;
                }
            };
            let declaration = crate::tier2a::policy_approval::DeclarationRef {
                domain: &domain.name,
                value,
                access,
            };
            if !approved(declaration) {
                skip(&mut out, SkipReason::NotApprovedOnThisMachine);
                continue;
            }
            let granted = FsAccess::from_settings(access);
            let scope = harness_policy::normalize::declared_scope(value);
            match out.passthrough.iter_mut().find(|fp| fp.path == root) {
                Some(existing) => {
                    existing.access = existing.access.wider(granted);
                    if scope.is_recursive() {
                        existing.scope = scope;
                    }
                }
                None => out.passthrough.push(FsPassthrough {
                    path: root,
                    access: granted,
                    // `--force-system-acl`（D-19）は`policy.json`からは使わせない。システム保護パスへ
                    // `SeRestorePrivilege`で強制付与するのは、宣言のついでにやってよい操作ではない
                    // （`harness fs`から明示的に行う）。
                    forced: false,
                    scope,
                }),
            }
        }
        out
    }
}

/// harnessのユーザースコープの制御ディレクトリ（`%APPDATA%\harness`）。
///
/// 台帳の置き場は`<config_dir>`だが、守るのは**その親**である——harnessが将来ここへ
/// 別のサブディレクトリを作っても、制御面である事実は同じ。綴りは
/// [`harness_grant_ledger::config_dir`]から導く（ここで`%APPDATA%\harness`と書き写すと、
/// 置き場を変えたときに静かにずれる。B-05）。
pub fn harness_user_dir() -> Option<PathBuf> {
    harness_grant_ledger::config_dir().and_then(|dir| dir.parent().map(Path::to_path_buf))
}

/// `.harness`（harnessの制御ディレクトリ）配下のパスか。
///
/// パス**要素**として`.harness`を持つかで判定する。前方一致で`<このworkspace>/.harness`だけを
/// 見ると、記録対象が別のリポジトリを走査したときにそちらの`.harness`を拾ってしまう——
/// どのworkspaceのものであれ、harnessの制御ディレクトリへの許可を出してよい理由は無い。
pub fn is_harness_control_path(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|component| component.eq_ignore_ascii_case(".harness"))
}

/// `value`が`root`自身か、その配下か。**配下判定の規則はこの1関数だけが持つ**（B-05・B-19）。
///
/// 値はワイルドカードを含み得る（`C:/Users/x/.cargo/**`）ので、**最初の`*`より前**の
/// 確定部分だけで比較する。綴りの正規化は`harness_policy::normalize::normalize_path`を通す
/// ——提案の値はその関数で揃えられているので、比較する側が別の規則を持つと一致しない（B-19）。
/// 大小は無視する（Windowsのパスは大小を区別しない）。
pub fn is_under(value: &str, root: &Path) -> bool {
    let value = harness_policy::normalize::normalize_path(value);
    let value = strip_verbatim_prefix(&value);
    let literal = value.split('*').next().unwrap_or("");
    let root = harness_policy::normalize::normalize_path(&root.to_string_lossy());
    // `canonicalize`したワークスペースは`\\?\C:\...`の形で来る。値の側は`C:/...`なので、
    // 前置を外さないと**同じ場所が配下と判定されない**（`harness.exe`は正規化した形を渡す）。
    let root = strip_verbatim_prefix(&root);
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    let literal_lower = literal.trim_end_matches('/').to_ascii_lowercase();
    let root_lower = root.to_ascii_lowercase();
    // 「root自身」または「root配下」。`C:/ws2`が`C:/ws`の配下と誤判定されないよう、
    // 直後が区切りであることまで見る。
    literal_lower == root_lower || literal_lower.starts_with(&format!("{root_lower}/"))
}

/// `//?/`（`\\?\`を正規化した形）の前置を外す。比較にだけ使う。
fn strip_verbatim_prefix(normalized: &str) -> &str {
    normalized.strip_prefix("//?/").unwrap_or(normalized)
}

/// Windowsの絶対パスか（`C:/...`か、UNCの`//host/...`）。区切りは`/`へ正規化済みであること。
///
/// `Path::is_absolute`を使わないのは、Windows以外のビルドで`C:/`を相対と判定するためである
/// ——`policy.json`の値はWindowsのパスで、判定は実行しているOSに依存させない。
fn is_absolute_windows_path(normalized: &str) -> bool {
    let bytes = normalized.as_bytes();
    let drive = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/';
    drive || normalized.starts_with("//")
}

#[cfg(test)]
#[path = "policy_grants_tests.rs"]
mod policy_grants_tests;
