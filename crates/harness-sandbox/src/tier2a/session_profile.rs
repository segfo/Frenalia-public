//! セッション単位のAppContainerプロファイル（D-37、`plans/DESIGN-SANDBOX-APPPOLICY.md`）。
//!
//! Tier2aは以前、固定名`harness.shell.sandbox`の**1プロファイル＝全セッション共通のpackage SID**で
//! 動いていた。この共有が、独立に見える複数の欠陥の共通の根だった（loopback exemptionの奪い合い
//! ＝[BUG-053](../../../docs/bugs/BUG-053.md)、プロファイル作成の並行競合＝BUG-054、WFP出口強制の
//! fail-open、そして**あるworkspaceのサンドボックスから別のworkspaceが読める**という封じ込めの破れ）。
//! 個別に塞いでも「共有された1つの主体」という構造が残る限り同じクラスが再生産されるため、
//! セッションごとに別プロファイル＝別package SIDにする。
//!
//! ## 何をこのモジュールが持つか
//!
//! - セッション固有プロファイル名の生成（[`PROFILE_PREFIX`]付き）と、そのプロセスでの確定
//! - プロセス生存を表明する名前付きmutex（`Local\harness-ac-<token>`）
//! - どのセッションがどのパスへACEを付けたかの台帳（`appcontainer-session-ledger.json`）
//! - 孤児（異常終了したセッション）の回収判定
//!
//! ## 台帳が消えても回収できる（台帳は最適化であって正しさの要件ではない）
//!
//! ACEはSIDしか保持せず、**プロファイルが存在していてもACLの表示は生SIDのまま**である
//! （実測）。一方で名前→SIDの導出は決定論的なので、「接頭辞付きのプロファイル名を列挙して
//! SIDを導出し、ACEと突き合わせる」という経路が使える。これが成立する条件が
//! **[`release`]がACE撤収を終えてから最後にプロファイルを削除する**ことで、途中で落ちても
//! 「接頭辞付きプロファイルが残っている」＝索引が生きている状態になる。
//!
//! 取りこぼした場合も、プロファイル名が一意なのでそのSIDは**二度と生成されない**。残った
//! ACEは死んだ主体宛の不活性な残骸であり、共有SID時代のように「未来の全セッションに対して
//! 生きた権限」にはならない（失敗時の安全側が逆転している）。

use std::path::{Path, PathBuf};

use harness_grant_ledger::{now_unix_secs, Ledger};
use serde::{Deserialize, Serialize};

/// セッションプロファイル名の接頭辞。**GCがこの接頭辞だけを頼りに孤児を列挙する**ため、
/// 変更するとそれ以前のセッションが作ったプロファイルを回収できなくなる。
pub const PROFILE_PREFIX: &str = "harness.shell.sandbox";

/// 台帳ファイル名。プロファイルはユーザー単位（HKCU）なので、台帳もユーザー単位で足りる。
const LEDGER_FILE: &str = "appcontainer-session-ledger.json";
const LEDGER_LOCK: &str = r"Local\harness-appcontainer-session-ledger";

fn owner_mutex_name(token: &str) -> String {
    format!(r"Local\harness-ac-{token}")
}

/// `token`のセッションプロファイル名。
pub fn profile_name_for(token: &str) -> String {
    format!("{PROFILE_PREFIX}.{token}")
}

/// harnessのセッションプロファイル名か。**信頼境界を越えて受け取った名前の検証**にも使う
/// （昇格側の`netfilterd`/`privhelper`は、渡された名前がこの形であることを確認してから
/// SIDを導出する）。区切り文字と英数字・ハイフンだけを許し、パス・ワイルドカード等を弾く。
pub fn is_session_profile_name(name: &str) -> bool {
    let Some(token) = name.strip_prefix(&format!("{PROFILE_PREFIX}.")) else {
        return false;
    };
    !token.is_empty()
        && token.len() <= 40
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// このプロセスのセッショントークン（プロセス内で一度だけ確定する）。
///
/// `pid`は生きているプロセス間で一意、`unix_secs`はpid再利用で同名になるのを避けるための
/// 補助。生存判定そのものは名前付きmutexで行うので、この値の一意性は「同時に生きている
/// セッション同士が衝突しない」ことだけを保証すればよい。
pub fn session_token() -> &'static str {
    static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| format!("{}-{}", std::process::id(), now_unix_secs()))
}

/// このプロセスのセッションプロファイル名。
pub fn current_profile_name() -> String {
    profile_name_for(session_token())
}

// --- 台帳 ---

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionLedger {
    #[serde(default)]
    pub sessions: Vec<SessionEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionEntry {
    pub token: String,
    pub profile_name: String,
    /// このセッションがACEを付けたパス（workspace root・CoW upper_dir・`--fs-allow`の穴）。
    /// 撤収はここを順に剥がす。台帳が失われた場合はプロファイル削除だけに縮退する。
    #[serde(default)]
    pub granted_paths: Vec<String>,
    pub created_at_unix_secs: u64,
    /// このセッションが起動したMCPサーバのプロファイル（D-38、`plans/DESIGN-MCP.md` §3.1）。
    ///
    /// **既存の台帳ファイルとの後方互換のため`#[serde(default)]`で後付けする**（実マシンに
    /// 既に存在する`appcontainer-session-ledger.json`は上の3フィールドしか持たない）。
    /// MCPプロファイルはセッションと同じ寿命なので、独立した台帳ではなくここへぶら下げる
    /// ——セッションが死ねば`plan_reclaim`が同じ判定で一緒に回収する。
    #[serde(default)]
    pub mcp: Vec<McpProfileEntry>,
}

/// セッション配下のMCPサーバプロファイル1件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpProfileEntry {
    pub profile_name: String,
    /// このMCPサーバのSID宛にACEを付けたパス（実行ファイル・依存ディレクトリ・
    /// 宣言が明示要求したworkspaceパス）。**workspaceは既定で含まれない**（§3.2）。
    #[serde(default)]
    pub granted_paths: Vec<String>,
}

fn ledger() -> Ledger<SessionLedger> {
    Ledger::in_config_dir(LEDGER_FILE, Some(LEDGER_LOCK))
}

// --- 回収判定（純粋関数。Win32もファイルも触らない） ---

/// 回収対象1件。
#[derive(Debug, Clone, PartialEq)]
pub struct ReclaimTarget {
    pub profile_name: String,
    pub granted_paths: Vec<String>,
    /// **このプロファイルが何を付与したかを台帳から復元できたか。**
    ///
    /// `false`＝台帳エントリが失われており、`granted_paths`が空なのは
    /// 「付与が無かった」ではなく「**分からない**」を意味する。この2つは絶対に混ぜない
    /// ——混ぜると「剥がすものが無い」と読んでプロファイルを消してしまう。
    ///
    /// プロファイル名を失うとSIDが導出できなくなり、そのSID宛のACEは
    /// **どのコマンドでも剥がせない孤児**になる（BUG-101で`%TEMP%`に1件実在した）。
    /// したがって`grants_known == false`のものは**削除しない**（名前を残す＝回収可能性を残す）。
    pub grants_known: bool,
}

/// harness由来のプロファイル名からセッショントークンを取り出す。
///
/// `run_shell`用は`harness.shell.sandbox.<token>`、MCPサーバ用は
/// `harness.mcp.<token>.<server-id>`。**どちらもトークンで生存判定する**ので、GCは種別を
/// 意識せずに回収できる（MCPプロファイルはセッションと同じ寿命、`mcp_profile`のdoc参照）。
pub fn token_of_profile(name: &str) -> Option<&str> {
    if let Some(token) = name.strip_prefix(&format!("{PROFILE_PREFIX}.")) {
        return (!token.is_empty()).then_some(token);
    }
    let suffix = name.strip_prefix(&format!(
        "{}.",
        crate::tier2a::mcp_profile::MCP_PROFILE_PREFIX
    ))?;
    let (token, server_id) = suffix.rsplit_once('.')?;
    (!token.is_empty() && !server_id.is_empty()).then_some(token)
}

/// 台帳と「実在するharnessプロファイル名の一覧」から、回収すべきものを決める。
///
/// - 台帳にあり、生存マーカーが無い → そのパスのACEを剥がしてプロファイルを消す
///   （`run_shell`用プロファイルと、そのセッションが起動したMCPサーバのプロファイルの両方）
/// - 台帳に無いが接頭辞付きプロファイルが実在し、生存マーカーも無い → `grants_known: false`。
///   **プロファイルは消さない**（BUG-101。かつては「プロファイルだけ消す」としていたが、
///   それは付与済みACEを永久に回収不能にする操作だった。詳細は[`ReclaimTarget::grants_known`]）
/// - 生存マーカーがある → 触らない（実行中の他セッション）
pub fn plan_reclaim(
    ledger: &SessionLedger,
    existing_profiles: &[String],
    is_live: &dyn Fn(&str) -> bool,
) -> Vec<ReclaimTarget> {
    let mut targets = Vec::new();
    for entry in &ledger.sessions {
        if is_live(&entry.token) {
            continue;
        }
        targets.push(ReclaimTarget {
            profile_name: entry.profile_name.clone(),
            granted_paths: entry.granted_paths.clone(),
            grants_known: true,
        });
        for mcp in &entry.mcp {
            targets.push(ReclaimTarget {
                profile_name: mcp.profile_name.clone(),
                granted_paths: mcp.granted_paths.clone(),
                grants_known: true,
            });
        }
    }
    let known: std::collections::HashSet<&str> = ledger
        .sessions
        .iter()
        .flat_map(|e| {
            std::iter::once(e.profile_name.as_str())
                .chain(e.mcp.iter().map(|m| m.profile_name.as_str()))
        })
        .collect();
    for name in existing_profiles {
        if known.contains(name.as_str()) {
            continue;
        }
        let Some(token) = token_of_profile(name) else {
            continue;
        };
        if !is_live(token) {
            targets.push(ReclaimTarget {
                profile_name: name.clone(),
                granted_paths: Vec::new(),
                grants_known: false,
            });
        }
    }
    targets
}

/// プロファイル名の**所有者**（[BUG-107](../../../docs/bugs/BUG-107.md)）。
///
/// 「誰のものか」の定義を[`token_of_profile`]1本に寄せるための型。GCが回収してよいかを決めるのも、
/// [`crate::tier2a::win_appcontainer::ensure_profile`]が作ってよいかを決めるのも同じ根拠でなければ
/// ならない——ずれると「作る側は自分のものと思い、回収する側は他人のものと思う」プロファイルが
/// でき、それは永久に残る（B-05: コンパイラが守らない一致には唯一の判定点を置く）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOwner<'a> {
    /// このプロセスのセッションのもの（`run_shell`用・MCPサーバ用の両方）。
    ThisSession,
    /// **他プロセス**のセッションのもの。作ってよいのは持ち主だけ。
    OtherSession(&'a str),
    /// トークンを持たない名前＝旧共有プロファイル（[`LEGACY_SHARED_PROFILE`]）。
    /// セッションに属さないので記録する相手も居ない。
    Unowned,
}

/// プロファイル名の所有者を判定する（純粋関数。Win32もファイルも触らない）。
pub fn owner_of_profile(name: &str) -> ProfileOwner<'_> {
    match token_of_profile(name) {
        Some(token) if token == session_token() => ProfileOwner::ThisSession,
        Some(other) => ProfileOwner::OtherSession(other),
        None => ProfileOwner::Unowned,
    }
}

/// 実在するharness由来のプロファイル名（台帳非依存の列挙）。**テスト専用の口。**
///
/// GCの内部で使っているものを、**増減を測るため**にcrate内のテストへ開ける。BUG-107は
/// 戻り値にも応答にも現れず「1実行あたり1件増える」という**実マシンの資源の数**でしか
/// 検出できなかった欠陥で、その回帰テストは実行の前後でこの集合を突き合わせる以外に
/// 書きようが無い。製品側の公開面は広げない（`grant_ace_mask_for_test`と同じ扱い）。
#[cfg(all(windows, test))]
pub(crate) fn existing_profile_names() -> Vec<String> {
    win::existing_profiles()
}

/// **1つの名前のプロファイルが実在するか。テスト専用の口。**
///
/// [`existing_profile_names`]と違い、ディレクトリを**列挙しない**（対象1件を`stat`するだけ）。
/// 列挙は`read_dir`が失敗すると空を返す設計で、`cargo test`のように**同じバイナリの別テストが
/// プロファイルを作り消ししている最中**は結果が揺れる。「増えていないこと」を測るテストが
/// その揺れを拾うと、直したはずの欠陥と無関係に赤くなる（実際に2/6の頻度で踏んだ）。
///
/// 測りたいのが**特定の1件**なら、そもそも列挙する必要が無い。
#[cfg(all(windows, test))]
pub(crate) fn profile_exists(name: &str) -> bool {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    PathBuf::from(local).join("Packages").join(name).is_dir()
}

// --- Windows依存部（生存マーカー・プロファイル列挙・実際の作成/削除） ---

#[cfg(windows)]
mod win {
    use super::*;
    use crate::win_common::{hold_mutex_for_process_lifetime, mutex_exists};

    pub(super) fn is_live(token: &str) -> bool {
        mutex_exists(&owner_mutex_name(token))
    }

    /// このプロセスの生存マーカーを立てる（プロセス終了＝正常/クラッシュを問わず消える）。
    pub(super) fn hold_marker(token: &str) -> Result<(), String> {
        hold_mutex_for_process_lifetime(&owner_mutex_name(token))
            .map_err(|e| format!("failed to create session marker: {e}"))
    }

    /// `%LOCALAPPDATA%\Packages`から接頭辞付きプロファイル名を列挙する（台帳非依存の回収経路）。
    /// `run_shell`用（D-37）とMCPサーバ用（D-38）の両方を拾う。
    pub(super) fn existing_profiles() -> Vec<String> {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return Vec::new();
        };
        let dir = PathBuf::from(local).join("Packages");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            // プロファイルのフォルダ名は「<名前>_<publisher hash>」形式なので、接頭辞で拾って
            // 名前部分だけを取り出す。
            .filter_map(|name| {
                let base = name.split('_').next().unwrap_or(&name).to_string();
                crate::tier2a::mcp_profile::is_harness_profile_name(&base).then_some(base)
            })
            .collect()
    }

    /// プロファイルを削除する。**戻り値を捨てないこと**——削除に失敗したのに台帳エントリを
    /// 消すと、そのプロファイルは「台帳に無いが実在する」分類へ落ち、次のGCが
    /// `grants_known: false`として拾う。そこで削除してしまうとSIDが二度と導出できなくなり、
    /// **そのSID宛のACEはどのコマンドでも剥がせない孤児になる**（BUG-101）。
    /// **[2026-08-12] 戻り値だけでは足りない。実際に消えたかを見る。**
    ///
    /// `DeleteAppContainerProfile`は**S_OKを返しながら何も消さないことがある**（実測。
    /// この機で`Storage`にも`Mappings`にもフォルダにも変化が無いまま`hr=0x00000000`が返った）。
    /// そのまま成功として扱うと、上位の`reclaim_targets`が**台帳エントリだけを落とす**——
    /// プロファイルは実在するのに記録が消えるので、次のGCからは`grants_known: false`に見え、
    /// **以後永久に回収されない**。実機に66件たまっていたのはこの形である（B-09/B-33:
    /// 他人の成功報告を根拠にしない。「呼んだ」と「消えた」は別の事実）。
    pub(super) fn delete_profile(name: &str) -> Result<(), String> {
        unsafe {
            let w = crate::win_common::wide(name);
            windows::Win32::Security::Isolation::DeleteAppContainerProfile(windows::core::PCWSTR(
                w.as_ptr(),
            ))
            .map_err(|e| e.to_string())?;
        }
        // 検算。ここで`Err`にすれば、呼び出し側は台帳エントリを残す（次回また試せる）。
        if existing_profiles().iter().any(|p| p == name) {
            return Err(format!(
                "DeleteAppContainerProfile reported success but {name} is still registered; \
                 keeping the ledger entry so it stays reclaimable"
            ));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod win {
    use super::*;
    pub(super) fn is_live(_token: &str) -> bool {
        false
    }
    pub(super) fn hold_marker(_token: &str) -> Result<(), String> {
        Ok(())
    }
    pub(super) fn existing_profiles() -> Vec<String> {
        Vec::new()
    }
    pub(super) fn delete_profile(_name: &str) -> Result<(), String> {
        Ok(())
    }
}

/// このセッションの生存マーカーを立て、台帳へ登録する（プロファイル自体の作成は
/// `win_appcontainer::ensure_profile`が行う）。冪等——同じプロセスから2回呼んでもよい。
pub fn begin_session() -> Result<String, String> {
    let token = session_token();
    win::hold_marker(token)?;
    let name = current_profile_name();
    let entry_name = name.clone();
    ledger().update(|l| {
        if !l.sessions.iter().any(|e| e.token == token) {
            l.sessions.push(SessionEntry {
                token: token.to_string(),
                profile_name: entry_name,
                granted_paths: Vec::new(),
                created_at_unix_secs: now_unix_secs(),
                mcp: Vec::new(),
            });
        }
    });
    Ok(name)
}

/// このセッションがACEを付けたパスを台帳へ記録する（撤収時に剥がす対象）。
pub fn record_granted_path(path: &Path) {
    record_granted_paths(std::slice::from_ref(&path.to_path_buf()));
}

/// 複数パスを**1回の台帳更新で**記録する。
///
/// # なぜ要るか（実測）
///
/// `Ledger::update`は1回ごとに「ロック取得 → 全文読取 → パース → 直列化 →
/// **`.bak`へ全文コピー** → 読取専用属性を外す → 全文書込 → 読取専用へ戻す」を行います。
/// この台帳はこの開発機で**66KB**あるので、1件あたり約200KBのファイルI/Oです。
/// workspace外のルートが668件あるドメインでは**約130MB**になり、数秒かかります。
///
/// **1件もACEを書いていない実行でも同じだけ払う**のが特に悪い点でした——
/// `already_sufficient`（前回の付与が生きているのでWin32を1回も呼ばない経路）でも、
/// 「このセッションが撤収責任を負う」記録は必要なので毎回呼ばれます（BUG-057）。
///
/// **ループの中で`update`を呼ばない。** 台帳のAPIは「1件足す」ように見えますが、
/// 実体は全文の読み書きです。
pub fn record_granted_paths(paths: &[std::path::PathBuf]) {
    if paths.is_empty() {
        return;
    }
    let token = session_token();
    let mut recorded = false;
    ledger().update(|l| {
        if let Some(entry) = l.sessions.iter_mut().find(|e| e.token == token) {
            recorded = true;
            for path in paths {
                let path_str = path.to_string_lossy().into_owned();
                if !entry.granted_paths.contains(&path_str) {
                    entry.granted_paths.push(path_str);
                }
            }
        }
    });
    // [BUG-101] **無言のno-opをやめる。** 台帳にこのセッションのエントリが無ければ、ここは
    // 何も書かずに戻る——付与は成功しているので呼び出し側は成功と読み、撤収の対象にも
    // ならないACEが実マシンに残る（`end_session`はエントリの`granted_paths`しか剥がさない）。
    // 「記録できなかった」は付与の失敗ではないので**止めはしない**が、黙りもしない（B-10）。
    if !recorded {
        eprintln!(
            "warning: could not record {} granted path(s) for session {token}: the session has no \
             ledger entry, so these ACEs will not be revoked automatically (see \
             docs/bugs/BUG-101.md)",
            paths.len()
        );
    }
}

/// このセッションが撤収責任を負っているパス（[`record_granted_path`]で積んだもの）。
///
/// [`end_session`]が実際に剥がす集合そのもので、「付与したのに記録し忘れていないか」を
/// 機械的に確かめるために公開する（BUG-057・BUG-059はどちらも**付与したのに記録しなかった**
/// 欠陥だった。台帳を読めなければ、その種の漏れはテストで固定できない）。
pub fn granted_paths_for_current_session() -> Vec<String> {
    let token = session_token();
    ledger()
        .load()
        .sessions
        .into_iter()
        .find(|e| e.token == token)
        .map(|e| e.granted_paths)
        .unwrap_or_default()
}

/// このセッションが起動するMCPサーバのプロファイルを台帳へ登録し、その名前を返す（D-38）。
/// 冪等——同じ`server_id`で2回呼んでもエントリは増えない。
///
/// **プロファイルの実作成（`ensure_profile`）より先に呼ぶこと。** 逆順だと、作成直後に落ちた
/// 場合に「実在するが台帳に無いプロファイル」が残る——接頭辞による回収経路があるので致命では
/// ないが、ACEを剥がす対象が分からなくなる。
pub fn record_mcp_profile(server_id: &str) -> String {
    let token = session_token();
    let name = crate::tier2a::mcp_profile::current_mcp_profile_name(server_id);
    let entry_name = name.clone();
    // [BUG-107] **ぶら下げる先が無ければ作る。** MCPエントリはセッションエントリの子なので、
    // `begin_session`を通っていないと下の`update`は**黙って何もしない**——直後に
    // `ensure_profile`が実資源を作るので、記録の無いプロファイルが残る（この欠陥の型そのもの）。
    // 冪等なので、既に通っていれば何も起きない。
    if let Err(e) = begin_session() {
        eprintln!(
            "warning: could not open a session ledger entry for the MCP profile {name} ({e}); \
             its AppContainer profile will not be reclaimed automatically \
             (see docs/bugs/BUG-107.md)"
        );
    }
    ledger().update(|l| {
        if let Some(entry) = l.sessions.iter_mut().find(|e| e.token == token) {
            if !entry.mcp.iter().any(|m| m.profile_name == entry_name) {
                entry.mcp.push(McpProfileEntry {
                    profile_name: entry_name,
                    granted_paths: Vec::new(),
                });
            }
        }
    });
    name
}

/// MCPサーバのSID宛にACEを付けたパスを台帳へ記録する（撤収時に剥がす対象）。
pub fn record_mcp_granted_path(profile_name: &str, path: &Path) {
    let token = session_token();
    let path_str = path.to_string_lossy().into_owned();
    ledger().update(|l| {
        let Some(entry) = l.sessions.iter_mut().find(|e| e.token == token) else {
            return;
        };
        let Some(mcp) = entry
            .mcp
            .iter_mut()
            .find(|m| m.profile_name == profile_name)
        else {
            return;
        };
        if !mcp.granted_paths.contains(&path_str) {
            mcp.granted_paths.push(path_str);
        }
    });
}

/// 回収（GC）と自セッションの撤収に共通の後始末。`revoke`は「そのパスのACEを剥がす」処理を
/// 呼び出し元から注入する（このモジュールはACL APIを知らない＝規則3の分割線）。
///
/// **順序が重要**: ACEを剥がしてから最後にプロファイルを削除する（モジュールdoc参照）。
///
/// # 削除してよい条件（BUG-101）
///
/// プロファイル名を消すとSIDが導出できなくなり、そのSID宛に残っているACEは
/// **どのコマンドでも剥がせない孤児**になります。したがって削除は
/// **「このプロファイルが何を付与したかを台帳から復元できた」場合に限り**行います
/// （`grants_known`）。復元できないものは名前を残す——回収可能性を残す方が、
/// プロファイルが1件積もることよりはるかに安全です。
///
/// **台帳エントリを消すのは、プロファイルを実際に削除できたときだけ**です。
/// 削除に失敗したのにエントリを消すと、次のGCから見て「台帳に無いが実在する」＝
/// `grants_known: false`へ落ち、以後この関数は二度とそのACEを剥がせなくなります。
///
/// 戻り値は[`ReclaimOutcome`]（B-09: 多段の副作用は件数を返す）。
/// 撤収コールバックの戻り値＝**剥がせなかったノードと理由**（空なら完全に剥がせた）。
///
/// [BUG-103] かつてコールバックは`()`を返しており、`revoke_session_grant`の中で
/// `let _ = revoke_ace_recursive(...)`と捨てられていた。撤収が1件も成功しなくても
/// 呼び出し側からは成功と区別が付かず、実マシンに`(OI)(CI)(R,W,D)`が残り続けた（B-09）。
///
/// このモジュールはACL APIを知らない（規則3の分割線）ので、ACL側の型
/// （`win_appcontainer::RevokeReport`）ではなく素のデータで受け取る。
pub type RevokeLeftovers = Vec<(PathBuf, String)>;

fn reclaim_targets(
    targets: &[ReclaimTarget],
    revoke: &dyn Fn(&Path, &str) -> RevokeLeftovers,
) -> ReclaimOutcome {
    let mut outcome = ReclaimOutcome::default();
    let mut deleted: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for target in targets {
        if !target.grants_known {
            // 何を付与したか分からない以上、剥がせない。名前を消せば永久に剥がせなくなるので残す。
            outcome.kept_unknown.push(target.profile_name.clone());
            continue;
        }
        let mut blocked_here = Vec::new();
        for path in &target.granted_paths {
            blocked_here.extend(revoke(Path::new(path), &target.profile_name));
            outcome.revoked_paths += 1;
        }
        // [BUG-101] **名前を捨てる直前に、この主体のACEが本当に残っていないかを測る。**
        // ここが最後の分岐点である——`DeleteAppContainerProfile`はSIDの導出元である名前を
        // 破棄するので、これ以降に残ったACEは`harness fs revoke`を含むどのコマンドでも
        // 剥がせない（SIDの導出は名前→SIDの一方向）。
        let audit = crate::tier2a::grant_audit::audit_profile(
            crate::tier2a::grant_audit::Stage::SessionEnd,
            &target.profile_name,
            &target.granted_paths,
        );
        if let Some(audit) = &audit {
            crate::tier2a::grant_audit::report(audit);
        }
        let unrecorded = audit.map(|a| a.present_unrecorded.len()).unwrap_or(0);
        // **剥がし残しがあるなら名前を残す。** 見送りの扱いは`grants_known: false`と同じ
        // （後から`harness fs revoke <path>`で剥がせる状態のまま置く）。プロファイルが1件
        // 積むことより、二度と剥がせないACEを作ることの方が重い（B-01の「不可逆な片方」）。
        if !blocked_here.is_empty() || unrecorded > 0 {
            outcome.kept_with_leftovers.push((
                target.profile_name.clone(),
                blocked_here.len(),
                unrecorded,
            ));
            outcome.blocked_paths.extend(blocked_here);
            continue;
        }
        outcome.blocked_paths.extend(blocked_here);
        match win::delete_profile(&target.profile_name) {
            Ok(()) => {
                outcome.deleted_profiles += 1;
                deleted.insert(target.profile_name.as_str());
            }
            // 削除できなかったので台帳エントリは**残す**（次回のGCが同じ経路で再試行できる）。
            Err(reason) => outcome
                .delete_failures
                .push((target.profile_name.clone(), reason)),
        }
    }
    if !deleted.is_empty() {
        ledger().update(|l| {
            l.sessions
                .retain(|e| !deleted.contains(e.profile_name.as_str()))
        });
    }
    outcome
}

/// [`reclaim_targets`]が実際に何をしたか。**「やった」と「うまくいった」は別の事実**なので、
/// 呼び出し側が区別できる形で返す（B-09）。
#[derive(Debug, Default, PartialEq)]
pub struct ReclaimOutcome {
    /// 実際に削除できたプロファイル数。
    pub deleted_profiles: usize,
    /// 撤収を試みたパスの延べ件数。
    pub revoked_paths: usize,
    /// 削除に失敗したプロファイルと理由。台帳エントリは残してある（次回再試行される）。
    pub delete_failures: Vec<(String, String)>,
    /// **付与内容が分からないので削除を見送ったプロファイル**（`grants_known: false`）。
    /// ここが増え続けるなら、台帳エントリが失われる経路が別に在るということ（B-11）。
    pub kept_unknown: Vec<String>,
    /// [BUG-101] **剥がし残しがあるので削除を見送ったプロファイル**と、その内訳
    /// `(プロファイル名, 剥がせなかったノード数, 台帳に無いACEの数)`。
    ///
    /// `kept_unknown`（何を付けたか分からない）とは別枠にする——あちらは「記録が無い」、
    /// こちらは「記録はあるが実体が残っている」で、次に打つ手が違う（こちらは
    /// `harness fs revoke <path>`で剥がせる）。
    pub kept_with_leftovers: Vec<(String, usize, usize)>,
    /// [BUG-103] **撤収を試みたが剥がせなかったノードと理由。**
    ///
    /// プロファイルは消えても、ここに挙がったノードのACEは実マシンに残っている。
    /// SIDはプロファイル名から導出するので、プロファイルが消えた後は
    /// **どのコマンドでも剥がせない孤児**になる——だから件数ではなく**名前**を残す
    /// （`icacls <path> /remove:g *<SID>`で追える形にする、B-09）。
    pub blocked_paths: RevokeLeftovers,
}

impl ReclaimOutcome {
    /// 人へ見せる要約。何も起きなかったときは`None`（無害な行で画面を埋めない）。
    pub fn summary(&self) -> Option<String> {
        if self.deleted_profiles == 0
            && self.delete_failures.is_empty()
            && self.kept_unknown.is_empty()
            && self.kept_with_leftovers.is_empty()
            && self.blocked_paths.is_empty()
        {
            return None;
        }
        let mut parts = Vec::new();
        if self.deleted_profiles > 0 {
            parts.push(format!(
                "回収したセッションプロファイル {} 件（撤収したパス {} 件）",
                self.deleted_profiles, self.revoked_paths
            ));
        }
        for (name, reason) in &self.delete_failures {
            parts.push(format!(
                "{name} の削除に失敗しました（{reason}）。台帳に残したので次回再試行します"
            ));
        }
        if !self.kept_unknown.is_empty() {
            parts.push(format!(
                "付与内容を台帳から復元できないプロファイル {} 件は削除を見送りました\
                 （消すとACEが剥がせなくなるため。`harness fs list`で確認できます）: {}",
                self.kept_unknown.len(),
                self.kept_unknown.join(", ")
            ));
        }
        // [BUG-101] 「剥がし残しがあるので名前を残した」——`kept_unknown`と混ぜない。
        // こちらは**まだ剥がせる**状態なので、次に打つ手（`harness fs revoke <path>`）がある。
        if !self.kept_with_leftovers.is_empty() {
            let detail: Vec<String> = self
                .kept_with_leftovers
                .iter()
                .map(|(name, blocked, unrecorded)| {
                    format!(
                        "{name}（剥がせなかったノード{blocked}件・台帳に無いACE{unrecorded}件）"
                    )
                })
                .collect();
            parts.push(format!(
                "ACEが残っているプロファイル {} 件は削除を見送りました（いま名前を捨てると\
                 SIDを導出できなくなり、二度と剥がせなくなるため）。`harness fs revoke <path>`で\
                 剥がしてください: {}",
                self.kept_with_leftovers.len(),
                detail.join(", ")
            ));
        }
        // [BUG-103] **剥がせなかったノードは名前で出す。** 件数だけだと`icacls`で追えず、
        // プロファイル削除後はSIDを導出できないので二度と剥がせない（B-09）。
        if !self.blocked_paths.is_empty() {
            const SHOWN: usize = 5;
            let head: Vec<String> = self
                .blocked_paths
                .iter()
                .take(SHOWN)
                .map(|(path, reason)| format!("{} ({reason})", path.display()))
                .collect();
            let mut line = format!(
                "**ACEを剥がせなかったノード {} 件**（このマシンに残ります）: {}",
                self.blocked_paths.len(),
                head.join(" / ")
            );
            if self.blocked_paths.len() > SHOWN {
                line.push_str(&format!(" ほか{}件", self.blocked_paths.len() - SHOWN));
            }
            parts.push(line);
        }
        Some(parts.join(" / "))
    }
}

/// D-37以前に使っていた**共有プロファイル**の名前。この名前のプロファイルが付けたACEは、
/// セッション単位化した後も実マシンに残り得るため、撤収系のコマンドは常にこれも対象にする。
/// `is_session_profile_name`は（接尾辞が無いので）これを拒否する——**セッションではない**
/// ことを型ではなく名前の形で区別している。
pub const LEGACY_SHARED_PROFILE: &str = PROFILE_PREFIX;

/// ACEの撤収対象になり得るharness由来のプロファイル名を列挙する（`harness fs revoke*`用）。
///
/// 旧共有プロファイルと、**生きていないセッション**のプロファイルを返す。実行中のセッションの
/// ものは含めない——他のharnessが使っている最中のACEを剥がすのは、BUG-053で直したのと同じ
/// 「実行中の他セッションから権限を奪う」誤りになる。
pub fn revocable_profile_names() -> Vec<String> {
    let mut names = vec![LEGACY_SHARED_PROFILE.to_string()];
    let ledger_names: Vec<(String, Vec<String>)> = ledger()
        .load()
        .sessions
        .into_iter()
        .map(|e| {
            let profiles = std::iter::once(e.profile_name)
                .chain(e.mcp.into_iter().map(|m| m.profile_name))
                .collect();
            (e.token, profiles)
        })
        .collect();
    for (token, profiles) in ledger_names {
        if win::is_live(&token) {
            continue;
        }
        for profile in profiles {
            if !names.contains(&profile) {
                names.push(profile);
            }
        }
    }
    for profile in win::existing_profiles() {
        let Some(token) = token_of_profile(&profile) else {
            continue;
        };
        if !win::is_live(token) && !names.contains(&profile) {
            names.push(profile);
        }
    }
    names
}

/// **生存している**セッション（とそのMCPサーバ）のプロファイル名を列挙する。
///
/// [`revocable_profile_names`]の裏返しで、「剥がしてはいけない側」を明示的に取るための関数。
/// 台帳に無いACEを既知パスから掃く経路（BUG-059の孤立ACE回収、`preflight`）が使う——
/// **プロファイルが削除済みのSIDは名前へ逆引きできない**（`DeriveAppContainerSidFrom
/// AppContainerName`は名前→SIDの一方向）ので、「死んだものを名指しして剥がす」方式が使えない。
/// 残す側を名指しし、それ以外を剥がすという向きにするしかない。
///
/// 実行中の他セッションのACEを巻き込まないことが、この関数の唯一の存在意義である
/// （BUG-053で直したのと同じ「実行中の他セッションから権限を奪う」誤りを繰り返さない）。
pub fn live_profile_names() -> Vec<String> {
    let mut names = Vec::new();
    for entry in ledger().load().sessions {
        if !win::is_live(&entry.token) {
            continue;
        }
        for profile in
            std::iter::once(entry.profile_name).chain(entry.mcp.into_iter().map(|m| m.profile_name))
        {
            if !names.contains(&profile) {
                names.push(profile);
            }
        }
    }
    // 台帳が失われていても、接頭辞付きプロファイルの列挙と生存マーカーで生存判定はできる
    // （`revocable_profile_names`と同じ二重化）。
    for profile in win::existing_profiles() {
        let Some(token) = token_of_profile(&profile) else {
            continue;
        };
        if win::is_live(token) && !names.contains(&profile) {
            names.push(profile);
        }
    }
    names
}

/// 死んだセッションの資源を回収する（起動時に呼ぶ）。
///
/// 返り値は**実際に回収できた件数**であって、対象として挙がった件数ではない
/// （`grants_known: false`のものは意図的に見送るため、両者は一致しない）。
/// 見送りや削除失敗の内訳は[`ReclaimOutcome`]で受け取る。
pub fn gc_dead_sessions_reporting(
    revoke: &dyn Fn(&Path, &str) -> RevokeLeftovers,
) -> ReclaimOutcome {
    let targets = plan_reclaim(&ledger().load(), &win::existing_profiles(), &win::is_live);
    reclaim_targets(&targets, revoke)
}

/// [`gc_dead_sessions_reporting`]の件数だけが要る呼び出し向け。
pub fn gc_dead_sessions(revoke: &dyn Fn(&Path, &str) -> RevokeLeftovers) -> usize {
    gc_dead_sessions_reporting(revoke).deleted_profiles
}

/// このセッションの資源を撤収する（正常終了時に呼ぶ。落ちた場合は次回起動の
/// [`gc_dead_sessions`]が同じ経路で回収する）。
///
/// [BUG-103] **結果を返す**（`#[must_use]`）。かつては`()`で、剥がせなかったノードが
/// ここで消えていた——`end_session`はセッション終了時の**唯一の撤収経路**なので、
/// ここで捨てると孤立ACEは誰の目にも触れずに実マシンへ残る。
#[must_use]
pub fn end_session(revoke: &dyn Fn(&Path, &str) -> RevokeLeftovers) -> ReclaimOutcome {
    let token = session_token();
    let Some(entry) = ledger()
        .load()
        .sessions
        .into_iter()
        .find(|e| e.token == token)
    else {
        return ReclaimOutcome::default();
    };
    // MCPサーバのプロファイルも同じ経路で撤収する（このセッションと同じ寿命、D-38）。
    // 自セッションは台帳エントリを読めているので`grants_known: true`（付与が0件だったのなら、
    // それは「分からない」ではなく「無かった」である）。
    let mut targets = vec![ReclaimTarget {
        profile_name: entry.profile_name,
        granted_paths: entry.granted_paths,
        grants_known: true,
    }];
    targets.extend(entry.mcp.into_iter().map(|m| ReclaimTarget {
        profile_name: m.profile_name,
        granted_paths: m.granted_paths,
        grants_known: true,
    }));
    reclaim_targets(&targets, revoke)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn entry(token: &str, paths: &[&str]) -> SessionEntry {
        SessionEntry {
            token: token.to_string(),
            profile_name: profile_name_for(token),
            granted_paths: paths.iter().map(|p| p.to_string()).collect(),
            created_at_unix_secs: 0,
            mcp: Vec::new(),
        }
    }

    fn entry_with_mcp(token: &str, servers: &[(&str, &[&str])]) -> SessionEntry {
        let mut e = entry(token, &[]);
        e.mcp = servers
            .iter()
            .map(|(id, paths)| McpProfileEntry {
                profile_name: crate::tier2a::mcp_profile::mcp_profile_name_for(token, id),
                granted_paths: paths.iter().map(|p| p.to_string()).collect(),
            })
            .collect();
        e
    }

    fn liveness(live: &HashSet<String>) -> impl Fn(&str) -> bool + '_ {
        move |token: &str| live.contains(token)
    }

    #[test]
    fn profile_names_carry_the_prefix_so_gc_can_find_them_without_the_ledger() {
        let name = profile_name_for("1234-99");
        assert!(name.starts_with(PROFILE_PREFIX));
        assert!(is_session_profile_name(&name));
    }

    /// 信頼境界を越えて受け取る名前の検証（昇格側が使う）。
    #[test]
    fn only_well_formed_session_profile_names_are_accepted() {
        assert!(is_session_profile_name("harness.shell.sandbox.1234-5678"));
        assert!(!is_session_profile_name("harness.shell.sandbox"));
        assert!(!is_session_profile_name("harness.shell.sandbox."));
        assert!(!is_session_profile_name("other.container.1234"));
        assert!(!is_session_profile_name("harness.shell.sandbox.../evil"));
        assert!(!is_session_profile_name("harness.shell.sandbox.a b"));
        assert!(!is_session_profile_name(&format!(
            "harness.shell.sandbox.{}",
            "x".repeat(41)
        )));
    }

    #[test]
    fn live_sessions_are_never_reclaimed() {
        let ledger = SessionLedger {
            sessions: vec![entry("alive", &["C:\\ws"]), entry("dead", &["C:\\other"])],
        };
        let mut live = HashSet::new();
        live.insert("alive".to_string());

        let targets = plan_reclaim(&ledger, &[], &liveness(&live));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].profile_name, profile_name_for("dead"));
        assert_eq!(targets[0].granted_paths, vec!["C:\\other".to_string()]);
    }

    /// 台帳が消えたプロファイルは、接頭辞付きの実在から**見つけられる**。ただし
    /// 付与内容は分からないので`grants_known: false`が立つ。
    #[test]
    fn profiles_without_a_ledger_entry_are_found_but_marked_unknown() {
        let empty = SessionLedger::default();
        let existing = vec![
            profile_name_for("orphan"),
            profile_name_for("running"),
            "some.other.appcontainer".to_string(),
        ];
        let mut live = HashSet::new();
        live.insert("running".to_string());

        let targets = plan_reclaim(&empty, &existing, &liveness(&live));
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].profile_name, profile_name_for("orphan"));
        assert!(targets[0].granted_paths.is_empty());
        assert!(
            !targets[0].grants_known,
            "台帳が無いので付与内容は「分からない」であって「無い」ではない（BUG-101）"
        );
    }

    /// **BUG-101の回帰テスト（孤児ACE製造機）。**
    ///
    /// 台帳エントリを失ったプロファイルを削除してはいけません。削除するとSIDが導出できなくなり、
    /// そのSID宛に残っているACEは`harness fs revoke`を含めどのコマンドでも剥がせなくなります
    /// （実際に`%TEMP%`へ1件残り、Tier1の許可側テスト2件が赤になりました）。
    ///
    /// **`grants_known: false`のときは削除しない**ことを固定します。
    #[test]
    fn a_profile_whose_grants_are_unknown_is_never_deleted() {
        let targets = vec![ReclaimTarget {
            profile_name: profile_name_for("lost-ledger"),
            granted_paths: Vec::new(),
            grants_known: false,
        }];
        let revoked = std::sync::Mutex::new(Vec::new());
        let outcome = reclaim_targets(&targets, &|path, _profile| {
            revoked.lock().unwrap().push(path.display().to_string());
            Vec::new()
        });

        assert_eq!(
            outcome.deleted_profiles, 0,
            "付与内容が分からないプロファイルを消すと、そのACEは永久に剥がせなくなる"
        );
        assert_eq!(
            outcome.kept_unknown,
            vec![profile_name_for("lost-ledger")],
            "見送ったことは件数として見えなければならない（B-09/B-11）"
        );
        assert!(
            revoked.lock().unwrap().is_empty(),
            "剥がす対象が分からないのだから、撤収も呼ばれないのが正しい"
        );
    }

    /// **対になる許可側**（B-35）。付与内容が分かっているものは、従来どおり撤収して削除します。
    /// これが無いと「全部見送る」実装でも上のテストが通ってしまい、GCの生死を判定できません。
    #[test]
    fn a_profile_whose_grants_are_known_is_still_revoked_and_deleted() {
        let targets = vec![ReclaimTarget {
            profile_name: profile_name_for("known"),
            granted_paths: vec!["C:\\a".to_string(), "C:\\b".to_string()],
            grants_known: true,
        }];
        let revoked = std::sync::Mutex::new(Vec::new());
        let outcome = reclaim_targets(&targets, &|path, _profile| {
            revoked.lock().unwrap().push(path.display().to_string());
            Vec::new()
        });

        assert_eq!(outcome.revoked_paths, 2);
        assert_eq!(
            revoked.lock().unwrap().clone(),
            vec!["C:\\a".to_string(), "C:\\b".to_string()]
        );
        assert!(
            outcome.kept_unknown.is_empty(),
            "分かっているものまで見送ってはいけない: {outcome:?}"
        );
        // `delete_profile`は非Windowsでは`Ok`のno-opなので、削除件数はどちらの環境でも1になる
        // （Windowsでは実在しないプロファイル名の削除が失敗し得るため、そこは件数で断定しない）。
        assert_eq!(
            outcome.deleted_profiles + outcome.delete_failures.len(),
            1,
            "削除を試みたことは必ず結果として残る（成功か、理由付きの失敗か）"
        );
    }

    /// 台帳にあるものを実在プロファイル側で二重に数えない。
    #[test]
    fn a_dead_session_is_reclaimed_once_even_if_both_sources_see_it() {
        let ledger = SessionLedger {
            sessions: vec![entry("dead", &["C:\\ws"])],
        };
        let existing = vec![profile_name_for("dead")];
        let targets = plan_reclaim(&ledger, &existing, &liveness(&HashSet::new()));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].granted_paths, vec!["C:\\ws".to_string()]);
    }

    /// **撤収順序の不変条件**: ACEを剥がしてから最後にプロファイルを削除する。逆順だと、
    /// 途中で落ちたときに「名前が消えてSIDを導出できないのにACEだけ残る」＝台帳が
    /// 失われた場合に回収不能な残骸になる。
    #[test]
    fn revocation_happens_before_the_profile_is_deleted() {
        let order = std::sync::Mutex::new(Vec::new());
        let targets = vec![ReclaimTarget {
            profile_name: profile_name_for("t"),
            granted_paths: vec!["C:\\a".to_string(), "C:\\b".to_string()],
            grants_known: true,
        }];
        // `win::delete_profile`は非Windowsではno-opなので、ここでは撤収側の順序だけを固定する。
        reclaim_targets(&targets, &|path, profile| {
            order
                .lock()
                .unwrap()
                .push(format!("revoke:{}:{profile}", path.display()));
            Vec::new()
        });
        let recorded = order.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![
                format!("revoke:C:\\a:{}", profile_name_for("t")),
                format!("revoke:C:\\b:{}", profile_name_for("t")),
            ]
        );
    }

    /// D-38: MCPサーバのプロファイルはセッションと同じ寿命で、セッションが死ねば
    /// `run_shell`用プロファイルと一緒に回収される。
    #[test]
    fn mcp_profiles_are_reclaimed_together_with_their_session() {
        let ledger = SessionLedger {
            sessions: vec![entry_with_mcp(
                "dead",
                &[("docs", &["C:\\mcp\\docs"]), ("jira", &[])],
            )],
        };
        let targets = plan_reclaim(&ledger, &[], &liveness(&HashSet::new()));

        let names: Vec<&str> = targets.iter().map(|t| t.profile_name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                profile_name_for("dead").as_str(),
                "harness.mcp.dead.docs",
                "harness.mcp.dead.jira",
            ]
        );
        assert_eq!(targets[1].granted_paths, vec!["C:\\mcp\\docs".to_string()]);
    }

    /// 実行中のセッションのMCPプロファイルは触らない（BUG-053と同じ「実行中の他セッションから
    /// 権限を奪う」誤りを、MCP側で再生産しない）。
    #[test]
    fn mcp_profiles_of_a_live_session_are_never_reclaimed() {
        let ledger = SessionLedger {
            sessions: vec![entry_with_mcp("alive", &[("docs", &["C:\\mcp\\docs"])])],
        };
        let mut live = HashSet::new();
        live.insert("alive".to_string());
        assert!(plan_reclaim(&ledger, &[], &liveness(&live)).is_empty());
    }

    /// 台帳が消えても、MCPプロファイルも接頭辞の実在から回収できる（`run_shell`側と同じ経路）。
    #[test]
    fn orphan_mcp_profiles_are_reclaimed_by_prefix_alone() {
        let existing = vec![
            "harness.mcp.orphan.docs".to_string(),
            "harness.mcp.running.docs".to_string(),
            "some.other.appcontainer".to_string(),
        ];
        let mut live = HashSet::new();
        live.insert("running".to_string());

        let targets = plan_reclaim(&SessionLedger::default(), &existing, &liveness(&live));
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].profile_name, "harness.mcp.orphan.docs");
    }

    /// 台帳にあるMCPプロファイルを、実在プロファイル側で二重に数えない。
    #[test]
    fn a_dead_mcp_profile_is_reclaimed_once_even_if_both_sources_see_it() {
        let ledger = SessionLedger {
            sessions: vec![entry_with_mcp("dead", &[("docs", &["C:\\mcp"])])],
        };
        let existing = vec![
            profile_name_for("dead"),
            "harness.mcp.dead.docs".to_string(),
        ];
        let targets = plan_reclaim(&ledger, &existing, &liveness(&HashSet::new()));
        assert_eq!(targets.len(), 2, "{targets:?}");
    }

    #[test]
    fn tokens_are_extracted_from_both_profile_families() {
        assert_eq!(
            token_of_profile("harness.shell.sandbox.1234-5678"),
            Some("1234-5678")
        );
        assert_eq!(
            token_of_profile("harness.mcp.1234-5678.docs"),
            Some("1234-5678")
        );
        assert_eq!(token_of_profile("harness.mcp.1234-5678"), None);
        assert_eq!(token_of_profile("microsoft.windowsterminal"), None);
    }

    /// 既存の台帳ファイル（`mcp`フィールドが無い）をそのまま読めること。実マシンには
    /// この形のJSONが既に存在するので、後方互換が崩れると起動時のGCが台帳を失う。
    #[test]
    fn a_pre_mcp_ledger_file_still_deserializes() {
        let legacy = r#"{"sessions":[{"token":"t","profile_name":"harness.shell.sandbox.t","granted_paths":["C:\\ws"],"created_at_unix_secs":1}]}"#;
        let ledger: SessionLedger = serde_json::from_str(legacy).unwrap();
        assert_eq!(ledger.sessions[0].granted_paths, vec!["C:\\ws".to_string()]);
        assert!(ledger.sessions[0].mcp.is_empty());
    }

    #[test]
    fn session_token_is_stable_within_the_process() {
        assert_eq!(session_token(), session_token());
        assert!(current_profile_name().ends_with(session_token()));
    }

    /// **BUG-107の核心（禁止側）。** 他プロセスのセッションに属する名前は`OtherSession`である。
    ///
    /// これを`ensure_profile`が`Err`にすることで、「昇格した別プロセスが親のセッション名で
    /// プロファイルを作り、しかし親ではないので台帳には載せられない」経路が閉じる。
    /// 判定はトークンだけで行うので、`run_shell`用（`harness.shell.sandbox.<token>`）でも
    /// MCPサーバ用（`harness.mcp.<token>.<id>`）でも同じ結論になる。
    #[test]
    fn a_profile_belonging_to_another_session_is_not_ours() {
        assert_eq!(
            owner_of_profile("harness.shell.sandbox.999999-1"),
            ProfileOwner::OtherSession("999999-1")
        );
        assert_eq!(
            owner_of_profile("harness.mcp.999999-1.docs"),
            ProfileOwner::OtherSession("999999-1")
        );
    }

    /// **対になる許可側**（B-35）。これが無いと「常に`OtherSession`を返す」実装でも上が通り、
    /// 自分のプロファイルまで作れなくなったことに気付けない。
    #[test]
    fn our_own_session_profiles_are_ours_in_both_families() {
        assert_eq!(
            owner_of_profile(&current_profile_name()),
            ProfileOwner::ThisSession
        );
        assert_eq!(
            owner_of_profile(&crate::tier2a::mcp_profile::current_mcp_profile_name(
                "docs"
            )),
            ProfileOwner::ThisSession
        );
    }

    /// 旧共有プロファイルはセッションに属さない（記録する相手が居ないので、従来どおり作れる）。
    /// **`OtherSession`へ落としてはいけない**——落とすと`harness fs revoke`等が旧共有名を
    /// 扱えなくなり、実マシンに残っているtraverse ACEを剥がせなくなる（BUG-046/BUG-061）。
    #[test]
    fn the_legacy_shared_profile_belongs_to_no_session() {
        assert_eq!(
            owner_of_profile(LEGACY_SHARED_PROFILE),
            ProfileOwner::Unowned
        );
        assert_eq!(
            owner_of_profile("microsoft.windowsterminal"),
            ProfileOwner::Unowned
        );
    }
}
