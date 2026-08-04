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

/// 回収対象1件。`granted_paths`が空なら「台帳を失ったのでプロファイル削除だけ行う」ケース。
#[derive(Debug, Clone, PartialEq)]
pub struct ReclaimTarget {
    pub profile_name: String,
    pub granted_paths: Vec<String>,
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
/// - 台帳に無いが接頭辞付きプロファイルが実在し、生存マーカーも無い → プロファイルだけ消す
///   （台帳が失われた場合の回収経路。モジュールdoc参照）
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
        });
        for mcp in &entry.mcp {
            targets.push(ReclaimTarget {
                profile_name: mcp.profile_name.clone(),
                granted_paths: mcp.granted_paths.clone(),
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
            });
        }
    }
    targets
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

    pub(super) fn delete_profile(name: &str) {
        unsafe {
            let w = crate::win_common::wide(name);
            let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
                windows::core::PCWSTR(w.as_ptr()),
            );
        }
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
    pub(super) fn delete_profile(_name: &str) {}
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
    let token = session_token();
    let path_str = path.to_string_lossy().into_owned();
    ledger().update(|l| {
        if let Some(entry) = l.sessions.iter_mut().find(|e| e.token == token) {
            if !entry.granted_paths.contains(&path_str) {
                entry.granted_paths.push(path_str);
            }
        }
    });
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
fn reclaim_targets(targets: &[ReclaimTarget], revoke: &dyn Fn(&Path, &str)) {
    for target in targets {
        for path in &target.granted_paths {
            revoke(Path::new(path), &target.profile_name);
        }
        win::delete_profile(&target.profile_name);
    }
    let reclaimed: std::collections::HashSet<&str> =
        targets.iter().map(|t| t.profile_name.as_str()).collect();
    ledger().update(|l| {
        l.sessions
            .retain(|e| !reclaimed.contains(e.profile_name.as_str()))
    });
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

/// 死んだセッションの資源を回収する（起動時に呼ぶ）。
pub fn gc_dead_sessions(revoke: &dyn Fn(&Path, &str)) -> usize {
    let targets = plan_reclaim(&ledger().load(), &win::existing_profiles(), &win::is_live);
    reclaim_targets(&targets, revoke);
    targets.len()
}

/// このセッションの資源を撤収する（正常終了時に呼ぶ。落ちた場合は次回起動の
/// [`gc_dead_sessions`]が同じ経路で回収する）。
pub fn end_session(revoke: &dyn Fn(&Path, &str)) {
    let token = session_token();
    let Some(entry) = ledger()
        .load()
        .sessions
        .into_iter()
        .find(|e| e.token == token)
    else {
        return;
    };
    // MCPサーバのプロファイルも同じ経路で撤収する（このセッションと同じ寿命、D-38）。
    let mut targets = vec![ReclaimTarget {
        profile_name: entry.profile_name,
        granted_paths: entry.granted_paths,
    }];
    targets.extend(entry.mcp.into_iter().map(|m| ReclaimTarget {
        profile_name: m.profile_name,
        granted_paths: m.granted_paths,
    }));
    reclaim_targets(&targets, revoke);
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

    /// 台帳が消えても、接頭辞付きプロファイルの実在から回収できる（パスは分からないので
    /// プロファイル削除だけに縮退する）。
    #[test]
    fn profiles_without_a_ledger_entry_are_reclaimed_by_prefix_alone() {
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
        }];
        // `win::delete_profile`は非Windowsではno-opなので、ここでは撤収側の順序だけを固定する。
        reclaim_targets(&targets, &|path, profile| {
            order
                .lock()
                .unwrap()
                .push(format!("revoke:{}:{profile}", path.display()));
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
}
