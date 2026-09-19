//! セッション単位のAppContainerプロファイル（D-37、`plans/DESIGN-SANDBOX-APPPOLICY.md`）。
//!
//! Tier2aは以前、固定名`harness.shell.sandbox`の**1プロファイル＝全セッション共通のpackage SID**で
//! 動いていた。この共有が、独立に見える複数の欠陥の共通の根だった（loopback exemptionの奪い合い
//! ＝[BUG-053](../../../docs/bugs/BUG-053.md)、プロファイル作成の並行競合＝BUG-054、WFP出口強制の
//! fail-open、そして**あるworkspaceのサンドボックスから別のworkspaceが読める**という封じ込めの破れ）。
//! 個別に塞いでも「共有された1つのSID」という構造が残る限り同じクラスが再生産されるため、
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
//! ACEは死んだSID宛の不活性な残骸であり、共有SID時代のように「未来の全セッションに対して
//! 生きた権限」にはならない（失敗時の安全側が逆転している）。

use std::path::{Path, PathBuf};

use harness_grant_ledger::{now_unix_secs, same_ledger_path, Ledger};
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
    /// このセッションがACEを付けたパス（workspace root・CoW diff_layer_dir・`--fs-allow`の穴）。
    /// 撤収はここを順に剥がす。台帳が失われた場合はプロファイル削除だけに縮退する。
    #[serde(default)]
    pub granted_paths: Vec<String>,
    pub created_at_unix_secs: u64,
    /// [§22.3.2] このセッションが**capability SID宛**に付けたACE（現状はCoWの差分層のみ）。
    ///
    /// # なぜ`granted_paths`と別の欄なのか
    ///
    /// 撤収に要る情報が違う。`granted_paths`の宛先SIDは**プロファイル名から導出**できるので
    /// パスだけで足りるが、capability SIDの名前は**乱数の秘密から導出**されるため、
    /// 名前そのものを持っていないと二度と宛先SIDへ到達できない（BUG-101と同型）。
    ///
    /// 混ぜてはいけない理由がもう1つある。preflightの自己検証（`grant_audit`）は
    /// `granted_paths`を「このセッションのpackage SID宛に付けたはずのパス」として読むので、
    /// 差分層をそこへ入れると**毎回のCoW起動で「台帳にあるのにACEが無い」**（幻の台帳エントリ）
    /// として報告される——宛先SIDが違うのだから、package SID宛のACEが無いのは正しい状態である。
    ///
    /// **既存の台帳ファイルとの後方互換のため`#[serde(default)]`**（実マシンに既に在る
    /// `appcontainer-session-ledger.json`はこの欄を持たない）。
    #[serde(default)]
    pub granted_capabilities: Vec<CapabilityGrant>,
    /// このセッションが起動したMCPサーバのプロファイル（D-38、`plans/DESIGN-MCP.md` §3.1）。
    ///
    /// **既存の台帳ファイルとの後方互換のため`#[serde(default)]`で後付けする**（実マシンに
    /// 既に存在する`appcontainer-session-ledger.json`は上の3フィールドしか持たない）。
    /// MCPプロファイルはセッションと同じ寿命なので、独立した台帳ではなくここへぶら下げる
    /// ——セッションが死ねば`plan_reclaim`が同じ判定で一緒に回収する。
    #[serde(default)]
    pub mcp: Vec<McpProfileEntry>,
}

/// [§22.3.2] capability SID宛に付けたACE1件（`(パス, 導出済みのcapability名)`）。
///
/// **名前を持つことがこの型の全てである。** capability SIDは名前の一方向ハッシュ
/// （`DeriveCapabilitySidsFromName`）なので、名前さえあれば秘密が無くても宛先SIDを再構成でき、
/// 撤収できる。逆に名前を失うと**どのコマンドでも剥がせないACE**になる——差分層が使う秘密は
/// ワークスペース側の台帳にあり、`harness fs revoke-workspace`／`fs prune`が**他人の都合で**
/// 消せるので、「撤収時に秘密から導出し直す」形は成立しない（§22.3.2の「2つで1つ」）。
///
/// 記録するのは名前であって秘密ではないので、この台帳の機密性の要求は上がらない。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub path: String,
    pub capability_name: String,
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
    /// [§22.3.2] このセッションがcapability SID宛に付けたACE（`(パス, capability名)`）。
    ///
    /// **`granted_paths`と違い、プロファイル名からは宛先SIDを導出できない**（capability SIDは
    /// 名前から導出され、その名前は乱数の秘密由来である）。だから撤収はここに記録された
    /// **名前**を使う。空であることは「capability宛の付与が無かった」を意味する
    /// ——`grants_known`が偽なら`granted_paths`と同じく「分からない」側なので、
    /// **2つを混ぜて読まないこと**。
    pub granted_capabilities: Vec<CapabilityGrant>,
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

/// このセッショントークンの持ち主がまだ生きているか
/// （[BUG-117](../../../../docs/bugs/BUG-117.md)）。
///
/// 判定は**名前付きmutex**（OSに名前を1つ登録して、同時に1人しか握れないようにする仕組み）の
/// 存在で行う。持ち主のプロセスがプロセス寿命ぶん握っているので、正常終了でも
/// `TerminateProcess`でも電源断でも、プロセスが消えた時点でOSがハンドルを閉じて名前が消える。
///
/// **PID・起動時刻・ファイルの存在で判定しない。** PIDは再利用されるし、
/// 記録は「書く前に落ちた」場合に残らない。
///
/// **この関数はプロセスをまたいだ回収のためにある。** プロファイルのGCが既に使っている
/// 判定を、`policy_learnd`のETWセッション回収からも引けるようにしただけで、
/// **新しい生存判定機構は作っていない。**
pub fn token_owner_is_live(token: &str) -> bool {
    win::is_live(token)
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
///
/// # 生きている他セッションが使っているcapability宛の付与は外す（2026-09-19）
///
/// capability SIDの宛先は`(workspace, 宣言パス, access級)`が鍵でセッションを含まないので、
/// **同じ付与を複数のセッションが記録している**ことがある。死んだ側の記録だけを見て剥がすと
/// 生きている側のACEまで消える。詳細は本体のコメント。
pub fn plan_reclaim(
    ledger: &SessionLedger,
    existing_profiles: &[String],
    is_live: &dyn Fn(&str) -> bool,
) -> Vec<ReclaimTarget> {
    // **capability SID宛の付与は共有される。** 宛先の鍵は`(workspace, 宣言パス, access級)`で
    // セッションを含まない（`workspace_capability`のdoc）ので、**同じものを複数のセッションが
    // 記録している**ことがある。死んだ側の記録だけを見て剥がすと、**生きている側の足元の
    // ACEを消す**——症状はそのセッションの次の操作が`ACCESS_DENIED`で落ちることで、
    // 剥がした側には何も起きないので原因に辿り着けない。
    //
    // # なぜ`granted_paths`には同じ見張りが要らないのか
    //
    // あちらの宛先は**そのセッションのpackage SID**で、定義からセッションごとに違う。
    // 共有され得るのはcapability宛だけである。
    let held_by_live: std::collections::HashSet<(&str, &str)> = ledger
        .sessions
        .iter()
        .filter(|e| is_live(&e.token))
        .flat_map(|e| {
            e.granted_capabilities
                .iter()
                .map(|g| (g.path.as_str(), g.capability_name.as_str()))
        })
        .collect();

    let mut targets = Vec::new();
    for entry in &ledger.sessions {
        if is_live(&entry.token) {
            continue;
        }
        targets.push(ReclaimTarget {
            profile_name: entry.profile_name.clone(),
            granted_paths: entry.granted_paths.clone(),
            granted_capabilities: entry
                .granted_capabilities
                .iter()
                .filter(|g| !held_by_live.contains(&(g.path.as_str(), g.capability_name.as_str())))
                .cloned()
                .collect(),
            grants_known: true,
        });
        for mcp in &entry.mcp {
            targets.push(ReclaimTarget {
                profile_name: mcp.profile_name.clone(),
                granted_paths: mcp.granted_paths.clone(),
                // MCPサーバはcapability群の対象外（§22.2.2。分離はD-38のプロファイル分離が
                // 担う）ので、capability宛の付与は持たない。
                granted_capabilities: Vec::new(),
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
                // 台帳エントリが無い＝**何を付けたか分からない**。capability側も同じく
                // 空だが、それは「無かった」ではない（`grants_known: false`が両方に掛かる）。
                granted_capabilities: Vec::new(),
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

    /// 剥がし終えたパスをworkspace一覧台帳（`harness fs list`が読む一覧）から落とす。
    ///
    /// **1回の`update`で全件落とす。** かつてこの掃除は撤収の実体
    /// （`win_appcontainer::revoke_session_grant`）の中にあり、パスごとに
    /// `remove_workspace_entry`を呼んでいた——つまり[`super::reclaim_targets_in`]の
    /// ループの中で台帳の全文読み書きが走っていた（付与側[`super::record_granted_paths`]の
    /// docが書いている実測と同じ形）。述語を受けてまとめて落とす部品は既にあるので、
    /// 新しく書かずにそこへ繋ぐ。
    ///
    /// 突合は`same_ledger_path`（台帳側が`remove_workspace_entry`で使っているのと同じ規則）。
    /// ここで自前に小文字化や区切りの正規化を書くと、パスの畳み込み規則が2つになる。
    pub(super) fn prune_workspace_paths(cleared: &[&str]) {
        crate::tier2a::workspace_ledger::prune_workspace_entries(|entry_path| {
            let entry_path = entry_path.to_string_lossy();
            cleared.iter().any(|p| same_ledger_path(&entry_path, p))
        });
    }

    /// [§22.3.2] 記録された**capability名**から宛先SIDを導出して、そのツリーから剥がす。
    ///
    /// [`super::ReclaimIo::revoke_capability`]の実体。`revoke_session_grant`と対になるが、
    /// 導出が違う（あちらはプロファイル名→package SID、こちらはcapability名→capability SID）。
    /// 名前の**形の検証**は`capability_sid_from_declaration_name`が行う——別種の名前が
    /// 渡されたときに黙って通さないため。
    ///
    /// SIDを導出できないときは**空ではなく理由を返す**（B-10:「剥がすものが無かった」と
    /// 「剥がしに行けなかった」を同じ値にしない）。空を返すと呼び出し側が名前を捨ててよいと
    /// 判断し、そのACEは二度と剥がせなくなる。
    pub(super) fn revoke_capability_grant(path: &Path, capability_name: &str) -> RevokeLeftovers {
        crate::tier2a::win_appcontainer::revoke_capability_grant(path, capability_name)
    }

    /// [§22.3.2] 剥がし終えたcapabilityの記録を`workspace-capability-ledger.json`から落とす。
    ///
    /// **述語を受けて1回の`update`で落とす既存の部品**（`prune_capability_entries`）へ繋ぐだけで、
    /// 新しい撤収の扉は作らない。`fs revoke-workspace`を拡張しないという§22.3.2の決定は
    /// 「差分層の後片付けの責任者は`session_profile`である」という意味なので、責任者側が
    /// 既存の部品を呼ぶこの形はその決定のとおりである。
    pub(super) fn forget_capability_entries(names: &[&str]) {
        let dropped = crate::tier2a::workspace_capability::prune_capability_entries(|entry| {
            names.contains(&entry.capability_name.as_str())
        });
        // 黙って消さない（B-11）。実マシンの記録を減らす操作なので、件数は残す。
        if !dropped.is_empty() {
            eprintln!(
                "note: dropped {} capability ledger entr(ies) whose ACEs were fully revoked: {}",
                dropped.len(),
                dropped.join(", ")
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
    pub(super) fn delete_profile(_name: &str) -> Result<(), String> {
        Ok(())
    }
    /// workspace一覧台帳（`tier2a::workspace_ledger`）はwindows専用モジュールなので、
    /// 非Windowsでは掃除するものが無い。
    pub(super) fn prune_workspace_paths(_cleared: &[&str]) {}
    /// ACL（capability SID）はWindows専用の機構なので、非Windowsでは剥がすものが無い。
    pub(super) fn revoke_capability_grant(_path: &Path, _capability_name: &str) -> RevokeLeftovers {
        Vec::new()
    }
    pub(super) fn forget_capability_entries(_names: &[&str]) {}
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
                granted_capabilities: Vec::new(),
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
    record_into_session_entry(
        |entry| {
            for path in paths {
                let path_str = path.to_string_lossy().into_owned();
                if !entry.granted_paths.contains(&path_str) {
                    entry.granted_paths.push(path_str);
                }
            }
        },
        || format!("{} granted path(s)", paths.len()),
    );
}

/// このセッションの台帳エントリへ1件書き込む。**エントリが無ければ開いて1回だけやり直す。**
///
/// # [BUG-101] なぜ無言のno-opにしないのか
///
/// 台帳にこのセッションのエントリが無いと、記録は何も書かずに戻る——付与は成功しているので
/// 呼び出し側は成功と読み、撤収の対象にもならないACEが実マシンに残る（`end_session`と
/// `gc_dead_sessions`はどちらもエントリの中しか剥がさない）。
///
/// # [BUG-147] なぜ警告だけで済ませないのか
///
/// 黙らないだけでは**ACEは残ったままである**。実際にその形で出たのがBUG-147で、
/// `--fork-session`が`begin_session`より前に差分層のACEを書き、起動が打ち切られた回の
/// ACEを誰も剥がせなくなっていた。エントリが無いのは付与の失敗ではないので**止めはしない**が、
/// **作れる相手なら作ってやり直す**（`begin_session`は冪等）。
///
/// # 費用（正常時は増えない）
///
/// エントリが在れば台帳の読み書きは**1回のまま**である。`Ledger::update`は1回ごとに全文を
/// 読み書きするので（[`record_granted_paths`]のdocの実測）、ここを無条件に2回にすると
/// 付与のたびに倍払うことになる。余分な2回（`begin_session`とやり直し）を払うのは
/// **エントリが無かったときだけ**で、しかも`begin_session`がそこでエントリを作るので、
/// **同じプロセスで払うのは最初の1回だけ**である——ループの中から呼ばれても2回目以降は
/// 通常経路で当たる。
///
/// `describe`をクロージャで受けるのは、**正常時に文字列を組み立てないため**である。
fn record_into_session_entry(
    mut write: impl FnMut(&mut SessionEntry),
    describe: impl Fn() -> String,
) {
    let token = session_token();
    if write_into_session_entry(token, &mut write) {
        return;
    }
    // [BUG-147] ぶら下げる先が無い。**作って1回だけやり直す。**
    if let Err(e) = begin_session() {
        eprintln!(
            "warning: could not record {} for session {token}: the session has no ledger entry \
             and opening one failed ({e}), so these ACEs will not be revoked automatically \
             (see docs/bugs/BUG-101.md)",
            describe()
        );
        return;
    }
    if !write_into_session_entry(token, &mut write) {
        // ここへ来るのは「`begin_session`が成功を返したのに、直後に読むとエントリが無い」
        // ときだけ——別プロセスが同時に落としたか、台帳を書けていないかである。
        // **黙らない**（B-10）: 撤収の索引が無いまま実マシンにACEが残る。
        eprintln!(
            "warning: could not record {} for session {token}: the session ledger entry is still \
             missing right after opening it, so these ACEs will not be revoked automatically \
             (see docs/bugs/BUG-101.md)",
            describe()
        );
    }
}

/// [`record_into_session_entry`]の1回ぶん。**このセッションのエントリを見つけて書けたか**を返す。
fn write_into_session_entry(token: &str, write: &mut impl FnMut(&mut SessionEntry)) -> bool {
    ledger().update(|l| match l.sessions.iter_mut().find(|e| e.token == token) {
        Some(entry) => {
            write(entry);
            true
        }
        None => false,
    })
}

/// [§22.3.2] capability SID宛に付けたACEを台帳へ記録する（撤収時に剥がす対象）。
///
/// [`record_granted_path`]のcapability版。**付与が成功した後にだけ呼ぶこと**——先に記録すると
/// 「台帳にあるのに実体が無い」逆向きの孤立になる（B-15）。
///
/// 台帳エントリが無いときの扱い（黙らない・作ってやり直す・費用）は
/// [`record_into_session_entry`]が持つ。
pub fn record_granted_capability(path: &Path, capability_name: &str) {
    let path_str = path.to_string_lossy().into_owned();
    record_into_session_entry(
        |entry| {
            if !entry
                .granted_capabilities
                .iter()
                .any(|g| g.path == path_str && g.capability_name == capability_name)
            {
                entry.granted_capabilities.push(CapabilityGrant {
                    path: path_str.clone(),
                    capability_name: capability_name.to_string(),
                });
            }
        },
        || format!("the capability grant on {path_str}"),
    );
}

/// **このセッションが撤収しなければならないものの件数**（パス＋capability宛の合計）。
///
/// # なぜ足し算をここに置くのか
///
/// 呼び出し側（ポリシーエディタの撤収）は「対象が0件なら[`end_session`]を呼ばない」という
/// 早期returnを持つ。その判定を`granted_paths`の件数だけで書くと、**capability宛しか
/// 付けていないセッションで撤収が丸ごと飛ぶ**——差分層のACEはそのセッションでは剥がされず、
/// 次の起動のGCまで残る。[§22.3.2]で「このセッションが付けたもの」の意味が2つの欄に
/// 割れた時点で、件数を数える場所も追随しなければならなかった（`B-06`）。
///
/// **足し算を呼び出し側に書かせない。** 2箇所が別々に足すと、欄が3つ目に増えたとき
/// 片方だけ更新されて静かにずれる（`B-05`）。数える場所はここ1つにする。
pub fn pending_revocation_count() -> usize {
    pending_revocation_count_in(&ledger(), session_token())
}

/// [`pending_revocation_count`]の判定部分（台帳を注入する）。**テストが実マシンの台帳を
/// 触らないための口**（`Ledger::at_path`を渡す。BUG-108と同じ理由）。
fn pending_revocation_count_in(ledger: &Ledger<SessionLedger>, token: &str) -> usize {
    ledger
        .load()
        .sessions
        .into_iter()
        .find(|e| e.token == token)
        .map(|e| e.granted_paths.len() + e.granted_capabilities.len())
        .unwrap_or(0)
}

/// [§22.3.2] capability SID宛に付けたACEのパス一覧（自己検証`grant_audit`が読む「記録」側）。
///
/// [`granted_paths_for_current_session`]のcapability版で、**別の集合である**ことが要点である
/// ——package SID宛の自己検証にこのパスを混ぜると、宛先SIDが違うのだからACEが無いのは当然なのに
/// 「幻の台帳エントリ」として毎回報告される。
pub fn granted_capability_paths_for_current_session() -> Vec<String> {
    capability_paths(|_| true)
}

/// [§22.3.2] **その宛先SIDのぶんだけ**を返す（自己検証`grant_audit`へ渡すのはこちら）。
///
/// # なぜ和を渡してはいけないのか
///
/// `grant_audit`は宛先SIDを**1本ずつ**測る。[`granted_capability_paths_for_current_session`]は
/// **全capability SIDの和**を返すので、そのまま渡すと**別のSIDのパス**が候補に入り、
/// そのSIDのACEが無いのは当然なのに「台帳にあるのにACEが載っていない（幻の台帳エントリ）」
/// として報告される——`HARNESS_GRANT_AUDIT=strict`ではその場で落ちる。
///
/// これは同モジュールが既に書いている罠と**同じ形**である（package SID宛の自己検証へ
/// capabilityのパスを混ぜると全件が偽陽性になる、という理由でそちらは別の集合にしてある）。
/// 混ぜてはいけない相手が「package SIDとcapability SID」だけでなく
/// **「別々のcapability SID同士」**にも及ぶ、というのが違いである。
///
/// # 1セッションが2枚以上記録し得る
///
/// セッション切替とfork（`/sessions`・`/fork`・`--fork-session`）は、そのたびに新しい差分層へ
/// ACEを付けて記録する。[BUG-147]で`--fork-session`の経路が`preflight`より前に記録するように
/// なったので、**`preflight`が自己検証を回す時点で2枚載っている回**が生まれ得る。
pub fn granted_capability_paths_for(capability_name: &str) -> Vec<String> {
    capability_paths(|g| g.capability_name == capability_name)
}

fn capability_paths(keep: impl Fn(&CapabilityGrant) -> bool) -> Vec<String> {
    let token = session_token();
    ledger()
        .load()
        .sessions
        .into_iter()
        .find(|e| e.token == token)
        .map(|e| {
            e.granted_capabilities
                .into_iter()
                .filter(|g| keep(g))
                .map(|g| g.path)
                .collect()
        })
        .unwrap_or_default()
}

/// **「死んだセッションがこのcapabilityを付けた」という台帳エントリを1件足す。テスト専用の口。**
///
/// GC（`gc_dead_sessions`）の経路を実機で測るために要る。実行中のプロセスは自分の生存マーカーを
/// 握っているので、**自分自身はどうやってもGCの対象にならない**——`is_live`が真を返すためで、
/// これは正しい動作である（実行中の他セッションから権限を奪わない、BUG-053）。
/// だから「GCが差分層のACEを剥がすか」を測るには、死んだセッションを1つ用意するしかない。
///
/// # なぜ現行セッションのエントリを「付け替え」ないのか
///
/// 付け替える形も書けるが、**実マシンに回収不能なプロファイルを1件残す**——現行セッションの
/// AppContainerプロファイルは実在するのに台帳エントリが消えるので、以後のGCからは
/// 「台帳に無いが実在する」＝`grants_known: false`に見え、**二度と削除されない**
/// （BUG-107で67件積み上がったのと同じ形）。テストが実マシンへ残骸を積む理由は無い。
///
/// **足す側なら残骸は生まれない。** ここで作る名前のプロファイルは実在しないので、
/// `DeleteAppContainerProfile`は成功し（存在しない名前にもS_OKを返す）、検算も
/// 「実在しない」で通り、エントリはGCが自分で片付ける。現行セッションのエントリは無傷である。
///
/// **製品から呼ばないこと。** このエントリは「回収してよい」と宣言したのと同じ意味を持つ。
#[cfg(all(windows, test))]
pub(crate) fn add_dead_session_with_capability_for_test(path: &Path, capability_name: &str) {
    // 生存マーカーを握っていないトークン。接頭辞は保つ（GCが`token_of_profile`で拾えるように）。
    let dead = format!("{}-dead-for-test", session_token());
    let entry = SessionEntry {
        token: dead.clone(),
        profile_name: profile_name_for(&dead),
        granted_paths: Vec::new(),
        granted_capabilities: vec![CapabilityGrant {
            path: path.to_string_lossy().into_owned(),
            capability_name: capability_name.to_string(),
        }],
        created_at_unix_secs: now_unix_secs(),
        mcp: Vec::new(),
    };
    ledger().update(|l| {
        l.sessions.retain(|e| e.token != dead);
        l.sessions.push(entry.clone());
    });
}

/// **台帳エントリを1件、名指しで落とす。テスト専用の後始末の口。**
///
/// [`add_dead_session_with_capability_for_test`]が足したエントリを、測定の終わりに戻すために要る。
///
/// # なぜGCで片付けないのか（実測で分かった）
///
/// `gc_dead_sessions`は**capabilityを剥がし終えたエントリしか落とさない**（`reclaim_targets_in`。
/// 剥がせていないのに名前を捨てると、SIDの導出元が失われて二度と剥がせなくなるため）。
/// 剥がす相手が実在しない測定——たとえば「名簿が死んだセッションを含まないこと」だけを見る回
/// ——では`revoke_capability_grant`が名前の検証で`Err`を返し、**エントリが台帳に残る**。
/// 実際に残した（2026-09-03のM1測定の1回目）。
///
/// **測定が足したものは、測定が落とす。** GCの判断に後始末を任せると、
/// GCの正しい慎重さがそのまま残骸になる。
///
/// **製品から呼ばないこと。** ACEが残っているのに記録だけ落とすのは、
/// 撤収不能なACEを作る操作そのものである（BUG-101）。
#[cfg(all(windows, test))]
pub(crate) fn forget_session_entry_for_test(token: &str) {
    ledger().update(|l| l.sessions.retain(|e| e.token != token));
}

/// 台帳に載っているセッションのトークン一覧（**後始末が効いたことを読み返すための口**）。
///
/// [`live_profile_names`]では代用できない——落としたいのは**エントリ**で、あちらが返すのは
/// 「生きている」と判定された名前だけである。死んだエントリが残っていても空に見える。
#[cfg(all(windows, test))]
pub(crate) fn ledger_session_tokens_for_test() -> Vec<String> {
    ledger()
        .load()
        .sessions
        .into_iter()
        .map(|e| e.token)
        .collect()
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

/// [`reclaim_targets_in`]が触る**実世界**の一式（[BUG-108](../../../docs/bugs/BUG-108.md)）。
///
/// かつて注入されていたのは`revoke`だけで、プロファイルの削除・台帳・自己検証は関数の中から
/// 直接呼んでいた。そのため**純粋な単体テストが実マシンの台帳（と、その唯一の復旧コピーである
/// `.bak`）を書き換えていた**——テストが渡すのは実在しないプロファイル名だが、
/// `DeleteAppContainerProfile`は存在しない名前にもS_OKを返すので削除が成功扱いになり、
/// 後続の`retain`が実台帳まで届いていた。**「テストが渡す名前は実在しない」は隔離の根拠に
/// ならない。隔離するのは名前ではなく依存の向き先である。**
///
/// **副作用はここに全部並べる。** [`reclaim_targets_in`]の中から実マシンを直接触らないこと
/// ——1つだけ注入可能にすると、残りが直呼びであることが構造から見えなくなる（それが
/// 今回の欠陥そのものだった）。副作用を増やすときはこの構造体へ足す（B-06）。
struct ReclaimIo<'a> {
    /// そのパスから`profile_name`宛のACEを剥がす。戻り値は**剥がせなかったノードと理由**
    /// （空なら完全に剥がせた）。
    ///
    /// # 宛先SIDが単数なので、同じツリーをプロファイルの数だけ歩き直す（未解消）
    ///
    /// 実体（`win_appcontainer::revoke_session_grant`）は単一SID版の`revoke_ace_recursive`を
    /// 使う。同じパスを複数のプロファイルが付与していると、**そのツリーをプロファイルの数だけ
    /// 舐め直す**。複数SIDを1周で剥がす`revoke_sids_recursive`は既にあるので、
    /// [`reclaim_targets_in`]が`ReclaimTarget`（プロファイル単位）を**パス→SID群へ転置**
    /// すれば1周に畳める。
    ///
    /// **畳んでいないのはこのコールバックの宛先SIDが単数だからである。** 複数にするには
    /// [`gc_dead_sessions_reporting`]・[`gc_dead_sessions`]・[`end_session`]の公開シグネチャを
    /// 変えることになり、渡す側は13ファイル（`harness-cli`・`harness-policy-editor`・
    /// このクレートの`preflight`とETWテスト群）に散っている。1周に畳めるかどうかは
    /// **その全部を同時に書き換えられるときに決めること。**
    ///
    /// 転置そのものに危険は無い——`revoke_sids_from_node`は1ノードのDACLを1回書き直して
    /// 全SIDを外すので、そのノードが剥がせなければ**載っていた全プロファイルが等しく
    /// 剥がせない**。剥がせなかったノードを共有する全プロファイルへ配ることは、意味の
    /// 歪みではなく事実である（`grants_known`・`blocked_here`・`unrecorded`の
    /// プロファイル単位の意味は保てる）。
    revoke: &'a dyn Fn(&Path, &str) -> RevokeLeftovers,
    /// [§22.3.2] **capability SID宛**のACEを、記録された名前から剥がす。
    ///
    /// [`Self::revoke`]と形は同じだが、第2引数の意味が違う——あちらは**プロファイル名**
    /// （`DeriveAppContainerSidFromAppContainerName`で導出）、こちらは**capability名**
    /// （`DeriveCapabilitySidsFromName`で導出）である。同じ関数では剥がせないので別の口にする。
    ///
    /// **公開シグネチャ（[`end_session`]・[`gc_dead_sessions`]）には出さない。** あちらの
    /// コールバックを増やすと呼び出し側13箇所（`harness-cli`・`harness-policy-editor`・
    /// このクレートのETWテスト群）を全部書き換えることになり、そのどれか1つが古い形のまま
    /// 残れば「片方の経路だけ撤収しない」という最も気付きにくい欠陥になる。ここは製品用の
    /// 組み立て（[`reclaim_targets`]）が差すだけの内部の口である。
    revoke_capability: &'a dyn Fn(&Path, &str) -> RevokeLeftovers,
    /// [§22.3.2] 剥がし終えたcapabilityの**台帳エントリ**（`workspace-capability-ledger.json`）を
    /// 落とす。**ACEを剥がし終えたときだけ呼ぶこと**（`B-01`「名前を捨てる操作を最後に置く」）。
    ///
    /// 差分層のcapabilityは**CoWセッションごとに1件増える**ので、これを呼ばないと記録が
    /// 際限なく積もる（§22.3.2が「撤収とGCを対で設計する」と言っている当のもの）。
    forget_capabilities: &'a dyn Fn(&[&str]),
    /// **台帳に記録が無いのに実在するACE**の件数（`grant_audit`の自己検証）。
    /// 0でなければ名前を捨てない（BUG-101）。人への報告もこの中で行う。
    unrecorded_aces: &'a dyn Fn(&str, &[String]) -> usize,
    /// AppContainerプロファイルを削除する。**「呼んだ」と「消えた」は別の事実**なので、
    /// 実装側（[`win::delete_profile`]）が削除後の実在を検算してから`Ok`を返す。
    delete_profile: &'a dyn Fn(&str) -> Result<(), String>,
    /// 回収できたセッションのエントリを落とす先の台帳。
    ledger: &'a Ledger<SessionLedger>,
    /// **1ノードも残さず剥がし終えたパス**をworkspace一覧台帳から落とす。
    ///
    /// 引数が単数ではなく集合なのは意図的である——この掃除はかつて撤収の実体
    /// （`win_appcontainer::revoke_session_grant`）の中にあり、パスごとに台帳の全文を
    /// 読み書きしていた。集合で受ける形にすると、呼び出しを**ループの外へ出す以外に
    /// 書きようが無くなる**（[`record_granted_paths`]のdocの実測と同じ理由）。
    prune_workspace_paths: &'a dyn Fn(&[&str]),
}

/// 製品経路の自己検証（`grant_audit`）。**台帳に無いACEの件数**を返し、報告もここで行う。
fn report_unrecorded_aces(profile_name: &str, granted_paths: &[String]) -> usize {
    let Some(audit) = crate::tier2a::grant_audit::audit_profile(
        crate::tier2a::grant_audit::Stage::SessionEnd,
        profile_name,
        granted_paths,
    ) else {
        return 0;
    };
    crate::tier2a::grant_audit::report(&audit);
    audit.present_unrecorded.len()
}

/// 製品経路の[`ReclaimIo`]（実Win32・実台帳）で回収する。
///
/// **既存のシグネチャのまま残してある**——呼び出し元（`gc_dead_sessions_reporting`・
/// `end_session`とその下流13箇所）を1行も変えずに副作用の注入を入れるため。
fn reclaim_targets(
    targets: &[ReclaimTarget],
    revoke: &dyn Fn(&Path, &str) -> RevokeLeftovers,
) -> ReclaimOutcome {
    reclaim_targets_in(
        &ReclaimIo {
            revoke,
            revoke_capability: &win::revoke_capability_grant,
            forget_capabilities: &win::forget_capability_entries,
            unrecorded_aces: &report_unrecorded_aces,
            delete_profile: &win::delete_profile,
            ledger: &ledger(),
            prune_workspace_paths: &win::prune_workspace_paths,
        },
        targets,
    )
}

/// [`reclaim_targets`]の本体（[`ReclaimIo`]で実世界を注入した形）。
///
/// # 台帳の更新は、どちらもループの外で1回だけ（B-01・BUG-057と同型）
///
/// この関数は「プロファイル×そのプロファイルが付与したパス」の二重ループを回す。
/// `Ledger::update`は1回ごとに台帳の全文を読み書きするので、**ループの中で台帳へ触ると
/// 対象の数だけ全文I/Oが積む**（付与側[`record_granted_paths`]のdocに実測がある）。
/// したがってこの関数がループの中でやるのは集合へ積むことだけで、実際の更新は末尾で
/// セッション台帳に1回・workspace一覧台帳に1回である。
fn reclaim_targets_in(io: &ReclaimIo<'_>, targets: &[ReclaimTarget]) -> ReclaimOutcome {
    let mut outcome = ReclaimOutcome::default();
    let mut deleted: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // workspace一覧台帳から落とす候補（そのツリーから1本残らず剥がせたパス）と、
    // 1ノードでも剥がし残したパス。**同じパスを複数のプロファイルが付与していることがある**
    // ので、ここでは両方へ積んでおき、差し引きは末尾でまとめて行う。
    let mut cleared: Vec<&str> = Vec::new();
    let mut still_held: Vec<&str> = Vec::new();
    // [§22.3.2] 1本残らず剥がせたcapabilityの名前。台帳から落とすのは**末尾で1回**
    // （台帳の更新をループの中でやらない、というこの関数の既存の約束と同じ理由）。
    let mut forgettable_capabilities: Vec<&str> = Vec::new();
    for target in targets {
        if !target.grants_known {
            // 何を付与したか分からない以上、剥がせない。名前を消せば永久に剥がせなくなるので残す。
            outcome.kept_unknown.push(target.profile_name.clone());
            continue;
        }
        let mut blocked_here = Vec::new();
        for path in &target.granted_paths {
            let leftovers = (io.revoke)(Path::new(path), &target.profile_name);
            // **一覧から記録を落としてよいのは、剥がし終えたパスだけ。** 記録を先に捨てて
            // 実体が残る向きの失敗を作らない（B-01の「対の片方だけ」）。プロファイル名の方は
            // 下の`kept_with_leftovers`が同じ理由で残す——両者は同じ判断の表と裏である。
            if leftovers.is_empty() {
                cleared.push(path.as_str());
            } else {
                still_held.push(path.as_str());
            }
            blocked_here.extend(leftovers);
            outcome.revoked_paths += 1;
        }
        // [§22.3.2] capability SID宛のACE（CoWの差分層）。**宛先SIDの導出が違うので別の口を通す**
        // （`ReclaimIo::revoke_capability`のdoc）。剥がし残しは`blocked_here`へ**同じ形で**
        // 積む——ここを別枠にすると、剥がせていないのにプロファイル名と台帳エントリを
        // 捨てる経路ができ、名前を失って二度と剥がせなくなる（BUG-101と同型）。
        for grant in &target.granted_capabilities {
            let leftovers = (io.revoke_capability)(Path::new(&grant.path), &grant.capability_name);
            if leftovers.is_empty() {
                // **剥がし終えたものだけ**、名前の記録を捨てる候補にする（`B-01`）。
                forgettable_capabilities.push(grant.capability_name.as_str());
            }
            blocked_here.extend(leftovers);
            outcome.revoked_paths += 1;
        }
        // [BUG-101] **名前を捨てる直前に、この宛先SIDのACEが本当に残っていないかを測る。**
        // ここが最後の分岐点である——`DeleteAppContainerProfile`はSIDの導出元である名前を
        // 破棄するので、これ以降に残ったACEは`harness fs revoke`を含むどのコマンドでも
        // 剥がせない（SIDの導出は名前→SIDの一方向）。
        let unrecorded = (io.unrecorded_aces)(&target.profile_name, &target.granted_paths);
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
        match (io.delete_profile)(&target.profile_name) {
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
    // 1ノードでも剥がし残したパスは、**別のプロファイルが剥がし終えていても**落とさない。
    // 突合は台帳側と同じ`same_ledger_path`を借りる（ここで自前に小文字化や区切りの正規化を
    // 書くと、パスの畳み込み規則が2つになる）。
    cleared.retain(|p| !still_held.iter().any(|held| same_ledger_path(held, p)));
    // 同じパスを複数のプロファイルが剥がし終えていることがあるので畳む（述語が短くなるだけで、
    // 重複していても結果は変わらない）。
    cleared.sort_unstable();
    cleared.dedup();
    if !cleared.is_empty() {
        (io.prune_workspace_paths)(&cleared);
    }
    // [§22.3.2/B-01] **名前を捨てるのは、そのACEがもう無いと確かめられたときだけ。**
    // 剥がし残しがあった名前はここに入っていないので、次のGCがもう一度引ける。
    forgettable_capabilities.sort_unstable();
    forgettable_capabilities.dedup();
    if !forgettable_capabilities.is_empty() {
        (io.forget_capabilities)(&forgettable_capabilities);
    }
    if !deleted.is_empty() {
        io.ledger.update(|l| {
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

/// 走行中の**他の**セッション（このプロセス自身のものを除く）のプロファイル名。
///
/// D-48のガード（走行中のセッションからtraverse ACEを剥がさない）が使う唯一の入口。
/// [`live_profile_names`]との違いは**自分を数えない**ことだけである。
///
/// **なぜ自分を除くのか。** D-48が守っているのは「頼んでいないセッションを巻き込むこと」で、
/// 剥がすと決めたプロセス自身は巻き添えではない。除かないと、自分でセッションを開いてから
/// 自分が付けたACEを`Drop`で剥がす測定用テスト（`policy_learnd::etw::fs_allow_reach_tests`）が
/// **自分のガードに掛かって撤収できなくなる**——製品側に撤収経路が無いのと同じ状態になり、
/// 永続capability SID ACEが実マシンへ残る（B-27）。
///
/// 判定は**トークン**で行う（プロファイル名の一致ではない）。同じセッションはMCPサーバ用の
/// プロファイル（`harness.mcp.<token>.<server-id>`、D-38）も持ち得るので、名前で比べると
/// 自分のMCPプロファイルだけが「他人」として残る。
pub fn other_live_profile_names() -> Vec<String> {
    without_session(live_profile_names(), session_token())
}

/// [`other_live_profile_names`]の判定部分（**純粋関数**）。
///
/// Win32もファイルも触らないので、単体テストは`#[ignore]`を付けず通常の`cargo test`で走らせる
/// ——ガードの判定が腐ったら実機E2Eを待たずに落ちるべきものだからである（D-48不変条件1と同じ規律）。
pub(crate) fn without_session(live: Vec<String>, own_token: &str) -> Vec<String> {
    live.into_iter()
        .filter(|name| token_of_profile(name) != Some(own_token))
        .collect()
}

/// [`live_profile_names`]が**どの材料から何を見たか**の内訳を1行で返す（診断専用）。
///
/// 件数だけでは「0件」の意味が2つに割れる——本当に走行中セッションが無いのか、
/// 材料（台帳ファイル・`%LOCALAPPDATA%\Packages`・名前付きmutex）が見えていないのか。
/// 前者と後者は、D-48のガード（走行中セッションからtraverse ACEを剥がさない）にとって
/// **正反対の意味**を持つ（後者はfail-openの穴）ので、区別できる形で残す。
///
/// 2段構えのどちらが落ちたかが分かるよう、段ごとに出す。
/// 1. 台帳（`%APPDATA%`配下。**昇格側で別ハイブになると空に見える**、`privhelper.rs`参照）
/// 2. トークンごとの名前付きmutex（`Local\`名前空間。ログオンセッションと整合性レベルの論点）
pub fn live_probe_report() -> String {
    let ledger_path = ledger()
        .path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unresolved>".to_string());
    let ledger_bytes = ledger()
        .path()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len().to_string())
        .unwrap_or_else(|| "<absent>".to_string());
    let entries: Vec<String> = ledger()
        .load()
        .sessions
        .into_iter()
        .map(|e| format!("{}:live={}", e.token, win::is_live(&e.token)))
        .collect();
    let profiles = win::existing_profiles();
    // 実機には死んだプロファイルが数十件たまる（BUG-101）ので、全件ではなく件数と
    // 「生きていると判定された分」だけを出す。
    let live_profiles: Vec<&String> = profiles
        .iter()
        .filter(|p| token_of_profile(p).is_some_and(win::is_live))
        .collect();
    format!(
        "APPDATA={:?} LOCALAPPDATA={:?} ledger={ledger_path} ({ledger_bytes} bytes) \
         ledger_entries=[{}] existing_profiles={} (live={live_profiles:?}) live_profile_names={:?}",
        std::env::var("APPDATA").unwrap_or_default(),
        std::env::var("LOCALAPPDATA").unwrap_or_default(),
        entries.join(", "),
        profiles.len(),
        live_profile_names(),
    )
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
        granted_capabilities: entry.granted_capabilities,
        grants_known: true,
    }];
    targets.extend(entry.mcp.into_iter().map(|m| ReclaimTarget {
        profile_name: m.profile_name,
        granted_paths: m.granted_paths,
        // MCPサーバはcapability群の対象外（§22.2.2）。`plan_reclaim`側と同じ理由。
        granted_capabilities: Vec::new(),
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
            granted_capabilities: Vec::new(),
            created_at_unix_secs: 0,
            mcp: Vec::new(),
        }
    }

    /// capability SID宛の付与を持つセッション（§22.3.2のCoW差分層）。
    fn entry_with_capabilities(token: &str, grants: &[(&str, &str)]) -> SessionEntry {
        let mut e = entry(token, &[]);
        e.granted_capabilities = grants
            .iter()
            .map(|(path, name)| CapabilityGrant {
                path: (*path).to_string(),
                capability_name: (*name).to_string(),
            })
            .collect();
        e
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

    // --- D-48のガードが使う生存判定（`without_session`） ---
    //
    // **禁止側と許可側を必ず対で置く**（B-35）。拒否側のassertだけだと、判定が
    // 「常に他セッションが居る」に壊れても「常に居ない」に壊れても片方は緑のままになる。

    /// 禁止側: 他のセッションが走っているなら、その名前が残る（＝撤収は拒否される）。
    #[test]
    fn another_running_session_is_reported_so_the_revoke_is_refused() {
        let live = vec![profile_name_for("999-1"), profile_name_for("888-2")];
        let others = without_session(live.clone(), "1234-5");
        assert_eq!(others, live);
    }

    /// 許可側: 走っているのが自分だけなら空になる（＝撤収は通る）。
    ///
    /// これが無いと、判定が「常に拒否」へ壊れたことを検出できない——そして
    /// 測定用テストの`Drop`が自分のガードに掛かり、永続ACEが実マシンに残る。
    #[test]
    fn the_calling_process_does_not_block_its_own_revoke() {
        let own = "1234-5";
        let others = without_session(vec![profile_name_for(own)], own);
        assert!(others.is_empty(), "{others:?}");
    }

    /// 自分のMCPサーバプロファイル（D-38）も自分の一部として除く。
    ///
    /// 判定を**トークン**で行う理由がここにある——プロファイル名の一致で比べると、
    /// `harness.mcp.<token>.<server-id>`だけが「他人」として残り、自分自身が
    /// 自分の撤収を止める。
    #[test]
    fn the_callers_own_mcp_profiles_are_part_of_itself() {
        let own = "1234-5";
        let live = vec![
            profile_name_for(own),
            crate::tier2a::mcp_profile::mcp_profile_name_for(own, "company-docs"),
        ];
        assert!(without_session(live, own).is_empty());
    }

    /// 他セッションのMCPプロファイルは他人として残る（上の裏）。
    #[test]
    fn another_sessions_mcp_profile_still_blocks() {
        let other = crate::tier2a::mcp_profile::mcp_profile_name_for("999-1", "company-docs");
        assert_eq!(without_session(vec![other.clone()], "1234-5"), vec![other]);
    }

    /// 生存しているものが1つも無ければ空（判定材料が無いときに撤収を止めない、
    /// D-48不変条件3と同じ向き）。
    #[test]
    fn nothing_running_means_nothing_blocks() {
        assert!(without_session(Vec::new(), "1234-5").is_empty());
    }

    /// **実マシンを一切触らない[`ReclaimIo`]**（[BUG-108](../../../docs/bugs/BUG-108.md)）。
    ///
    /// 台帳は`Ledger::at_path`の一時ファイルを指し、プロファイル削除と自己検証は
    /// 「呼ばれたこと」を記録して既定値を返すだけになる。**これが無いと、この単体テストは
    /// 実マシンの`%APPDATA%\harness\config\appcontainer-session-ledger.json`と、その唯一の
    /// 復旧コピーである`.bak`を書き換える。**
    ///
    /// 撤収と削除は**1本の列（`events`）へ同じ順序で積む**——「ACEを剥がしてから最後に
    /// プロファイルを削除する」はこのモジュールの不変条件なので、2つを別々に記録すると
    /// 順序そのものを測れない（実際、以前の回帰テストは撤収しか記録しておらず、削除を
    /// 先頭へ移動しても緑のままだった）。
    struct FakeIo {
        ledger: Ledger<SessionLedger>,
        events: std::sync::Mutex<Vec<String>>,
        /// **workspace一覧台帳の掃除が何回・どの集合で呼ばれたか**（1要素＝1回の`update`）。
        ///
        /// `events`へ混ぜない。あちらが測っているのは「撤収→削除」の**順序**で、こちらが
        /// 測りたいのは**呼ばれた回数**である——落ちる記録は同じなので、回数を測らないと
        /// 「パスごとに1回」へ戻ったことに気付けない。
        workspace_prunes: std::sync::Mutex<Vec<Vec<String>>>,
        /// [§22.3.2] **capability台帳から名前を捨てた回数と集合**（1要素＝1回の`update`）。
        ///
        /// `workspace_prunes`と分けるのは、落とす先の台帳が別だからである
        /// （あちらは`workspace-grant-ledger`、こちらは`workspace-capability-ledger`）。
        /// **名前を捨てる操作なので、剥がし残しがあったときに呼ばれていないことを測る**
        /// のがこの欄の主目的である（`B-01`の「名前を捨てる操作を最後に置く」）。
        capability_forgets: std::sync::Mutex<Vec<Vec<String>>>,
        /// `delete_profile`の戻り値。`Err`にすると「削除できなかった」経路を測れる。
        delete_result: Result<(), String>,
        /// `unrecorded_aces`の戻り値。0以外＝台帳に無いACEが実在する（BUG-101の保護）。
        unrecorded: usize,
        /// 撤収が**剥がし残す**`(パス, プロファイル名)`の組。実FSでは「剥がせないノード」を
        /// 非昇格で作れない（`revoke.rs`の`revoke_tree_for_tests`のdoc）ので、剥がし残しが
        /// 一覧台帳の掃除へどう効くかはここで作る。
        blocked: Vec<(String, String)>,
        /// 一時ディレクトリ。`ledger`が指す先なので、テストが終わるまで生かす。
        _dir: tempfile::TempDir,
    }

    impl FakeIo {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            Self {
                ledger: Ledger::at_path(dir.path().join(LEDGER_FILE), None),
                events: std::sync::Mutex::new(Vec::new()),
                workspace_prunes: std::sync::Mutex::new(Vec::new()),
                capability_forgets: std::sync::Mutex::new(Vec::new()),
                delete_result: Ok(()),
                unrecorded: 0,
                blocked: Vec::new(),
                _dir: dir,
            }
        }

        /// 一時台帳へエントリを積んでおく（回収が何を落とすかを測るため）。
        fn with_sessions(self, tokens: &[&str]) -> Self {
            self.ledger.save(&SessionLedger {
                sessions: tokens.iter().map(|t| entry(t, &[])).collect(),
            });
            self
        }

        /// 実マシンを触らない[`ReclaimIo`]を組んで回収する。**副作用の注入点はここ1箇所**。
        fn reclaim(&self, targets: &[ReclaimTarget]) -> ReclaimOutcome {
            let note = |event: String| self.events.lock().unwrap().push(event);
            let revoke = |path: &Path, profile: &str| {
                note(format!("revoke:{}:{profile}", path.display()));
                let path_str = path.to_string_lossy();
                if self
                    .blocked
                    .iter()
                    .any(|(p, prof)| *p == *path_str && prof == profile)
                {
                    return vec![(path.to_path_buf(), "blocked by the fake".to_string())];
                }
                RevokeLeftovers::new()
            };
            let delete = |profile: &str| {
                note(format!("delete:{profile}"));
                self.delete_result.clone()
            };
            // [§22.3.2] capability宛の撤収。`blocked`の突合は`revoke`と同じ形にしてある
            // ——テスト側で別の判定を書くと、製品側で2つの経路が同じ扱いになっているか
            // どうかをこのフェイクが測れなくなる。
            let revoke_capability = |path: &Path, capability: &str| {
                note(format!("revoke_cap:{}:{capability}", path.display()));
                let path_str = path.to_string_lossy();
                if self
                    .blocked
                    .iter()
                    .any(|(p, name)| *p == *path_str && name == capability)
                {
                    return vec![(path.to_path_buf(), "blocked by the fake".to_string())];
                }
                RevokeLeftovers::new()
            };
            let forget_capabilities = |names: &[&str]| {
                self.capability_forgets
                    .lock()
                    .unwrap()
                    .push(names.iter().map(|n| (*n).to_string()).collect());
            };
            let unrecorded_aces = |_profile: &str, _recorded: &[String]| self.unrecorded;
            let prune_workspace_paths = |cleared: &[&str]| {
                self.workspace_prunes
                    .lock()
                    .unwrap()
                    .push(cleared.iter().map(|p| (*p).to_string()).collect());
            };
            reclaim_targets_in(
                &ReclaimIo {
                    revoke: &revoke,
                    revoke_capability: &revoke_capability,
                    forget_capabilities: &forget_capabilities,
                    unrecorded_aces: &unrecorded_aces,
                    delete_profile: &delete,
                    ledger: &self.ledger,
                    prune_workspace_paths: &prune_workspace_paths,
                },
                targets,
            )
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        /// workspace一覧台帳の掃除の呼び出し履歴（1要素＝1回の`update`）。
        fn workspace_prunes(&self) -> Vec<Vec<String>> {
            self.workspace_prunes.lock().unwrap().clone()
        }

        /// capability台帳から名前を捨てた履歴（1要素＝1回の`update`）。
        fn capability_forgets(&self) -> Vec<Vec<String>> {
            self.capability_forgets.lock().unwrap().clone()
        }

        /// 一時台帳に残っているセッションのトークン。
        fn remaining_tokens(&self) -> Vec<String> {
            self.ledger
                .load()
                .sessions
                .into_iter()
                .map(|e| e.token)
                .collect()
        }
    }

    fn known_target(token: &str, paths: &[&str]) -> ReclaimTarget {
        ReclaimTarget {
            profile_name: profile_name_for(token),
            granted_paths: paths.iter().map(|p| p.to_string()).collect(),
            granted_capabilities: Vec::new(),
            grants_known: true,
        }
    }

    /// [§22.3.2] capability SID宛の付与を持つ回収対象（CoWの差分層）。
    fn known_target_with_capabilities(token: &str, grants: &[(&str, &str)]) -> ReclaimTarget {
        ReclaimTarget {
            granted_capabilities: grants
                .iter()
                .map(|(path, name)| CapabilityGrant {
                    path: (*path).to_string(),
                    capability_name: (*name).to_string(),
                })
                .collect(),
            ..known_target(token, &[])
        }
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

    /// **生きている他セッションが使っているcapability宛の付与は剥がさない。**
    ///
    /// capability SIDの宛先は`(workspace, 宣言パス, access級)`が鍵でセッションを含まないので、
    /// **同じ付与を複数のセッションが記録する**。死んだ側の記録だけを見て剥がすと、
    /// 生きている側のACEまで消える——症状はそのセッションの次の操作が`ACCESS_DENIED`で
    /// 落ちることで、剥がした側には何も起きないので原因に辿り着けない。
    ///
    /// **Redirector DLLの許可を宣言宛へ移した回（2026-09-19）に入れた。** それまでは
    /// 差分層のように「たまたま共有されることがある」程度だったが、DLLは**全セッションが
    /// 同じ2ファイルへ同じ宛先で**記録するので、常に踏む形になった。
    #[test]
    fn a_capability_grant_that_a_live_session_still_holds_is_not_reclaimed() {
        let shared = ("C:\\tools\\harness_redirector.dll", "harnessDeclShared");
        let own = ("C:\\tmp\\dead-only", "harnessDeclOwn");
        let ledger = SessionLedger {
            sessions: vec![
                entry_with_capabilities("alive", &[shared]),
                entry_with_capabilities("dead", &[shared, own]),
            ],
        };
        let mut live = HashSet::new();
        live.insert("alive".to_string());

        let targets = plan_reclaim(&ledger, &[], &liveness(&live));
        assert_eq!(targets.len(), 1, "{targets:?}");
        let names: Vec<&str> = targets[0]
            .granted_capabilities
            .iter()
            .map(|g| g.capability_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["harnessDeclOwn"],
            "生きているセッションがまだ使っている宛先を剥がそうとしている"
        );
    }

    /// **対の側**（`B-35`）: 誰も生きていなければ、共有されていた付与も剥がす。
    ///
    /// これが無いと「常に剥がさない」実装でも上のテストは緑になり、
    /// **撤収経路の無い孤立ACE**がファイルに残り続ける（BUG-017/059が繰り返し踏んだ形）。
    #[test]
    fn a_shared_capability_grant_is_reclaimed_once_no_session_holds_it() {
        let shared = ("C:\\tools\\harness_redirector.dll", "harnessDeclShared");
        let ledger = SessionLedger {
            sessions: vec![
                entry_with_capabilities("gone-1", &[shared]),
                entry_with_capabilities("gone-2", &[shared]),
            ],
        };

        let targets = plan_reclaim(&ledger, &[], &liveness(&HashSet::new()));
        assert_eq!(targets.len(), 2);
        assert!(
            targets.iter().all(|t| t.granted_capabilities.len() == 1),
            "誰も使っていない宛先が剥がされずに残っている: {targets:?}"
        );
    }

    /// package SID宛の付与には同じ見張りを掛けない（**宛先がセッションごとに違う**ので
    /// 共有され得ない）。掛けると、同じパスを2セッションが開いたときに片方が永久に残る。
    #[test]
    fn path_grants_are_not_affected_by_the_shared_capability_guard() {
        let ledger = SessionLedger {
            sessions: vec![entry("alive", &["C:\\ws"]), entry("dead", &["C:\\ws"])],
        };
        let mut live = HashSet::new();
        live.insert("alive".to_string());

        let targets = plan_reclaim(&ledger, &[], &liveness(&live));
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].granted_paths,
            vec!["C:\\ws".to_string()],
            "package SID宛はセッションごとに違うので、同じパスでも剥がしてよい"
        );
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
            // 空でも「無かった」ではなく「**分からない**」（`grants_known: false`）。
            granted_capabilities: Vec::new(),
            grants_known: false,
        }];
        let io = FakeIo::new();
        let outcome = io.reclaim(&targets);

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
            io.events().is_empty(),
            "剥がす対象が分からないのだから、撤収も削除も呼ばれないのが正しい: {:?}",
            io.events()
        );
    }

    /// **対になる許可側**（B-35）。付与内容が分かっているものは、従来どおり撤収して削除します。
    /// これが無いと「全部見送る」実装でも上のテストが通ってしまい、GCの生死を判定できません。
    #[test]
    fn a_profile_whose_grants_are_known_is_still_revoked_and_deleted() {
        let targets = vec![known_target("known", &["C:\\a", "C:\\b"])];
        let io = FakeIo::new().with_sessions(&["known"]);
        let outcome = io.reclaim(&targets);

        assert_eq!(outcome.revoked_paths, 2);
        assert_eq!(
            io.events(),
            vec![
                format!("revoke:C:\\a:{}", profile_name_for("known")),
                format!("revoke:C:\\b:{}", profile_name_for("known")),
                format!("delete:{}", profile_name_for("known")),
            ]
        );
        assert!(
            outcome.kept_unknown.is_empty(),
            "分かっているものまで見送ってはいけない: {outcome:?}"
        );
        // [BUG-108] 削除が注入されたので、実Win32の気まぐれ（実在しない名前にもS_OKを返す）に
        // 左右されずに件数を断定できる。以前は`deleted + failures == 1`としか書けなかった。
        assert_eq!(outcome.deleted_profiles, 1);
        assert!(outcome.delete_failures.is_empty(), "{outcome:?}");
    }

    /// **[BUG-108] 消えた台帳エントリは、削除できたプロファイルのぶんだけ。**
    ///
    /// 台帳の`retain`は`reclaim_targets`の中でしか走らないので、注入前はこの振る舞いを
    /// 測る手段が無かった（測ろうとすると実マシンの台帳を書き換えることになる）。
    #[test]
    fn only_the_deleted_profile_loses_its_ledger_entry() {
        let io = FakeIo::new().with_sessions(&["dead", "alive"]);
        let outcome = io.reclaim(&[known_target("dead", &["C:\\ws"])]);

        assert_eq!(outcome.deleted_profiles, 1);
        assert_eq!(
            io.remaining_tokens(),
            vec!["alive".to_string()],
            "回収していないセッションのエントリを巻き込んで消してはいけない"
        );
    }

    /// **対になる禁止側**（B-35）。削除に失敗したら台帳エントリは**残す**。
    ///
    /// 消してしまうと、そのプロファイルは次のGCから「台帳に無いが実在する」＝
    /// `grants_known: false`へ落ち、以後どのコマンドでもACEを剥がせなくなる（BUG-101）。
    #[test]
    fn a_profile_that_could_not_be_deleted_keeps_its_ledger_entry() {
        let mut io = FakeIo::new().with_sessions(&["dead"]);
        io.delete_result = Err(
            "DeleteAppContainerProfile reported success but it is still \
                                registered"
                .to_string(),
        );
        let outcome = io.reclaim(&[known_target("dead", &["C:\\ws"])]);

        assert_eq!(outcome.deleted_profiles, 0);
        assert_eq!(outcome.delete_failures.len(), 1, "{outcome:?}");
        assert_eq!(
            io.remaining_tokens(),
            vec!["dead".to_string()],
            "削除できなかったのにエントリを消すと、次のGCが付与内容不明として永久に見送る"
        );
    }

    /// **台帳に無いACEが残っているプロファイルは削除しない**（BUG-101の中心的な保護）。
    ///
    /// この分岐は実マシンに実ACEが在るときしか踏めず、[BUG-108](../../../docs/bugs/BUG-108.md)で
    /// 自己検証を注入するまでテストが1本も無かった。名前を捨てるとSIDを導出できなくなるので、
    /// **撤収が終わっていない宛先SIDの名前は残す**のが正しい。
    #[test]
    fn a_profile_with_unrecorded_aces_is_kept_and_keeps_its_ledger_entry() {
        let mut io = FakeIo::new().with_sessions(&["dead"]);
        io.unrecorded = 1;
        let outcome = io.reclaim(&[known_target("dead", &["C:\\ws"])]);

        assert_eq!(outcome.deleted_profiles, 0);
        assert_eq!(
            outcome.kept_with_leftovers,
            vec![(profile_name_for("dead"), 0, 1)],
            "剥がし残しの内訳（剥がせなかったノード数・台帳に無いACE数）を出す（B-09）"
        );
        assert!(
            !io.events().iter().any(|e| e.starts_with("delete:")),
            "削除は呼ばれてはいけない: {:?}",
            io.events()
        );
        assert_eq!(io.remaining_tokens(), vec!["dead".to_string()]);
    }

    /// **workspace一覧台帳の掃除はパスごとではなく、バッチ全体で1回。**
    ///
    /// `Ledger::update`は1回ごとに台帳の全文を読み書きする（`record_granted_paths`のdocに
    /// 実測がある）。かつて撤収側は`revoke_session_grant`の中から`remove_workspace_entry(path)`を
    /// パスごとに呼んでおり、**付与側が既に直した形の未修正版**として残っていた。
    ///
    /// 落ちる記録は1件ずつでも同じなので、**回数を測らないと直ったことを固定できない**。
    #[test]
    fn the_workspace_ledger_is_pruned_once_for_the_whole_batch() {
        let io = FakeIo::new().with_sessions(&["a", "b"]);
        io.reclaim(&[
            known_target("a", &["C:\\ws1", "C:\\ws2"]),
            known_target("b", &["C:\\ws3"]),
        ]);

        let prunes = io.workspace_prunes();
        assert_eq!(
            prunes.len(),
            1,
            "3パスで3回台帳を書き直してはいけない: {prunes:?}"
        );
        assert_eq!(
            prunes[0],
            vec![
                "C:\\ws1".to_string(),
                "C:\\ws2".to_string(),
                "C:\\ws3".to_string()
            ],
            "剥がし終えた3パスが1回の述語で落ちること"
        );
    }

    /// **対になる禁止側**（B-35）。剥がし残したパスの記録は落とさない。
    ///
    /// 一覧台帳は`harness fs list`が読む索引で、記録を先に捨てると「ACEは残っているのに
    /// 一覧に出てこない」状態になる（B-01の「対の片方だけ」）。許可側だけだと
    /// 「常に全部落とす」実装でも緑のままになる。
    #[test]
    fn a_path_that_still_holds_an_ace_keeps_its_workspace_ledger_entry() {
        let mut io = FakeIo::new().with_sessions(&["a"]);
        io.blocked = vec![("C:\\stuck".to_string(), profile_name_for("a"))];
        let outcome = io.reclaim(&[known_target("a", &["C:\\clean", "C:\\stuck"])]);

        assert_eq!(
            io.workspace_prunes(),
            vec![vec!["C:\\clean".to_string()]],
            "剥がせたパスだけを落とす: {:?}",
            io.workspace_prunes()
        );
        assert_eq!(outcome.blocked_paths.len(), 1, "{outcome:?}");
        assert_eq!(
            outcome.kept_with_leftovers.len(),
            1,
            "剥がし残しがあるならプロファイル名も残る（記録を落とす判断は表と裏）: {outcome:?}"
        );
        assert_eq!(io.remaining_tokens(), vec!["a".to_string()]);
    }

    /// **同じパスを2つのプロファイルが付与していて、片方が剥がし残したら落とさない。**
    ///
    /// 掃除をループの外へ出すと、判定の単位が「このプロファイルの撤収が終わったか」から
    /// **「そのパスに載っていた全プロファイル分が終わったか」**へ変わる。1件ずつ落として
    /// いたころは、先に終わった方が記録を落としてしまう向きの取りこぼしがあった。
    #[test]
    fn a_path_shared_by_two_profiles_is_forgotten_only_when_both_are_clean() {
        let mut io = FakeIo::new().with_sessions(&["a", "b"]);
        io.blocked = vec![("C:\\shared".to_string(), profile_name_for("b"))];
        io.reclaim(&[
            known_target("a", &["C:\\shared"]),
            known_target("b", &["C:\\shared"]),
        ]);

        assert!(
            io.workspace_prunes().is_empty(),
            "aが剥がし終えても、bのACEが残っているうちは一覧から消さない: {:?}",
            io.workspace_prunes()
        );
    }

    /// **対になる許可側**（B-35）。両方が剥がし終えたら落とす——ただし2プロファイル分で
    /// 2回書き直さない。
    #[test]
    fn a_path_shared_by_two_clean_profiles_is_forgotten_once() {
        let io = FakeIo::new().with_sessions(&["a", "b"]);
        io.reclaim(&[
            known_target("a", &["C:\\shared"]),
            known_target("b", &["C:\\shared"]),
        ]);

        assert_eq!(
            io.workspace_prunes(),
            vec![vec!["C:\\shared".to_string()]],
            "同じパスを2度述語へ渡す必要は無い: {:?}",
            io.workspace_prunes()
        );
    }

    /// 剥がしたパスが1つも無ければ、台帳へは一度も触らない（無害な全文書き直しを起こさない）。
    #[test]
    fn nothing_to_forget_means_the_workspace_ledger_is_never_opened() {
        let io = FakeIo::new();
        io.reclaim(&[ReclaimTarget {
            profile_name: profile_name_for("lost-ledger"),
            granted_paths: Vec::new(),
            // 空でも「無かった」ではなく「**分からない**」（`grants_known: false`）。
            granted_capabilities: Vec::new(),
            grants_known: false,
        }]);

        assert!(
            io.workspace_prunes().is_empty(),
            "{:?}",
            io.workspace_prunes()
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
    ///
    /// [BUG-108] **以前このテストは順序を測っていなかった。** 記録していたのが撤収だけで、
    /// 削除は`win::delete_profile`の直呼び（非Windowsではno-op）だったため、削除を撤収より
    /// 先へ移動しても緑のままだった——つまり不変条件そのものには歯が無かった。削除も
    /// 注入して**同じ列**へ積むことで、初めて順序を固定できる。
    #[test]
    fn revocation_happens_before_the_profile_is_deleted() {
        let io = FakeIo::new().with_sessions(&["t"]);
        io.reclaim(&[known_target("t", &["C:\\a", "C:\\b"])]);

        assert_eq!(
            io.events(),
            vec![
                format!("revoke:C:\\a:{}", profile_name_for("t")),
                format!("revoke:C:\\b:{}", profile_name_for("t")),
                format!("delete:{}", profile_name_for("t")),
            ]
        );
    }

    // --- [§22.3.2] CoW差分層のcapability SID宛ACEの撤収 ---
    //
    // **禁止側と許可側を対で置く**（`B-35`）。「剥がせたら名前を捨てる」だけを測ると、
    // 判定が「常に捨てる」に壊れても緑のままになる——そして常に捨てる側へ壊れることは、
    // **剥がせていないACEの名前を失う**という最悪の形（BUG-101と同型）である。

    /// 許可側: 1本残らず剥がせたら、capability台帳から名前を捨てる。
    ///
    /// 捨てないとCoWセッションごとに記録が1件積もる（§22.3.2が「撤収とGCを対で設計する」と
    /// 言っている当のもの）。
    #[test]
    fn a_fully_revoked_capability_grant_has_its_name_dropped() {
        let io = FakeIo::new().with_sessions(&["t"]);
        let outcome = io.reclaim(&[known_target_with_capabilities(
            "t",
            &[(
                r"C:\cow\sess-1",
                "harnessDecl00112233445566778899aabbccddeeff",
            )],
        )]);

        assert_eq!(
            io.capability_forgets(),
            vec![vec![
                "harnessDecl00112233445566778899aabbccddeeff".to_string()
            ]],
            "剥がし終えた名前は捨てられていなければならない"
        );
        assert_eq!(outcome.deleted_profiles, 1);
        assert!(outcome.kept_with_leftovers.is_empty());
    }

    /// 禁止側: 1本でも剥がし残したら、名前を**捨てない**しプロファイルも消さない。
    ///
    /// capability SIDは名前の一方向導出なので、名前を捨てた瞬間にそのACEは
    /// **どのコマンドでも剥がせなくなる**（`B-01`の「不可逆な片方」）。
    #[test]
    fn a_blocked_capability_grant_keeps_its_name_and_its_profile() {
        let io = FakeIo {
            blocked: vec![(
                r"C:\cow\sess-1".to_string(),
                "harnessDecl00112233445566778899aabbccddeeff".to_string(),
            )],
            ..FakeIo::new()
        }
        .with_sessions(&["t"]);
        let outcome = io.reclaim(&[known_target_with_capabilities(
            "t",
            &[(
                r"C:\cow\sess-1",
                "harnessDecl00112233445566778899aabbccddeeff",
            )],
        )]);

        assert!(
            io.capability_forgets().is_empty(),
            "剥がせていない名前を捨ててはいけない: {:?}",
            io.capability_forgets()
        );
        assert_eq!(
            outcome.deleted_profiles, 0,
            "剥がし残しがあるならプロファイルも残す"
        );
        assert_eq!(outcome.kept_with_leftovers.len(), 1);
        // 台帳エントリも残る（次回のGCがもう一度引ける）。
        assert_eq!(io.remaining_tokens(), vec!["t".to_string()]);
    }

    /// capability宛の撤収も**プロファイル削除より先**である（package SID宛と同じ不変条件）。
    ///
    /// 順序が逆だと、セッション台帳のエントリが先に消えて`granted_capabilities`ごと失われる
    /// ——名前を失ったACEは二度と剥がせない。
    #[test]
    fn capability_revocation_also_happens_before_the_profile_is_deleted() {
        let io = FakeIo::new().with_sessions(&["t"]);
        io.reclaim(&[ReclaimTarget {
            granted_paths: vec![r"C:\ws".to_string()],
            ..known_target_with_capabilities(
                "t",
                &[(
                    r"C:\cow\sess-1",
                    "harnessDecl00112233445566778899aabbccddeeff",
                )],
            )
        }]);

        assert_eq!(
            io.events(),
            vec![
                format!("revoke:C:\\ws:{}", profile_name_for("t")),
                "revoke_cap:C:\\cow\\sess-1:harnessDecl00112233445566778899aabbccddeeff"
                    .to_string(),
                format!("delete:{}", profile_name_for("t")),
            ]
        );
    }

    /// 台帳から回収対象を組み立てるとき、capability宛の付与も一緒に運ばれる。
    ///
    /// [BUG-057と同型] ここが落ちると、撤収の**実装は正しいのに対象が空**になり、
    /// 「撤収が走ったのに何も剥がれない」という無言の失敗になる。
    #[test]
    fn capability_grants_are_carried_from_the_ledger_into_the_reclaim_plan() {
        let ledger = SessionLedger {
            sessions: vec![entry_with_capabilities(
                "dead",
                &[(
                    r"C:\cow\sess-1",
                    "harnessDecl00112233445566778899aabbccddeeff",
                )],
            )],
        };
        let targets = plan_reclaim(&ledger, &[], &liveness(&HashSet::new()));

        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].granted_capabilities,
            vec![CapabilityGrant {
                path: r"C:\cow\sess-1".to_string(),
                capability_name: "harnessDecl00112233445566778899aabbccddeeff".to_string(),
            }]
        );
    }

    /// **capability宛しか付けていないセッションを「撤収するものが無い」と数えない。**
    ///
    /// ポリシーエディタの撤収は「対象0件なら`end_session`を呼ばずに戻る」という早期returnを
    /// 持つ。その判定が`granted_paths`だけを数えていたため、差分層しか付けていないセッションで
    /// **撤収が丸ごと飛んでいた**（`B-06`: 「このセッションが付けたもの」の意味が2つの欄に
    /// 割れたのに、数える側が追随していなかった）。
    #[test]
    fn a_session_with_only_capability_grants_is_not_counted_as_nothing_to_revoke() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger: Ledger<SessionLedger> = Ledger::at_path(dir.path().join(LEDGER_FILE), None);
        ledger.save(&SessionLedger {
            sessions: vec![entry_with_capabilities(
                "t",
                &[(
                    r"C:\cow\sess-1",
                    "harnessDecl00112233445566778899aabbccddeeff",
                )],
            )],
        });

        assert_eq!(
            pending_revocation_count_in(&ledger, "t"),
            1,
            "capability宛の付与を数えないと、撤収そのものが呼ばれない"
        );
    }

    /// 両方あれば合計する（片方だけ数える形へ戻っていないか）。
    #[test]
    fn both_kinds_of_grant_are_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger: Ledger<SessionLedger> = Ledger::at_path(dir.path().join(LEDGER_FILE), None);
        let mut e = entry("t", &[r"C:\ws", r"C:\other"]);
        e.granted_capabilities = vec![CapabilityGrant {
            path: r"C:\cow\sess-1".to_string(),
            capability_name: "harnessDecl00112233445566778899aabbccddeeff".to_string(),
        }];
        ledger.save(&SessionLedger { sessions: vec![e] });

        assert_eq!(pending_revocation_count_in(&ledger, "t"), 3);
    }

    /// 何も付けていないセッションは0（早期returnが正しく効く側も測る、`B-35`）。
    #[test]
    fn a_session_that_granted_nothing_counts_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger: Ledger<SessionLedger> = Ledger::at_path(dir.path().join(LEDGER_FILE), None);
        ledger.save(&SessionLedger {
            sessions: vec![entry("t", &[])],
        });

        assert_eq!(pending_revocation_count_in(&ledger, "t"), 0);
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
