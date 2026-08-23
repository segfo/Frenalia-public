//! ワークスペース＋モード単位のcapability名とその秘密（D-54、`plans/DESIGN-SANDBOX-APPPOLICY.md`）。
//!
//! workspaceツリーへ付けるFSのACEは、**セッションのpackage SIDではなくこのcapability SID宛**に
//! 付ける。理由は費用である——NTFSのアクセス判定は対象オブジェクト自身のDACLしか見ないため、
//! 26万ファイルのworkspaceを読み書きさせるには26万個のACEコピーが物理的に要る。主体が
//! セッション単位（D-37）だと、この26万件を**起動のたびに**書き直すことになる（実測60秒、
//! [BUG-081](../../../docs/bugs/BUG-081.md)）。付与の形はもともと「workspaceとモードで決まる」
//! ものであって（同じworkspaceでのモード混在は`workspace_ledger::begin_workspace_mode`が既に
//! 禁止している）、セッションの属性ではない。主体をその形に合わせれば、付与は**ワークスペース
//! につき一度きり**で済む。
//!
//! **D-37は撤回しない。** package SIDはセッション単位のままで、置き換えるのはFSのACEの主体
//! だけである（loopback exemptionの奪い合い・WFP出口強制・プロファイル作成の競合という
//! D-37の他の根拠はネットワークとプロファイルの話で、FSとは独立に成立している）。
//!
//! ## capability名は必ずランダム秘密から導出する（この決定の核）
//!
//! capability SIDは名前から誰でも導出でき（`DeriveCapabilitySidsFromName`）、
//! **`CreateProcess`＋`SECURITY_CAPABILITIES`でトークンへ任意に積める**（特権不要の通常操作）。
//! つまり「名前を知っている者は、そのcapabilityを持つAppContainerを自分で作れる」。
//!
//! 固定名`harnessSandboxTraverse`（[`crate::tier2a::win_appcontainer::TRAVERSE_CAPABILITY_NAME`]）の
//! 残存リスクが許容できているのは、それで得られるのが祖先の通過と属性読取だけ＝通常のユーザー
//! プロセスが既に持つ権限と同等だからである。**ワークスペース全体のRWへ広げると、この論拠は
//! 成立しない。**
//!
//! | アクター | 現状できること | 名前が推測可能だった場合に増えるもの |
//! |---|---|---|
//! | 同一ユーザーのプロセス（マルウェア含む） | workspaceへフルアクセス（`<user>:(I)(F)`） | **何も増えない**（既に負けている） |
//! | **別のローカルアカウント**（この機の`CodexSandboxUsers`等） | workspaceへのNTFSアクセス無し | **workspace全体のRW**。中IL・非AppContainerのプロセスは任意capability付きAppContainerを作れるので、ACEにトークンが一致してしまう |
//! | 別workspaceのharnessサンドボックス | 自分のworkspaceのみ | 他workspaceへ到達（ただし「AppContainer内から別capabilityのAppContainerを作れるか」というOS挙動に依存する。作れないはずだが実測前） |
//!
//! 2行目が**OS挙動への仮定を一切置かずに秘密を要求する**根拠である。したがって名前は
//! パスのハッシュ（＝パスを知る者なら誰でも導出できる）ではなく、workspaceごとに生成した
//! 128bit乱数から導出し、`%APPDATA%\harness\config\`のマシンローカル台帳へ保存する。
//! サンドボックスはworkspace外のこのファイルを読めない（P-01）ので、名前を知り得ない。
//!
//! ## 乱数が取れなければ失敗する（fail-closed）
//!
//! [`ensure_capability_name`]はOSのCSPRNGが使えないとき`Err`を返し、**弱い乱数へ退避しない**。
//! 秘密が推測可能になった瞬間に上表の2行目が現実になるので、ここだけは台帳の他の経路
//! （読めなければ空とみなすfail-open）と方針が逆になる。呼び出し元（`preflight`）は
//! Tier2aを諦めてTier1へ降格すればよい。
//!
//! ## モードごとに別の秘密を持つ
//!
//! `rwx`（通常起動）と`ro`（`--sandbox tier2a-cow`）で別のcapabilityにする。同じworkspaceを日を変えて
//! 両モードで使うと両方のACEがツリーへ載るが、子トークンへ積むのは**そのセッションのモードの
//! capabilityだけ**なので、ROセッションが過去のRWX用ACEで書けてしまうことはない。
//!
//! ## この台帳が持たないもの
//!
//! 「実際にツリーへACEが載っているか」は台帳では判定しない。権威は常に実物のACLであり、
//! 付与側（`acl_grant`）がrootのACEを読んで冪等に判断する。台帳が持つのは**名前の登録簿**
//! （同じworkspaceに毎回同じ名前を割り当てる）と**撤収の索引**（`harness fs revoke-workspace`が
//! 剥がすべき主体を引く）の2つだけである。台帳を失っても実マシンに残るのは
//! 「二度と導出されない秘密宛の不活性なACE」であって、生きた権限ではない。

use std::path::Path;

use harness_grant_ledger::{now_unix_secs, Ledger};
use serde::{Deserialize, Serialize};

/// capability名の接頭辞。`DeriveCapabilitySidsFromName`は名前を大文字化してからハッシュする
/// ため大文字小文字は区別されない。既存の`harnessSandboxTraverse`と同じcamelCaseに揃える。
pub const CAPABILITY_NAME_PREFIX: &str = "harnessWs";

/// 秘密の長さ（バイト）。128bit——推測（総当たり）に対して十分で、かつ名前が長くなりすぎない。
pub const SECRET_LEN: usize = 16;

const LEDGER_FILE: &str = "workspace-capability-ledger.json";
const LEDGER_LOCK: &str = r"Local\harness-workspace-capability-ledger";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceCapabilityEntry {
    /// canonicalize済みworkspaceパス（表示用にそのまま持つ。突合は[`workspace_key`]で行う）。
    pub workspace: String,
    /// `rwx`（通常起動）/`ro`（`--sandbox tier2a-cow`）。`workspace_ledger::KNOWN_MODES`と同じ語彙。
    pub mode: String,
    /// 128bit乱数の16進表現。**これが漏れるとcapability名が導出できる**ので、台帳ファイルの
    /// 置き場（`%APPDATA%\harness\config\`＝サンドボックスから読めない、P-01）が防御になる。
    pub secret_hex: String,
    /// [`capability_name_from_secret`]の結果。秘密から毎回導出できるが、台帳を人が読んだとき
    /// ACLに出るSIDと突き合わせられるように保存しておく。
    pub capability_name: String,
    pub granted_at_unix_secs: u64,
    /// 背景ジョブ（`win_appcontainer::grant_job`のフェーズ0＝既存子孫への継承ACE伝播、
    /// 0.5＝`.harness/`再保護、1＝救済walk）を**最後まで完走した**時刻。`None`なら未完了で、
    /// 次の起動がもう一度回す。
    ///
    /// **「rootにACEが載っているか」では代用できない。** rootへの付与とジョブは別の段で、
    /// 間で落ちる（クラッシュ・強制終了）ことがある。rootだけを見て判断すると、その一度の
    /// 中断で保護DACL配下が永久に到達不能なまま固定される。完走を別に記録するのはそのため。
    ///
    /// **[BUG-110] この時刻だけでは足りない**——記録しているのは「**そのとき在ったツリー**を
    /// 検証した」であって「このパスは以後ずっと検証済み」ではない。対になる
    /// [`Self::root_file_id`]と**必ず一緒に**読み書きすること。
    #[serde(default)]
    pub tree_verified_at_unix_secs: Option<u64>,
    /// [BUG-110] [`Self::tree_verified_at_unix_secs`]を立てたとき、rootが**どのオブジェクト
    /// だったか**（`win_common::directory_identity`）。
    ///
    /// workspaceディレクトリを削除して同じパスへ作り直すと、rootは別のオブジェクトになり
    /// 中身も総入れ替えになる。それでも旧・実装は「パスとモードが同じなら検証済み」と
    /// 判定し、伝播フェーズごと丸ごと省略していた——その結果、**起動前から在ったファイルが
    /// サンドボックスから一切見えない**workspaceが出来上がる（拒否ではなく「無い」に見えるので
    /// 気付けない）。
    ///
    /// `None`（この欄が無かった頃の台帳）は**未検証として扱う**。1回だけ余計にジョブが回る
    /// のに対し、誤って検証済みと信じると到達不能なツリーで走り続ける。
    #[serde(default)]
    pub root_file_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceCapabilityLedger {
    #[serde(default)]
    pub entries: Vec<WorkspaceCapabilityEntry>,
}

fn ledger() -> Ledger<WorkspaceCapabilityLedger> {
    Ledger::in_config_dir(LEDGER_FILE, Some(LEDGER_LOCK))
}

/// 台帳内でworkspaceを突き合わせる鍵。Windowsのパスは大文字小文字を区別しないので小文字化し、
/// 区切りを`\`へ揃え、`\\?\`（verbatim）前置を落とす。
///
/// 綴りの揺れで別エントリを作ると、**同じツリーへ2つの主体のACEを撒く**ことになる。
/// `std::fs::canonicalize`はWindowsで`\\?\`付きを返す一方、設定やCLI引数から来るパスには
/// 付いていないので、前置の有無はごく普通に混在する。
///
/// 呼び出し側はcanonicalize済みのパスを渡すこと——`..`や8.3短縮名の解決までは行わない。
pub fn workspace_key(path: &Path) -> String {
    let s = path.to_string_lossy().replace('/', "\\").to_lowercase();
    match s.strip_prefix(r"\\?\unc\") {
        Some(unc) => format!(r"\\{unc}"),
        None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 秘密からcapability名を導出する純粋関数。**秘密が1bitでも違えば別の名前＝別のSIDになる**
/// ことがD-54の安全性の全てなので、ここは可逆な連結のままにしておく（ハッシュを噛ませても
/// 強度は上がらず、台帳と実物の突合だけが難しくなる）。
pub fn capability_name_from_secret(secret: &[u8]) -> String {
    format!("{CAPABILITY_NAME_PREFIX}{}", to_hex(secret))
}

/// harnessが発行したworkspace capabilityの名前の形か。**信頼境界を越えて受け取った名前の
/// 検証**に使う（昇格側の`privhelper`は、渡された名前がこの形であることを確認してから
/// SIDを導出する。`session_profile::is_session_profile_name`と同じ役割）。
pub fn is_workspace_capability_name(name: &str) -> bool {
    let Some(hex) = name.strip_prefix(CAPABILITY_NAME_PREFIX) else {
        return false;
    };
    hex.len() == SECRET_LEN * 2 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// OSのCSPRNGで`SECRET_LEN`バイトを埋める。失敗は`Err`（弱い乱数へ退避しない、モジュールdoc参照）。
#[cfg(windows)]
fn generate_secret() -> Result<[u8; SECRET_LEN], String> {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_ALG_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut secret = [0u8; SECRET_LEN];
    let status = unsafe {
        BCryptGenRandom(
            BCRYPT_ALG_HANDLE::default(),
            &mut secret,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status.is_err() {
        return Err(format!(
            "BCryptGenRandom failed with NTSTATUS {:#010x}; refusing to derive a workspace \
             capability name from a weaker source of randomness",
            status.0
        ));
    }
    Ok(secret)
}

#[cfg(not(windows))]
fn generate_secret() -> Result<[u8; SECRET_LEN], String> {
    use std::io::Read;
    let mut secret = [0u8; SECRET_LEN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(|e| {
            format!(
                "could not read /dev/urandom ({e}); refusing to derive a workspace capability \
                 name from a weaker source of randomness"
            )
        })?;
    Ok(secret)
}

/// 台帳を明示して[`ensure_capability_name`]を行う実体（テストが`%APPDATA%`を汚さないための
/// 注入点。`Ledger::at_path`を渡す）。
///
/// 1回の`update`（＝1回のロック区間）で読み取りと追記を済ませる——複数の`harness.exe`が同時に
/// 同じworkspaceを開いたとき、両方が「エントリが無い」と判定して別々の秘密を書くと、片方の
/// 付与したACEがもう片方から見えない主体宛になる。
fn ensure_capability_name_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
) -> Result<String, String> {
    let key = workspace_key(workspace);
    ledger.update(|l| {
        if let Some(entry) = l
            .entries
            .iter()
            .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
        {
            return Ok(entry.capability_name.clone());
        }
        let secret = generate_secret()?;
        let name = capability_name_from_secret(&secret);
        l.entries.push(WorkspaceCapabilityEntry {
            workspace: workspace.to_string_lossy().into_owned(),
            mode: mode.to_string(),
            secret_hex: to_hex(&secret),
            capability_name: name.clone(),
            granted_at_unix_secs: now_unix_secs(),
            tree_verified_at_unix_secs: None,
            root_file_id: None,
        });
        Ok(name)
    })
}

/// [BUG-110] workspaceのrootディレクトリ**そのもの**の識別子。取得できなければ`None`
/// （消えている・開けない）で、その場合は常に「未検証」側へ倒れる。
///
/// Windows以外はinode＋デバイス番号で同じ意味を作る（この機構自体はWindows専用だが、
/// 台帳の判定ロジックは全プラットフォームでテストできる状態を保つ）。
fn root_identity(workspace: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        crate::win_common::directory_identity(workspace).ok()
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(workspace)
            .ok()
            .map(|m| format!("{:08x}-{:016x}", m.dev(), m.ino()))
    }
}

fn tree_is_verified_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
) -> bool {
    let key = workspace_key(workspace);
    let Some(entry) = ledger
        .load()
        .entries
        .into_iter()
        .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
    else {
        return false;
    };
    if entry.tree_verified_at_unix_secs.is_none() {
        return false;
    }
    // [BUG-110] 記録が指しているのは「**そのとき在ったツリー**」である。rootが別のオブジェクト
    // に入れ替わっていたら、その記録はこのツリーについて何も言っていない。
    // 旧台帳（`None`）と、いま識別子を取れない場合（`None`）は、どちらも未検証扱い。
    match (&entry.root_file_id, root_identity(workspace)) {
        (Some(recorded), Some(current)) => recorded == &current,
        _ => false,
    }
}

/// 背景ジョブ（伝播＋救済walk）が完走済みか（[`WorkspaceCapabilityEntry::tree_verified_at_unix_secs`]
/// と[`WorkspaceCapabilityEntry::root_file_id`]の**両方**を見る）。
/// `false`なら呼び出し側（`preflight`）はジョブを回す。
///
/// **これは「このツリーは到達可能か」の答えではない**——答えているのは「以前このrootを
/// 検証し、それ以来rootが入れ替わっていない」までである。実際にACEが載っているかは
/// `acl_grant::top_level_children_missing_ace`が別途測る（`preflight`は両方を見る、BUG-110）。
pub fn tree_is_verified(workspace: &Path, mode: &str) -> bool {
    tree_is_verified_in(&ledger(), workspace, mode)
}

fn mark_tree_verified_in(ledger: &Ledger<WorkspaceCapabilityLedger>, workspace: &Path, mode: &str) {
    let key = workspace_key(workspace);
    let now = now_unix_secs();
    // [BUG-110] 「いつ」と「何を」は対で書く。片方だけ更新すると、次回の判定が
    // 古い識別子と新しい時刻を突き合わせることになる。
    let identity = root_identity(workspace);
    ledger.update(|l| {
        if let Some(entry) = l
            .entries
            .iter_mut()
            .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
        {
            entry.tree_verified_at_unix_secs = Some(now);
            entry.root_file_id = identity.clone();
        }
    });
}

/// 背景ジョブの完走を記録する。**ジョブが`Ok`で終わったときだけ**呼ぶこと——途中で失敗した
/// のに記録すると、以後どの起動もやり直さなくなる。
///
/// 該当エントリが無ければ何もしない。実運用ではあり得ない（付与の主体を得る
/// [`ensure_capability_name`]が必ず先に走ってエントリを作る）が、順序を逆にした呼び出しは
/// **黙って記録されない**——つまり次回もジョブを回す側（安全側）へ倒れる。
pub fn mark_tree_verified(workspace: &Path, mode: &str) {
    mark_tree_verified_in(&ledger(), workspace, mode);
}

/// `workspace`（canonicalize済み）＋`mode`のcapability名を返す。初回は秘密を生成して台帳へ
/// 記録し、2回目以降は同じ名前を返す（冪等）。
pub fn ensure_capability_name(workspace: &Path, mode: &str) -> Result<String, String> {
    ensure_capability_name_in(&ledger(), workspace, mode)
}

fn lookup_capability_name_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
) -> Option<String> {
    let key = workspace_key(workspace);
    ledger
        .load()
        .entries
        .into_iter()
        .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
        .map(|e| e.capability_name)
}

/// 既に発行済みの名前だけを引く（**生成はしない**）。撤収・一覧のように「まだ無いなら何も
/// しなくてよい」経路が使う。
pub fn lookup_capability_name(workspace: &Path, mode: &str) -> Option<String> {
    lookup_capability_name_in(&ledger(), workspace, mode)
}

fn forget_capability_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
) -> Vec<String> {
    let key = workspace_key(workspace);
    ledger.update(|l| {
        let mut removed = Vec::new();
        l.entries.retain(|e| {
            let hit = workspace_key(Path::new(&e.workspace)) == key
                && (mode.is_empty() || e.mode == mode);
            if hit {
                removed.push(e.capability_name.clone());
            }
            !hit
        });
        removed
    })
}

/// 台帳からこのworkspaceのエントリを落とし、落とした名前を返す（`mode`が空なら全モード）。
///
/// **ACEを剥がし終えてから呼ぶこと。** 先に台帳から消すと主体を引けなくなり、ツリーに
/// 撤収経路の無いACEが残る（`session_profile`のモジュールdocと同じ順序の不変条件。
/// BUG-017/BUG-059が繰り返し踏んだ「孤立ACE」の形）。
pub fn forget_capability(workspace: &Path, mode: &str) -> Vec<String> {
    forget_capability_in(&ledger(), workspace, mode)
}

fn prune_capability_entries_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    should_remove: &dyn Fn(&Path) -> bool,
) -> Vec<String> {
    ledger.update(|l| {
        let mut removed = Vec::new();
        l.entries.retain(|e| {
            if should_remove(Path::new(&e.workspace)) {
                removed.push(e.workspace.clone());
                false
            } else {
                true
            }
        });
        removed
    })
}

/// `should_remove`がtrueを返したworkspaceのエントリを落とす（`harness fs prune`、D-53）。
///
/// 実在しないworkspaceのエントリだけが対象になる（判定は呼び出し側が持つ）。**消えたツリーの
/// ACEを撤収できなくなる心配は無い**——ツリー自体が無いので撤収すべきものが存在しない。
/// 使い捨てのワークスペース（テストのtempdir等）を開くたびに1件増えるので、これが無いと
/// 秘密の記録が際限なく積もる。
pub fn prune_capability_entries(should_remove: impl Fn(&Path) -> bool) -> Vec<String> {
    prune_capability_entries_in(&ledger(), &should_remove)
}

/// 台帳の全エントリ（`harness fs list`の表示用）。
pub fn all_entries() -> Vec<WorkspaceCapabilityEntry> {
    ledger().load().entries
}

/// 台帳ファイルの場所（`harness fs list`がユーザーへ示す用）。
pub fn ledger_path() -> Option<std::path::PathBuf> {
    ledger().path().map(|p| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ledger(dir: &Path) -> Ledger<WorkspaceCapabilityLedger> {
        Ledger::at_path(dir.join("workspace-capability-ledger.json"), None)
    }

    /// D-54の核: 名前は秘密**だけ**から決まる。同じworkspaceでも秘密が変われば別の名前
    /// （＝別のcapability SID）になり、パスを知っているだけでは導出できない。
    #[test]
    fn the_name_is_derived_from_the_secret_and_nothing_else() {
        let a = capability_name_from_secret(&[0u8; SECRET_LEN]);
        let mut other = [0u8; SECRET_LEN];
        other[SECRET_LEN - 1] = 1;
        let b = capability_name_from_secret(&other);
        assert_ne!(a, b);
        assert_eq!(a, "harnessWs00000000000000000000000000000000");
        assert_eq!(b, "harnessWs00000000000000000000000000000001");
    }

    #[test]
    fn only_well_formed_capability_names_are_accepted() {
        assert!(is_workspace_capability_name(&capability_name_from_secret(
            &[0xabu8; SECRET_LEN]
        )));
        assert!(!is_workspace_capability_name("harnessSandboxTraverse"));
        assert!(!is_workspace_capability_name("harnessWs"));
        assert!(!is_workspace_capability_name("harnessWsZZ"));
        // 長さが違うものは弾く（短い＝秘密が短い、長い＝別形式）。
        assert!(!is_workspace_capability_name("harnessWs00"));
        assert!(!is_workspace_capability_name(
            "harnessWs000000000000000000000000000000000"
        ));
    }

    /// 同じworkspace・同じモードなら、何度呼んでも同じ名前が返る（2回目の起動で付与を
    /// やり直さないための前提）。
    #[test]
    fn the_same_workspace_and_mode_always_get_the_same_name() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let first = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        let second = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        assert_eq!(first, second);
        assert_eq!(l.load().entries.len(), 1);
    }

    /// 綴りの揺れ（大文字小文字・区切り）で別エントリを作らない。作ってしまうと、同じ
    /// ツリーへ2つの主体のACEを撒くことになる。
    #[test]
    fn spelling_differences_do_not_create_a_second_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let a = ensure_capability_name_in(&l, Path::new("C:\\Work\\Repo"), "rwx").unwrap();
        let b = ensure_capability_name_in(&l, Path::new("c:/work/repo"), "rwx").unwrap();
        assert_eq!(a, b);
        assert_eq!(l.load().entries.len(), 1);
    }

    /// `std::fs::canonicalize`が返す`\\?\`付きのパスと、CLI引数から来る素のパスが
    /// 同じエントリを指すこと。ここがずれると同じツリーへ2つの主体のACEを撒く。
    #[test]
    fn a_verbatim_prefixed_path_matches_the_plain_one() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let a = ensure_capability_name_in(&l, Path::new(r"\\?\C:\work\repo"), "rwx").unwrap();
        let b = ensure_capability_name_in(&l, Path::new(r"C:\work\repo"), "rwx").unwrap();
        assert_eq!(a, b);
        assert_eq!(l.load().entries.len(), 1);
        assert_eq!(
            workspace_key(Path::new(r"\\?\UNC\server\share\dir")),
            workspace_key(Path::new(r"\\server\share\dir"))
        );
    }

    /// モードが違えば別の主体になる（`--sandbox tier2a-cow`のROセッションが、過去のRWX用ACEを使えない）。
    #[test]
    fn different_modes_get_different_capabilities() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let rwx = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        let ro = ensure_capability_name_in(&l, ws, "ro").unwrap();
        assert_ne!(rwx, ro);
        assert_eq!(l.load().entries.len(), 2);
    }

    /// 別workspaceは別の秘密（＝到達できない別主体）。
    #[test]
    fn different_workspaces_get_different_capabilities() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let a = ensure_capability_name_in(&l, Path::new("C:\\work\\a"), "rwx").unwrap();
        let b = ensure_capability_name_in(&l, Path::new("C:\\work\\b"), "rwx").unwrap();
        assert_ne!(a, b);
    }

    /// 生成された名前は検証関数を通る（発行側と検証側の形が食い違わないことの固定）。
    #[test]
    fn generated_names_pass_their_own_validator() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let name = ensure_capability_name_in(&l, Path::new("C:\\work\\repo"), "rwx").unwrap();
        assert!(is_workspace_capability_name(&name), "{name}");
    }

    #[test]
    fn lookup_does_not_create_an_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        assert!(lookup_capability_name_in(&l, ws, "rwx").is_none());
        assert!(l.load().entries.is_empty());
        let name = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        assert_eq!(
            lookup_capability_name_in(&l, ws, "rwx").as_deref(),
            Some(name.as_str())
        );
    }

    #[test]
    fn forgetting_removes_only_the_requested_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let rwx = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        ensure_capability_name_in(&l, ws, "ro").unwrap();
        assert_eq!(forget_capability_in(&l, ws, "rwx"), vec![rwx]);
        assert_eq!(l.load().entries.len(), 1);
        assert_eq!(l.load().entries[0].mode, "ro");
    }

    /// モードを空にすると全モードを落とす（`harness fs revoke-workspace`が
    /// 「このworkspaceの主体を全部消す」ために使う）。
    #[test]
    fn forgetting_with_an_empty_mode_removes_every_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        ensure_capability_name_in(&l, ws, "rwx").unwrap();
        ensure_capability_name_in(&l, ws, "ro").unwrap();
        assert_eq!(forget_capability_in(&l, ws, "").len(), 2);
        assert!(l.load().entries.is_empty());
    }

    /// 新しいエントリは未検証で始まり、明示的に記録するまで`false`のまま。
    ///
    /// **workspaceは実在するディレクトリでなければならない**——[BUG-110]以降、検証済みの
    /// 判定はrootの識別子の一致まで見るためである。
    #[test]
    fn a_new_entry_starts_unverified_and_can_be_marked() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();
        assert!(!tree_is_verified_in(&l, &ws, "rwx"));
        mark_tree_verified_in(&l, &ws, "rwx");
        assert!(tree_is_verified_in(&l, &ws, "rwx"));
        // モードが違えば別の検証状態（ROツリーはRWXの完走を借りられない）。
        assert!(!tree_is_verified_in(&l, &ws, "ro"));
    }

    /// 台帳を書き直しても検証済みマークが落ちないこと（`ensure`は冪等で、既存エントリを
    /// 作り直さない）。ここが壊れると毎起動でO(ファイル数)のwalkが復活する。
    #[test]
    fn re_ensuring_the_name_does_not_clear_the_verified_mark() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();
        mark_tree_verified_in(&l, &ws, "rwx");
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();
        assert!(tree_is_verified_in(&l, &ws, "rwx"));
    }

    /// **[BUG-110]の回帰**: 同じパスへ作り直したworkspaceは、もう検証済みではない。
    ///
    /// これがE2E（`tier2a_cow_commit_matrix`のN・P〜S）で実際に起きた形をそのまま縮めたもの
    /// である——テストが`case_dir()`でworkspaceを毎回削除・再作成するため、2回目以降は
    /// 「検証済み」と判定されて背景ジョブ（＝既存子孫への継承ACE伝播）が丸ごと省略され、
    /// 起動**前**に置いたファイルがサンドボックスから一切見えなくなっていた。
    ///
    /// 判定からroot識別子の比較を外すと、ここが赤くなる。
    #[test]
    fn a_workspace_recreated_at_the_same_path_is_no_longer_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();
        mark_tree_verified_in(&l, &ws, "rwx");
        assert!(tree_is_verified_in(&l, &ws, "rwx"));

        std::fs::remove_dir_all(&ws).unwrap();
        std::fs::create_dir(&ws).unwrap();
        assert!(
            !tree_is_verified_in(&l, &ws, "rwx"),
            "パスは同じでも別のディレクトリオブジェクトなので、以前の検証は当てはまらない"
        );

        // 作り直した側で回し直せば、また検証済みになる（片道の劣化にしない）。
        mark_tree_verified_in(&l, &ws, "rwx");
        assert!(tree_is_verified_in(&l, &ws, "rwx"));
    }

    /// workspaceごと消えていれば、記録が何であれ未検証（識別子を取れない＝安全側）。
    #[test]
    fn a_vanished_workspace_is_never_reported_as_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();
        mark_tree_verified_in(&l, &ws, "rwx");
        std::fs::remove_dir_all(&ws).unwrap();
        assert!(!tree_is_verified_in(&l, &ws, "rwx"));
    }

    /// 既存の台帳ファイル（`tree_verified_at_unix_secs`・`root_file_id`が無い）を
    /// そのまま読めること。**読めるだけでなく、検証済みとは扱わない**——[BUG-110]以前の
    /// 台帳は「どのツリーを検証したか」を持っていないので、その主張は検算できない。
    #[test]
    fn a_ledger_file_without_the_verified_field_still_deserializes() {
        let legacy = r#"{"entries":[{"workspace":"C:\\ws","mode":"rwx","secret_hex":"00","capability_name":"harnessWs00","granted_at_unix_secs":1}]}"#;
        let ledger: WorkspaceCapabilityLedger = serde_json::from_str(legacy).unwrap();
        assert_eq!(ledger.entries[0].tree_verified_at_unix_secs, None);
        assert_eq!(ledger.entries[0].root_file_id, None);
    }

    /// [BUG-110] 旧台帳（`tree_verified_at_unix_secs`はあるが`root_file_id`が無い）は
    /// **未検証**として扱う。1回だけ余計にジョブが回るのに対し、誤って検証済みと信じると
    /// 到達不能なツリーで走り続ける。
    #[test]
    fn an_old_ledger_entry_without_a_root_id_is_treated_as_unverified() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        let l = test_ledger(tmp.path());
        l.update(|entries| {
            entries.entries.push(WorkspaceCapabilityEntry {
                workspace: ws.to_string_lossy().into_owned(),
                mode: "rwx".to_string(),
                secret_hex: "00".to_string(),
                capability_name: "harnessWs00".to_string(),
                granted_at_unix_secs: 1,
                tree_verified_at_unix_secs: Some(2),
                root_file_id: None,
            });
        });
        assert!(!tree_is_verified_in(&l, &ws, "rwx"));
    }

    /// 秘密が実際にランダムであること（同じ入力から2つの名前を作って一致しない）。
    /// CSPRNGが定数を返す実装ミスを拾う最低限の網。
    #[test]
    fn two_freshly_generated_secrets_differ() {
        let a = generate_secret().expect("CSPRNG");
        let b = generate_secret().expect("CSPRNG");
        assert_ne!(a, b);
        assert_ne!(a, [0u8; SECRET_LEN]);
    }
}
