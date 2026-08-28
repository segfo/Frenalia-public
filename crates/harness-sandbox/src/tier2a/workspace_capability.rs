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
    /// **このエントリが何の主体か**（§22.3）。
    ///
    /// - `None` — このworkspaceツリー**本体**の主体（D-54）。この欄が無かった頃の台帳は
    ///   すべてこちらに読める。
    /// - `Some(畳み込み済み宣言パス)` — `--fs-allow`の**宣言1件**の主体
    ///   （§22.2.0「群 = 宣言1件」）。
    ///
    /// **既存の経路（workspace本体）は必ず`None`で突き合わせること**（[`matches`]）。
    /// 突合から外すと、宣言エントリが workspace 本体の主体として返り、**ツリー全体へ
    /// 宣言用の主体を撒く**——「同じツリーへ2つの主体のACEを撒かない」という
    /// [`workspace_key`]の目的を、鍵の別の軸で破ることになる。
    #[serde(default)]
    pub declaration: Option<String>,
    /// **`declaration`によって語彙が変わる。**
    ///
    /// - `declaration == None` — `rwx`（通常起動）/`ro`（`--sandbox tier2a-cow`）。
    ///   `workspace_ledger::KNOWN_MODES`と同じ語彙。
    /// - `declaration == Some(_)` — access級（`FsAccess::label()`。`read`/`read_write`/
    ///   `read_exec`/`read_write_exec`）。§22.2.0が導出鍵に含めると決めた「access級」で、
    ///   **新しい語彙を作らずに既存の`label()`をそのまま鍵にしている**。
    ///
    /// 2つの語彙は値が1つも重ならないが、**それに依存しない**——突合は必ず
    /// `declaration`と対で行う（[`matches`]）。
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
    /// 背景準備を開始した時刻。別プロセスの`harness fs list`も`preparing`を表示できるよう、
    /// プロセス内のジョブ状態だけに置かずこの台帳へ残す。
    #[serde(default)]
    pub preparation_started_at_unix_secs: Option<u64>,
    /// 準備を開始したrootの識別子。同じパスへ別のworkspaceが作り直されたとき、古い
    /// `preparing`/`failed`を新しいrootへ適用しないための対になる値。
    #[serde(default)]
    pub preparation_root_file_id: Option<String>,
    /// 最後の背景準備が失敗した時刻と理由。次の準備開始で消し、成功時にも消す。
    #[serde(default)]
    pub preparation_failed_at_unix_secs: Option<u64>,
    #[serde(default)]
    pub preparation_error: Option<String>,
}

/// capability台帳に永続化された、現在のrootに対する準備ジョブの状態。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedWorkspacePreparation {
    None,
    Preparing,
    Failed(String),
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

/// 宣言パスを台帳内で突き合わせる鍵（§22.2.0の「畳み込み済みパス」）。
///
/// **[`workspace_key`]と同じ規則をそのまま使う**——FS軸の畳み込みは1つでなければならず
/// （§22.5・B-20）、2つ目を書くと`C:/x`と`c:\x`が別のSIDになって同じ木へ二重にACEを撒く。
/// 別名にしてあるのは呼ぶ側の意図（workspaceを指すのか宣言を指すのか）を読めるようにするためで、
/// 規則を分けるためではない。
pub fn declaration_key(path: &Path) -> String {
    workspace_key(path)
}

/// 台帳エントリの突合。**3つの軸（workspace・宣言・mode）を必ず揃って見る。**
///
/// `declaration`を突合から落とすと、workspace本体を引いたつもりで宣言エントリが返る
/// （[`WorkspaceCapabilityEntry::declaration`]のdoc）。1箇所にまとめてあるのは、
/// 引く場所が増えるたびに軸を1本落とす形の漏れを防ぐためである（B-05）。
fn matches(
    entry: &WorkspaceCapabilityEntry,
    workspace: &str,
    declaration: Option<&str>,
    mode: &str,
) -> bool {
    workspace_key(Path::new(&entry.workspace)) == workspace
        && entry.declaration.as_deref() == declaration
        && entry.mode == mode
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

/// 宣言（`--fs-allow`）のcapability名の接頭辞。workspace本体（[`CAPABILITY_NAME_PREFIX`]）と
/// **綴りを分ける**——台帳やACLを人が読んだとき、どちらの軸の主体かが名前だけで分かるようにする。
pub const DECLARATION_NAME_PREFIX: &str = "harnessDecl";

/// §22.2.0の導出鍵`(秘密, 畳み込み済みパス, access級)`を1つの名前へ畳む純粋関数。
///
/// # なぜ workspace 本体（[`capability_name_from_secret`]）と違ってハッシュなのか
///
/// あちらは秘密だけが入力なので可逆な連結でよい。こちらは**3つの入力を1つの名前へ
/// 畳む必要がある**——そしてそれは見た目の都合ではなく、**信頼境界の要求**である。
///
/// 昇格側（`privhelper`）は非特権の親から秘密を受け取り、`(その秘密, 自分で畳み込んだ
/// 書込先のパス, access級)`から主体を導出する（§22.3.1）。パスが導出入力に入っているから、
/// **宣言Aの秘密を使って別のパスBへAの主体を付けさせることができない**。名前が秘密だけから
/// 決まる形だと、この束縛は成立せず「秘密を1つ持てば任意のパスへその主体を書かせられる」
/// ——現行のpackage SID方式が持っていない束縛を新たに得る、という§22.3.1の表の3行目が
/// 成り立たなくなる。
///
/// 入力は**長さを前置してから**連結する。区切り文字だけで繋ぐと、`("ab","c")`と`("a","bc")`が
/// 同じバイト列になる組み合わせを作れてしまう（境界をまたぐ入力を1つの鍵へ畳むときの定石）。
///
/// 秘密は**16進表現のまま**受け取る。台帳にもワイヤにもこの形で載っているので、
/// 両側で`hex→bytes`の変換を挟まない——変換が2箇所にあると、片方だけが失敗したときに
/// 「同じ秘密なのに別の主体」という最も気付きにくい形でずれる。
///
/// 出力はSHA-256の**先頭128bit**。D-54が秘密に要求したのと同じ強度で、名前も短く保てる。
pub fn declaration_capability_name(
    secret_hex: &str,
    folded_path: &str,
    access_class: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // 用途を混ぜないための領域分離（同じ秘密を別の目的へ流用したときに同じ名前が出ない）。
    hasher.update(b"harness/fs-allow-capability/v1");
    for field in [secret_hex, folded_path, access_class] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    format!("{DECLARATION_NAME_PREFIX}{}", to_hex(&digest[..SECRET_LEN]))
}

/// harnessが発行した宣言capability名の形か（[`is_workspace_capability_name`]の宣言版）。
pub fn is_declaration_capability_name(name: &str) -> bool {
    let Some(hex) = name.strip_prefix(DECLARATION_NAME_PREFIX) else {
        return false;
    };
    hex.len() == SECRET_LEN * 2 && hex.chars().all(|c| c.is_ascii_hexdigit())
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
    ensure_name_in(ledger, workspace, None, mode).map(|c| c.capability_name)
}

/// workspace本体（`declaration == None`）と宣言（`Some`）の**両方**が通る発行の実体。
///
/// 秘密の生成と台帳への追記を1つにしてあるのは、**片方だけ別の書き方をすると
/// 「宣言の秘密だけ弱い乱数から作る」形の劣化が起こり得る**ためである
/// （[`generate_secret`]はCSPRNGが使えなければ`Err`を返し、弱い乱数へ退避しない）。
fn ensure_name_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    declaration: Option<&str>,
    mode: &str,
) -> Result<DeclarationCapability, String> {
    let key = workspace_key(workspace);
    ledger.update(|l| {
        if let Some(entry) = l
            .entries
            .iter()
            .find(|e| matches(e, &key, declaration, mode))
        {
            return Ok(DeclarationCapability {
                secret_hex: entry.secret_hex.clone(),
                capability_name: entry.capability_name.clone(),
            });
        }
        let secret = generate_secret()?;
        let secret_hex = to_hex(&secret);
        // **名前の作り方は軸で違う**（[`declaration_capability_name`]のdoc）。workspace本体は
        // 秘密だけから、宣言は`(秘密, 畳み込み済みパス, access級)`から決まる。
        let name = match declaration {
            None => capability_name_from_secret(&secret),
            Some(declared) => declaration_capability_name(&secret_hex, declared, mode),
        };
        l.entries.push(WorkspaceCapabilityEntry {
            workspace: workspace.to_string_lossy().into_owned(),
            declaration: declaration.map(|d| d.to_string()),
            mode: mode.to_string(),
            secret_hex: secret_hex.clone(),
            capability_name: name.clone(),
            granted_at_unix_secs: now_unix_secs(),
            // 宣言エントリはツリーの救済walkを持たない（対象は宣言されたパスだけで、
            // workspaceのような26万ノードの木ではない）ので、この2欄は`None`のまま使わない。
            tree_verified_at_unix_secs: None,
            root_file_id: None,
            preparation_started_at_unix_secs: None,
            preparation_root_file_id: None,
            preparation_failed_at_unix_secs: None,
            preparation_error: None,
        });
        Ok(DeclarationCapability {
            secret_hex,
            capability_name: name,
        })
    })
}

/// 宣言1件の主体と、その**導出の前像**。
///
/// `secret_hex`が要るのは昇格側へ渡す経路だけである（§22.3.1: SIDではなく秘密を渡し、
/// 受信側が書込先のパスを自分で畳み込んで導出する）。**それ以外の場所へ持ち出さないこと**
/// ——とくにログ・エラーメッセージ・台帳以外のファイルへ出さない。
#[derive(Debug, Clone, PartialEq)]
pub struct DeclarationCapability {
    pub secret_hex: String,
    pub capability_name: String,
}

/// `workspace`が宣言した`declared_path`（`--fs-allow`の1件）＋`access_class`の主体の名前。
/// 初回は秘密を生成して台帳へ記録し、2回目以降は同じ名前を返す（冪等）。
///
/// **これが§22.2.0の導出鍵`(秘密, 畳み込み済みパス, access級)`の実体である。** 秘密は
/// workspace＋宣言ごとに1つで、同じ宣言をする複数のドメインは同じ名前＝同じSIDを共有する
/// ——ACEの本数が「宣言の種類数」で止まり、ドメイン数倍にならないのはこのためである（§22.3.3）。
fn ensure_declaration_capability_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    declared_path: &Path,
    access_class: &str,
) -> Result<DeclarationCapability, String> {
    let declaration = declaration_key(declared_path);
    ensure_name_in(ledger, workspace, Some(&declaration), access_class)
}

/// [`ensure_declaration_capability_in`]の製品用（`%APPDATA%`の台帳）。
///
/// **秘密まで返すのは、昇格側へ渡す経路が要求するからである**（§22.3.1）。名前だけで足りる
/// 呼び出しは[`ensure_declaration_capability_name`]を使い、秘密を持ち回さないこと。
pub fn ensure_declaration_capability(
    workspace: &Path,
    declared_path: &Path,
    access_class: &str,
) -> Result<DeclarationCapability, String> {
    ensure_declaration_capability_in(&ledger(), workspace, declared_path, access_class)
}

/// [`ensure_declaration_capability_name`]の**発行しない版**（workspace本体に対する
/// [`lookup_capability_name`]と同じ関係）。まだ発行されていなければ`None`。
///
/// **3つの軸（workspace・宣言パス・access級）で絞る。** パスだけで引く
/// [`declaration_capability_names`]と使い分けること——あちらは「このパスへ発行した主体を
/// **全部**」剥がす撤収の索引で、こちらは「**この級の**主体1つ」を名指しする用である。
/// 級を落として引くと、子のトークンへ**宣言より広い主体**を積む形になる。
pub fn lookup_declaration_capability_name(
    workspace: &Path,
    declared_path: &Path,
    access_class: &str,
) -> Option<String> {
    lookup_declaration_capability_name_in(&ledger(), workspace, declared_path, access_class)
}

fn lookup_declaration_capability_name_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    declared_path: &Path,
    access_class: &str,
) -> Option<String> {
    let key = workspace_key(workspace);
    let declaration = declaration_key(declared_path);
    ledger
        .load()
        .entries
        .into_iter()
        .find(|e| matches(e, &key, Some(declaration.as_str()), access_class))
        .map(|e| e.capability_name)
}

/// 名前だけが要る呼び出し（本体プロセス内での付与・撤収）用。
pub fn ensure_declaration_capability_name(
    workspace: &Path,
    declared_path: &Path,
    access_class: &str,
) -> Result<String, String> {
    ensure_declaration_capability(workspace, declared_path, access_class)
        .map(|c| c.capability_name)
}

/// テスト用の薄い包み（既存テストが名前だけを見ているため）。
#[cfg(test)]
fn ensure_declaration_capability_name_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    declared_path: &Path,
    access_class: &str,
) -> Result<String, String> {
    ensure_declaration_capability_in(ledger, workspace, declared_path, access_class)
        .map(|c| c.capability_name)
}

fn declaration_capability_names_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<String> {
    let declaration = declaration_key(declared_path);
    let workspace_filter = workspace.map(workspace_key);
    ledger
        .load()
        .entries
        .into_iter()
        .filter(|e| e.declaration.as_deref() == Some(declaration.as_str()))
        .filter(|e| match &workspace_filter {
            Some(key) => &workspace_key(Path::new(&e.workspace)) == key,
            None => true,
        })
        .map(|e| e.capability_name)
        .collect()
}

/// `declared_path`宛に発行済みの宣言capability名を引く（**生成はしない**）。
///
/// **これが§22.2.1の「分類器を使わず、宣言から導出したSIDを名指しで剥がす」の索引である。**
/// ACLを列挙して「この主体は何者か」を推定する必要がそもそも無い——撤収すべき主体は
/// 宣言から一意に決まるので、台帳はその対応表を持つだけでよい。
///
/// `workspace`が`Some`ならそのworkspaceが発行したものだけに絞る。**絞らない側
/// （`None`）を使ってよいのは、そのパスを名指しした明示操作（`harness fs revoke <path>`）
/// だけである**——他のworkspaceの主体まで剥がすので、暗黙の経路から呼ぶと
/// [BUG-046](../../../docs/bugs/BUG-046.md)（他人の使っているACEを純減させる）と同じ形になる。
pub fn declaration_capability_names(
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<String> {
    declaration_capability_names_in(&ledger(), declared_path, workspace)
}

/// `declared_path`宛に発行済みの宣言capabilityを、**発行元のworkspaceつきで**引く
/// （`(workspaceのパス, capability名)`）。
///
/// [`declaration_capability_names`]との違いは発行元が付くことだけである。撤収側が
/// 「この主体を**まだ使っているharnessが走っていないか**」を問うのに要る——主体は
/// workspace単位で共有されるので、判定の単位もworkspaceになる
/// （生存判定そのものは[`crate::tier2a::workspace_ledger::live_modes`]が持つ既存の門で、
/// ここでは持たない）。
pub fn declaration_capability_issuers(declared_path: &Path) -> Vec<(String, String)> {
    let declaration = declaration_key(declared_path);
    ledger()
        .load()
        .entries
        .into_iter()
        .filter(|e| e.declaration.as_deref() == Some(declaration.as_str()))
        .map(|e| (e.workspace, e.capability_name))
        .collect()
}

/// `declared_path`宛に発行済みの宣言capabilityの**導出の前像**（`(秘密, access級)`）。
///
/// # ここだけが秘密を台帳の外へ出す（撤収側）
///
/// **昇格側へ委譲する撤収経路のためだけに在る。** §22.3.1が「SIDでも名前でもなく秘密を渡し、
/// 受信側が自分で畳み込んだパスから導出する」と決めたので、撤収も付与と同じものを渡す必要が
/// ある。付与側の入口は[`ensure_declaration_capability`]で、そちらは**発行もする**——
/// 撤収で発行してしまうと「剥がしに来た関数が資源を作る」ことになる（`B-01`）ので、
/// こちらは引くだけである。
///
/// **呼ぶ場所を増やさないこと。** 秘密は持ち回った先ぶんだけログ・エラー文へ載る面が増える。
/// 名前だけで足りる経路（本体プロセス内の撤収）は[`declaration_capability_names`]を使う。
///
/// `workspace`の絞り込みの意味は[`declaration_capability_names`]と同じ。
pub fn declaration_capability_preimages(
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<(String, String)> {
    declaration_capability_preimages_in(&ledger(), declared_path, workspace)
}

fn declaration_capability_preimages_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<(String, String)> {
    let declaration = declaration_key(declared_path);
    let workspace_filter = workspace.map(workspace_key);
    ledger
        .load()
        .entries
        .into_iter()
        .filter(|e| e.declaration.as_deref() == Some(declaration.as_str()))
        .filter(|e| match &workspace_filter {
            Some(key) => &workspace_key(Path::new(&e.workspace)) == key,
            None => true,
        })
        .map(|e| (e.secret_hex, e.mode))
        .collect()
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
        .find(|e| matches(e, &key, None, mode))
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
            .find(|e| matches(e, &key, None, mode))
        {
            entry.tree_verified_at_unix_secs = Some(now);
            entry.root_file_id = identity.clone();
            entry.preparation_started_at_unix_secs = None;
            entry.preparation_root_file_id = None;
            entry.preparation_failed_at_unix_secs = None;
            entry.preparation_error = None;
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

fn mark_tree_preparing_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
) {
    let key = workspace_key(workspace);
    let identity = root_identity(workspace);
    let now = now_unix_secs();
    ledger.update(|l| {
        if let Some(entry) = l
            .entries
            .iter_mut()
            .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
        {
            entry.preparation_started_at_unix_secs = Some(now);
            entry.preparation_root_file_id = identity.clone();
            entry.preparation_failed_at_unix_secs = None;
            entry.preparation_error = None;
        }
    });
}

/// 背景ジョブを登録した直後に`preparing`を永続化する。
pub fn mark_tree_preparing(workspace: &Path, mode: &str) {
    mark_tree_preparing_in(&ledger(), workspace, mode);
}

fn mark_tree_preparation_failed_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
    error: &str,
) {
    let key = workspace_key(workspace);
    let now = now_unix_secs();
    ledger.update(|l| {
        if let Some(entry) = l
            .entries
            .iter_mut()
            .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
        {
            entry.preparation_failed_at_unix_secs = Some(now);
            entry.preparation_error = Some(error.to_string());
        }
    });
}

/// 背景ジョブの失敗理由を、次回の準備開始まで表示できるよう永続化する。
pub fn mark_tree_preparation_failed(workspace: &Path, mode: &str, error: &str) {
    mark_tree_preparation_failed_in(&ledger(), workspace, mode, error);
}

fn recorded_workspace_preparation_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    workspace: &Path,
    mode: &str,
) -> RecordedWorkspacePreparation {
    let key = workspace_key(workspace);
    let current_identity = root_identity(workspace);
    let Some(entry) = ledger
        .load()
        .entries
        .into_iter()
        .find(|e| workspace_key(Path::new(&e.workspace)) == key && e.mode == mode)
    else {
        return RecordedWorkspacePreparation::None;
    };
    if entry.preparation_started_at_unix_secs.is_none()
        || entry.preparation_root_file_id != current_identity
    {
        return RecordedWorkspacePreparation::None;
    }
    match entry.preparation_error {
        Some(error) => RecordedWorkspacePreparation::Failed(error),
        None => RecordedWorkspacePreparation::Preparing,
    }
}

/// 現在のrootに対して台帳へ記録された準備状態。生存判定は呼び出し側がmode mutexで行う。
pub fn recorded_workspace_preparation(
    workspace: &Path,
    mode: &str,
) -> RecordedWorkspacePreparation {
    recorded_workspace_preparation_in(&ledger(), workspace, mode)
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
        .find(|e| matches(e, &key, None, mode))
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
            // `mode`が空＝「このworkspaceの主体を全部」。**宣言エントリもここに入る**
            // ——§22.2.1が「秘密の台帳を失った場合の保険」として`fs revoke-workspace`に
            // 群SIDまで剥がさせると決めており、扉を増やさないためにこの1本が担う。
            // `mode`を指定した場合はworkspace本体だけ（宣言の`mode`はaccess級という
            // 別の語彙なので、値が偶然一致しても巻き込まない）。
            let hit = workspace_key(Path::new(&e.workspace)) == key
                && if mode.is_empty() {
                    true
                } else {
                    e.declaration.is_none() && e.mode == mode
                };
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

impl WorkspaceCapabilityEntry {
    /// 人へ見せる1行の名札。**秘密も名前も含めない**——この文字列は
    /// [`prune_capability_entries`]の戻り値としてCLIの報告へそのまま出る。
    ///
    /// workspace本体は従来どおりworkspaceのパスだけ。宣言エントリは**どのパスの許可か**が
    /// 主語なので、宣言パスを先に置いて発行元のworkspaceを添える（workspaceだけを出すと、
    /// 「消えた記録が何の許可だったか」が報告から分からない）。
    pub fn display_label(&self) -> String {
        match &self.declaration {
            None => self.workspace.clone(),
            Some(declared) => format!("{declared} (declared by {})", self.workspace),
        }
    }

    /// **このエントリの記録を捨ててよいかを判定するとき、実在を測るべきパス。**
    ///
    /// workspace本体の主体のACEはworkspaceツリーそのものに載るが、宣言（`--fs-allow`）の
    /// 主体のACEは**workspaceの外の宣言パス**に載る。したがって「もう撤収すべきものが無い」と
    /// 言える条件はエントリの種類で違い、**workspaceの実在で一律に判定すると、
    /// 宣言先が生きているのに剥がすための名前だけを捨てることになる**（`B-01`）。
    ///
    /// 判定そのもの（実在するか・ボリュームへ到達できるか）は呼び出し側が持つ。ここは
    /// **どのパスを見るか**だけを1箇所で決める——測る側と落とす側で別々に書くと、
    /// 片方だけ更新されて静かにずれる（`B-05`）。
    ///
    /// **綴りは必ず畳んで返す**（[`workspace_key`]/[`declaration_key`]と同じ規則）。
    /// 台帳の中では`workspace`が生のパス・`declaration`が畳み込み済みキーという非対称が
    /// あり、素のまま返すと**エントリの種類によって綴りの規則が違う文字列**が出てくる。
    /// 突き合わせに使う値なので、ここで揃えておかないと「同じパスなのに一致しない」形の
    /// 取り違えが呼び出し側に生まれる（`B-19`: 畳み込みは境界で1度だけ）。
    /// 人へ見せる綴りが要るときは[`Self::display_label`]を使うこと。
    pub fn prune_target(&self) -> String {
        match &self.declaration {
            Some(declared) => declared.clone(),
            None => workspace_key(Path::new(&self.workspace)),
        }
    }
}

fn prune_capability_entries_in(
    ledger: &Ledger<WorkspaceCapabilityLedger>,
    should_remove: &dyn Fn(&WorkspaceCapabilityEntry) -> bool,
) -> Vec<String> {
    ledger.update(|l| {
        let mut removed = Vec::new();
        l.entries.retain(|e| {
            if should_remove(e) {
                removed.push(e.display_label());
                false
            } else {
                true
            }
        });
        removed
    })
}

/// `should_remove`がtrueを返したエントリを落とす（`harness fs prune`、D-53、および
/// §22.2.1の「宣言が消えたときの差分撤収」の後始末）。
///
/// # 述語がエントリ全体を受け取る理由
///
/// **workspaceのパスだけでは、本体エントリと宣言エントリを呼び出し側で区別できない。**
/// 宣言エントリ（`declaration`が`Some`）が指すACEは**workspaceの外の宣言パス**に載っている
/// ので、判定に使うべき対象がそもそも違う——workspaceが消えたことは、そのACEが消えたことを
/// 意味しない。ここを`&Path`（workspace）のままにしておくと、**剥がすための名前だけが先に
/// 消える**＝孤児ACEが確定する。
///
/// **記録を捨ててよいのは、それが指すACEがもう無いと確かめられたときだけである**
/// （`B-01`「名前で到達する設計では、名前を捨てる操作を最後に置く」）。判定は呼び出し側が持つ。
pub fn prune_capability_entries(
    should_remove: impl Fn(&WorkspaceCapabilityEntry) -> bool,
) -> Vec<String> {
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

    // --- 宣言（`--fs-allow`）の主体、§22.2.0「群 = 宣言1件」 ---

    /// **§22.3.1が昇格側に要求する束縛そのもの。** 同じ秘密でも、書込先のパスや access級が
    /// 違えば別の名前になる——だから昇格側は「宣言Aの秘密を使って別のパスBへAの主体を
    /// 付ける」ことができない。ここが秘密だけの関数に戻ると、その束縛は無言で消える。
    #[test]
    fn the_declaration_name_is_bound_to_the_path_and_the_access_class() {
        let secret = "00112233445566778899aabbccddeeff";
        let base = declaration_capability_name(secret, r"c:\tools\node", "read");
        assert_ne!(
            base,
            declaration_capability_name(secret, r"c:\tools\other", "read"),
            "パスが導出に入っていない"
        );
        assert_ne!(
            base,
            declaration_capability_name(secret, r"c:\tools\node", "read_write"),
            "access級が導出に入っていない"
        );
        assert_ne!(
            base,
            declaration_capability_name("ffeeddccbbaa99887766554433221100", r"c:\tools\node", "read"),
            "秘密が導出に入っていない"
        );
        assert!(is_declaration_capability_name(&base), "{base}");
        // workspace本体の名前と取り違えない（接頭辞で見分けられる）。
        assert!(!is_workspace_capability_name(&base));
        assert!(!is_declaration_capability_name(&capability_name_from_secret(
            &[0u8; SECRET_LEN]
        )));
    }

    /// 長さ前置が効いていること。区切りだけで繋ぐと、境界をずらした別の組が同じ
    /// バイト列になり**別の宣言が同じ主体を共有する**。
    #[test]
    fn shifting_the_boundary_between_inputs_does_not_collide() {
        let secret = "00112233445566778899aabbccddeeff";
        assert_ne!(
            declaration_capability_name(secret, r"c:\ab", "read"),
            declaration_capability_name(secret, r"c:\a", "bread"),
        );
    }

    /// §22.2.0の核: 同じ宣言をするドメインは**何もしなくても同じSIDを共有する**。
    /// ここが壊れると、宣言のたびに別のACEが同じノードへ積まれる（§22.3.3の費用の前提が崩れる）。
    #[test]
    fn the_same_declaration_always_gets_the_same_name() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let decl = Path::new("C:\\tools\\node");
        let a = ensure_declaration_capability_name_in(&l, ws, decl, "read").unwrap();
        let b = ensure_declaration_capability_name_in(&l, ws, decl, "read").unwrap();
        assert_eq!(a, b);
        assert_eq!(l.load().entries.len(), 1);
    }

    /// access級が違えば別の主体（`read`で開けた穴が`read_write`のドメインへ渡らない）。
    #[test]
    fn a_different_access_class_gets_a_different_declaration_capability() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let decl = Path::new("C:\\tools\\node");
        let ro = ensure_declaration_capability_name_in(&l, ws, decl, "read").unwrap();
        let rw = ensure_declaration_capability_name_in(&l, ws, decl, "read_write").unwrap();
        assert_ne!(ro, rw);
        assert_eq!(l.load().entries.len(), 2);
    }

    /// 宣言パスが違えば別の主体（宣言していないパスへ、別の宣言の主体で届かない）。
    /// §22.3.0.2の受け入れ条件2「宣言したドメインだけがパスを見る」の土台。
    #[test]
    fn a_different_declared_path_gets_a_different_capability() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let a =
            ensure_declaration_capability_name_in(&l, ws, Path::new("C:\\tools\\a"), "read").unwrap();
        let b =
            ensure_declaration_capability_name_in(&l, ws, Path::new("C:\\tools\\b"), "read").unwrap();
        assert_ne!(a, b);
    }

    /// 宣言パスの綴り揺れで別エントリを作らない。作ると**同じノードへ2つの主体のACEを撒く**
    /// （§22.2.0が畳み込み関数を必ず通せと書いている理由そのもの）。
    #[test]
    fn declaration_spelling_differences_do_not_create_a_second_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let a = ensure_declaration_capability_name_in(&l, ws, Path::new("C:\\Tools\\Node"), "read")
            .unwrap();
        let b = ensure_declaration_capability_name_in(&l, ws, Path::new("c:/tools/node"), "read")
            .unwrap();
        let c =
            ensure_declaration_capability_name_in(&l, ws, Path::new(r"\\?\C:\tools\node"), "read")
                .unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(l.load().entries.len(), 1);
    }

    /// **workspace本体の主体と宣言の主体が互いを潰さない。** `declaration`を突合から
    /// 落とすと、`workspace_capability_sid`が宣言用の主体を返し、26万ノードのツリー全体へ
    /// 宣言用のACEを撒くことになる。
    #[test]
    fn a_declaration_entry_is_never_returned_as_the_workspace_subject() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        // 宣言を**先に**登録する（後勝ちで隠れるのではなく、そもそも別軸であることを見る）。
        let decl = ensure_declaration_capability_name_in(&l, ws, Path::new("C:\\tools\\node"), "rwx")
            .unwrap();
        let body = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        assert_ne!(decl, body);
        assert_eq!(lookup_capability_name_in(&l, ws, "rwx").as_deref(), Some(body.as_str()));
        // 逆向きも見る: workspace本体を引いても宣言の索引には出ない。
        assert_eq!(
            declaration_capability_names_in(&l, Path::new("C:\\tools\\node"), Some(ws)),
            vec![decl]
        );
    }

    /// 撤収の索引（§22.2.1「宣言から導出したSIDを名指しで剥がす」）。
    /// workspaceで絞れること・絞らなければ全workspace分が出ることの両方を固定する。
    #[test]
    fn the_revocation_index_can_be_scoped_to_one_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let a = Path::new("C:\\work\\a");
        let b = Path::new("C:\\work\\b");
        let decl = Path::new("C:\\tools\\node");
        let from_a = ensure_declaration_capability_name_in(&l, a, decl, "read").unwrap();
        let from_b = ensure_declaration_capability_name_in(&l, b, decl, "read").unwrap();
        assert_ne!(from_a, from_b, "workspaceが違えば別の秘密＝別の主体");

        assert_eq!(declaration_capability_names_in(&l, decl, Some(a)), vec![from_a.clone()]);
        let all = declaration_capability_names_in(&l, decl, None);
        assert_eq!(all.len(), 2);
        assert!(all.contains(&from_a) && all.contains(&from_b));
        // 宣言されていないパスには何も出ない（空を返す＝剥がすものが無い）。
        assert!(declaration_capability_names_in(&l, Path::new("C:\\tools\\other"), None).is_empty());
    }

    /// §22.2.1の保険: `fs revoke-workspace`（＝`mode`が空）は**宣言の主体まで**落とす。
    /// 扉を増やさずに「秘密の台帳を失う前に全部剥がせる」を成立させているのがここ。
    #[test]
    fn forgetting_a_whole_workspace_also_drops_its_declaration_capabilities() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\repo");
        let body = ensure_capability_name_in(&l, ws, "rwx").unwrap();
        let decl = ensure_declaration_capability_name_in(&l, ws, Path::new("C:\\tools\\node"), "read")
            .unwrap();

        // モードを指定した撤収はworkspace本体だけ（宣言は残る）。
        assert_eq!(forget_capability_in(&l, ws, "rwx"), vec![body]);
        assert_eq!(l.load().entries.len(), 1);
        assert_eq!(l.load().entries[0].declaration.as_deref(), Some("c:\\tools\\node"));

        // 空モードは全部（宣言も）。
        assert_eq!(forget_capability_in(&l, ws, ""), vec![decl]);
        assert!(l.load().entries.is_empty());
    }

    /// **記録を捨ててよいかを測る対象は、エントリの種類で違う**（`B-01`/`B-14`）。
    ///
    /// 宣言（`--fs-allow`）の主体のACEは**workspaceの外の宣言パス**に載る。使い捨ての
    /// workspaceが消えても、宣言先（`C:\tools\node`のような常設のパス）にはACEが残るので、
    /// workspaceの実在だけで判定すると**剥がすための名前だけが先に消える**——その主体は
    /// どのコマンドでも剥がせない孤児になる。
    ///
    /// 許可側と禁止側を対で置く（`B-35`）: 宣言先が生きていれば残す／両方消えていれば落とす。
    #[test]
    fn a_declaration_entry_is_pruned_by_its_declared_path_not_by_its_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = Path::new("C:\\work\\throwaway");
        let alive = Path::new("C:\\tools\\node");
        let dead = Path::new("C:\\tools\\removed");
        ensure_capability_name_in(&l, ws, "rwx").unwrap();
        ensure_declaration_capability_name_in(&l, ws, alive, "read").unwrap();
        ensure_declaration_capability_name_in(&l, ws, dead, "read").unwrap();

        // 「見るべきパス」がエントリの種類で切り替わること（判定そのものは呼び出し側）。
        // 綴りはどちらも畳み込み済みで揃っている（台帳の中では`workspace`だけ生のパス）。
        let entries = l.load().entries;
        assert_eq!(entries[0].prune_target(), workspace_key(ws));
        assert_eq!(entries[1].prune_target(), declaration_key(alive));

        // workspaceが消えた、という判定でエントリを落とす（＝`fs prune`が旧実装でやっていた形）。
        // 宣言先が生きているエントリは**残らなければならない**。
        let ws_key = workspace_key(ws);
        let dead_key = declaration_key(dead);
        let removed = prune_capability_entries_in(&l, &|e| {
            // 「workspaceが消えた」と「宣言先が消えた」の両方を渡す実際の形。
            e.prune_target() == ws_key || e.prune_target() == dead_key
        });
        assert_eq!(removed.len(), 2, "{removed:?}");
        let left = l.load().entries;
        assert_eq!(left.len(), 1, "the still-declared path must keep its subject: {left:?}");
        assert_eq!(left[0].declaration.as_deref(), Some(declaration_key(alive).as_str()));

        // 名札は「何の許可の記録が消えたか」を出す（workspaceだけでは読み手に分からない）。
        // 突合に使う`prune_target`と違い、**人へ見せる綴りは台帳に入っているまま**である。
        assert!(
            removed
                .iter()
                .any(|r| r.contains("c:\\tools\\removed") && r.contains("C:\\work\\throwaway")),
            "{removed:?}"
        );
    }

    /// **台帳ごとに保存されている綴りが違うので、比べる前に必ず畳む。**
    ///
    /// workspace台帳と通行台帳は`\\?\C:\...`の**生のパス**を持ち、capability台帳は
    /// **畳み込み済みの鍵**を持つ。「このツリー配下か」を素の前方一致で書くと、`\\?\`が
    /// 付いている側だけ一致せず——**掃除したつもりで1件も落ちない**。
    ///
    /// 実際に `docs/bugs/BUG-140.md` の残骸を片付けるコードを書いたときこの形を踏みかけた
    /// （`docs/bugs/BUG-141.md`と同じ「黙って何もしない」）。片方向だけでなく**両方の綴りが
    /// 同じ鍵へ落ちること**を固定する。
    #[test]
    fn every_spelling_of_the_same_path_folds_to_one_key() {
        let folded = workspace_key(Path::new(r"C:\harness-fsallow-1\ws"));
        for spelling in [
            r"C:\harness-fsallow-1\ws",
            r"\\?\C:\harness-fsallow-1\ws",
            r"c:\HARNESS-fsallow-1\WS",
            "C:/harness-fsallow-1/ws",
            r"\\?\c:/harness-fsallow-1\ws",
        ] {
            assert_eq!(
                workspace_key(Path::new(spelling)),
                folded,
                "綴り {spelling:?} が別の鍵へ落ちた。前方一致で突き合わせる呼び出し側が黙って外れる"
            );
        }
        // **前方一致が成立すること**まで測る（鍵が揃うだけでは、根で絞る判定は守れない）。
        let root_key = workspace_key(Path::new(r"C:\harness-fsallow-1"));
        assert!(
            workspace_key(Path::new(r"\\?\C:\harness-fsallow-1\ws")).starts_with(&root_key),
            "生のパスを持つ台帳のエントリが、畳んだ根の前方一致に掛からない"
        );
    }

    /// 宣言エントリが混ざっても、workspace本体の「検証済み」判定は影響を受けない
    /// （宣言エントリは救済walkを持たないので`tree_verified_*`を使わない）。
    #[test]
    fn declaration_entries_do_not_disturb_the_workspace_verified_mark() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();
        mark_tree_verified_in(&l, &ws, "rwx");
        ensure_declaration_capability_name_in(&l, &ws, Path::new("C:\\tools\\node"), "read")
            .unwrap();
        assert!(tree_is_verified_in(&l, &ws, "rwx"));
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
                declaration: None,
                mode: "rwx".to_string(),
                secret_hex: "00".to_string(),
                capability_name: "harnessWs00".to_string(),
                granted_at_unix_secs: 1,
                tree_verified_at_unix_secs: Some(2),
                root_file_id: None,
                preparation_started_at_unix_secs: None,
                preparation_root_file_id: None,
                preparation_failed_at_unix_secs: None,
                preparation_error: None,
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

    #[test]
    fn preparation_state_is_persistent_and_scoped_to_the_root_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let l = test_ledger(tmp.path());
        let ws = tmp.path().join("repo");
        std::fs::create_dir(&ws).unwrap();
        ensure_capability_name_in(&l, &ws, "rwx").unwrap();

        assert_eq!(
            recorded_workspace_preparation_in(&l, &ws, "rwx"),
            RecordedWorkspacePreparation::None
        );
        mark_tree_preparing_in(&l, &ws, "rwx");
        assert_eq!(
            recorded_workspace_preparation_in(&l, &ws, "rwx"),
            RecordedWorkspacePreparation::Preparing
        );
        mark_tree_preparation_failed_in(&l, &ws, "rwx", "propagation failed");
        assert_eq!(
            recorded_workspace_preparation_in(&l, &ws, "rwx"),
            RecordedWorkspacePreparation::Failed("propagation failed".to_string())
        );

        std::fs::remove_dir(&ws).unwrap();
        std::fs::create_dir(&ws).unwrap();
        assert_eq!(
            recorded_workspace_preparation_in(&l, &ws, "rwx"),
            RecordedWorkspacePreparation::None,
            "an old failure must not describe a replacement root"
        );

        mark_tree_preparing_in(&l, &ws, "rwx");
        mark_tree_verified_in(&l, &ws, "rwx");
        assert!(tree_is_verified_in(&l, &ws, "rwx"));
        assert_eq!(
            recorded_workspace_preparation_in(&l, &ws, "rwx"),
            RecordedWorkspacePreparation::None,
            "successful verification clears the transient preparation state"
        );
    }
}
