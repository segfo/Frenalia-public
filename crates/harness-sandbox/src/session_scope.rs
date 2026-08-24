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

/// ワークスペースと同じボリュームへ差分層を置くときの、そのボリューム上の根の名前（D-81）。
///
/// ボリュームのルート直下に置く（`D:\.harness-cow\<session-id>`）。**ワークスペースの中では
/// ないことが要点**で、`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §9 が
/// 外配置を選んだ理由（再帰的なパスマッピングの防止・列挙から隠せる・Commit対象と差分領域の
/// 分離・相対パス衝突の回避・ACLの独立管理）は、この配置でも全部そのまま保たれる。
pub const PER_VOLUME_COW_DIRNAME: &str = ".harness-cow";

/// ユーザープロファイルのボリューム上にあるCoW差分層の根（`%LOCALAPPDATA%\harness\data\cow`）。
///
/// `data_local_dir()`は`%LOCALAPPDATA%\harness\data`で、台帳群が使う`config_dir()`
/// （`%APPDATA%\harness\config`）とは別系統。
///
/// **これは「唯一の根」ではない**（D-81）。ワークスペースが別のボリュームにあれば、差分層は
/// そちらの[`PER_VOLUME_COW_DIRNAME`]へ置かれる。棚卸しは[`cow_upper_roots`]で全部を掃くこと。
pub fn cow_profile_upper_root() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.data_local_dir().join("cow"))
}

/// 差分層の根をどこに取るかの計画（[`plan_cow_upper_root`]の答え）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CowUpperRootPlan {
    /// ワークスペースがプロファイルと同じボリュームにある。従来どおり`%LOCALAPPDATA%`。
    Profile,
    /// ワークスペースが別のボリュームにある。そのボリュームのルート直下へ置く。
    PerVolume(PathBuf),
    /// 別ボリュームだが、そこに根を置くべきではない。`%LOCALAPPDATA%`へ戻す（理由付き）。
    ProfileFallback(String),
}

/// 2つのボリュームのマウントポイントが同じものを指すか。
///
/// **ボリュームの同一判定はこの1関数だけが持つ**（`bug-pattern-rules` B-19: 同じ判断に
/// 規則が2つあると、片方だけ直って静かにずれる）。末尾の区切りの有無と大小文字を吸収する
/// ——`GetVolumePathNameW`は入力の綴りを引き継ぐので`d:\`と`D:\`が同じ実行の中で混ざり得る。
fn same_volume(a: &Path, b: &Path) -> bool {
    fn key(p: &Path) -> String {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_lowercase()
    }
    key(a) == key(b)
}

/// 差分層の根を決める**規則そのもの**（純関数。Win32もFSも触らない）。
///
/// ボリュームの採取は呼び出し側（[`cow_upper_root_for_workspace`]）が行う——採取と判定を
/// 分けてあるので、この規則は`cargo test`で普通に検算できる。
///
/// | ワークスペースのボリューム | 根 |
/// |---|---|
/// | プロファイルと同じ | [`CowUpperRootPlan::Profile`]（＝いままでと同じ場所） |
/// | それ以外 | [`CowUpperRootPlan::PerVolume`] |
///
/// **比べる相手は「システムドライブ」でも「`C:`」でもなく、`%LOCALAPPDATA%`が実際に
/// 載っているボリュームである。** ドライブ文字はこの関数のどこにも現れない——WindowsはD:や
/// Z:にも入るし、プロファイルだけ別ドライブへリダイレクトしている環境もあるので、
/// `C:`を特別扱いした瞬間にそれらの環境で置き場が狂う。
/// **「プロファイルのボリューム」を基準にするのは、そこが降格先の根が実際に在る場所だから**
/// である（システムドライブを基準にすると、プロファイルがD:でワークスペースもD:のとき
/// 「別ボリューム」と誤判定して、同じボリューム上に根を2つ作ってしまう）。
/// 採取は呼び出し側が`GetVolumePathNameW`で行う。
///
/// **ワークスペースがボリュームのルート自身なら`Err`**。その場合だけは差分層が
/// ワークスペースの**中**に入ってしまい、書込がまた差分層へ誘導される再帰と、
/// 読取専用にしたツリーの中に書込可能な穴を開けることの両方が起きる（§9が避けた形）。
pub fn plan_cow_upper_root(
    workspace_root: &Path,
    workspace_volume: &Path,
    profile_volume: &Path,
    workspace_volume_is_remote: bool,
) -> Result<CowUpperRootPlan, String> {
    if same_volume(workspace_root, workspace_volume) {
        return Err(format!(
            "--sandbox tier2a-cow: the workspace is a volume root ({}); the copy-on-write diff \
             area would have to live inside the workspace itself. Point --cwd at a subdirectory.",
            workspace_root.display()
        ));
    }
    if same_volume(workspace_volume, profile_volume) {
        return Ok(CowUpperRootPlan::Profile);
    }
    // **ネットワーク共有のルートに根を掘らない。** そこは他人と共有している場所であり、
    // そもそもCoWはリモートのボリューム上では成立しない（[`cow_volume_gate`]が後で拒否する）。
    // ここで作ってしまうと、**起動を拒否する直前に共有のルートへディレクトリを1つ残す**
    // ——置き場を決める側と境界を検算する側で順序が逆なので、ここでも止める必要がある。
    if workspace_volume_is_remote {
        return Ok(CowUpperRootPlan::ProfileFallback(format!(
            "{} is on a network location, so no diff area root is created there",
            workspace_volume.display()
        )));
    }
    Ok(CowUpperRootPlan::PerVolume(
        workspace_volume.join(PER_VOLUME_COW_DIRNAME),
    ))
}

/// [`cow_upper_root_for_workspace`]の答え。**降格したことを黙らせないために2値で返す**。
#[derive(Debug, Clone)]
pub struct CowUpperRoot {
    pub root: PathBuf,
    /// ワークスペースのボリューム上に根を作れず`%LOCALAPPDATA%`へ戻した理由。
    /// `Some`なら**呼び出し側は必ず表示する**（`bug-pattern-rules` B-09）。
    pub fell_back: Option<String>,
}

/// このワークスペース向けの差分層の根を決めて、使える状態にする（D-81）。
///
/// # なぜワークスペースのボリュームへ置くのか
///
/// 差分層はセッションが終わっても自動では消えない。ワークスペースが取り外せる媒体
/// （USB・外付け）にあると、媒体を抜いた時点でワークスペースは到達不能になる一方、
/// 差分層がプロファイル側（通常C:）に残る。台帳の掃除判定
/// （[`harness_grant_ledger::prune`]）は「本当に消えた」と「ボリュームへ到達できないだけ」を
/// 区別して後者は必ず残す側へ倒すので、**この形の差分層は永久に判定できず溜まり続ける**。
/// 同じボリュームに置けば媒体ごと消え、判定する対象がそもそも生まれない。
/// 容量も、ワークスペースを置いているデータ用ドライブの側へ付いていく。
///
/// # 根が作れないときは拒否ではなく降格する
///
/// ボリュームのルートへ書けない（権限が無い等）場合は`%LOCALAPPDATA%`へ戻し、理由を
/// [`CowUpperRoot::fell_back`]で返す。**これは境界の降格ではなく後片付けの降格**である
/// ——CoWの隔離（ワークスペースを読取専用にするACL）はどちらの置き場でも同じように張れて、
/// 失われるのは「媒体と一緒に消える」性質だけなので、隔離が取れないときは降格せず拒否する
/// というD-75の射程には入らない。
pub fn cow_upper_root_for_workspace(workspace_root: &Path) -> Result<CowUpperRoot, String> {
    let profile_root = cow_profile_upper_root().ok_or_else(|| {
        "--sandbox tier2a-cow: could not resolve %LOCALAPPDATA% for the CoW upper directory (is \
         HOME/USERPROFILE set?)"
            .to_string()
    })?;

    #[cfg(windows)]
    {
        let Some(workspace_volume) = crate::win_common::volume_mount_point_of(workspace_root)
        else {
            // どのボリュームか分からないなら、従来の置き場のままにする。**「同じボリューム」と
            // 決めつけない**——決めつけるとワークスペース側のルートに根を作ろうとして、
            // 見当違いの場所へディレクトリを生やす。
            return Ok(CowUpperRoot {
                root: profile_root,
                fell_back: Some(format!(
                    "could not determine which volume {} lives on; keeping the CoW diff area \
                     under %LOCALAPPDATA%",
                    workspace_root.display()
                )),
            });
        };
        let Some(profile_volume) = crate::win_common::volume_mount_point_of(&profile_root) else {
            return Ok(CowUpperRoot {
                root: profile_root,
                fell_back: Some(
                    "could not determine which volume %LOCALAPPDATA% lives on; keeping the CoW \
                     diff area there"
                        .to_string(),
                ),
            });
        };
        // ネットワーク越しかどうかは**置き場を決める前**に要る（`plan_cow_upper_root`のdoc）。
        // 採れなかったときは「リモートかもしれない」側＝根を作らない側へ倒す。
        let workspace_is_remote = crate::win_common::volume_capability(&workspace_volume)
            .map(|c| c.is_remote)
            .unwrap_or(true);
        match plan_cow_upper_root(
            workspace_root,
            &workspace_volume,
            &profile_volume,
            workspace_is_remote,
        )? {
            CowUpperRootPlan::Profile => Ok(CowUpperRoot {
                root: profile_root,
                fell_back: None,
            }),
            CowUpperRootPlan::ProfileFallback(reason) => Ok(CowUpperRoot {
                root: profile_root,
                fell_back: Some(reason),
            }),
            CowUpperRootPlan::PerVolume(root) => match std::fs::create_dir_all(&root) {
                Ok(()) => Ok(CowUpperRoot {
                    root,
                    fell_back: None,
                }),
                Err(e) => Ok(CowUpperRoot {
                    root: profile_root,
                    fell_back: Some(format!(
                        "could not create {} ({e}); keeping the CoW diff area under \
                         %LOCALAPPDATA%, which means it will NOT go away with the volume",
                        root.display()
                    )),
                }),
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = workspace_root;
        Ok(CowUpperRoot {
            root: profile_root,
            fell_back: None,
        })
    }
}

/// いま差分層が置かれ得る根を全部返す（棚卸し用。`harness cow list`/`gc`）。
///
/// D-81で根が1つではなくなったので、**列挙は必ずここを通す**——`%LOCALAPPDATA%`だけを見ると
/// 別ボリュームのセッションが「無いもの」として扱われ、`cow list`から消え、GCの対象にも
/// ならない（`bug-pattern-rules` B-05: 綴りを他所で組み立て直さない）。
///
/// 到達できないボリュームは黙って飛ばすのではなく、返り値の2つ目（件数）で数える。
/// 「0件だった」と「材料が見えていなかった」を呼び出し側が区別できるようにするため。
pub fn cow_upper_roots() -> (Vec<PathBuf>, usize) {
    let mut roots = Vec::new();
    let mut unreachable = 0usize;
    if let Some(profile) = cow_profile_upper_root() {
        roots.push(profile);
    }
    #[cfg(windows)]
    for drive in crate::win_common::logical_drive_roots() {
        let candidate = drive.join(PER_VOLUME_COW_DIRNAME);
        match std::fs::metadata(&candidate) {
            Ok(m) if m.is_dir() => {
                if !roots.iter().any(|r| same_volume(r, &candidate)) {
                    roots.push(candidate);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // 媒体が抜かれている・オフラインのネットワークドライブ。**在るとも無いとも言えない。**
            Err(_) => unreachable += 1,
        }
    }
    (roots, unreachable)
}

/// `root`（[`cow_upper_root_for_workspace`]や[`cow_upper_roots`]が返したもの）の下での、
/// あるセッションの差分層の位置。**この結合を他所で書かない**（B-05）。
pub fn cow_upper_dir_in(root: &Path, session_id: &str) -> PathBuf {
    root.join(session_id)
}

/// CoWの境界を張れるボリュームかを判定するための、そのボリュームの素の事実。
///
/// 採取は`crate::win_common::volume_capability`（Win32）、判定は[`cow_volume_gate`]（純関数）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeCapability {
    /// `FILE_PERSISTENT_ACLS`。ACLを永続化できるか。
    pub persistent_acls: bool,
    /// ファイルシステム名（`NTFS`・`exFAT`等）。拒否理由を人に名指しするために持つ。
    pub filesystem: String,
    /// ネットワーク越し（SMB等）か。
    pub is_remote: bool,
}

/// そのボリュームでCoWの境界を張れるかの検算（D-81）。**判定だけの純関数。**
///
/// # なぜ要るのか
///
/// CoWの境界はACLそのものである（D-30）——ワークスペースへ読取専用ACEを付け、差分層へ
/// 書込ACEを付ける。この2つが成立して初めて「フックが無効化されても書込は`ACCESS_DENIED`で
/// 止まる」（D-01: 境界はカーネル強制側に置き、Redirector DLLは境界にしない）が言える。
/// 検査が無かったため、隔離されていない状態で「隔離されている」とモデルへ宣言し得た
/// （[BUG-129](../../../docs/bugs/BUG-129.md)）。同じ形の穴をD-72が[BUG-113]で塞いでいる。
///
/// # 通さないものが3つある
///
/// 1. **ACLを保持できないボリューム**——FAT32・exFAT（USBメモリ・SDカードの既定）。
///    ACEを付ける先が無いので境界がゼロになる。
/// 2. **ネットワーク越しのボリューム**——SMB共有。こちらは**サーバ側がNTFSなら
///    `FILE_PERSISTENT_ACLS`を立てて返す**ので、ACLの有無だけを見ると通ってしまう。
///    しかしAppContainerのpackage SIDは**このマシンのローカルな主体**であり、
///    共有越しの相手にそのSIDを解決させることはできない。**ACEは書けたように見えて
///    何も強制しない。**
/// 3. **DACLの書込を実際には拒否するボリューム**——この開発機の`E:`（第三者製の暗号化
///    ファイルシステム`cryptoFs`）が実例。`FILE_PERSISTENT_ACLS`を立てて返し、ローカルで、
///    `WRITE_DAC`付きのハンドルも普通に開けるのに、**書き込む瞬間だけ`ACCESS_DENIED`を返す**
///    （実測、2026-08-24。内容を1ビットも変えない書き戻しすら通らない）。
///
/// **1と2はファイルシステムの自己申告に基づく判定である。** 申告どおりでない実装が現実に
/// 在る以上、最後は[`crate::win_common::can_write_dacl`]で**実際に書けることを確かめる**。
/// 3件とも別々の嘘だった、というのがこの関所の形である——「その機構が在るか」を問うAPIの
/// 答えは、「その機構が自分の使い方で効くか」を意味しない。
///
/// # 判定できないときは拒否へ倒す
///
/// `probe`が`None`（問い合わせ自体が失敗した）なら**拒否する**。ここはセキュリティ境界
/// そのものなので、`shared-state-exclusion` 問5の分岐は「閉じる」側である——境界が張れるか
/// 分からないまま張ったことにする方が危険で、能力が無いときは降格ではなく拒否するという
/// 上位原則（`docs/SECURITY-PRINCIPLES.md` P-05）にも従う。
pub fn cow_volume_gate(
    what: &str,
    path: &Path,
    probe: Option<VolumeCapability>,
    dacl_writable: Option<bool>,
) -> Result<(), String> {
    let Some(cap) = probe else {
        return Err(format!(
            "--sandbox tier2a-cow: could not determine whether the volume holding the {what} \
             ({}) can enforce an isolation boundary. Refusing to start rather than claim a \
             boundary that may not exist.",
            path.display()
        ));
    };
    if cap.is_remote {
        return Err(format!(
            "--sandbox tier2a-cow: the {what} ({}) is on a network location. Copy-on-write \
             isolation is enforced by ACLs granted to this machine's AppContainer package SID, \
             and a remote server cannot resolve that SID -- the ACEs would appear to be written \
             while enforcing nothing. Use a local volume, or pick a weaker isolation explicitly \
             with --sandbox.",
            path.display()
        ));
    }
    if !cap.persistent_acls {
        return Err(format!(
            "--sandbox tier2a-cow: the volume holding the {what} ({}) uses {}, which cannot \
             store ACLs. Copy-on-write isolation is enforced by ACLs (a read-only workspace \
             plus a writable diff area), so on this volume the boundary cannot be established \
             at all. Move the workspace to an NTFS volume, or pick a weaker isolation \
             explicitly with --sandbox.",
            path.display(),
            cap.filesystem
        ));
    }
    // **申告の最後は実測で裏を取る**（上のdoc「3」）。ここへ来た時点で
    // 「ACLを持てると言っていて、ローカルで」ある。それでも書けないことがある。
    if dacl_writable != Some(true) {
        return Err(format!(
            "--sandbox tier2a-cow: the {what} ({}) is on a {} volume that reports it can store              ACLs, but it rejected a no-op DACL write. Copy-on-write isolation cannot be              enforced where access rights cannot be written. Move the workspace to an NTFS              volume, or pick a weaker isolation explicitly with --sandbox.",
            path.display(),
            cap.filesystem
        ));
    }
    Ok(())
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeTemplate {
    /// マニフェスト方式。[`StagingMode::Live`]（オーバーレイ無し）もここに含む。
    Staging(StagingMode),
    /// CoW方式（D-30）。**`StagingMode`を持たない**——CoWのときステージングモードは必ず
    /// `Live`だからで、持たせないことが「CoWかつ`--staged`」を書けなくしている。
    ///
    /// **差分層の根を値として持つ**（D-81）。根はワークスペースのボリュームで決まるので
    /// もはや定数ではないが、ワークスペースはプロセス寿命で不変（起動時に1度だけ完全修飾化
    /// する、BUG-068）なので**根もプロセス寿命で不変**であり、モードと同じ場所に置ける。
    /// ここに持たせず`scope_for`が毎回ワークスペースから引き直す形にすると、
    /// **同じ根を2箇所で導出する**ことになり、片方だけ規則が変わったときに静かにずれる
    /// （`bug-pattern-rules` B-05）。
    Cow { upper_root: PathBuf },
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
            // 根は**起動時に実際に決まった差分層の親**から取る（D-81）。ワークスペースから
            // 導出し直さないのは、導出規則を2箇所に持たないためである（B-05）。
            crate::shell_tier::WorkspaceWriteMode::Cow { upper_dir } => ScopeTemplate::Cow {
                upper_root: upper_dir
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| upper_dir.clone()),
            },
            crate::shell_tier::WorkspaceWriteMode::DirectRw => ScopeTemplate::Staging(staging_mode),
        }
    }

    /// セッションIDからそのセッションのオーバーレイ位置を引く。
    ///
    /// CoWの根は[`ScopeTemplate::Cow`]が値として持っている（D-81）ので、ここでは結合するだけ
    /// ——`%LOCALAPPDATA%`が解決できない異常環境は**起動時に`resolve_staging_and_write_mode`が
    /// 拒否している**ため、テンプレートが`Cow`である時点で根は確定している。
    pub fn scope_for(&self, session_id: &str) -> SessionScope {
        let (staging, cow_upper_dir) = match self {
            ScopeTemplate::Cow { upper_root } => (
                StagingConfig {
                    // CoWのステージングモードは常に`Live`（マニフェスト方式との併用は拒否済み）。
                    mode: StagingMode::Live,
                    sandbox_dir: None,
                },
                Some(cow_upper_dir_in(upper_root, session_id)),
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

/// オーバーレイの実体を消す。**片付けの唯一の実行点**（[`prepare_scope`]の対）。
///
/// 呼ぶのは2箇所——`harness discard`（`SandboxFs::discard`）と、差分層のGC
/// （`tier2a::workspace_ledger::run_cow_gc`）。どちらも「もう要らないオーバーレイを消す」
/// という同じ操作なので、**削除経路を2つ持たない**（`bug-pattern-rules` B-05）。
///
/// GC側が`SandboxFs::discard`をそのまま呼べない理由も、ここへ集約する動機である——
/// あちらは`SandboxFs`を開く必要があり、**元のワークスペースが既に消えている差分層**
/// （実測で106件中59件）では開けない。回収の対象はまさにそういうものなので、
/// ワークスペースを要求しない形の入口が要る。
pub fn remove_overlay_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        // 既に無いのは目的が達成されている状態。呼び出し側に失敗として見せない。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

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

    // `--staged`（workspace内`.harness/sandbox/<id>`）は作るだけで終わり。**ACLは触らない**——
    // このオーバーレイを読み書きするのはharness自身のプロセスだけで、サンドボックスの子から
    // 見せる必要が無い（むしろ`.harness/`はD-05/D-09で子から隔離してある）。新しく作った
    // ディレクトリは保護済みの`.harness/`から継承するのでAppContainer宛ACEを持たない。
    #[cfg(windows)]
    if scope.cow_upper_dir.is_some() {
        // D-82: **実体を作ってから生存マーカーを確保するまでをGCのロックで囲む。**
        // この区間の差分層は「在るのに生きている印が無い」ので、並行して走る別の
        // `harness.exe`のGCからは空の殻に見える。`preflight`の起動経路にも同じ囲いがあり、
        // **両方に入れて初めて直列化が成立する**（片側だけでは何も守らない）。
        return harness_grant_ledger::with_named_lock(
            crate::tier2a::workspace_ledger::COW_GC_LOCK_NAME,
            || {
                create_overlay_dir(&dir)?;
                prepare_cow_upper(workspace_root, scope, &dir)
            },
        );
    }
    create_overlay_dir(&dir)?;
    Ok(1)
}

fn create_overlay_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| {
        format!(
            "could not create the overlay directory {}: {e}",
            dir.display()
        )
    })
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
        let root = cow_profile_upper_root().unwrap();
        let scope = ScopeTemplate::Cow {
            upper_root: root.clone(),
        }
        .scope_for("session-abc");
        assert_eq!(scope.staging.sandbox_dir, None);
        let upper = scope.cow_upper_dir.as_ref().unwrap();
        assert!(upper.ends_with("session-abc"), "{}", upper.display());
        assert!(upper.starts_with(&root));
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

    // --- 差分層の置き場の規則（D-81） ---

    fn vol(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    /// ワークスペースがプロファイルと同じボリュームなら、置き場は従来どおり。
    #[test]
    fn same_volume_as_the_profile_keeps_the_diff_area_where_it_was() {
        assert_eq!(
            plan_cow_upper_root(Path::new(r"C:\work\proj"), &vol(r"C:\"), &vol(r"C:\"), false).unwrap(),
            CowUpperRootPlan::Profile
        );
    }

    /// 別ボリュームなら、そのボリュームのルート直下へ置く。**ワークスペースの中ではない。**
    #[test]
    fn a_different_volume_gets_its_own_root_outside_the_workspace() {
        let plan =
            plan_cow_upper_root(Path::new(r"D:\work\proj"), &vol(r"D:\"), &vol(r"C:\"), false).unwrap();
        assert_eq!(
            plan,
            CowUpperRootPlan::PerVolume(vol(r"D:\").join(PER_VOLUME_COW_DIRNAME))
        );
        let CowUpperRootPlan::PerVolume(root) = plan else {
            unreachable!()
        };
        assert!(
            !root.starts_with(r"D:\work\proj"),
            "§9の外配置を崩してはいけない: {}",
            root.display()
        );
    }

    /// ドライブ文字を持たないマウント先でも同じ規則が効く（先頭2文字での判定にしていない）。
    #[test]
    fn a_volume_mounted_on_a_directory_is_treated_as_its_own_volume() {
        let plan = plan_cow_upper_root(
            Path::new(r"C:\mnt\data\proj"),
            &vol(r"C:\mnt\data\"),
            &vol(r"C:\"),
            false,
        )
        .unwrap();
        assert_eq!(
            plan,
            CowUpperRootPlan::PerVolume(vol(r"C:\mnt\data\").join(PER_VOLUME_COW_DIRNAME))
        );
    }

    /// **システムドライブを`C:`と決めつけない。** プロファイルがD:にある環境では、
    /// D:のワークスペースが「同じボリューム」側になる。Windowsは`D:`や`Z:`にも入るし、
    /// プロファイルだけを別ドライブへリダイレクトしている環境もある。
    #[test]
    fn the_profile_volume_is_whatever_the_api_says_it_is_not_c() {
        // プロファイルがD:、ワークスペースもD: → 従来の置き場（プロファイル側）。
        assert_eq!(
            plan_cow_upper_root(Path::new(r"D:\work\proj"), &vol(r"D:\"), &vol(r"D:\"), false).unwrap(),
            CowUpperRootPlan::Profile
        );
        // プロファイルがD:、ワークスペースがC: → **C:の方が「別ボリューム」側になる。**
        // ここが`Profile`になる実装は、システムドライブをC:と決め打っている証拠である。
        assert_eq!(
            plan_cow_upper_root(Path::new(r"C:\work\proj"), &vol(r"C:\"), &vol(r"D:\"), false).unwrap(),
            CowUpperRootPlan::PerVolume(vol(r"C:\").join(PER_VOLUME_COW_DIRNAME))
        );
        // プロファイルがZ:でも同じ規則が効く（ドライブ文字に意味を持たせていないこと）。
        assert_eq!(
            plan_cow_upper_root(Path::new(r"Z:\work\proj"), &vol(r"Z:\"), &vol(r"Z:\"), false).unwrap(),
            CowUpperRootPlan::Profile
        );
    }

    /// 末尾の区切りと大小文字の揺れで「別ボリューム」と誤判定しない（B-19）。
    #[test]
    fn volume_comparison_ignores_case_and_a_trailing_separator() {
        assert_eq!(
            plan_cow_upper_root(Path::new(r"c:\work\proj"), &vol(r"c:"), &vol(r"C:\"), false).unwrap(),
            CowUpperRootPlan::Profile
        );
    }

    /// **拒否側**: ワークスペースがボリュームのルート自身なら起動できない。
    /// ここを通すと差分層がワークスペースの中に入り、再帰と読取専用ツリーの穴が同時に生じる。
    #[test]
    fn a_workspace_that_is_a_volume_root_is_rejected() {
        let err = plan_cow_upper_root(Path::new(r"D:\"), &vol(r"D:\"), &vol(r"C:\"), false)
            .expect_err("the diff area would have to live inside the workspace");
        assert!(err.contains("volume root"), "理由を名指しすること: {err}");
    }

    // --- ボリュームがACLを保持できるかの検問（D-81 / Part B） ---

    fn cap(persistent_acls: bool, filesystem: &str, is_remote: bool) -> VolumeCapability {
        VolumeCapability {
            persistent_acls,
            filesystem: filesystem.to_string(),
            is_remote,
        }
    }

    /// **許可側**（拒否側と対で測る、`test-logic-rules`）。ローカルのNTFSは通る。
    #[test]
    fn a_local_volume_that_stores_acls_passes_the_gate() {
        assert!(cow_volume_gate(
            "workspace",
            Path::new(r"C:\ws"),
            Some(cap(true, "NTFS", false)),
            Some(true)
        )
        .is_ok());
    }

    /// **拒否側**: ACLを持てないボリュームでは境界そのものが張れないので起動を拒否する。
    #[test]
    fn a_volume_without_acls_is_refused_and_the_filesystem_is_named() {
        let err = cow_volume_gate(
            "workspace",
            Path::new(r"X:\ws"),
            Some(cap(false, "exFAT", false)),
            Some(true),
        )
        .expect_err("copy-on-write isolation is enforced by ACLs");
        assert!(err.contains("exFAT"), "打つ手が分かるように名指しする: {err}");
    }

    /// **拒否側（ACLは在るのに拒否する唯一のケース）**: ネットワーク共有は
    /// サーバがNTFSなら`FILE_PERSISTENT_ACLS`を立てて返すが、AppContainerのpackage SIDは
    /// ローカルの主体なので**ACEは書けたように見えて何も強制しない**。
    /// ACLフラグだけを見る実装だとここが通ってしまう。
    #[test]
    fn a_network_volume_is_refused_even_though_it_reports_persistent_acls() {
        let err = cow_volume_gate(
            "workspace",
            Path::new(r"\server\share\ws"),
            Some(cap(true, "NTFS", true)),
            Some(true),
        )
        .expect_err("a remote server cannot resolve this machine's AppContainer SID");
        assert!(
            err.contains("network"),
            "なぜ通らないのかが分かる文言にする: {err}"
        );
    }

    /// **判定不能はセキュリティ境界なので閉じる側へ倒す**（`shared-state-exclusion` 問5）。
    /// ここが`Ok`へ倒れると、境界が張れているか分からないまま「隔離した」と宣言してしまう。
    #[test]
    fn an_unprobeable_volume_is_refused_rather_than_assumed_capable() {
        assert!(cow_volume_gate("workspace", Path::new(r"X:\ws"), None, Some(true)).is_err());
    }

    /// **申告どおりでないボリュームを実測で弾く。** この開発機の`E:`（`cryptoFs`）が実例で、
    /// ACLを保持できると申告し、ローカルで、`WRITE_DAC`付きのハンドルも開けるのに、
    /// **DACLを書き込む瞬間だけ拒否する**。ここが無いと境界ゼロのまま起動を試みる。
    #[test]
    fn a_volume_that_reports_acls_but_rejects_dacl_writes_is_refused() {
        let err = cow_volume_gate(
            "workspace",
            Path::new(r"E:\ws"),
            Some(cap(true, "cryptoFs", false)),
            Some(false),
        )
        .expect_err("a volume that cannot accept a DACL write cannot enforce the boundary");
        assert!(
            err.contains("cryptoFs") && err.contains("DACL"),
            "何が起きたかが分かる文言にする: {err}"
        );
    }

    /// 実測そのものができなかった場合も拒否側へ倒す（判定不能は閉じる）。
    #[test]
    fn an_unprobeable_dacl_write_is_refused_too() {
        assert!(cow_volume_gate(
            "workspace",
            Path::new(r"E:\ws"),
            Some(cap(true, "NTFS", false)),
            None
        )
        .is_err());
    }

    /// ネットワーク共有のルートに差分層の根を掘らない。**起動を拒否する直前に
    /// 共有のルートへディレクトリを1つ残す**のを防ぐ（置き場を決める側と検算側で順序が逆）。
    #[test]
    fn a_network_workspace_never_gets_a_diff_area_root_on_the_share() {
        let plan = plan_cow_upper_root(
            Path::new(r"\server\share\proj"),
            &vol(r"\server\share\"),
            &vol(r"C:\"),
            true,
        )
        .unwrap();
        assert!(
            matches!(plan, CowUpperRootPlan::ProfileFallback(_)),
            "共有のルートに根を作ってはいけない: {plan:?}"
        );
    }
}

#[cfg(all(test, windows))]
mod volume_diagnostics {
    use super::*;

    /// **この実マシンの全ドライブを、本番と同じ経路で判定して並べる診断。**
    ///
    /// `#[ignore]`にしてあるのはマシン固有の結果を返すためで、CIの合否には使えない。
    /// それでも置いてあるのは、`cow_volume_gate`が「机上の規則」ではなく
    /// **実際にこの機のボリュームをどう分類するか**を、いつでも測り直せるようにするため。
    ///
    /// この機での実測（2026-08-24）:
    ///
    /// | ドライブ | 種別 | FS | `FILE_PERSISTENT_ACLS` | 判定 |
    /// |---|---|---|---|---|
    /// | `C:\` | 固定 | NTFS | あり | 通す |
    /// | `E:\` | 固定 | cryptoFs | あり | 通す（**AppContainerのACEが実際に効くかは未確認**） |
    /// | `G:\` | 固定 | FAT32 | **無し** | 拒否 |
    /// | `X:\` | **ネットワーク** | NTFS | **あり** | 拒否 |
    /// | `Z:\` | **ネットワーク** | NTFS | **あり** | 拒否 |
    ///
    /// **`X:`/`Z:`がこの機構の要点そのものである**——ネットワーク共有なのに
    /// `FILE_PERSISTENT_ACLS`を**立てて返す**。ACLのフラグだけを見ていたら通していた。
    ///
    /// **この診断が測るのはドライブ直下（`C:\`等）であって、本番が測る対象ではない。**
    /// 本番はワークスペースと差分層の**パス**を測る。ドライブ直下は一般ユーザーがDACLを
    /// 書けないので、この診断では`C:\`も「拒否」と出る——**それは正常**で、
    /// 「C:ではCoWが動かない」ことを意味しない。本番と同じパスで測るのは
    /// [`super::path_gate_diagnostics`]の方である。
    /// 実行: `cargo test -p harness-sandbox --lib volume_diagnostics -- --ignored --nocapture`
    #[test]
    #[ignore = "machine-specific diagnostic; prints the verdict for every drive on this machine"]
    fn print_cow_volume_verdict_for_every_drive() {
        for root in crate::win_common::logical_drive_roots() {
            let cap = crate::win_common::volume_capability(&root);
            let dacl_writable = root
                .exists()
                .then(|| crate::win_common::can_write_dacl(&root));
            let verdict = cow_volume_gate("workspace", &root, cap.clone(), dacl_writable);
            println!(
                "{:<5} dacl_writable={:<12} cap={:<70} -> {}",
                root.display(),
                format!("{dacl_writable:?}"),
                format!("{cap:?}"),
                match &verdict {
                    Ok(()) => "ACCEPT".to_string(),
                    Err(e) => format!("REFUSE: {}", e.split(". ").next().unwrap_or(e)),
                }
            );
        }
    }
}

#[cfg(all(test, windows))]
mod path_gate_diagnostics {
    use super::*;

    /// **本番が実際に測るのと同じ「パス」で関所を通す診断。**
    ///
    /// `volume_diagnostics`はドライブ直下（`C:\`等）を測るが、そこは一般ユーザーが
    /// DACLを書けないので必ず拒否になる——**本番が測るのはワークスペースと差分層のパス**で
    /// あって、ドライブ直下ではない。両者を取り違えると「C:でもCoWが動かない」と誤読する。
    ///
    /// 対象は`HARNESS_GATE_PROBE_PATHS`（`;`区切り）で渡す。
    /// 実行例:
    /// `HARNESS_GATE_PROBE_PATHS='C:\repo;E:\harness_cow\proj' cargo test -p harness-sandbox --lib path_gate_diagnostics -- --ignored --nocapture`
    #[test]
    #[ignore = "machine-specific diagnostic; pass paths via HARNESS_GATE_PROBE_PATHS"]
    fn print_cow_volume_verdict_for_given_paths() {
        let Ok(list) = std::env::var("HARNESS_GATE_PROBE_PATHS") else {
            println!("set HARNESS_GATE_PROBE_PATHS to a ';'-separated list of paths");
            return;
        };
        for raw in list.split(';').filter(|s| !s.is_empty()) {
            let path = Path::new(raw);
            let cap = crate::win_common::volume_mount_point_of(path)
                .and_then(|m| crate::win_common::volume_capability(&m));
            let dacl_writable = path.exists().then(|| crate::win_common::can_write_dacl(path));
            let verdict = cow_volume_gate("workspace", path, cap.clone(), dacl_writable);
            println!(
                "{:<45} exists={:<5} dacl_writable={:<12} fs={:<10} remote={:<5} -> {}",
                raw,
                path.exists(),
                format!("{dacl_writable:?}"),
                cap.as_ref().map(|c| c.filesystem.as_str()).unwrap_or("?"),
                cap.as_ref().map(|c| c.is_remote).unwrap_or(false),
                match &verdict {
                    Ok(()) => "ACCEPT".to_string(),
                    Err(e) => format!("REFUSE: {}", e.split(". ").next().unwrap_or(e)),
                }
            );
        }
    }
}
