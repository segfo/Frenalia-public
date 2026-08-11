//! [`super::parse::access_from_create_options`]が寄りかかっている**前提そのもの**を実測で固定する
//! （`plans/PLAN-M15.7-FOLLOWUP.md` W3、拘束的決定 D-46）。
//!
//! # 何を証明したいのか
//!
//! ETWの`Create`は`DesiredAccess`を運ばない（RESULTS.md §3.1）。手掛かりは`CreateOptions`の
//! 上位8bitに載る`CreateDisposition`だけで、現行の推定はこう倒している。
//!
//! | disposition | 推定 |
//! |---|---|
//! | 2 `FILE_CREATE` / 4 `FILE_OVERWRITE` / 5 `FILE_OVERWRITE_IF` | `ReadWrite` |
//! | 0 `FILE_SUPERSEDE` / 1 `FILE_OPEN` / 3 `FILE_OPEN_IF` | `Read` |
//!
//! この非対称は恣意ではなく、**片側だけ証明が成立する**ことの反映である——というのが主張である。
//! ただし証明の中身は「呼び出し側が書込を名指しした」ではない（初稿はそう書いて実測で潰れた。
//! [`the_write_bit_is_added_by_the_io_manager_not_required_from_the_caller`]参照）。正しくはこう:
//!
//! - disposition 2/4/5 の拒否は「**read許可では直らない**」ことの証明になる。IOマネージャが
//!   dispositionを見て`FILE_WRITE_DATA`を実効マスクへ足すため、read許可だけの状態では
//!   呼び出し側が書込を1ビットも要求していなくても拒否されるからである（P1/P2/P3）
//! - disposition 0/1/3 は何も証明しない。read許可で通ることもあり（N1）、
//!   書込がそこを通って拒否されることもある（N2）
//!
//! **主張の前半は経験的な命題であって、自明ではない。** だからここで測る。RESULTS.md §17は
//! 「同じ書込が`Add-Content`では3、`cmd`の`>`では5になる」という**不完全さ**を実測したが、
//! 「5を観測したら`fs.read`では直らないと言い切れるか」という**健全性**の側は測っていなかった。
//!
//! # 停止規則（この前提が偽だったら）
//!
//! [`overwrite_dispositions_cannot_succeed_under_a_read_only_grant`]（P1/P2/P3）が緑でなければ、
//! 「2/4/5 ⇒ readでは足りない」は成立せず、`access_from_create_options`は**推定を廃して
//! 常に`Read`**へ倒さなければならない（`fs.read`で足りない分はW4の昇格の梯子＝
//! `harness_policy::insufficient`が回収する）。テストが落ちたときにそれが読めるよう、
//! assertのメッセージへ書いてある。
//!
//! # なぜETWも管理者権限も要らないのか
//!
//! 測っているのはWindowsのアクセスチェックそのものであって、それをETWがどう報告するかではない。
//! `NtCreateFile`を直接呼んで戻り値のNTSTATUSを見れば足りる。したがってこのテストは
//! `#[ignore]`を付けず、`cargo test --workspace`で常時走る——**前提が将来のWindows更新で
//! 変わったら、その日のうちに赤くなる**のが望ましい。
//!
//! マシンの状態は変えない（`tempfile::tempdir()`配下のACLのみ）。

use std::path::Path;

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF,
    FILE_SUPERSEDE, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

use super::parse::STATUS_ACCESS_DENIED;

/// `OBJ_CASE_INSENSITIVE`。
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// `FILE_NON_DIRECTORY_FILE`。ディレクトリを掴んでしまわないよう常に立てる。
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;

/// `NtCreateFile`を1回呼び、NTSTATUSを返す（成功したハンドルは即座に閉じる）。
///
/// `RootDirectory`は使わず`\??\<DOSパス>`の絶対NTパスで開く——相対openの報告形式は
/// [`super::spike_tests`]の担当で、ここでは関係が無い。
fn nt_create(
    path: &Path,
    desired_access: FILE_ACCESS_RIGHTS,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
) -> i32 {
    let nt_path = format!(r"\??\{}", path.display());
    let mut name_w: Vec<u16> = nt_path.encode_utf16().collect();
    let mut name = UNICODE_STRING {
        Length: (name_w.len() * 2) as u16,
        MaximumLength: (name_w.len() * 2) as u16,
        Buffer: windows::core::PWSTR(name_w.as_mut_ptr()),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: HANDLE::default(),
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle = HANDLE::default();
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &attrs,
            &mut iosb,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            NTCREATEFILE_CREATE_OPTIONS(FILE_NON_DIRECTORY_FILE),
            None,
            0,
        )
    };
    if !handle.is_invalid() {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
    status.0
}

/// 観測を1件ずつ表に出すための薄い記録。**assertが落ちたときに、何がどう返ったのかが
/// メッセージだけで分かる**ようにしておく（測定の再実行なしに判断できることを優先する）。
struct Observation {
    label: &'static str,
    status: i32,
}

impl Observation {
    fn take(
        label: &'static str,
        path: &Path,
        access: FILE_ACCESS_RIGHTS,
        disposition: NTCREATEFILE_CREATE_DISPOSITION,
    ) -> Self {
        let status = nt_create(path, access, disposition);
        println!("{label:<52} status={:#010X} {}", status, describe(status));
        Self { label, status }
    }

    fn succeeded(&self) -> bool {
        self.status >= 0
    }

    fn access_denied(&self) -> bool {
        self.status as u32 == STATUS_ACCESS_DENIED
    }
}

fn describe(status: i32) -> &'static str {
    match status as u32 {
        0x0000_0000 => "STATUS_SUCCESS",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000_0035 => "STATUS_OBJECT_NAME_COLLISION",
        0xC000_003A => "STATUS_OBJECT_PATH_NOT_FOUND",
        _ if status >= 0 => "(success)",
        _ => "(other failure)",
    }
}

/// 読み書きとも自由に行える普通のファイルを作る。
fn permissive_file(dir: &Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"payload").expect("create the probe file");
    path
}

/// 現在のユーザーへ**読取だけ**を許すDACLに置き換えたファイルを作る。
///
/// `icacls <path> /inheritance:r /grant <user>:(R)`。継承ACEを落として読取1本だけにするので、
/// 所有者として残るのは`READ_CONTROL`/`WRITE_DAC`（所有者に常に与えられる）であって
/// `FILE_WRITE_DATA`ではない。**`fs.read`だけを許可した状態**の忠実な再現になる。
///
/// 後始末: `tempdir`のDropはこのファイルを削除するが、削除に要る`FILE_DELETE_CHILD`は
/// 親（無加工の一時ディレクトリ）が持っているので通る。
fn read_only_file(dir: &Path, name: &str) -> std::path::PathBuf {
    let path = permissive_file(dir, name);
    let user = std::env::var("USERNAME").expect("USERNAME is set on Windows");
    let output = std::process::Command::new("icacls")
        .arg(&path)
        .arg("/inheritance:r")
        .arg("/grant")
        .arg(format!("{user}:(R)"))
        .output()
        .expect("run icacls");
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

// ---------------------------------------------------------------------------
// Part 1 — 「read許可だけの状態」でどのdispositionが成立するか（W3の核心）
// ---------------------------------------------------------------------------

/// **測定の対照（§18.5規律3・4）。** これが崩れていたらPart 1は何も証明しない。
///
/// - C1: read許可下で既存を開く（`FILE_OPEN`）は**成功しなければならない**
/// - C2: read許可下で書込アクセスを要求するのは**失敗しなければならない**
///   （＝DACLの差し替えが本当に効いていること）
#[test]
fn controls_the_read_only_dacl_allows_reading_and_refuses_writing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = read_only_file(dir.path(), "control.txt");

    let c1 = Observation::take(
        "C1 READ  + FILE_OPEN(1)",
        &path,
        FILE_GENERIC_READ,
        FILE_OPEN,
    );
    let c2 = Observation::take(
        "C2 WRITE + FILE_OPEN(1)",
        &path,
        FILE_GENERIC_WRITE,
        FILE_OPEN,
    );

    assert!(
        c1.succeeded(),
        "{}: reading a file granted to us as read-only must succeed. If it does not, the DACL \
         replacement went too far and the rest of Part 1 proves nothing (status {:#010X})",
        c1.label,
        c1.status
    );
    assert!(
        c2.access_denied(),
        "{}: writing must be refused under a read-only DACL. If it is not, the DACL replacement \
         did not take effect and every 'denied' below would be meaningless (status {:#010X})",
        c2.label,
        c2.status
    );
}

/// **W3の核心（P2）。** read許可**だけ**の状態では、`FILE_OVERWRITE_IF`(5)は
/// 呼び出し側が書込を1ビットも要求していなくても拒否される。
///
/// 理由は[`the_write_bit_is_added_by_the_io_manager_not_required_from_the_caller`]が示すとおり、
/// **IOマネージャがdispositionを見て`FILE_WRITE_DATA`を要求へ足す**からである。したがって:
///
/// > disposition 4/5/0 の`Create`が`STATUS_ACCESS_DENIED`で終わったなら、
/// > **`fs.read`をいくら足してもそれは直らない**。read_writeが必要である。
///
/// これが「観測されたdisposition 2/4/5に対して`ReadWrite`を提案してよい」の中身であり、
/// P-03（要求された権限を超えて与えない）にも反しない——実際に要求されていたからである。
#[test]
fn overwrite_dispositions_cannot_succeed_under_a_read_only_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = read_only_file(dir.path(), "overwrite.txt");

    let p1 = Observation::take(
        "P1 READ  + FILE_OVERWRITE(4)",
        &path,
        FILE_GENERIC_READ,
        FILE_OVERWRITE,
    );
    let p2 = Observation::take(
        "P2 READ  + FILE_OVERWRITE_IF(5)",
        &path,
        FILE_GENERIC_READ,
        FILE_OVERWRITE_IF,
    );
    let p3 = Observation::take(
        "P3 READ  + FILE_SUPERSEDE(0)",
        &path,
        FILE_GENERIC_READ,
        FILE_SUPERSEDE,
    );

    for observation in [&p1, &p2, &p3] {
        assert!(
            observation.access_denied(),
            "{}: this disposition succeeded although only read is granted (status {:#010X}). \
             The premise behind access_from_create_options is then FALSE: a denial carrying \
             disposition 2/4/5 would no longer prove that read is insufficient, and the function \
             must stop inferring ReadWrite and always return Read \
             (plans/PLAN-M15.7-FOLLOWUP.md W3, the stopping rule; the shortfall is then recovered \
             by harness_policy::insufficient escalation).",
            observation.label,
            observation.status
        );
    }
}

/// **反証側（N1・N2）。** `FILE_OPEN_IF`(3)は読取でも書込でも使われる＝**何も証明しない**。
///
/// - N1がread許可下で成功する ⇒ 3の拒否に対して`fs.read`は**有効な修正になりうる**。
///   だから`Read`へ倒す（P-03: 判らないなら狭い側）
/// - N2がread許可下で拒否される ⇒ 書込も3を通る。つまり3を観測して「読取だった」とも言えない。
///   **この不完全さは残る**——`Add-Content`の書込が`fs.read`として提案されるのはここが原因で、
///   W4の昇格の梯子（既に許可済みなのに拒否された ⇒ readでは足りない）が回収する
#[test]
fn open_if_proves_nothing_because_both_read_and_write_travel_through_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = read_only_file(dir.path(), "open_if.txt");

    let n1 = Observation::take(
        "N1 READ  + FILE_OPEN_IF(3)",
        &path,
        FILE_GENERIC_READ,
        FILE_OPEN_IF,
    );
    let n2 = Observation::take(
        "N2 WRITE + FILE_OPEN_IF(3)",
        &path,
        FILE_GENERIC_WRITE,
        FILE_OPEN_IF,
    );

    assert!(
        n1.succeeded(),
        "{}: read-only access through FILE_OPEN_IF must succeed under a read grant; if it did \
         not, disposition 3 would carry a write implication after all and the Read fallback \
         would be wrong for a different reason than assumed (status {:#010X})",
        n1.label,
        n1.status
    );
    assert!(
        n2.access_denied(),
        "{}: a write through FILE_OPEN_IF must be refused under a read-only grant -- this is \
         what makes disposition 3 ambiguous, and it is why the inference is incomplete rather \
         than unsound (status {:#010X})",
        n2.label,
        n2.status
    );
}

/// **どこが門なのかの切り分け。** 書込ビットは**呼び出し側に要求されない**。
/// DACLが許していれば、`DesiredAccess`に書込を1ビットも入れずに`FILE_OVERWRITE_IF`が通る。
///
/// つまりアクセスチェックの入力になっているのは呼び出し側が名指しした`DesiredAccess`ではなく、
/// **IOマネージャがdispositionを見て足した後の実効マスク**である。Part 1の拒否がACLを
/// 差し替えたときにだけ現れるのは、そのため。
///
/// この区別を記録しておかないと、「呼び出し側が書込を要求した証拠」という誤った言い方のまま
/// 実装を読み替える事故が起きる（実際、W3の初稿はその誤りで書かれていて、このテストの
/// 初回実行で潰れた）。
#[test]
fn the_write_bit_is_added_by_the_io_manager_not_required_from_the_caller() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = permissive_file(dir.path(), "permissive.txt");

    let observation = Observation::take(
        "IO READ  + FILE_OVERWRITE_IF(5) [permissive DACL]",
        &path,
        FILE_GENERIC_READ,
        FILE_OVERWRITE_IF,
    );

    assert!(
        observation.succeeded(),
        "{}: with a permissive DACL this must succeed. If it fails, the write requirement is \
         enforced against the caller's DesiredAccess after all, and the explanation in \
         overwrite_dispositions_cannot_succeed_under_a_read_only_grant needs rewriting \
         (status {:#010X})",
        observation.label,
        observation.status
    );
    assert_eq!(
        std::fs::metadata(&path).expect("stat the probe").len(),
        0,
        "the file was truncated even though the caller never asked for write access -- this is \
         the observable consequence of the IO manager adding FILE_WRITE_DATA"
    );
}

// ---------------------------------------------------------------------------
// Part 2 — `FILE_CREATE`(2)は親ディレクトリへの書込権を要求する
// ---------------------------------------------------------------------------

/// `dir`へ現在のユーザー向けの`FILE_ADD_FILE`拒否ACEを1本だけ足す。
///
/// `icacls <dir> /deny <user>:(WD)`。`(WD)`はディレクトリでは`FILE_ADD_FILE`を意味する。
/// **`/inheritance:r`は使わない**——列挙・削除の権利は残しておく必要がある
/// （残さないと`tempdir`のDropが後始末に失敗して一時ディレクトリが残る）。
/// ACL操作を`icacls`に任せるのは[`super::spike_tests`]と同じ判断（`grant_ace_mask`は
/// package SID向けのGRANTしか扱わない）。
fn deny_file_creation_in(dir: &Path) {
    let user = std::env::var("USERNAME").expect("USERNAME is set on Windows");
    let output = std::process::Command::new("icacls")
        .arg(dir)
        .arg("/deny")
        .arg(format!("{user}:(WD)"))
        .output()
        .expect("run icacls");
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// **P4。** `FILE_CREATE`(2)は「作る」ことの要求であり、親ディレクトリの`FILE_ADD_FILE`を要する。
///
/// Part 1の3つと違い、こちらの拒否はACL由来である——dispositionが`DesiredAccess`へ書込ビットを
/// 要求するのではなく、**要求先が親ディレクトリの書込権**という形で現れる。証明の向きは同じで、
/// 「disposition 2を観測した ⇒ 呼び出し側は作成＝書込を要求した」が言える。
///
/// C3は対照で、拒否ACEが読取まで潰していないこと（＝P4の拒否が`FILE_ADD_FILE`の欠落によるもので
/// あって、ディレクトリ全体が触れなくなったせいではないこと）を確かめる。
#[test]
fn file_create_requires_write_access_on_the_parent_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let probe_dir = dir.path().join("no-add-file");
    std::fs::create_dir(&probe_dir).expect("create the probe directory");
    let existing = permissive_file(&probe_dir, "existing.txt");

    deny_file_creation_in(&probe_dir);

    let c3 = Observation::take(
        "C3 READ  + FILE_OPEN(1)   [existing]",
        &existing,
        FILE_GENERIC_READ,
        FILE_OPEN,
    );
    let p4 = Observation::take(
        "P4 READ  + FILE_CREATE(2) [new name]",
        &probe_dir.join("created.txt"),
        FILE_GENERIC_READ,
        FILE_CREATE,
    );

    assert!(
        c3.succeeded(),
        "{}: the deny ACE was supposed to remove FILE_ADD_FILE only, but reading an existing \
         file in that directory failed too -- the measurement is confounded (status {:#010X})",
        c3.label,
        c3.status
    );
    assert!(
        p4.access_denied(),
        "{}: creating a new file succeeded although FILE_ADD_FILE is denied on the parent \
         (status {:#010X}). If this holds, disposition 2 no longer proves write intent either \
         and the stopping rule in this module's doc applies.",
        p4.label,
        p4.status
    );
}
