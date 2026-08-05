//! **既に許可済みなのに拒否された** ＝ その許可では足りない、という推論（実測: `plans/etw-spike/RESULTS.md` §15）。
//!
//! # なぜこれが言えるのか
//!
//! Windowsのアクセスチェックは `DesiredAccess ⊆ granted` で成否が決まる。したがって
//! **既に`fs.read`で許可したパスで拒否が観測された**なら、要求には`FILE_GENERIC_READ`の
//! 外のビットが含まれていたことが**確定する**（推測ではない）。実機の真理値表:
//!
//! | 許可済み | read | write | exec | delete |
//! |---|---|---|---|---|
//! | なし | 拒否 | 拒否 | 拒否 | 拒否 |
//! | **read** | **成功** | 拒否 | 拒否 | 拒否 |
//! | **read+write** | **成功** | **成功** | 拒否 | 拒否 |
//!
//! これは4656（`AccessMask`）に頼らずに提案の精度を上げる唯一の経路である。ETWのイベント自体は
//! `DesiredAccess`を持たず、`CreateDisposition`の差は呼び出し側の都合でしかない（§15.2）ので、
//! **「許可済みの内容」との突き合わせだけが事実に基づく信号**になる。
//!
//! # なぜ「read+write許可下の拒否」を`read_exec`と断定しないのか
//!
//! `FILE_EXECUTE`も`DELETE`も`FILE_GENERIC_READ`/`FILE_GENERIC_WRITE`のどちらにも含まれない。
//! つまり「read+writeを許可済みで拒否」からは**実行か削除**までしか絞れず、どちらかは決まらない。
//! 断定せず、両方を挙げて人に選ばせる（D-42: 適用は常にユーザーの明示操作）。

use harness_config::FsAccess;

/// 既に設定で許可されているFSパス（`fs.read` / `fs.read_write` / `fs.read_exec`）。
///
/// `harness-cli`が`.harness/settings.json`から組み立てて渡す。**このクレートはファイルを
/// 読まない**（純粋性の維持）。
#[derive(Debug, Clone, Default)]
pub struct GrantedPaths {
    entries: Vec<(String, FsAccess)>,
}

impl GrantedPaths {
    pub fn new(entries: Vec<(String, FsAccess)>) -> Self {
        Self { entries }
    }

    /// `.harness/settings.json`由来と`fs-passthrough-ledger.json`由来を合流させる。
    ///
    /// **設定ファイル側を優先する**（同じパスが両方にあれば台帳側を捨てる）。台帳は
    /// `writable: bool`しか持たず`read`と`read_exec`を区別できないのに対し、設定側は
    /// 正確なaccess種別を持つため。台帳にしか無いパスは`--fs-allow`由来である。
    ///
    /// 台帳を混ぜるのは、**`--fs-allow`で穴を開けたユーザーにも「その許可では足りない」を
    /// 届けるため**である（`plans/PLAN-M15.7-FOLLOWUP.md` W4）。設定ファイルしか見ていなかった
    /// 頃は、`--fs-allow`利用者だけが永遠に同じ`fs.read`提案を受け取り続けていた。
    pub fn merged(settings: Vec<(String, FsAccess)>, ledger: Vec<(String, FsAccess)>) -> Self {
        let mut entries = settings;
        for (path, access) in ledger {
            let already = entries
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(&path));
            if !already {
                entries.push((path, access));
            }
        }
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `path`を覆っている許可のうち**最も広いもの**を返す。
    ///
    /// 設定のエントリはディレクトリのこともあるので、前方一致で「配下か」を見る。
    /// 境界はコンポーネント単位で判定する——`C:/data` が `C:/database/x` を覆っていると
    /// 誤判定すると、無関係なパスに「許可済みなのに拒否された」と言うことになる。
    pub fn covering(&self, path: &str) -> Option<FsAccess> {
        let mut widest: Option<FsAccess> = None;
        for (granted, access) in &self.entries {
            if covers(granted, path) {
                widest = Some(match widest {
                    Some(current) => wider(current, *access),
                    None => *access,
                });
            }
        }
        widest
    }
}

/// `granted`が`path`を覆うか（同一、または`path`が`granted`配下）。
fn covers(granted: &str, path: &str) -> bool {
    let granted = granted.trim_end_matches('/');
    if granted.is_empty() {
        return false;
    }
    if path.eq_ignore_ascii_case(granted) {
        return true;
    }
    // コンポーネント境界を跨いだ前方一致を弾く（`C:/data` vs `C:/database/x`）。
    path.len() > granted.len()
        && path[..granted.len()].eq_ignore_ascii_case(granted)
        && path.as_bytes()[granted.len()] == b'/'
}

fn wider(a: FsAccess, b: FsAccess) -> FsAccess {
    // read < read_exec / read_write（後2者は互いに比較不能なので、read_writeを広いとみなす）。
    match (a, b) {
        (FsAccess::ReadWrite, _) | (_, FsAccess::ReadWrite) => FsAccess::ReadWrite,
        (FsAccess::ReadExec, _) | (_, FsAccess::ReadExec) => FsAccess::ReadExec,
        _ => FsAccess::Read,
    }
}

/// 「既に許可済みなのに拒否された」ときに、何が足りないと言えるか。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insufficient {
    /// `read`許可下での拒否 → 書込・削除・実行のいずれか。
    ReadWasNotEnough,
    /// `read_exec`許可下での拒否 → 書込か削除。
    ReadExecWasNotEnough,
    /// `read_write`許可下での拒否 → 実行か削除。
    ReadWriteWasNotEnough,
}

impl Insufficient {
    /// 提案へ載せる説明。**何が確定していて何が確定していないか**を書き分ける。
    pub fn explain(&self) -> &'static str {
        match self {
            Insufficient::ReadWasNotEnough =>
                "this path is ALREADY allowed as fs.read, and the sandbox still denied it -- so \
                 the request needed more than read (a write, a delete, or an execute). Moving it \
                 to fs.read_write (write/delete) or fs.read_exec (running a program) is what \
                 will actually fix it; adding fs.read again will not",
            Insufficient::ReadExecWasNotEnough =>
                "this path is ALREADY allowed as fs.read_exec, and the sandbox still denied it -- \
                 so the request needed write or delete access. fs.read_write is what will fix it",
            Insufficient::ReadWriteWasNotEnough =>
                "this path is ALREADY allowed as fs.read_write, and the sandbox still denied it -- \
                 so the request needed to execute a program there (fs.read_exec), or it needed a \
                 right this mechanism does not grant at all (taking ownership, changing the ACL)",
        }
    }
}

/// 既存の許可と拒否されたaccessから、「その許可では足りなかった」と言えるかを判定する。
///
/// **拒否された`access`が推定値であることに注意**——ETW由来なら`Read`へ倒れている（§15.3）。
/// だからこそ、この関数は`access`ではなく**既存の許可**を根拠にする。
pub fn diagnose(granted: Option<FsAccess>) -> Option<Insufficient> {
    match granted? {
        FsAccess::Read => Some(Insufficient::ReadWasNotEnough),
        FsAccess::ReadExec => Some(Insufficient::ReadExecWasNotEnough),
        FsAccess::ReadWrite => Some(Insufficient::ReadWriteWasNotEnough),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denial_under_an_existing_read_grant_means_read_was_not_enough() {
        let granted = GrantedPaths::new(vec![("C:/tools".to_string(), FsAccess::Read)]);

        let verdict = diagnose(granted.covering("C:/tools/bin/rustc.exe"));

        assert_eq!(verdict, Some(Insufficient::ReadWasNotEnough));
        assert!(verdict.unwrap().explain().contains("ALREADY allowed as fs.read"));
    }

    /// 許可していないパスの拒否からは何も言えない（実測の真理値表の1行目）。
    #[test]
    fn a_denial_on_an_ungranted_path_yields_no_diagnosis() {
        let granted = GrantedPaths::new(vec![("C:/tools".to_string(), FsAccess::Read)]);

        assert_eq!(granted.covering("C:/elsewhere/x.txt"), None);
        assert_eq!(diagnose(None), None);
    }

    /// **コンポーネント境界を跨いだ前方一致で誤爆しない。**
    /// `C:/data`が`C:/database/x`を覆っていると誤ると、無関係なパスに
    /// 「許可済みなのに拒否された」と言うことになる。
    #[test]
    fn coverage_respects_component_boundaries() {
        let granted = GrantedPaths::new(vec![("C:/data".to_string(), FsAccess::Read)]);

        assert_eq!(granted.covering("C:/data/file.txt"), Some(FsAccess::Read));
        assert_eq!(granted.covering("C:/data"), Some(FsAccess::Read));
        assert_eq!(granted.covering("C:/database/file.txt"), None);
    }

    #[test]
    fn coverage_is_case_insensitive_and_ignores_a_trailing_slash() {
        let granted = GrantedPaths::new(vec![("C:/Tools/".to_string(), FsAccess::ReadExec)]);

        assert_eq!(
            granted.covering("c:/tools/bin/x.exe"),
            Some(FsAccess::ReadExec)
        );
    }

    /// 複数のエントリが覆う場合は最も広いものを採る（狭い方を根拠にすると誤診する）。
    #[test]
    fn the_widest_covering_grant_wins() {
        let granted = GrantedPaths::new(vec![
            ("C:/tools".to_string(), FsAccess::Read),
            ("C:/tools/bin".to_string(), FsAccess::ReadWrite),
        ]);

        assert_eq!(
            diagnose(granted.covering("C:/tools/bin/x")),
            Some(Insufficient::ReadWriteWasNotEnough)
        );
    }

    /// `read_write`許可下の拒否は**実行か削除**までしか絞れない。断定しない。
    #[test]
    fn a_read_write_grant_narrows_to_execute_or_a_right_we_do_not_grant() {
        let text = Insufficient::ReadWriteWasNotEnough.explain();

        assert!(text.contains("fs.read_exec"));
        assert!(
            text.contains("does not grant at all"),
            "it must admit that some rights are outside this mechanism"
        );
    }
}
