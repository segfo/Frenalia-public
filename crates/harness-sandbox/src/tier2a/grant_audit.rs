//! 「付与したACEが台帳に載っているか」をその場で検算する自己検証（[BUG-101](../../../docs/bugs/BUG-101.md)欠陥①）。
//!
//! # 何を測るのか
//!
//! 不変条件は1つだけである。
//!
//! > **このセッションのSID宛のACEが実在するパスは、すべて台帳の`granted_paths`に
//! > 載っていなければならない。**
//!
//! 破れると、AppContainerプロファイルを削除した瞬間にそのACEは**名前で到達不能**になる
//! ——SIDはプロファイル名からの一方向導出（`DeriveAppContainerSidFromAppContainerName`）
//! なので、名前を捨てるとSIDを二度と導出できず、`harness fs revoke`を含むどのコマンドでも
//! 剥がせない孤児になる。
//!
//! BUG-101の欠陥①は一度修正した（`grants_known`＝「付与が無かった」と「分からない」を型で
//! 分ける）が、**修正後も孤児が2件作られたことを実測した**。見落としていた場合分けは
//! 「台帳エントリは在るが`granted_paths`が不完全」で、この状態だと`end_session`は記録分だけ
//! 剥がしてプロファイルを削除する。「分かる／分からない」の2値では足りず、
//! **記録が完全か**を測る必要がある——それがこのモジュールである。
//!
//! # なぜ「台帳 vs 台帳」ではなく「DACL vs 台帳」なのか
//!
//! 付与側が「記録するつもりだった集合」と台帳を突き合わせても、**付与側の思い込みが
//! そのまま両辺に乗る**ので差が出ない。ここが見るのは**実マシンのDACL**（[`sid_ace_mask`]）で、
//! 台帳と突き合わせるのはその実測値である。付与経路がどこで記録を落としたかに依らず差が出る。
//!
//! # どこで記録するか（なぜ低レベルの絞り口だけに置かないのか）
//!
//! DACL書込の絞り口は`acl_grant::grant_ace_mask_with_checked`ただ1つで、全ての付与が
//! そこを通る。しかし**そこだけに置くと使えない**——`fix_descendants_missing_ace`
//! （継承が届かなかった既存子孫の救済）は同じ絞り口を子孫の数だけ通るので、
//! 26万ノードのworkspaceでは26万件が積まれ、しかも**子孫は元々台帳に載らない**（撤収は
//! rootからの再帰で行う）ため全件が「記録漏れ」として偽陽性になる。
//!
//! そこで**root付与の入口で[`enter_root`]のガードを張り**、その内側で起きた低レベルの
//! 書込は記録しない。ガードを張らずに絞り口へ直接来た書込（`grant_ace_mask`を直に呼ぶ
//! 経路）は記録する——**入口を1つ足したときに黙って対象外にならない**ようにするため（B-06）。
//!
//! **2つの口は役割が違う**（実測で確認した、2026-08-12）。`grant_ace_inheritable_access`から
//! [`note_root_grant`]を外しても記録は落ちない——絞り口側が拾うからである。つまり
//! **網羅性は絞り口が担保し、root側のガードは件数を潰す（子孫を記録しない）ためだけに在る**。
//! 新しい付与の入口を足す人は、ガードを張り忘れても計装から漏れることはない。
//!
//! 呼び出し位置は`#[track_caller]`で取る。報告が`preflight.rs:516`／`session_scope.rs:245`の
//! ように**経路そのものを名指しする**ので、「どの付与経路が記録を落としているか」が
//! 推測ではなく観測になる。
//!
//! # 対象にしない主体
//!
//! - **workspace capability SID**（`S-1-15-3-*`、D-54）。workspaceツリーへの付与は
//!   セッションより長生きするのが仕様で、`granted_paths`へ**意図的に記録しない**
//!   （記録すると`end_session`がツリー全体の再帰撤収を回す）。撤収は
//!   `harness fs revoke-workspace`が明示的に行う。ここで測ると全件が偽陽性になる。
//! - **祖先traverseのcapability SID**。同じ理由（`traverse-grant-ledger`が別に持つ）。
//!
//! 対象は**セッションのpackage SIDとMCPサーバのpackage SID**（どちらも同じGCで
//! プロファイルが削除される＝同じ形の孤児を作り得る主体）である。
//!
//! # 継承ACEは測れない
//!
//! [`sid_ace_mask`]は`GetExplicitEntriesFromAclW`なので**明示ACEしか見ない**。
//! 継承で届いているだけのノードは「無い」と出る。撤収の単位はrootへの明示ACEなので
//! これで正しいが、「アクセスが届いているか」を問う用途にこの結果を流用してはいけない。

use std::path::{Path, PathBuf};

// --- 動作モード ---

/// 自己検証の強さ。`HARNESS_GRANT_AUDIT`で切り替える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 一切測らない（逃がし弁）。
    Off,
    /// 測って報告する。**既定**——実運用の1回がそのまま測定になる。
    Report,
    /// 差が出たらその場で落とす。`cargo test`をこのモードで回すのが本命の測定。
    Strict,
}

/// `HARNESS_GRANT_AUDIT`の値をモードへ写す。**未設定は`Report`**（既定で測る）。
///
/// 綴りを間違えたときに黙って`Off`へ落ちないよう、**知らない値は`Report`**にする
/// ——計装を無効化するには`off`と明示的に書かせる（B-10: 無言で機能が消える形を作らない）。
pub fn parse_mode(value: Option<&str>) -> Mode {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("off") | Some("0") | Some("false") => Mode::Off,
        Some("strict") => Mode::Strict,
        _ => Mode::Report,
    }
}

/// このプロセスのモード（環境変数は起動時に1度だけ読む）。
pub fn mode() -> Mode {
    static MODE: std::sync::OnceLock<Mode> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        parse_mode(
            std::env::var("HARNESS_GRANT_AUDIT")
                .ok()
                .as_deref()
                .map(|s| s as &str),
        )
    })
}

// --- 付与の記録（プロセス内レジストリ） ---

/// 付与を要求したコード位置。`#[track_caller]`で取るので**呼び出し元**を指す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {
    pub file: &'static str,
    pub line: u32,
    /// 別プロセス（特権分離ヘルパー、D-16）へ委譲した付与か。
    ///
    /// 委譲したものは**この絞り口を通らない**（書くのは昇格側のプロセス）。
    /// 呼び出し側が「依頼した」ことだけを記録し、実際に載ったかはDACLの実測で決める。
    pub delegated: bool,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file, self.line)?;
        if self.delegated {
            write!(f, " (privhelper経由)")?;
        }
        Ok(())
    }
}

/// 「この主体へ、このパスの付与を要求した」という1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAttempt {
    /// 付与先の主体（SID文字列）。
    pub sid: String,
    pub path: PathBuf,
    pub origin: Origin,
}

fn registry() -> &'static std::sync::Mutex<Vec<GrantAttempt>> {
    static REGISTRY: std::sync::OnceLock<std::sync::Mutex<Vec<GrantAttempt>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// 付与の要求を1件記録する。同じ（主体, パス）の重複は積まない。
pub fn note_attempt(sid: &str, path: &Path, origin: Origin) {
    if mode() == Mode::Off {
        return;
    }
    let mut attempts = registry().lock().unwrap_or_else(|e| e.into_inner());
    if attempts.iter().any(|a| {
        a.sid == sid
            && harness_grant_ledger::same_ledger_path(
                &a.path.to_string_lossy(),
                &path.to_string_lossy(),
            )
    }) {
        return;
    }
    attempts.push(GrantAttempt {
        sid: sid.to_string(),
        path: path.to_path_buf(),
        origin,
    });
}

/// この主体へ付与を要求したパス一覧。
pub fn attempts_for(sid: &str) -> Vec<GrantAttempt> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|a| a.sid == sid)
        .cloned()
        .collect()
}

#[cfg(test)]
fn clear_registry() {
    registry().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

// --- root付与のガード（子孫の救済書込を記録しないための境界） ---

thread_local! {
    static IN_ROOT_GRANT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// root付与の入口であることを表すガード。**このガードが生きている間、低レベルの
/// 書込（[`note_low_level`]）は記録しない**——`fix_descendants_missing_ace`が
/// 子孫の数だけ絞り口を通るため（モジュールdoc参照）。
///
/// ネストしても最も外側だけが効く（内側の`enter_root`は何もしない）。
#[must_use = "the guard ends the root-grant scope when dropped"]
pub struct RootScope {
    outermost: bool,
}

impl Drop for RootScope {
    fn drop(&mut self) {
        if self.outermost {
            IN_ROOT_GRANT.with(|f| f.set(false));
        }
    }
}

/// root付与の範囲に入る。最も外側の呼び出しだけがガードを立てる。
pub fn enter_root() -> RootScope {
    let outermost = IN_ROOT_GRANT.with(|f| {
        let was = f.get();
        f.set(true);
        !was
    });
    RootScope { outermost }
}

/// いまroot付与の内側か（低レベルの記録を抑止するかの判定）。
pub fn in_root_grant() -> bool {
    IN_ROOT_GRANT.with(|f| f.get())
}

// --- いつ測るか（同じ差分でも意味が反転する） ---

/// 測定した時点。**表示の見出しと「台帳にあるのにACEが無い」の読み方を同時に決める。**
///
/// 2つを別々の引数にすると、片方だけ渡し間違えても型は通る（B-05: コンパイラが守らない
/// 対応関係を作らない）。時点が1つ決まれば両方が決まるので、引数は1つにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// 付与の直後（`preflight`）。**ここが本題**——記録が完全かを測る。
    Preflight,
    /// 撤収の直後・プロファイル削除の直前（`end_session`／GC）。
    SessionEnd,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Preflight => "preflight",
            Stage::SessionEnd => "end_session",
        }
    }

    /// 「台帳にあるのにACEが載っていない」を差として報告するか。
    ///
    /// **撤収の直後は報告しない。** そこでACEが無いのは**剥がしたから**であって、
    /// 幻の台帳エントリではない。報告すると撤収に成功した全件が毎回「差」として出て、
    /// 本物の1件（記録されていないACE）が埋もれる（B-09: 数える対象を間違えない）。
    fn reports_ledger_only(self) -> bool {
        matches!(self, Stage::Preflight)
    }
}

// --- 突き合わせ（純粋関数） ---

/// 1パスに対するDACLの実測結果。**「読めなかった」を「無い」へ畳まない**（B-10）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// 明示ACEが載っている（許可マスク）。
    Present(u32),
    /// 明示ACEは無い。
    Absent,
    /// DACLを読めなかった。**成功にも失敗にも数えない第3の状態**。
    Unreadable(String),
}

/// 実測1件（どこから要求されたかを添える）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbedPath {
    pub path: PathBuf,
    pub probe: Probe,
    /// 付与を要求したコード位置。台帳にだけ在るパス（前のセッションが記録したもの等）は`None`。
    pub origin: Option<Origin>,
}

/// 自己検証の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAudit {
    /// どの時点で測ったか（[`Stage`]）。
    pub stage: Stage,
    /// 測った主体（SID文字列）。
    pub subject: String,
    /// 実際にDACLを読んだパス数。
    pub checked: usize,
    /// **ACEは実在するのに台帳に無い**。これが探しているもの（孤児予備軍）。
    pub present_unrecorded: Vec<ProbedPath>,
    /// 台帳には在るのにACEが無い（幻の台帳エントリ）。害は小さいが数える。
    pub recorded_absent: Vec<PathBuf>,
    /// DACLを読めなかったパスと理由。
    pub unreadable: Vec<(PathBuf, String)>,
}

impl GrantAudit {
    /// 不変条件が保たれているか。**`unreadable`は破れとは数えない**——読めなかったことは
    /// 「載っていない」の証明にも「載っている」の証明にもならない。ただし報告はする。
    pub fn holds(&self) -> bool {
        self.present_unrecorded.is_empty()
    }

    /// 人へ見せる要約。何も言うことが無ければ`None`（無害な行で画面を埋めない）。
    pub fn summary(&self) -> Option<String> {
        if self.present_unrecorded.is_empty()
            && self.recorded_absent.is_empty()
            && self.unreadable.is_empty()
        {
            return None;
        }
        let mut parts = Vec::new();
        if !self.present_unrecorded.is_empty() {
            const SHOWN: usize = 5;
            let head: Vec<String> = self
                .present_unrecorded
                .iter()
                .take(SHOWN)
                .map(|p| match p.origin {
                    Some(origin) => format!("{} ({origin})", p.path.display()),
                    None => format!("{} (付与元不明)", p.path.display()),
                })
                .collect();
            let mut line = format!(
                "**台帳に記録されていないACEが {} 件あります**（{}）。このプロファイルを削除すると\
                 SIDを導出できなくなり、二度と剥がせません（docs/bugs/BUG-101.md）: {}",
                self.present_unrecorded.len(),
                self.subject,
                head.join(" / ")
            );
            if self.present_unrecorded.len() > SHOWN {
                line.push_str(&format!(" ほか{}件", self.present_unrecorded.len() - SHOWN));
            }
            parts.push(line);
        }
        if !self.recorded_absent.is_empty() {
            parts.push(format!(
                "台帳にあるのにACEが載っていないパス {} 件（幻の台帳エントリ）",
                self.recorded_absent.len()
            ));
        }
        if !self.unreadable.is_empty() {
            parts.push(format!(
                "DACLを読めなかったパス {} 件（載っているかどうか判定できていません）: {}",
                self.unreadable.len(),
                self.unreadable
                    .iter()
                    .take(3)
                    .map(|(path, reason)| format!("{} ({reason})", path.display()))
                    .collect::<Vec<_>>()
                    .join(" / ")
            ));
        }
        Some(format!(
            "自己検証（{}）: {}",
            self.stage.label(),
            parts.join(" / ")
        ))
    }
}

/// 候補パスの集合を作る。**レジストリと台帳の和**（両方向の差を見るため）。
///
/// 綴り（`/`と`\`・大小文字・末尾区切り）で重複させない——台帳のパスは書き手によって
/// 綴りが違う（policy.json由来は`C:/…`、`--fs-allow`由来は`C:\…`）ので、
/// 文字列一致で数えると**存在しない差分**を報告する（BUG-101欠陥②と同じ罠、B-19）。
pub fn candidates(
    attempts: &[GrantAttempt],
    recorded: &[String],
) -> Vec<(PathBuf, Option<Origin>)> {
    let mut out: Vec<(PathBuf, Option<Origin>)> = Vec::new();
    let mut push = |path: PathBuf, origin: Option<Origin>| {
        if out
            .iter()
            .any(|(p, _)| same_path(&p.to_string_lossy(), &path.to_string_lossy()))
        {
            return;
        }
        out.push((path, origin));
    };
    for attempt in attempts {
        push(attempt.path.clone(), Some(attempt.origin));
    }
    for path in recorded {
        push(PathBuf::from(path), None);
    }
    out
}

/// パスの同一判定。**全台帳が共有する1つの規則**を通す（コピーを作らない、§5.0）。
fn same_path(a: &str, b: &str) -> bool {
    harness_grant_ledger::same_ledger_path(a, b)
}

/// 実測と台帳を突き合わせる。**純粋関数**——実機もWin32も要らないので全数テストできる。
pub fn classify(
    stage: Stage,
    subject: &str,
    probed: Vec<ProbedPath>,
    recorded: &[String],
) -> GrantAudit {
    let is_recorded = |path: &Path| {
        recorded
            .iter()
            .any(|r| same_path(r, &path.to_string_lossy()))
    };

    let mut audit = GrantAudit {
        stage,
        subject: subject.to_string(),
        checked: probed.len(),
        present_unrecorded: Vec::new(),
        recorded_absent: Vec::new(),
        unreadable: Vec::new(),
    };
    for entry in probed {
        match &entry.probe {
            Probe::Present(_) => {
                if !is_recorded(&entry.path) {
                    audit.present_unrecorded.push(entry);
                }
            }
            // 撤収の直後は、剥がしたのだからACEが無いのが正しい（[`Stage`]）。
            Probe::Absent => {
                if stage.reports_ledger_only() && is_recorded(&entry.path) {
                    audit.recorded_absent.push(entry.path);
                }
            }
            Probe::Unreadable(reason) => {
                audit.unreadable.push((entry.path.clone(), reason.clone()));
            }
        }
    }
    audit
}

/// 結果を報告する。`Strict`のときは差があればその場で落とす。
///
/// **`panic!`は`std::thread::panicking()`が偽のときだけ**。この関数は`Drop`の中からも
/// 呼ばれるので、巻き戻し中にpanicするとプロセスがabortする（原因の表示ごと失われる）。
pub fn report(audit: &GrantAudit) {
    let Some(summary) = audit.summary() else {
        // **測って差が無かった**ことは、`Strict`（＝測定のためのモード）でだけ明示する。
        // ここを常に黙ると「差が無かった」と「そもそも測っていない」が区別できない——
        // 0件マッチとpassが同じ出力になるのはB-12そのもので、測定の結論を無効にする。
        // 既定（`Report`）で出さないのは、実運用の画面を無害な行で埋めないため。
        if mode() == Mode::Strict {
            eprintln!(
                "note: 自己検証（{}）: {} 件のパスを実測し、台帳との差はありませんでした（{}）",
                audit.stage.label(),
                audit.checked,
                audit.subject
            );
        }
        return;
    };
    if audit.holds() {
        eprintln!("note: {summary}");
        return;
    }
    eprintln!("warning: {summary}");
    if mode() == Mode::Strict && !std::thread::panicking() {
        panic!("HARNESS_GRANT_AUDIT=strict: {summary}");
    }
}

// --- Windows依存部（DACLの実測） ---

#[cfg(windows)]
mod win {
    use super::*;
    use windows::Win32::Security::PSID;

    /// この主体のSID文字列。導出できなければ`None`（記録できないことを付与の失敗にはしない）。
    pub(super) fn sid_string(sid: PSID) -> Option<String> {
        crate::win_common::sid_to_string(sid).ok()
    }

    /// 候補を1件ずつ実測する。**進捗は既存のセルへ流す**（`passthrough_progress`）
    /// ——数百件になり得る同期区間で、何も出ないと「固まった」と読まれる（B-23(a)）。
    pub(super) fn probe_all(
        sid: PSID,
        candidates: Vec<(PathBuf, Option<Origin>)>,
    ) -> Vec<ProbedPath> {
        let phase =
            crate::tier2a::win_appcontainer::passthrough_progress::begin_audit(candidates.len());
        let probed = candidates
            .into_iter()
            .map(|(path, origin)| {
                crate::tier2a::win_appcontainer::passthrough_progress::advance();
                let probe = match crate::tier2a::win_appcontainer::sid_ace_mask(&path, sid) {
                    Ok(Some(mask)) => Probe::Present(mask),
                    Ok(None) => Probe::Absent,
                    Err(e) => Probe::Unreadable(e.to_string()),
                };
                ProbedPath {
                    path,
                    probe,
                    origin,
                }
            })
            .collect();
        drop(phase);
        probed
    }
}

/// この主体について、いま実マシンに載っているACEと台帳を突き合わせる（Windows）。
///
/// `sid`は**副作用の無い導出**で得たものを渡すこと——撤収・検算の経路が
/// `ensure_profile`（＝存在しなければ作る）を呼ぶと、削除済みプロファイルを復活させる
/// （BUG-101欠陥②で7箇所直したのと同じ誤り）。
#[cfg(windows)]
pub fn audit_subject(
    stage: Stage,
    sid: windows::Win32::Security::PSID,
    recorded: &[String],
) -> Option<GrantAudit> {
    if mode() == Mode::Off {
        return None;
    }
    let subject = win::sid_string(sid)?;
    let attempts = attempts_for(&subject);
    let candidates = candidates(&attempts, recorded);
    if candidates.is_empty() {
        return None;
    }
    let probed = win::probe_all(sid, candidates);
    Some(classify(stage, &subject, probed, recorded))
}

/// プロファイル名から主体を導出して[`audit_subject`]を呼ぶ（セッション／MCPで共通）。
#[cfg(windows)]
pub fn audit_profile(stage: Stage, profile_name: &str, recorded: &[String]) -> Option<GrantAudit> {
    if mode() == Mode::Off {
        return None;
    }
    let sid = crate::tier2a::win_appcontainer::derive_profile_sid(profile_name).ok()?;
    audit_subject(stage, sid.as_psid(), recorded)
}

/// 非Windowsでは測るものが無い（ACLはWindows専用の機構）。
#[cfg(not(windows))]
pub fn audit_profile(
    _stage: Stage,
    _profile_name: &str,
    _recorded: &[String],
) -> Option<GrantAudit> {
    None
}

// --- 付与側から呼ぶ口（Windows） ---

/// **root付与の入口**で呼ぶ。要求を記録し、子孫の救済書込を記録しないガードを返す。
#[cfg(windows)]
#[track_caller]
pub fn note_root_grant(path: &Path, sid: windows::Win32::Security::PSID) -> RootScope {
    if mode() != Mode::Off && !in_root_grant() {
        if let Some(subject) = win::sid_string(sid) {
            let caller = std::panic::Location::caller();
            note_attempt(
                &subject,
                path,
                Origin {
                    file: caller.file(),
                    line: caller.line(),
                    delegated: false,
                },
            );
        }
    }
    enter_root()
}

/// DACL書込の絞り口から呼ぶ。**root付与の内側なら何もしない**（モジュールdoc参照）。
#[cfg(windows)]
#[track_caller]
pub fn note_low_level_grant(path: &Path, sid: windows::Win32::Security::PSID) {
    if mode() == Mode::Off || in_root_grant() {
        return;
    }
    let Some(subject) = win::sid_string(sid) else {
        return;
    };
    let caller = std::panic::Location::caller();
    note_attempt(
        &subject,
        path,
        Origin {
            file: caller.file(),
            line: caller.line(),
            delegated: false,
        },
    );
}

/// **別プロセス（特権分離ヘルパー）へ委譲した付与**を記録する。
///
/// 昇格側が書くACEはこのプロセスの絞り口を通らないので、ここで「依頼した」ことだけを
/// 残す。実際に載ったかはDACLの実測が決める——**依頼と結果を同じ値にしない**（B-09）。
#[cfg(windows)]
#[track_caller]
pub fn note_delegated_grant(path: &Path, sid: windows::Win32::Security::PSID) {
    if mode() == Mode::Off {
        return;
    }
    let Some(subject) = win::sid_string(sid) else {
        return;
    };
    let caller = std::panic::Location::caller();
    note_attempt(
        &subject,
        path,
        Origin {
            file: caller.file(),
            line: caller.line(),
            delegated: true,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin {
            file: "preflight.rs",
            line: 516,
            delegated: false,
        }
    }

    fn probed(path: &str, probe: Probe) -> ProbedPath {
        ProbedPath {
            path: PathBuf::from(path),
            probe,
            origin: Some(origin()),
        }
    }

    /// 既定は「測る」。**綴りを間違えても計装が黙って消えない**こと（B-10）。
    #[test]
    fn the_default_mode_measures_and_an_unknown_spelling_does_not_silently_disable_it() {
        assert_eq!(parse_mode(None), Mode::Report);
        assert_eq!(parse_mode(Some("strict")), Mode::Strict);
        assert_eq!(parse_mode(Some("STRICT")), Mode::Strict);
        assert_eq!(parse_mode(Some("off")), Mode::Off);
        assert_eq!(parse_mode(Some("0")), Mode::Off);
        // 綴り間違い・意図不明の値は無効化しない。
        assert_eq!(parse_mode(Some("strct")), Mode::Report);
        assert_eq!(parse_mode(Some("")), Mode::Report);
    }

    /// **これが探しているもの**: ACEは実在するのに台帳に無い。
    #[test]
    fn an_ace_that_exists_without_a_ledger_entry_is_reported_with_its_call_site() {
        let audit = classify(
            Stage::Preflight,
            "S-1-15-2-x",
            vec![probed("C:\\Users\\me\\.cargo", Probe::Present(0x1301bf))],
            &[],
        );
        assert!(!audit.holds());
        assert_eq!(audit.present_unrecorded.len(), 1);
        assert_eq!(
            audit.present_unrecorded[0].origin.map(|o| o.line),
            Some(516),
            "どの付与経路が記録を落としたかが分からなければ、測った意味が無い"
        );
        let summary = audit.summary().expect("差があるなら必ず言う");
        assert!(summary.contains("preflight.rs:516"), "{summary}");
    }

    /// **対になる許可側**（B-35）。正しく記録された付与では差が出ないこと。
    /// これが無いと「常に差ありと言う」実装でも上のテストが緑になり、機構の生死を判定できない。
    #[test]
    fn an_ace_that_is_recorded_is_not_reported() {
        let audit = classify(
            Stage::Preflight,
            "S-1-15-2-x",
            vec![probed("C:\\Users\\me\\.cargo", Probe::Present(0x1301bf))],
            &["C:\\Users\\me\\.cargo".to_string()],
        );
        assert!(audit.holds());
        assert!(audit.summary().is_none(), "{audit:?}");
    }

    /// 綴りが違うだけの同じ対象を「記録漏れ」と言わないこと（B-19）。
    /// 台帳の書き手は複数あり、policy.json由来は`/`、`--fs-allow`由来は`\`で入る。
    #[test]
    fn the_same_target_spelled_differently_is_the_same_target() {
        for recorded in [
            "C:/Users/me/.cargo",
            "c:\\users\\me\\.cargo",
            "C:\\Users\\me\\.cargo\\",
        ] {
            let audit = classify(
                Stage::Preflight,
                "S-1-15-2-x",
                vec![probed("C:\\Users\\me\\.cargo", Probe::Present(0x1301bf))],
                &[recorded.to_string()],
            );
            assert!(
                audit.holds(),
                "{recorded} は同じ対象を指しているのに記録漏れと報告された: {audit:?}"
            );
        }
    }

    /// 別の対象は別のまま（上のテストが「常に同じ」へ退化していないこと、B-35）。
    #[test]
    fn a_different_target_is_still_different() {
        let audit = classify(
            Stage::Preflight,
            "S-1-15-2-x",
            vec![probed("C:\\Users\\me\\.cargo", Probe::Present(0x1301bf))],
            &["C:/Users/me/.cargo-other".to_string()],
        );
        assert!(!audit.holds(), "{audit:?}");
    }

    /// 「読めなかった」を「無い」へ畳まない（B-10）。不変条件の破れとしては数えず、
    /// **必ず報告に出す**——判定できていないことが分からなくなるのが一番悪い。
    #[test]
    fn an_unreadable_dacl_is_a_third_state() {
        let audit = classify(
            Stage::Preflight,
            "S-1-15-2-x",
            vec![probed(
                "C:\\Windows\\System32\\config",
                Probe::Unreadable("access denied".to_string()),
            )],
            &[],
        );
        assert!(audit.holds(), "読めなかっただけで不変条件は破れていない");
        assert_eq!(audit.unreadable.len(), 1);
        let summary = audit.summary().expect("判定できなかったことは黙らない");
        assert!(summary.contains("読めなかった"), "{summary}");
    }

    /// 台帳にあるのにACEが無い（幻の台帳エントリ）は、**付与直後なら**逆向きの差として数える。
    #[test]
    fn a_ledger_entry_without_an_ace_is_counted_the_other_way_right_after_granting() {
        let audit = classify(
            Stage::Preflight,
            "S-1-15-2-x",
            vec![probed("C:\\gone", Probe::Absent)],
            &["C:\\gone".to_string()],
        );
        assert!(audit.holds(), "孤児を作る向きではない");
        assert_eq!(audit.recorded_absent, vec![PathBuf::from("C:\\gone")]);
    }

    /// **同じ差分が、撤収の直後には差ではない**（[`Stage`]）。剥がしたのだからACEが無いのが
    /// 正しく、ここで報告すると撤収に成功した全件が毎回「差」として並び、本物の1件
    /// （記録されていないACE）が埋もれる。
    ///
    /// **実測で見つけた**（2026-08-12、`e2e-fs-allow`の3ケースすべてで
    /// 「台帳にあるのにACEが載っていないパス 1 件」が出た）。計装が自分でノイズを作っていた。
    #[test]
    fn the_same_difference_is_not_a_finding_right_after_revoking() {
        let audit = classify(
            Stage::SessionEnd,
            "S-1-15-2-x",
            vec![probed("C:\\revoked", Probe::Absent)],
            &["C:\\revoked".to_string()],
        );
        assert!(audit.holds());
        assert!(
            audit.recorded_absent.is_empty(),
            "撤収済みを「幻の台帳エントリ」と呼ばない: {audit:?}"
        );
        assert!(
            audit.summary().is_none(),
            "黙るべき場面で黙ること: {audit:?}"
        );
    }

    /// ただし**撤収の直後でも「ACEが残っているのに台帳に無い」は報告する**（B-35の対）。
    /// ここを止めると、プロファイル削除の直前という最後の分岐点で何も見えなくなる。
    #[test]
    fn an_unrecorded_ace_is_still_a_finding_right_after_revoking() {
        let audit = classify(
            Stage::SessionEnd,
            "S-1-15-2-x",
            vec![probed("C:\\left-behind", Probe::Present(0x1301bf))],
            &[],
        );
        assert!(!audit.holds(), "{audit:?}");
        assert_eq!(audit.present_unrecorded.len(), 1);
    }

    /// 候補はレジストリと台帳の**和**（両方向を見るため）で、綴り違いで二重に数えない。
    #[test]
    fn candidates_are_the_union_of_the_registry_and_the_ledger() {
        let attempts = vec![GrantAttempt {
            sid: "S-1-15-2-x".to_string(),
            path: PathBuf::from("C:\\a"),
            origin: origin(),
        }];
        let out = candidates(&attempts, &["C:/a".to_string(), "C:\\b".to_string()]);
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[0].0, PathBuf::from("C:\\a"));
        assert!(out[0].1.is_some(), "レジストリ由来は付与位置を持つ");
        assert_eq!(out[1].0, PathBuf::from("C:\\b"));
        assert!(out[1].1.is_none(), "台帳にだけ在るものは付与位置を持たない");
    }

    /// root付与のガードは最も外側だけが効く（子孫の救済書込を記録しないための境界）。
    #[test]
    fn only_the_outermost_root_scope_owns_the_guard() {
        assert!(!in_root_grant());
        let outer = enter_root();
        assert!(in_root_grant());
        {
            let _inner = enter_root();
            assert!(in_root_grant());
        }
        assert!(
            in_root_grant(),
            "内側のガードが落ちても、外側が生きている間は範囲内のまま"
        );
        drop(outer);
        assert!(!in_root_grant());
    }

    /// 同じ（主体, パス）を2回要求しても1件。付与が2回走る経路
    /// （`already_sufficient`のスキップと実付与）で二重に数えない。
    #[test]
    fn the_same_grant_is_recorded_once() {
        clear_registry();
        note_attempt("S-1-15-2-dedup", Path::new("C:\\a"), origin());
        note_attempt("S-1-15-2-dedup", Path::new("C:/a/"), origin());
        assert_eq!(attempts_for("S-1-15-2-dedup").len(), 1);
        note_attempt("S-1-15-2-dedup", Path::new("C:\\b"), origin());
        assert_eq!(attempts_for("S-1-15-2-dedup").len(), 2);
        assert!(
            attempts_for("S-1-15-2-other").is_empty(),
            "主体が違えば別の集合"
        );
        clear_registry();
    }
}
