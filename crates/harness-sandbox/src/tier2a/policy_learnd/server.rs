//! **管理者権限側**（`harness-policy-learnd.exe`として昇格起動されたプロセス）の実装。
//!
//! `client.rs`とファイルを分けているのは`docs/CODE-STRUCTURE-RULES.md`規則3
//! （「信頼境界は必ず分割線にする」）による。どのコードが昇格した権限で動くのかを
//! ファイル単位で判別できないと、セキュリティレビューが成立しない。
//!
//! # 昇格側が親を信じない点
//!
//! 親（harness本体）は非特権で、攻撃者と同じ権限で動きうる（P-01）。したがって受け取った
//! 要求は**すべて受信側で検証する**:
//!
//! - `session_profile` — `is_session_profile_name`で形を検証（任意のAppContainerを対象にさせない）
//! - `fs_audit_log_path` — `validate_audit_sink_path`で`<workspace>/.harness/sandbox/`配下に限定
//!   （管理者権限での任意パス追記プリミティブにしない）
//!
//! # fail-openは「失敗を隠さない」形で行う（D-43）
//!
//! ETWが張れなくてもharnessは止めない。ただし**張れなかった事実・取りこぼした件数は
//! 制御レコードとして`fs-audit.jsonl`へ必ず書く**。「黙って空」と「本当に拒否が無かった」を
//! 読む側が区別できなければ、fail-openは単なる隠蔽になる。

use std::io::Write;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING,
};

use harness_policy::event::{FsAuditEvent, FsAuditKind};

use super::etw::parse::{to_settings_path, AccessRecord, Denial};
use super::etw::scope::{ScopeTracker, ScopeVerdict};
use super::etw::session::EtwFsSession;
use super::etw::volumes::drive_letter_map;
use super::{LearnError, LearnPolicy, LearnRequest, LearnResponse};
use crate::elevated_launch::validate_audit_sink_path;
use crate::win_common::wide;
use crate::win_pipe_ipc::{read_framed_timeout, write_framed_timeout};

/// `StartCollect`を待つタイムアウト。
const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// 応答書込のタイムアウト。
const RESPONSE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 収集中の1回のドレイン間隔。短すぎるとロック競合、長すぎるとクラッシュ時の損失が増える。
const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// daemon側エントリポイント（`harness-policy-learnd.exe`のmainから呼ぶ、昇格トークンで実行される）。
pub fn serve(pipe_name: &str) -> Result<(), LearnError> {
    let pipe = unsafe {
        let pipe_name_w = wide(pipe_name);
        CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
        .map_err(LearnError::from)?
    };
    let result = serve_inner(pipe);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

/// 収集**1世代**分の状態。`StartCollect`のたびに作り直す。
///
/// # 何ひとつ持ち越さない（D-56 段階2の核心）
///
/// netfilterdはフィルタを張り直すだけでよかったが、収集器は**要求ごとに状態を持ち越しては
/// いけない**。持ち越すと次のように壊れる:
///
/// | 持ち越すもの | 何が起きるか |
/// |---|---|
/// | ETWセッション | 記録していない時間帯のイベントが次の記録へ混ざる |
/// | [`ScopeTracker`] | 前の記録で覚えたPIDの帰属が次の記録の判定に使われる（PIDは再利用される） |
/// | [`ProcessTree`] | 同上。しかも実行像が別プロセスのものとして載る |
/// | `written` | `Stopped`の件数が累積になり、UIが出す「今回の件数」と食い違う |
/// | `sink_path` | **前の記録のJSONLへ書き続ける**（記録1回＝1ディレクトリが崩れる） |
///
/// だから世代の状態は1つの構造体に閉じ、`StartCollect`で丸ごと作り直す。
struct Generation {
    /// `None`ならETWを張れなかった（D-43 fail-open。事実は制御レコードに残る）。
    session: Option<EtwFsSession>,
    sink_path: std::path::PathBuf,
    tracker: ScopeTracker,
    tree: ProcessTree,
    dropped: Dropped,
    written: u64,
    record_all: bool,
}

impl Generation {
    /// 検証済みの要求からETWセッションを張る。**張れなくても`Some`を返す**（fail-open）。
    fn start(policy: &LearnPolicy, sink_path: std::path::PathBuf) -> Self {
        // [BUG-117] **自分のセッションを張る前に、所有者の死んだ残留セッションを回収する。**
        // 撤収は`stop()`と`Drop`しかなく、どちらも`TerminateProcess`では走らない。
        // 名前は起動のたびに変わるので`ERROR_ALREADY_EXISTS`の分岐には当たらず、
        // 残った側は誰にも触られないまま`Microsoft-Windows-Kernel-File`を有効にし続ける。
        //
        // 回収したことは**黙らせない**——マシン全体のファイル操作に発火し続けていた
        // 資源を止めたという、運用者が知るべき事実である。
        let reclaimed = super::etw::session::stop_orphaned_fs_sessions();
        if reclaimed > 0 {
            append_control(
                &sink_path,
                &format!("etw_orphan_sessions_stopped: {reclaimed}"),
            );
        }
        let session_name = format!(
            "{}{}",
            super::etw::session::FS_SESSION_PREFIX,
            policy.session_profile
        );
        let start_result = if policy.record_all {
            EtwFsSession::start_record_all(&session_name)
        } else {
            EtwFsSession::start(&session_name)
        };
        let session = match start_result {
            Ok(session) => Some(session),
            Err(e) => {
                append_control(&sink_path, &format!("etw_session_start_failed: {e}"));
                None
            }
        };
        if let Some(session) = session.as_ref() {
            if !session.kernel_process_enabled() {
                append_control(
                    &sink_path,
                    "kernel_process_provider_unavailable: scoping falls back to per-PID token \
                     queries, which cannot resolve processes that already exited",
                );
            }
        }
        Self {
            session,
            sink_path,
            tracker: ScopeTracker::new(policy.session_profile.clone())
                .with_harness_pid(policy.harness_pid)
                .with_spawn_daemon_pid(policy.spawn_daemon_pid),
            tree: ProcessTree::new(),
            dropped: Dropped::default(),
            written: 0,
            record_all: policy.record_all,
        }
    }

    fn etw_available(&self) -> bool {
        self.session.is_some()
    }

    /// 溜まったイベントを1バッチ書き出す。
    fn drain(&mut self, volumes: &[(String, String)]) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        self.written += if self.record_all {
            let (starts, records) = session.drain_records();
            flush_batch_record_all(
                &self.sink_path,
                &mut self.tracker,
                &mut self.tree,
                volumes,
                starts,
                records,
                &mut self.dropped,
            )
        } else {
            let (starts, denials) = session.drain();
            flush_batch(
                &self.sink_path,
                &mut self.tracker,
                &mut self.tree,
                volumes,
                starts,
                denials,
                &mut self.dropped,
            )
        };
    }

    /// 最後の取り残しを回収し、ETWセッションを止め、統計を制御レコードとして残す。
    /// **この世代で**書けた件数を返す。
    fn finish(mut self, volumes: &[(String, String)]) -> u64 {
        self.drain(volumes);
        if let Some(session) = self.session.take() {
            let outcome = session.stop();
            record_collection_stats(&self.sink_path, &outcome, &self.tracker, &self.dropped);
        }
        self.written
    }
}

/// 要求の連続を捌く（D-56 段階2）。`Teardown`・パイプ切断・待機タイムアウトで終わる。
fn serve_inner(pipe: HANDLE) -> Result<(), LearnError> {
    let volumes = drive_letter_map();
    let mut current: Option<Generation> = None;

    loop {
        // 収集中はドレイン間隔で起き、待機中は長く待つ（エディタを開いたまま考えている
        // 時間を待つのがD-56の目的そのもの）。
        let timeout = if current.is_some() {
            DRAIN_INTERVAL
        } else {
            START_TIMEOUT
        };
        let request_bytes = match read_framed_timeout(pipe, timeout) {
            Ok(bytes) => bytes,
            Err(e) => {
                let message = e.to_string();
                let timed_out = message.contains("timed out") || message.contains("timeout");
                if timed_out && current.is_some() {
                    // 収集中のタイムアウトは「ドレインの合図」。
                    if let Some(generation) = current.as_mut() {
                        generation.drain(&volumes);
                    }
                    continue;
                }
                // 待機中のタイムアウト、またはパイプ切断（＝親の死）。**応答は送らない**
                // ——送り先の親が既に存在しない可能性が高い。
                break;
            }
        };

        match serde_json::from_slice::<LearnRequest>(&request_bytes) {
            Ok(LearnRequest::StartCollect(policy)) => {
                if current.is_some() {
                    // **黙って無視しない。** 無視すると親は「新しい記録が始まった」と思って
                    // 前の世代の観測を今回の結果として読む（B-32）。
                    let _ = send(
                        pipe,
                        &LearnResponse::Err(
                            "already collecting; send StopCollect before StartCollect".into(),
                        ),
                    );
                    continue;
                }
                // **要求ごとに検証をやり直す**（D-56 不変条件2）。1回目に通ったからといって
                // 2回目のパスを信用しない——親は非特権で、攻撃者と同じ権限で動きうる（P-01）。
                let sink_path = match validate_request(&policy) {
                    Ok(path) => path,
                    Err(message) => {
                        let _ = send(pipe, &LearnResponse::Err(message));
                        continue;
                    }
                };
                let generation = Generation::start(&policy, sink_path);
                let etw_available = generation.etw_available();
                current = Some(generation);
                send(
                    pipe,
                    &LearnResponse::Started {
                        etw_available,
                        spawn_daemon_pid: policy.spawn_daemon_pid,
                    },
                )?;
            }
            Ok(LearnRequest::StopCollect) => {
                let written = match current.take() {
                    Some(generation) => generation.finish(&volumes),
                    None => 0,
                };
                send(pipe, &LearnResponse::Stopped { written })?;
            }
            Ok(LearnRequest::Teardown) => {
                let written = match current.take() {
                    Some(generation) => generation.finish(&volumes),
                    None => 0,
                };
                // 応答送信の失敗はここでは致命的としない（親が既に読み取りを諦めている
                // 可能性がある）。**収集していない状態でのTeardownも正常な要求**である
                // ——「何も収集していない世代を畳んで終了する」だけ。
                let _ = send(
                    pipe,
                    &LearnResponse::TornDown {
                        denials_written: written,
                    },
                );
                return Ok(());
            }
            Err(e) => {
                // **接続は維持する。** 壊れた要求1件でdaemonを畳むと、回復可能な失敗が
                // UACの追加1回になる（netfilterdの`ApplyRules`拒否と同じ扱い）。
                let _ = send(pipe, &LearnResponse::Err(format!("malformed request: {e}")));
            }
        }
    }

    // 親が消えた経路。収集中なら畳んでから終わる（ETWセッションを残さない）。
    if let Some(generation) = current.take() {
        generation.finish(&volumes);
    }
    Ok(())
}

/// 親から受け取った要求を、昇格側の責任で検証する。
fn validate_request(policy: &LearnPolicy) -> Result<std::path::PathBuf, String> {
    if !crate::tier2a::session_profile::is_session_profile_name(&policy.session_profile) {
        return Err(format!(
            "rejected malformed session profile name: {:?}",
            policy.session_profile
        ));
    }
    validate_audit_sink_path(&policy.fs_audit_log_path, &policy.workspace_root)
        .map_err(|e| format!("rejected audit sink path: {e}"))
}

/// 1バッチ分を判定して書き出し、書けた件数を返す。
///
/// `ProcessStart`を**先に**食わせるのは、スコープ判定の「親が対象なら子も対象」が
/// その情報に依存するため（同じバッチ内で子の拒否が先に来ても解決できるようにする）。
///
/// `tree`（プロセスの素性）は**record-all版と共通**である。かつてdeny-only側は
/// `with_process(pid, None)`で実行像を載せていなかったが、そのままでは
/// 「どのプロセスが拒否されたのか」がPIDでしか分からない（終了後は誰にも解決できない）。
/// 片方のモードにだけ素性がある状態は、読む側（`Aggregate`）に2つの分岐を強いる（B-01）。
fn flush_batch(
    sink_path: &Path,
    tracker: &mut ScopeTracker,
    tree: &mut ProcessTree,
    volumes: &[(String, String)],
    starts: Vec<super::etw::session::ProcessStartInfo>,
    denials: Vec<Denial>,
    dropped: &mut Dropped,
) -> u64 {
    for start in &starts {
        // **ProcessStart時にprobeする**（拒否イベント時ではなく）。実測でharnessのAppContainerは
        // `PackageFullName`を報告しないと判明したため、第1世代を識別できるのはこのprobeだけで、
        // かつ`ProcessStart`の時点ならそのプロセスはまだ生きている（RESULTS.md §11）。
        tracker.on_process_start_probing(start, probe_pid_in_container);
        remember_identity(tree, start, volumes, dropped);
    }

    let mut written = 0u64;
    for denial in denials {
        let verdict = tracker.classify(denial.pid, probe_pid_in_container);
        if verdict != ScopeVerdict::InScope {
            continue;
        }
        let Some(path) = to_settings_path(&denial.file_name, volumes) else {
            // 設定へ書けない形（名前付きパイプ・未知のボリューム）。件数だけ数えて捨てる。
            dropped.paths = dropped.paths.saturating_add(1);
            continue;
        };
        let identity = tree.get(&denial.pid);
        let mut event = FsAuditEvent::denied(
            FsAuditKind::Etw,
            path,
            denial.access,
            format!("STATUS_ACCESS_DENIED ({:#010X})", denial.status),
            denial.timestamp_unix_ms,
        )
        .with_process(denial.pid, identity.and_then(|i| i.image_name.clone()));
        if let Some(parent_pid) = identity.and_then(|i| i.parent_pid) {
            event = event.with_parent_process(parent_pid);
        }
        if append_event(sink_path, &event) {
            written += 1;
        }
    }
    written
}

/// `ProcessStart`から拾った素性を[`ProcessTree`]へ入れる。**実行像は設定パスへ寄せてから**入れる。
///
/// ETWが報告する`ImageName`はNT形式（`\Device\HarddiskVolume3\...`）である。ファイル名側
/// （`FileName`）は既に[`to_settings_path`]を通しているのに実行像だけ生のままだったため、
/// 読む側は同じJSONLの中に2種類の綴りを持つことになっていた。**変換はボリューム対応表を
/// 持っているこちら側（昇格側）でしかできない**——非昇格の読み手は`\Device\HarddiskVolumeN`が
/// どのドライブかを知らない。
///
/// 変換できないもの（未知のボリューム）は`None`にする。**生のNTパスを載せない**のは、
/// それが読む側で「設定へ書ける値」と誤解され得るからで、代わりに件数を制御レコードへ出す。
fn remember_identity(
    tree: &mut ProcessTree,
    start: &super::etw::session::ProcessStartInfo,
    volumes: &[(String, String)],
    dropped: &mut Dropped,
) {
    let image_name = match start.image_name.as_deref() {
        Some(raw) => match to_settings_path(raw, volumes) {
            Some(path) => Some(path),
            None => {
                dropped.images = dropped.images.saturating_add(1);
                None
            }
        },
        None => None,
    };
    tree.insert(
        start.pid,
        ProcessIdentity {
            parent_pid: start.parent_pid,
            image_name,
        },
    );
}

/// [`flush_batch`]のrecord-all版（`LearnPolicy.record_all`、ポリシー定義モードのTier1パス）。
/// 拒否だけでなく許可も含めて全アクセスを書き出す。
///
/// **スコープprobeに`probe_pid_in_container`を使わない**——Tier1（制限トークン）には
/// AppContainerのpackage SIDが無いため、`TokenIsAppContainer`照会は生存中のTier1プロセスに
/// 対しても確定的に`Some(false)`（「AppContainerではない」）を返してしまい、対象を
/// 永久に除外してしまう（`LearnPolicy.record_all`のdoc参照）。代わりに常に`None`を返す
/// クロージャを渡し、`harness_pid`起点の親子継承（signal 2＋フォールバック）だけで
/// スコープを決めさせる。
///
/// `tree`は**呼び出しをまたいで生き残る**（`serve_inner`が所有する）。プロセスは
/// バッチNの`ProcessStart`で現れ、バッチN+1以降のアクセスを行うため、この関数の
/// ローカルに置くと親PID・画像名がほぼ全件で欠落する。
fn flush_batch_record_all(
    sink_path: &Path,
    tracker: &mut ScopeTracker,
    tree: &mut ProcessTree,
    volumes: &[(String, String)],
    starts: Vec<super::etw::session::ProcessStartInfo>,
    records: Vec<AccessRecord>,
    dropped: &mut Dropped,
) -> u64 {
    for start in &starts {
        tracker.on_process_start_probing(start, |_pid| None);
        remember_identity(tree, start, volumes, dropped);
    }

    let mut written = 0u64;
    for record in records {
        let verdict = tracker.classify(record.pid, |_pid| None);
        if verdict != ScopeVerdict::InScope {
            continue;
        }
        let Some(path) = to_settings_path(&record.file_name, volumes) else {
            // 設定へ書けない形（名前付きパイプ・未知のボリューム）。件数だけ数えて捨てる。
            dropped.paths = dropped.paths.saturating_add(1);
            continue;
        };
        // **statusの名前を決め打ちにしない。** `allowed`が偽なのは`STATUS_ACCESS_DENIED`のときだけ
        // だが、成功以外のNTSTATUS（`OBJECT_NAME_NOT_FOUND`等）も`allowed=true`として届く。
        // 名前と実際のコードが食い違う文言を残すと、後から読む側が誤読する（B-32）。
        let reason = match record.status {
            0 => "observed".to_string(),
            super::etw::parse::STATUS_ACCESS_DENIED => {
                format!("STATUS_ACCESS_DENIED ({:#010X})", record.status)
            }
            status => format!("observed (NTSTATUS {status:#010X})"),
        };
        let identity = tree.get(&record.pid);
        let mut event = FsAuditEvent::observed(
            FsAuditKind::Etw,
            path,
            record.access,
            record.allowed,
            reason,
            record.timestamp_unix_ms,
        )
        .with_process(record.pid, identity.and_then(|i| i.image_name.clone()))
        // NTSTATUSを残す。「開けた」と「探しに行ったが無かった」は、これが無いと区別できない
        // （`FsAuditEvent::target_was_missing`）。
        .with_status(record.status);
        // 親PIDが分かるのは`ProcessStart`を観測できた世代だけ。分からないものは
        // `None`のまま残す（推測で埋めない——ツリー表示が嘘の親子関係を描くため）。
        if let Some(parent_pid) = identity.and_then(|i| i.parent_pid) {
            event = event.with_parent_process(parent_pid);
        }
        if append_event(sink_path, &event) {
            written += 1;
        }
    }
    written
}

/// `ProcessStart`から拾ったプロセスの素性（record-allのツリー表示用）。
///
/// スコープ判定（[`ScopeTracker`]）とは別に持つ。あちらが答えるのは「対象か」だけで、
/// 「誰の子か・何の実行ファイルか」は保持しない——判定に不要な情報を判定器へ足すと、
/// 判定の単体テストがツリー表示の都合で壊れるようになる。
#[derive(Debug, Clone)]
struct ProcessIdentity {
    parent_pid: Option<u32>,
    image_name: Option<String>,
}

/// **設定へ書けなかったので捨てた件数。** 捨てたこと自体は必ず数える（D-43・B-09）——
/// 「観測できなかった」と「書けない形だったので落とした」は、読む側にとって別の事実である。
///
/// 2つを1つの構造体に束ねているのは、[`flush_batch`]系の引数が増えすぎて
/// 「どちらの`&mut u64`か」が呼び出し側で見分けられなくなったため。
#[derive(Debug, Default)]
struct Dropped {
    /// アクセス先のパス（名前付きパイプ・未知のボリューム）。
    paths: u64,
    /// プロセスの実行像（未知のボリューム）。`fs.read_exec`の候補にできない分である。
    images: u64,
}

/// PID → 素性。**PID再利用は上書きで扱う**（新しい`ProcessStart`が来たら古い素性を捨てる）。
/// [`ScopeTracker`]が`ProcessSequenceNumber`で行っている扱いと同じ方針だが、
/// こちらは表示用なので順序の逆転までは追わない。
type ProcessTree = std::collections::HashMap<u32, ProcessIdentity>;

/// **取りこぼしを隠さない**（D-43）。収集の統計を制御レコードとして残す。
fn record_collection_stats(
    sink_path: &Path,
    outcome: &super::etw::session::EtwFsOutcome,
    tracker: &ScopeTracker,
    dropped: &Dropped,
) {
    if dropped.images > 0 {
        append_control(
            sink_path,
            &format!(
                "unconvertible_image_paths: {} process(es) started from an image path that cannot \
                 be expressed in settings (unmapped volume), so they carry no image_path and \
                 cannot become fs.read_exec proposals",
                dropped.images
            ),
        );
    }
    if outcome.events_lost > 0 || outcome.realtime_buffers_lost > 0 {
        append_control(
            sink_path,
            &format!(
                "etw_events_lost: {} event(s), {} realtime buffer(s) -- the collection is \
                 incomplete for this session",
                outcome.events_lost, outcome.realtime_buffers_lost
            ),
        );
    }
    if dropped.paths > 0 {
        append_control(
            sink_path,
            &format!(
                "unconvertible_paths: {} event(s) had a path that cannot be expressed in settings \
                 (named pipes, unmapped volumes) and were dropped",
                dropped.paths
            ),
        );
    }
    let unresolved = tracker.unresolved_count();
    if unresolved > 0 {
        append_control(
            sink_path,
            &format!(
                // record-allでは拒否以外も流れるので「denial」とは言えない（B-32: 文言は
                // ユーザーがその瞬間に取る行動を決める唯一の入力）。両モード共通の語にする。
                "unresolved_process_scope: {unresolved} event(s) came from a process that had \
                 already exited, so it could not be attributed to this sandbox and was dropped"
            ),
        );
    }
    if tracker.attributed_by_parentage_count() > 0 {
        append_control(
            sink_path,
            &format!(
                "attributed_by_parentage: {} process(es) were treated as in-scope because \
                 their parent was harness and the token query did not complete in time (they \
                 had already exited). This is an inference, not a proof.",
                tracker.attributed_by_parentage_count()
            ),
        );
    }
    if !tracker.package_name_ever_matched() {
        append_control(
            sink_path,
            "package_identity_never_matched: scoping relied entirely on per-PID token queries \
             (ProcessStart did not report a matching PackageFullName for this session)",
        );
    }
}

fn append_event(sink_path: &Path, event: &FsAuditEvent) -> bool {
    let Ok(mut line) = event.to_jsonl_line() else {
        return false;
    };
    line.push('\n');
    if let Some(parent) = sink_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sink_path)
    {
        Ok(mut f) => f.write_all(line.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

fn append_control(sink_path: &Path, reason: &str) {
    let event = FsAuditEvent::control(reason, harness_policy::event::now_unix_ms());
    let _ = append_event(sink_path, &event);
}

/// signal 3（`crate::tier2a::policy_learnd::etw::scope`）: PIDのトークンがAppContainerかを照会する。
///
/// **プロセスが既に終了していると失敗する**（`None`）。これは仕様であって欠陥ではない——
/// 取りこぼしは境界の欠落を意味しない（P-07）。件数は`ScopeTracker`が数え、制御レコードへ出る。
pub(crate) fn probe_pid_in_container(pid: u32) -> Option<bool> {
    use windows::Win32::Foundation::HANDLE as WinHandle;
    use windows::Win32::Security::{GetTokenInformation, TokenIsAppContainer, TOKEN_QUERY};
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut token = WinHandle::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
        if !opened {
            let _ = CloseHandle(process);
            return None;
        }
        let mut is_app_container: u32 = 0;
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenIsAppContainer,
            Some(&mut is_app_container as *mut u32 as *mut core::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
        if !ok {
            return None;
        }
        // NOTE: ここではAppContainerであることまでしか見ていない。**このセッションの**
        // package SIDと一致するかの照合は`TokenAppContainerSid`が要るが、それは
        // A-4dの実測でどちらの経路が主になるかを確定してから足す（現状は
        // `ProcessStart`経由の判定が主で、こちらは補助）。
        Some(is_app_container != 0)
    }
}

fn send(pipe: HANDLE, response: &LearnResponse) -> Result<(), LearnError> {
    let bytes = serde_json::to_vec(response)
        .map_err(|e| LearnError::Ipc(format!("failed to serialize response: {e}")))?;
    write_framed_timeout(pipe, &bytes, RESPONSE_WRITE_TIMEOUT)
        .map_err(|e| LearnError::Ipc(e.to_string()))
}

#[cfg(test)]
mod flush_batch_record_all_tests {
    use super::super::etw::session::ProcessStartInfo;
    use super::*;
    use harness_config::FsAccess;

    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// `harness_pid`起点のブートストラップ（`ScopeTracker`のsignal 2フォールバック）で
    /// 第1世代が対象と判定され、その後の許可・拒否どちらのアクセスも書き出される。
    /// Tier1にはAppContainer signalが無いため、probeクロージャは常に`None`を返す
    /// （`flush_batch_record_all`のdoc参照）——それでもこの経路だけで拾えることを確認する。
    #[test]
    fn writes_both_allowed_and_denied_records_for_in_scope_processes() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some("cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![
            AccessRecord {
                file_name: r"C:\work\Cargo.toml".to_string(),
                pid: 200,
                access: FsAccess::Read,
                status: 0,
                allowed: true,
                timestamp_unix_ms: 1,
                create_options: 0,
            },
            AccessRecord {
                file_name: r"C:\Windows\System32\secret.dll".to_string(),
                pid: 200,
                access: FsAccess::Read,
                status: 0xC000_0022,
                allowed: false,
                timestamp_unix_ms: 2,
                create_options: 0,
            },
        ];

        let written = flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut ProcessTree::new(),
            &volumes,
            starts,
            records,
            &mut dropped,
        );

        assert_eq!(written, 2);
        let lines = read_lines(&sink_path);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["allowed"], true);
        assert_eq!(lines[0]["reason"], "observed");
        assert_eq!(lines[1]["allowed"], false);
        assert!(lines[1]["reason"]
            .as_str()
            .unwrap()
            .contains("STATUS_ACCESS_DENIED"));
        assert_eq!(dropped.paths, 0);
    }

    /// `harness_pid`のブートストラップに繋がらないPID（親子関係が一切分からない）は
    /// `Unknown`判定になり、書き出されない——`InScope`を確認できないものを無条件で
    /// 拾わないことが記録モードの正しさの前提。
    #[test]
    fn unresolved_processes_are_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("");
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let records = vec![AccessRecord {
            file_name: r"C:\work\Cargo.toml".to_string(),
            pid: 999,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        let written = flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut ProcessTree::new(),
            &volumes,
            Vec::new(),
            records,
            &mut dropped,
        );

        assert_eq!(written, 0);
        assert!(!sink_path.exists());
    }

    /// 設定へ書けないパス（未知のボリューム）は書かず、件数だけ数える。
    #[test]
    fn unconvertible_paths_are_counted_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: None,
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![AccessRecord {
            file_name: r"\Device\HarddiskVolume999\unknown.txt".to_string(),
            pid: 200,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        let written = flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut ProcessTree::new(),
            &volumes,
            starts,
            records,
            &mut dropped,
        );

        assert_eq!(written, 0);
        assert_eq!(dropped.paths, 1);
    }

    /// **`parent_process_id`/`image_path`に実際に書き手が居ることの回帰テスト。**
    /// この2つはプロセスツリー表示のために足されたが、当初は代入箇所が本番に1つも無く、
    /// 永久に`None`のままだった（B-01「対の片方だけ実装」）。
    ///
    /// **`image_path`は設定パスの綴りで載る**（`file_name`側と同じ）。ETWが報告する
    /// `ImageName`はNT形式なので、載せる前に`to_settings_path`を通す——ここが生のままだと、
    /// 同じJSONLに2種類の綴りが混在し、読む側が`fs.read_exec`の候補にできない。
    #[test]
    fn records_carry_the_parent_pid_and_image_name_from_process_start() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut tree = ProcessTree::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some(r"C:\Users\me\.cargo\bin\cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![AccessRecord {
            file_name: r"C:\work\Cargo.toml".to_string(),
            pid: 200,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            starts,
            records,
            &mut dropped,
        );

        let lines = read_lines(&sink_path);
        assert_eq!(lines[0]["process_id"], 200);
        assert_eq!(lines[0]["parent_process_id"], 100);
        assert_eq!(
            lines[0]["image_path"], "C:/Users/me/.cargo/bin/cargo.exe",
            "the image path must be written in the settings spelling, not the raw NT/DOS one"
        );
        assert_eq!(dropped.images, 0);
    }

    /// **設定パスへ寄せられない実行像は載せず、件数だけ数える。**
    ///
    /// 載せてしまうと、読む側はそれを`fs.read_exec`の候補値として使い、設定へ書けない
    /// （あるいは相対パスとして誤解される）値を提案することになる。落としたことは
    /// 制御レコードに出るので「観測できなかった」とは区別できる（D-43・B-09）。
    #[test]
    fn an_image_path_that_cannot_be_expressed_in_settings_is_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut tree = ProcessTree::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            // ボリュームを解決できない形（実運用では未マップのボリューム）。
            image_name: Some(r"\Device\HarddiskVolume999\tool.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![AccessRecord {
            file_name: r"C:\work\Cargo.toml".to_string(),
            pid: 200,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            starts,
            records,
            &mut dropped,
        );

        let lines = read_lines(&sink_path);
        assert_eq!(lines.len(), 1, "the access itself is still recorded");
        assert!(
            lines[0].get("image_path").is_none(),
            "a path that cannot be written into settings must not be published as one: {:?}",
            lines[0]
        );
        assert_eq!(dropped.images, 1);
    }

    /// **素性はバッチをまたいで生き残る。** プロセスはあるバッチの`ProcessStart`で現れ、
    /// 別のバッチでファイルを触る——`ProcessTree`を関数のローカルにすると、実運用では
    /// ほぼ全件で親PID・画像名が欠落する（`flush_batch_record_all`のdoc参照）。
    #[test]
    fn identities_survive_across_batches() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut tree = ProcessTree::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        // バッチ1: ProcessStartだけが届く（アクセスはまだ無い）。
        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            vec![ProcessStartInfo {
                pid: 200,
                parent_pid: Some(100),
                image_name: Some(r"C:\tools\rustc.exe".to_string()),
                package_full_name: None,
                process_sequence_number: Some(1),
            }],
            Vec::new(),
            &mut dropped,
        );

        // バッチ2: そのプロセスのアクセスだけが届く。
        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            Vec::new(),
            vec![AccessRecord {
                file_name: r"C:\work\src\lib.rs".to_string(),
                pid: 200,
                access: FsAccess::Read,
                status: 0,
                allowed: true,
                timestamp_unix_ms: 2,
                create_options: 0,
            }],
            &mut dropped,
        );

        let lines = read_lines(&sink_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["parent_process_id"], 100);
        assert_eq!(lines[0]["image_path"], "C:/tools/rustc.exe");
    }

    /// **deny-only側の拒否レコードにも実行像が載る。**
    ///
    /// かつてこちらは`with_process(pid, None)`で、拒否したプロセスがPIDでしか分からなかった
    /// （プロセスが終了した後は誰にも解決できない）。record-all側にだけ素性があると、
    /// 読む側は同じJSONLに2つの形を想定することになる（B-01: 対の片方だけ実装しない）。
    #[test]
    fn denial_records_also_carry_the_image_path() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut tree = ProcessTree::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some(r"C:\Users\me\.cargo\bin\cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let denials = vec![Denial {
            file_name: r"C:\secret\keys.txt".to_string(),
            pid: 200,
            access: FsAccess::Read,
            status: 0xC000_0022,
            timestamp_unix_ms: 3,
            create_options: 0,
        }];

        let written = flush_batch(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            starts,
            denials,
            &mut dropped,
        );

        assert_eq!(written, 1);
        let lines = read_lines(&sink_path);
        assert_eq!(lines[0]["allowed"], false);
        assert_eq!(lines[0]["image_path"], "C:/Users/me/.cargo/bin/cargo.exe");
        assert_eq!(lines[0]["parent_process_id"], 100);
    }

    /// 記録モードが実際に送る`session_profile`は、昇格側の`validate_request`が使う
    /// `is_session_profile_name`を通らなければならない（通らなければ収集は一度も
    /// 始まらない）。ワイヤ形式テストが提示する名前と、この検証を突き合わせる。
    #[test]
    fn the_profile_name_the_record_mode_sends_passes_the_elevated_side_validation() {
        let name = crate::tier2a::session_profile::current_profile_name();
        assert!(
            crate::tier2a::session_profile::is_session_profile_name(&name),
            "record mode would be rejected by the collector: {name}"
        );
    }
}
