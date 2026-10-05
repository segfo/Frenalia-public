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

use super::etw::mof::MofFsSession;
use super::etw::parse::{to_settings_path, AccessRecord, Denial};
use super::etw::scope::{ScopeTracker, ScopeVerdict};
use super::etw::session::EtwFsSession;
use super::etw::volumes::drive_letter_map;
use super::instances::{self, ProcessIdentity, ProcessInstances};
use super::observed::{ArgvEvent, ObservedCandidates, Resolution};
use super::{LearnError, LearnPolicy, LearnRequest, LearnResponse};
use crate::elevated_launch::validate_audit_sink_path;
use crate::win_common::wide;
use crate::win_pipe_ipc::{read_framed_timeout, write_framed_timeout};

/// **最初の**`StartCollect`を待つタイムアウト。
///
/// 1件目だけ短いのは、「daemonは起きたが親が要求を送らない」を検知できるようにするため。
/// ここで無期限に待つと、昇格トークンを握ったプロセスが誰にも使われないまま残る。
const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// [BUG-098] **2件目以降**の要求を待つ時間。
///
/// # なぜ実質無期限なのか（D-56そのもの）
///
/// この収集器の寿命は**呼び出し側プロセスに合わせる**と決まっている（D-56）。決定の理由は
/// 「ポリシーエディタは1回の起動で記録を何度も走らせる道具（記録→承認→パス2→出力を見て→
/// もう一度パス2）なのに、実行のたびにdaemonを起こし直してUACが出ていた」——
/// **その「出力を見て考えている時間」を待つことが目的である。**
///
/// 旧実装は待機中も[`START_TIMEOUT`]（60秒）で待ち、**時間切れで終了していた**。
/// ユーザーが60秒考えると収集器が消え、次の記録でパイプが切れているので起こし直し＝
/// **UACが1回増える**。D-56が消したはずの症状を、この収集器だけが再生産していた
/// （[BUG-098](../../../../docs/bugs/BUG-098.md)）。
///
/// 値は兄弟の`netfilterd::DAEMON_IDLE_TIMEOUT`と同じ根拠で決める
/// （`WaitForSingleObject`の最大値、約49.7日）。**別々の定数として持つ**のは、
/// 片方を変えたときにもう片方が黙って追随するのは意図ではないため。
///
/// **時間で畳まなくてよい根拠**は、親が死ねばパイプが切れ、`read_framed_timeout`が
/// `ERROR_BROKEN_PIPE`で失敗して自発的に撤収することである（寿命はタイマーではなく
/// OSハンドルに紐づく、`netfilterd`と同じ規律）。
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(u32::MAX as u64);
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
/// | [`ProcessInstances`] | 同上。しかも実行像が別プロセスのものとして載る |
/// | `written` | `Stopped`の件数が累積になり、UIが出す「今回の件数」と食い違う |
/// | `sink_path` | **前の記録のJSONLへ書き続ける**（記録1回＝1ディレクトリが崩れる） |
///
/// だから世代の状態は1つの構造体に閉じ、`StartCollect`で丸ごと作り直す。
struct Generation {
    /// `None`ならETWを張れなかった（D-43 fail-open。事実は制御レコードに残る）。
    session: Option<EtwFsSession>,
    /// argv観測のセッション（段階6d、§10.3）。**`capture_argv`のときだけ`Some`**で、
    /// **張れなければこの世代は作られない**（fail-open のFS側とは逆。§10.3）。
    argv_session: Option<MofFsSession>,
    /// 観測した候補の積み先。`argv_session`と対で`Some`になる。
    candidates: Option<ObservedCandidates>,
    sink_path: std::path::PathBuf,
    tracker: ScopeTracker,
    instances: ProcessInstances,
    dropped: Dropped,
    written: u64,
    record_all: bool,
}

impl Generation {
    /// 検証済みの要求からETWセッションを張る。
    ///
    /// # 2つのセッションで扱いが逆である（§10.3）
    ///
    /// - **FS収集**は張れなくても世代を作る（D-43 fail-open）。harnessは止めず、
    ///   張れなかった事実は制御レコードに残る
    /// - **argv観測**は張れなければ`Err`を返し、**記録そのものを始めさせない**（fail-closed）。
    ///   黙ってargv無しで続けると「argvが観測されなかった辺」と「argvを観測できなかった辺」が
    ///   区別できなくなる
    ///
    /// **この非対称は意図であって書き漏れではない。** 応答（`LearnResponse::Err`）と
    /// 制御レコードの両方に出すのも同じ理由で、片方だけを見た人がもう片方も同じだと読むためである。
    fn start(policy: &LearnPolicy, sink_path: std::path::PathBuf) -> Result<Self, String> {
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
        let kernel_process_enabled = session
            .as_ref()
            .map(|session| session.kernel_process_enabled())
            .unwrap_or(false);
        if session.is_some() && !kernel_process_enabled {
            append_control(
                &sink_path,
                "kernel_process_provider_unavailable: scoping falls back to per-PID token \
                 queries, which cannot resolve processes that already exited",
            );
        }

        let (argv_session, candidates) = if policy.capture_argv {
            // **exeのフルパスはマニフェスト側からしか来ない**（`observed`のモジュールdoc）。
            // プロセス生成のプロバイダが載っていないと、argvが取れても突き合わせる相手が
            // 居らず候補が1件も出ない——**「張れたが何も出ない記録」を作らない**ので、
            // ここもfail-closedにする（§10.3の趣旨はセッションの本数ではなく、
            // 「候補が出ない記録を黙って続けない」ことである）。
            if !kernel_process_enabled {
                let reason = "argv capture was requested, but the Kernel-Process provider is not \
                              available in this session, so observed command lines could not be \
                              matched to a full image path (no candidate could be produced)";
                append_control(&sink_path, "argv_capture_unavailable: no kernel-process provider");
                return Err(reason.to_string());
            }
            let argv_name = format!(
                "{}{}",
                super::etw::session::ARGV_SESSION_PREFIX,
                policy.session_profile
            );
            match MofFsSession::start_process_only(&argv_name) {
                Ok(session) => {
                    append_control(&sink_path, "argv_capture_started: fail-closed (a recording is \
                                                refused when this session cannot be started)");
                    (
                        Some(session),
                        Some(ObservedCandidates::new(&policy.workspace_root)),
                    )
                }
                Err(e) => {
                    // **黙って続けない。** 制御レコードにも残す——応答だけに書くと、
                    // 後からログを読む人には「FS収集と同じくfail-openだった」と見える。
                    append_control(&sink_path, &format!("argv_capture_unavailable: {e}"));
                    return Err(format!(
                        "could not start the argv capture session ({e}); it needs one of the \
                         machine-wide system logger slots (8 max, and they are shared with EDR \
                         and profiling tools). Free one and retry: logman query -ets"
                    ));
                }
            }
        } else {
            (None, None)
        };

        Ok(Self {
            session,
            argv_session,
            candidates,
            sink_path,
            tracker: ScopeTracker::new(policy.session_profile.clone())
                .with_harness_pid(policy.harness_pid)
                .with_spawn_daemon_pid(policy.spawn_daemon_pid),
            instances: ProcessInstances::new(),
            dropped: Dropped::default(),
            written: 0,
            record_all: policy.record_all,
        })
    }

    /// argv観測を張ったか（応答の`argv_capture`欄。要求した値のechoではない）。
    fn argv_capture(&self) -> bool {
        self.argv_session.is_some()
    }

    fn etw_available(&self) -> bool {
        self.session.is_some()
    }

    /// 溜まったイベントを1バッチ書き出す。
    fn drain(&mut self, volumes: &[(String, String)]) {
        // **FS側を先に回す。** 候補の突き合わせはマニフェスト側が埋める台帳
        // （`tracker`・`instances`）を引くので、順序を逆にすると同じバッチで届いた生成が
        // 毎回1回ぶん持ち越される（結果は変わらないが、持ち越しが常に満杯になる）。
        self.drain_fs(volumes);
        self.drain_argv(volumes);
    }

    fn drain_fs(&mut self, volumes: &[(String, String)]) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        self.written += if self.record_all {
            let (starts, records) = session.drain_records();
            flush_batch_record_all(
                &self.sink_path,
                &mut self.tracker,
                &mut self.instances,
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
                &mut self.instances,
                volumes,
                starts,
                denials,
                &mut self.dropped,
            )
        };
    }

    /// argv観測の1バッチを候補へ落とす（段階6d）。
    ///
    /// **exeのフルパスと親はマニフェスト側の台帳から引く**——MOFの`ImageFileName`は
    /// 葉の名前しか持たず、`argv[0]`は呼び出し元が書いた綴りのままだからである
    /// （実測、`plans/etw-spike/RESULTS.md` §22.4）。
    fn drain_argv(&mut self, _volumes: &[(String, String)]) {
        // 台帳（`tracker`・`instances`）と積み先（`candidates`）を同時に可変で借りるので、
        // フィールドごとに分解して借りる。
        let Generation {
            argv_session: Some(session),
            candidates: Some(candidates),
            tracker,
            instances,
            sink_path,
            ..
        } = self
        else {
            return;
        };

        let mut events = Vec::new();
        for start in session.drain_process_starts() {
            match (start.pid, start.command_line) {
                (Some(pid), Some(argv)) => events.push(ArgvEvent { pid, argv }),
                // **コマンドラインが無い版が届いた**（`Process_V2`未満）か、pidが無い。
                // どちらも突き合わせようがないので数える（黙って捨てない）。
                _ => candidates.count_missing_command_line(),
            }
        }
        if events.is_empty() {
            return;
        }

        let now = harness_policy::event::now_unix_ms();
        let result = candidates.observe(
            events,
            |pid| resolve_for_candidate(pid, tracker, instances),
            now,
        );
        if let Err(e) = result {
            // **記録の失敗で収集を止めない**（`P-07`）。事実は制御レコードへ残す。
            append_control(sink_path, &format!("argv_candidate_write_failed: {e}"));
        }
    }

    /// 最後の取り残しを回収し、ETWセッションを止め、統計を制御レコードとして残す。
    /// **この世代で**書けた件数を返す。
    fn finish(mut self, volumes: &[(String, String)]) -> u64 {
        self.drain(volumes);
        if let Some(session) = self.session.take() {
            let outcome = session.stop();
            record_collection_stats(&self.sink_path, &outcome, &self.tracker, &self.dropped);
        }
        if let Some(session) = self.argv_session.take() {
            let dropped = session.dropped_process_starts();
            let outcome = session.stop();
            // **止めたあとに最後の1バッチが残っている。** `stop`は溜まっている分を
            // `MofFsOutcome`で返すので、そこから拾わないと**記録の末尾が丸ごと落ちる**。
            if let Some(candidates) = self.candidates.as_mut() {
                let now = harness_policy::event::now_unix_ms();
                let mut events = Vec::new();
                for start in outcome.process_starts {
                    match (start.pid, start.command_line) {
                        (Some(pid), Some(argv)) => events.push(ArgvEvent { pid, argv }),
                        _ => candidates.count_missing_command_line(),
                    }
                }
                let tracker = &mut self.tracker;
                let instances = &self.instances;
                let _ = candidates.observe(
                    events,
                    |pid| resolve_for_candidate(pid, tracker, instances),
                    now,
                );
                if let Err(e) = candidates.finish(now) {
                    append_control(&self.sink_path, &format!("argv_candidate_write_failed: {e}"));
                }
                record_argv_stats(&self.sink_path, candidates.stats(), dropped);
            }
        }
        self.written
    }
}

/// 観測したpidを、候補の1行にできるかどうかへ畳む（段階6d）。
///
/// **スコープ判定は既存の[`ScopeTracker`]に任せる**——同じ判定を2つ作ると、直したときに
/// FSの記録と候補の記録で「対象」の意味が食い違う。`probe`を渡さないのは、record-allの
/// 経路では`OpenProcess`照会がTier1のプロセスに対して確定的に「AppContainerではない」と
/// 答えてしまい、**対象を永久に除外する**ためである（`LearnPolicy::record_all`のdoc）。
///
/// スコープは分かるが素性が台帳に無い場合は[`Resolution::Unknown`]を返す——
/// **マニフェスト側のイベントがまだ届いていないだけ**かもしれないので、
/// 呼び出し側（[`ObservedCandidates::observe`]）が1度だけ持ち越してやり直す。
fn resolve_for_candidate(
    pid: u32,
    tracker: &mut ScopeTracker,
    instances: &ProcessInstances,
) -> Resolution {
    match tracker.classify(pid, |_| None) {
        ScopeVerdict::OutOfScope => Resolution::OutOfScope,
        ScopeVerdict::Unknown => Resolution::Unknown,
        // 時刻を`u64::MAX`にして「その pid の最も新しい開始」を引く＝旧`ProcessTree::get`と同じ
        // （P2c-1 では振る舞いを変えない。P2c-2 でこの関数ごと`process_audit.rs`の結び付けに替える）。
        ScopeVerdict::InScope => match instances.at(pid, u64::MAX) {
            // 実行像が未知のボリュームだったものは`exe: None`になり、候補にせず数えられる
            // （生のNTパスを載せない——読む側で「宣言へ書ける値」と誤解され得るため）。
            Some(identity) => Resolution::InScope {
                exe: identity.image_name.clone(),
                parent_exe: identity
                    .parent_pid
                    .and_then(|parent| instances.at(parent, u64::MAX))
                    .and_then(|parent| parent.image_name.clone()),
            },
            None => Resolution::Unknown,
        },
    }
}

/// argv観測の取りこぼしを制御レコードへ残す（D-43: 隠さない）。
///
/// **0件の項目は書かない。** 全部書くと、実際に落ちているものが並びに埋もれる。
fn record_argv_stats(
    sink_path: &Path,
    stats: super::observed::ArgvStats,
    dropped_by_capacity: u64,
) {
    append_control(
        sink_path,
        &format!(
            "argv_capture_summary: recorded={} out_of_scope={}",
            stats.recorded, stats.out_of_scope
        ),
    );
    if stats.unresolved > 0 {
        append_control(
            sink_path,
            &format!(
                "argv_without_image: {} observed command line(s) could not be matched to a \
                 process start from the Kernel-Process provider, so they produced no candidate",
                stats.unresolved
            ),
        );
    }
    if stats.without_exe > 0 {
        append_control(
            sink_path,
            &format!(
                "argv_without_settings_path: {} process(es) started from an image path that \
                 cannot be expressed in settings (unmapped volume)",
                stats.without_exe
            ),
        );
    }
    if stats.without_command_line > 0 {
        append_control(
            sink_path,
            &format!(
                "argv_missing_command_line: {} process start event(s) carried no command line \
                 (an older MOF event version, or no pid)",
                stats.without_command_line
            ),
        );
    }
    if dropped_by_capacity > 0 {
        append_control(
            sink_path,
            &format!(
                "argv_events_dropped_by_capacity: {dropped_by_capacity} process start event(s) \
                 were discarded before they could be drained"
            ),
        );
    }
}

/// 要求の連続を捌く（D-56 段階2）。`Teardown`・パイプ切断・待機タイムアウトで終わる。
/// 次の読取をどれだけ待つか。**3つの状態がそれぞれ別の理由で別の値を持つ。**
///
/// | いまの状態 | 待つ時間 | 時間切れの意味 |
/// |---|---|---|
/// | 収集中 | [`DRAIN_INTERVAL`] | **ドレインの合図**（終了ではない） |
/// | まだ1件も受けていない | [`START_TIMEOUT`] | 親が要求を送ってこない。**畳んで終了する** |
/// | 1件以上受けて、いまは待機中 | [`IDLE_TIMEOUT`] | 実質来ない。親の死はパイプ切断で分かる |
///
/// # 切り出してある理由（[BUG-098](../../../../docs/bugs/BUG-098.md)）
///
/// 旧実装はこの3つを2つに畳んでいた——**待機中とハンドシェイク待ちが同じ60秒**で、
/// しかも時間切れで終了していた。畳んだ結果「ユーザーが60秒考えると収集器が消える」となり、
/// 次の記録でUACが1回増える。**D-56が消したはずの症状を、この収集器だけが再生産していた。**
///
/// 分岐がループの中にインラインで書かれていると、**この3つが別物だという主張をテストで
/// 留められない**。関数にしてあるのは、対の試験（下記`timeout_selection_tests`）を
/// 置けるようにするためである。
fn next_read_timeout(collecting: bool, first_request: bool) -> std::time::Duration {
    if collecting {
        DRAIN_INTERVAL
    } else if first_request {
        START_TIMEOUT
    } else {
        IDLE_TIMEOUT
    }
}

fn serve_inner(pipe: HANDLE) -> Result<(), LearnError> {
    let volumes = drive_letter_map();
    let mut current: Option<Generation> = None;
    // [BUG-098] 1件目だけ短く待つ。2件目以降は実質無期限——**待つのがD-56の目的そのもの**。
    let mut first_request = true;

    loop {
        let timeout = next_read_timeout(current.is_some(), first_request);
        let request_bytes = match read_framed_timeout(pipe, timeout) {
            Ok(bytes) => {
                first_request = false;
                bytes
            }
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
                // ここへ来るのは (a) 1件目が来ないまま`START_TIMEOUT`が過ぎた、
                // (b) パイプが切れた（＝親の死）、のどちらか。**応答は送らない**
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
                // **argv観測が張れなければここで断る**（§10.3 fail-closed）。FS収集の
                // 失敗（fail-open）と**扱いが逆**なのは、argv無しで記録を続けると
                // 「観測されなかった辺」と「観測できなかった辺」が区別できなくなるためである。
                let generation = match Generation::start(&policy, sink_path) {
                    Ok(generation) => generation,
                    Err(reason) => {
                        // **専用の変種で返す。** 呼び出し側はこの失敗だけ別扱いする
                        // （記録を始めない）ので、`Err`に混ぜると文面での判定になる。
                        let _ = send(pipe, &LearnResponse::ArgvCaptureUnavailable { reason });
                        continue;
                    }
                };
                let etw_available = generation.etw_available();
                let argv_capture = generation.argv_capture();
                current = Some(generation);
                send(
                    pipe,
                    &LearnResponse::Started {
                        etw_available,
                        spawn_daemon_pid: policy.spawn_daemon_pid,
                        // **要求のechoではなく、実際に張れたかを返す。** echoにすると
                        // 「頼まれたから true と書いただけ」の実装でも呼び出し側が通してしまう。
                        argv_capture: Some(argv_capture),
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
    let sink = validate_audit_sink_path(&policy.fs_audit_log_path, &policy.workspace_root)
        .map_err(|e| format!("rejected audit sink path: {e}"))?;
    if policy.capture_argv {
        // **候補の積み先にも同じ検問を掛ける**（段階6d）。パスは要求から受け取らず
        // `workspace_root`から導出するが、それだけでは足りない——途中の
        // `.harness/transitions`がジャンクションなら、**昇格プロセスが任意の場所へ
        // 追記する**ことになる（`validate_sink_under`が親を`canonicalize`して潰す）。
        //
        // **置き場が無ければ断る。** 作るのは非昇格のharnessの仕事で（BUG-109。昇格側が
        // 作ると所有者が`BUILTIN\Administrators`になり、以後`.harness/**`の保護が完成しない）、
        // ここで作ってしまうと**その不変条件が黙って壊れる**。FS側のシンクが
        // 「存在すること」を要求しているのと同じ形である。
        //
        // **比べる相手は`workspace_root`である。** 置き場そのもの
        // （`.harness/transitions`）を許可範囲に渡すと、**そこがジャンクションでも
        // 「自分自身の下」になって必ず通る**——限定として何も言っていないことになる。
        crate::elevated_launch::validate_sink_under(
            &super::observed::observed_path(&policy.workspace_root),
            &policy.workspace_root,
        )
        .map_err(|e| {
            format!(
                "rejected transition candidate sink: {e} (the non-elevated side creates \
                 .harness/transitions/ before asking; see docs/bugs/BUG-109.md)"
            )
        })?;
    }
    Ok(sink)
}

/// 1バッチ分を判定して書き出し、書けた件数を返す。
///
/// `ProcessStart`を**先に**食わせるのは、スコープ判定の「親が対象なら子も対象」が
/// その情報に依存するため（同じバッチ内で子の拒否が先に来ても解決できるようにする）。
///
/// `instances`（プロセスの素性）は**record-all版と共通**である。かつてdeny-only側は
/// `with_process(pid, None)`で実行像を載せていなかったが、そのままでは
/// 「どのプロセスが拒否されたのか」がPIDでしか分からない（終了後は誰にも解決できない）。
/// 片方のモードにだけ素性がある状態は、読む側（`Aggregate`）に2つの分岐を強いる（B-01）。
fn flush_batch(
    sink_path: &Path,
    tracker: &mut ScopeTracker,
    instances: &mut ProcessInstances,
    volumes: &[(String, String)],
    starts: Vec<super::etw::session::ProcessStartInfo>,
    denials: Vec<Denial>,
    dropped: &mut Dropped,
) -> u64 {
    for start in &starts {
        // **ProcessStart時にprobeする**（拒否イベント時ではなく）。実測でharnessのAppContainerは
        // `PackageFullName`を報告しないと判明したため、第1世代を識別できるのはこのprobeだけで、
        // かつ`ProcessStart`の時点ならそのプロセスはまだ生きている（RESULTS.md §11）。
        let in_scope = tracker.on_process_start_probing(start, probe_pid_in_container);
        let is_scope_root = tracker.is_scope_root(start.parent_pid);
        if instances::remember(instances, start, volumes, in_scope, is_scope_root) {
            dropped.images = dropped.images.saturating_add(1);
        }
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
        // **pid と時刻で引く**——同じまとまりの中で pid が使い回されても、この拒否より前に
        // 始まった最も新しいインスタンスに付く（`instances::ProcessInstances::at`）。
        let identity = instances.at(denial.pid, denial.timestamp_unix_ms);
        let event = FsAuditEvent::denied(
            FsAuditKind::Etw,
            path,
            denial.access,
            format!("STATUS_ACCESS_DENIED ({:#010X})", denial.status),
            denial.timestamp_unix_ms,
        );
        let event = attach_identity(event, denial.pid, identity);
        if append_event(sink_path, &event) {
            written += 1;
        }
    }
    written
}

/// FS の記録1行へ、そのアクセスをしたプロセスのインスタンスの素性を付ける。
///
/// **FS の行を組む2か所（[`flush_batch`]・[`flush_batch_record_all`]）がこの1つを通る**——
/// 片方にだけ通し番号を付けると、読む側（エディタ）は記録のモードによって「位置」を組めたり
/// 組めなかったりする（`B-01`・`B-06`。決定23(6)「2か所の両方」）。
///
/// 親PIDが分かるのは`ProcessStart`を観測できた世代だけ。分からないものは`None`のまま残す
/// （推測で埋めない——ツリー表示が嘘の親子関係を描くため）。通し番号も同じで、番号を持てない
/// 版（`ProcessStart` v0〜v2）や開始を観測していないプロセスの行には付けない。
fn attach_identity(
    event: FsAuditEvent,
    pid: u32,
    identity: Option<&ProcessIdentity>,
) -> FsAuditEvent {
    let mut event = event.with_process(pid, identity.and_then(|i| i.image_name.clone()));
    if let Some(parent_pid) = identity.and_then(|i| i.parent_pid) {
        event = event.with_parent_process(parent_pid);
    }
    if let Some(seq) = identity.and_then(|i| i.seq) {
        event = event.with_process_sequence_number(seq);
    }
    event
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
/// `instances`は**呼び出しをまたいで生き残る**（`serve_inner`が所有する）。プロセスは
/// バッチNの`ProcessStart`で現れ、バッチN+1以降のアクセスを行うため、この関数の
/// ローカルに置くと親PID・画像名がほぼ全件で欠落する。
fn flush_batch_record_all(
    sink_path: &Path,
    tracker: &mut ScopeTracker,
    instances: &mut ProcessInstances,
    volumes: &[(String, String)],
    starts: Vec<super::etw::session::ProcessStartInfo>,
    records: Vec<AccessRecord>,
    dropped: &mut Dropped,
) -> u64 {
    for start in &starts {
        let in_scope = tracker.on_process_start_probing(start, |_pid| None);
        let is_scope_root = tracker.is_scope_root(start.parent_pid);
        if instances::remember(instances, start, volumes, in_scope, is_scope_root) {
            dropped.images = dropped.images.saturating_add(1);
        }
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
        // pid と時刻で引く（[`flush_batch`]と同じ。同じまとまりの中の pid の使い回しに耐える）。
        let identity = instances.at(record.pid, record.timestamp_unix_ms);
        let event = FsAuditEvent::observed(
            FsAuditKind::Etw,
            path,
            record.access,
            record.allowed,
            reason,
            record.timestamp_unix_ms,
        )
        // NTSTATUSを残す。「開けた」と「探しに行ったが無かった」は、これが無いと区別できない
        // （`FsAuditEvent::target_was_missing`）。
        .with_status(record.status);
        let event = attach_identity(event, record.pid, identity);
        if append_event(sink_path, &event) {
            written += 1;
        }
    }
    written
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
            parent_process_sequence_number: None,
            timestamp_unix_ms: 0,
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
            &mut ProcessInstances::new(),
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
            &mut ProcessInstances::new(),
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
            parent_process_sequence_number: None,
            timestamp_unix_ms: 0,
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
            &mut ProcessInstances::new(),
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
        let mut instances = ProcessInstances::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some(r"C:\Users\me\.cargo\bin\cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
            parent_process_sequence_number: None,
            timestamp_unix_ms: 0,
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
            &mut instances,
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
        let mut instances = ProcessInstances::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            // ボリュームを解決できない形（実運用では未マップのボリューム）。
            image_name: Some(r"\Device\HarddiskVolume999\tool.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
            parent_process_sequence_number: None,
            timestamp_unix_ms: 0,
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
            &mut instances,
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
    /// 別のバッチでファイルを触る——表（`ProcessInstances`）を関数のローカルにすると、実運用では
    /// ほぼ全件で親PID・画像名が欠落する（`flush_batch_record_all`のdoc参照）。
    #[test]
    fn identities_survive_across_batches() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut instances = ProcessInstances::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        // バッチ1: ProcessStartだけが届く（アクセスはまだ無い）。
        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut instances,
            &volumes,
            vec![ProcessStartInfo {
                pid: 200,
                parent_pid: Some(100),
                image_name: Some(r"C:\tools\rustc.exe".to_string()),
                package_full_name: None,
                process_sequence_number: Some(1),
                parent_process_sequence_number: None,
                timestamp_unix_ms: 0,
            }],
            Vec::new(),
            &mut dropped,
        );

        // バッチ2: そのプロセスのアクセスだけが届く。
        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut instances,
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
        let mut instances = ProcessInstances::new();
        let volumes = drive_letter_map();
        let mut dropped = Dropped::default();

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some(r"C:\Users\me\.cargo\bin\cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
            parent_process_sequence_number: None,
            timestamp_unix_ms: 0,
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
            &mut instances,
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

    /// `flush_batch`（拒否だけ）の試験で使う pid。**実在し得ない値にしてある**——`flush_batch`は
    /// スコープ判定で本物の`OpenProcess`を呼ぶので、たまたま同じ pid のプロセスがこの機械に居ると
    /// 「AppContainerではない」と答えられて行が書かれない。開けなければ、親が harness 本体である
    /// ことを根拠にした救済（`ScopeTracker::is_scope_root`）で対象になる。
    const UNOPENABLE_PID: u32 = 0xFFFF_FF00;

    fn start_at(pid: u32, seq: Option<u64>, image: &str, at_ms: u64) -> ProcessStartInfo {
        ProcessStartInfo {
            pid,
            parent_pid: Some(100),
            image_name: Some(image.to_string()),
            package_full_name: None,
            process_sequence_number: seq,
            parent_process_sequence_number: Some(1),
            timestamp_unix_ms: at_ms,
        }
    }

    fn denial_at(pid: u32, file_name: &str, at_ms: u64) -> Denial {
        Denial {
            file_name: file_name.to_string(),
            pid,
            access: FsAccess::Read,
            status: 0xC000_0022,
            timestamp_unix_ms: at_ms,
            create_options: 0,
        }
    }

    fn access_at(pid: u32, file_name: &str, at_ms: u64) -> AccessRecord {
        AccessRecord {
            file_name: file_name.to_string(),
            pid,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: at_ms,
            create_options: 0,
        }
    }

    /// **FS の行を書く2か所の両方が、アクセスしたインスタンスの通し番号を書く**
    /// （決定23(6)。2か所のうち2か所）。
    ///
    /// 片方にだけ付けると、エディタは記録のモードによって「記録した木の位置」を組めたり組めなかったり
    /// する。番号を持てないインスタンス（`ProcessStart` v0〜v2）の行には**キーごと出さない**
    /// （`null`を書かない＝既存の行の書式を変えない）ことを対の側で見る。
    #[test]
    fn both_writers_attach_the_process_sequence_number() {
        let dir = tempfile::tempdir().unwrap();
        let volumes = drive_letter_map();

        // record-all（パス1）の書き手。
        let record_all_sink = dir.path().join("record-all.jsonl");
        flush_batch_record_all(
            &record_all_sink,
            &mut ScopeTracker::new("").with_harness_pid(Some(100)),
            &mut ProcessInstances::new(),
            &volumes,
            vec![
                start_at(200, Some(665_736), r"C:\tools\a.exe", 0),
                start_at(300, None, r"C:\tools\old.exe", 0),
            ],
            vec![
                access_at(200, r"C:\work\a.txt", 1),
                access_at(300, r"C:\work\old.txt", 1),
            ],
            &mut Dropped::default(),
        );
        let lines = read_lines(&record_all_sink);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0]["process_sequence_number"], 665_736);
        assert!(
            lines[1].get("process_sequence_number").is_none(),
            "番号の無いインスタンスの行にキーが出た: {:?}",
            lines[1]
        );

        // 拒否だけ（通常運用・パス2）の書き手。
        let deny_sink = dir.path().join("deny-only.jsonl");
        flush_batch(
            &deny_sink,
            &mut ScopeTracker::new("").with_harness_pid(Some(100)),
            &mut ProcessInstances::new(),
            &volumes,
            vec![
                start_at(UNOPENABLE_PID, Some(665_737), r"C:\tools\b.exe", 0),
                start_at(UNOPENABLE_PID - 4, None, r"C:\tools\old.exe", 0),
            ],
            vec![
                denial_at(UNOPENABLE_PID, r"C:\secret\b.txt", 1),
                denial_at(UNOPENABLE_PID - 4, r"C:\secret\old.txt", 1),
            ],
            &mut Dropped::default(),
        );
        let lines = read_lines(&deny_sink);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0]["process_sequence_number"], 665_737);
        assert!(
            lines[1].get("process_sequence_number").is_none(),
            "番号の無いインスタンスの行にキーが出た: {:?}",
            lines[1]
        );
    }

    /// **同じまとまり（2秒ごとのドレイン1回）の中で pid が使い回されても、正しいインスタンスに付く。**
    ///
    /// 旧表（pid → 素性の上書き）は、後の開始を入れた時点で前のプロセスのアクセスにも後の素性
    /// （実行像・番号）を付けていた。開始より前のアクセスは前のインスタンス、後のアクセスは後の
    /// インスタンスに付くことを、FS の行を書く2か所の両方で確かめる。
    #[test]
    fn a_pid_reused_within_one_batch_is_attributed_to_the_right_instance() {
        let dir = tempfile::tempdir().unwrap();
        let volumes = drive_letter_map();
        let check = |lines: Vec<serde_json::Value>| {
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert_eq!(lines[0]["process_sequence_number"], 1);
            assert_eq!(lines[0]["image_path"], "C:/tools/first.exe");
            assert_eq!(lines[1]["process_sequence_number"], 2);
            assert_eq!(lines[1]["image_path"], "C:/tools/second.exe");
        };

        let record_all_sink = dir.path().join("record-all.jsonl");
        flush_batch_record_all(
            &record_all_sink,
            &mut ScopeTracker::new("").with_harness_pid(Some(100)),
            &mut ProcessInstances::new(),
            &volumes,
            vec![
                start_at(200, Some(1), r"C:\tools\first.exe", 1),
                start_at(200, Some(2), r"C:\tools\second.exe", 5),
            ],
            vec![
                access_at(200, r"C:\work\one.txt", 2),
                access_at(200, r"C:\work\two.txt", 6),
            ],
            &mut Dropped::default(),
        );
        check(read_lines(&record_all_sink));

        let deny_sink = dir.path().join("deny-only.jsonl");
        flush_batch(
            &deny_sink,
            &mut ScopeTracker::new("").with_harness_pid(Some(100)),
            &mut ProcessInstances::new(),
            &volumes,
            vec![
                start_at(UNOPENABLE_PID, Some(1), r"C:\tools\first.exe", 1),
                start_at(UNOPENABLE_PID, Some(2), r"C:\tools\second.exe", 5),
            ],
            vec![
                denial_at(UNOPENABLE_PID, r"C:\secret\one.txt", 2),
                denial_at(UNOPENABLE_PID, r"C:\secret\two.txt", 6),
            ],
            &mut Dropped::default(),
        );
        check(read_lines(&deny_sink));
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

    /// **[段階6d] 候補の積み先も受信側で検証する**（`P-01`）。
    ///
    /// 要求から受け取るのは`workspace_root`だけで、積み先はそこから導出する。だが導出だけでは
    /// 足りない——**途中がジャンクションなら、昇格プロセスが任意の場所へ追記する**ことになる。
    ///
    /// ここで固定するのは「置き場が無ければ断る」側である（**作るのは非昇格のharness**で、
    /// 昇格側が作ると所有者が`BUILTIN\Administrators`になり`.harness/**`の保護が完成しない。
    /// BUG-109）。ジャンクションの解決そのものは`elevated_launch`の検問が持つ。
    #[test]
    fn a_recording_that_captures_argv_is_rejected_when_the_candidate_sink_is_missing() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let sink_dir = workspace.path().join(".harness").join("sandbox").join("g1");
        std::fs::create_dir_all(&sink_dir).expect("create sink dir");
        let mut policy = LearnPolicy {
            session_profile: crate::tier2a::session_profile::current_profile_name(),
            workspace_root: workspace.path().to_path_buf(),
            fs_audit_log_path: sink_dir.join("fs-audit.jsonl"),
            harness_pid: None,
            spawn_daemon_pid: None,
            record_all: true,
            capture_argv: true,
        };

        // `.harness/transitions/`がまだ無い＝非昇格側の先行作成が失敗している。
        let error = validate_request(&policy).expect_err("置き場が無いのに受理された");
        assert!(error.contains("transition candidate sink"), "{error}");

        // **対の側**: 先に作ってあれば通る（これが無いと「常に断る」実装でも緑になり、
        // argv観測が一度も始まらない）。
        std::fs::create_dir_all(crate::tier2a::transitions_log::transitions_dir(
            workspace.path(),
        ))
        .expect("create transitions dir");
        validate_request(&policy).expect("先行作成してあるのに断られた");

        // argvを頼まない記録は、置き場の有無に関係なく通る（波及範囲を広げない）。
        let other = tempfile::tempdir().expect("tempdir");
        let other_sink = other.path().join(".harness").join("sandbox").join("g1");
        std::fs::create_dir_all(&other_sink).expect("create sink dir");
        policy.workspace_root = other.path().to_path_buf();
        policy.fs_audit_log_path = other_sink.join("fs-audit.jsonl");
        policy.capture_argv = false;
        validate_request(&policy).expect("argvを頼んでいない記録まで止まっている");
    }
}

#[cfg(test)]
mod timeout_selection_tests {
    use super::{next_read_timeout, DRAIN_INTERVAL, IDLE_TIMEOUT, START_TIMEOUT};

    /// 許可側——**1件でも受けたあとの待機は、時間で打ち切らない。**
    ///
    /// これがD-56の本体である（ユーザーがエディタで考えている時間を待つ）。
    /// 旧実装はここが60秒で、しかも時間切れで終了していた。
    #[test]
    fn once_a_request_has_arrived_the_idle_wait_is_effectively_unbounded() {
        let waited = next_read_timeout(false, false);
        assert_eq!(waited, IDLE_TIMEOUT);
        assert!(
            waited > std::time::Duration::from_secs(60 * 60),
            "[BUG-098] the collector must outlive the user thinking in the editor. \
             Anything on a human timescale re-creates the extra UAC prompt that D-56 removed: \
             {waited:?}"
        );
    }

    /// 禁止側——**最初の1件だけは短く待つ。**
    ///
    /// 片側だけだと「常に無期限に待つ」実装でも上のテストは通る。そうすると
    /// **昇格トークンを握ったプロセスが、誰にも使われないまま残る**。
    #[test]
    fn the_first_request_is_still_waited_for_only_briefly() {
        let waited = next_read_timeout(false, true);
        assert_eq!(waited, START_TIMEOUT);
        assert!(
            waited <= std::time::Duration::from_secs(60),
            "[BUG-098] a daemon that was started but never spoken to holds an elevated token; \
             that state must stay detectable: {waited:?}"
        );
    }

    /// 収集中は、待機の話とは無関係にドレイン間隔で起きる（1件目かどうかも効かない）。
    #[test]
    fn while_collecting_the_wait_is_the_drain_interval_regardless() {
        assert_eq!(next_read_timeout(true, true), DRAIN_INTERVAL);
        assert_eq!(next_read_timeout(true, false), DRAIN_INTERVAL);
    }
}
