//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）] 拒否されたopenを、受付（broker）へ
//! 1往復して**1回だけ**やり直すための子側。
//!
//! # ここは境界ではない（D-01）
//!
//! 1件も通らなくても失われるのは速さだけである。境界はNTFSのDACLとAppContainer tokenのままで、
//! このDLLが外されても・迂回されても`ACCESS_DENIED`が残る。だから**失敗はすべて
//! 「やり直さない」へ倒す**——例外を投げたり、開けたことにしたりはしない。
//!
//! # 呼ばれるのは失敗した後だけである（着手条件4）
//!
//! フックは本来のopenを**先に**呼び、`ACCESS_DENIED`が返ったときだけここへ来る。
//! 成功経路でパスを分類しない理由は費用で、`plans/mac-spike/RESULTS.md` §S25が
//! 「前に置くと1 openあたり+28.3 µs、後ろなら+1.4 µs」を実測している。
//!
//! # なぜ`harness-sandbox`のフレーミングを共有しないのか
//!
//! このクレートは**注入先の非信頼プロセス内で動く**ので、境界を構成する側のクレートに
//! 依存しない（`Cargo.toml`の宣言）。したがってワイヤ形式は**両端で別々に実装される**
//! ——ずれたことをコンパイラは教えてくれないので、[`frame_tests`]がバイト列を固定し、
//! 受付側（`harness-sandbox`の`win_pipe_ipc`）にも同じ形式の固定テストがある。
//!
//! # 再入させない
//!
//! ここが使う`CreateFileW`/`ReadFile`/`WriteFile`は`NtCreateFile`へ降りてフックに戻るが、
//! 呼び出し元が`ReentryGuard`を握ったままここへ来るので、フック本体は素通しする。
//! **ガードを持たずにここを呼んではいけない**——要求のためのopenが自分自身の要求を生む。

use std::sync::Mutex;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::*;

/// 1往復に掛ける上限。**新しい数字を増やさない**（着手条件5）——既存の
/// ready ハンドシェイク（`wait_cow_ready`）と同じ5秒。
///
/// ここに引っ掛かるのは「受付が居るのに返事が来ない」＝writerが全walkに占有されているか
/// マシンが詰まっているかで、**どちらも待ち先は同じ**なので、諦めて元の拒否を返す
/// （呼び出し側がbarrierへ倒す判断を持つ）。
const ROUNDTRIP_TIMEOUT_MS: u32 = 5_000;

/// [D-88] 「準備が終わるまで待つ」要求の上限。**待つのが目的なので長い。**
///
/// 5秒で切ると「フックも無く、準備も終わっていない」という最悪の組み合わせで走り出す。
/// 数字は起動側の準備待ちの上限（`grant_job::WAIT_TIMEOUT`＝300秒）に合わせてある
/// ——**待ち先が同じなら上限も同じであるべき**で、こちらだけ短いと、
/// 起動側がまだ待つ気でいるのに子だけ先に諦めることになる。
const WAIT_PREPARED_TIMEOUT_MS: u32 = 300_000;

/// 受付への接続。**1本を張りっぱなしにする**——1 openごとに接続し直すと、
/// §S20が測った往復29.2 µsに接続の費用が毎回乗る。
static CONNECTION: Mutex<Option<isize>> = Mutex::new(None);

/// 受付の答え。`harness-sandbox`側の`FaultResponse`と**同じ綴り**でなければならない
/// （[`response_tests`]が固定する）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FaultOutcome {
    /// 付与された。**同じopenを1回だけ**やり直してよい。
    Retry,
    /// **受付へ届かなかった**（パイプが無い・切れた・返事が来ない）。やはり1回だけやり直す。
    ///
    /// # なぜ諦めずにやり直すのか（ここが barrier の代わりである）
    ///
    /// 受付は**準備が完走した時点で閉じる**。したがって「届かない」の最も多い原因は
    /// 「**もう全部配り終わった**」であり、そのときやり直せば開く。設計書§5.1.3は
    /// このケースを「全walk barrierで待ってから、失敗したopenだけを1回再試行する」と
    /// 定めているが、**1プロセスの中では待つ相手が既に居ない**——待ちの終わりと
    /// 受付が閉じる瞬間が同じだからである。だから待たずに、同じ「1回だけの再試行」を行う。
    ///
    /// **限界**: 準備が**失敗して**終わった場合も同じ経路を通り、やり直しても開かない。
    /// そのときは元の拒否がそのまま返る——`Unavailable`を`Denied`へ翻訳していないので、
    /// 権限が広がる側へは倒れない。
    RetryAnyway,
    /// **ポリシー拒否**。全walkが終わっても変わらないので、**やり直さない**。
    ///
    /// ここを[`Self::RetryAnyway`]と混ぜてはいけない——workspace外や`.harness/`への
    /// アクセスを、拒否されるたびに2回ずつ叩くことになる。
    GiveUp,
}

/// [D-88] **フックを入れられなかった子を、動かす前に待たせる。**
///
/// 準備が終わるまで受付が返事をしないので、この呼び出しはそのぶんブロックする。
/// 返ってから一時停止を解けば、その子はフックが無くても**配り終わったツリー**を見る。
///
/// # なぜ「待つ」がここでしか選べないのか
///
/// 走り出した後は巻き戻せない——`ls`が半分読んだところで「やっぱり最初から待とう」には
/// できない。**一時停止中の子だけが、まだ何も起きていないので待てる。**
///
/// 受付へ届かなければ`false`を返す。呼び出し側は**それでも動かす**こと——
/// 動かさないと一時停止のまま残る（`B-01`: 止めたものを動かす対を必ず書く）。
pub(crate) fn wait_until_workspace_prepared(cfg: &Config) -> bool {
    if cfg.broker_pipe.is_none() {
        return false;
    }
    matches!(
        roundtrip_request(cfg, "{\"kind\":\"wait_prepared\"}", WAIT_PREPARED_TIMEOUT_MS),
        FaultOutcome::Retry
    )
}

/// 拒否されたパスを受付へ伝え、やり直してよいかを返す。
///
/// **呼び出し側は`ReentryGuard`を握っていること**（モジュールdoc）。
pub(crate) fn request_fault_in(cfg: &Config, path: &Path) -> FaultOutcome {
    // 以降、**受付へ届かなかった場合はすべて`RetryAnyway`**（[`FaultOutcome::RetryAnyway`]のdoc）。
    // `GiveUp`を返すのは受付が明示的に拒否したときだけである。
    let request = format!(
        "{{\"kind\":\"grant\",\"path\":{}}}",
        json_string(&path.to_string_lossy())
    );
    roundtrip_request(cfg, &request, ROUNDTRIP_TIMEOUT_MS)
}

/// 受付へ1件送って答えを待つ。接続は張りっぱなしにし、切れていたら**1度だけ**張り直す。
///
/// `timeout_ms`を引数にしてあるのは、**待つのが目的の要求**（[`wait_until_workspace_prepared`]）と
/// **速さが目的の要求**（fault）で上限が違うからである——前者を5秒で切ると、
/// 「フックも無く準備も終わっていない」という最悪の組み合わせで走り出す。
fn roundtrip_request(cfg: &Config, request: &str, timeout_ms: u32) -> FaultOutcome {
    let Some(pipe_name) = cfg.broker_pipe.as_deref() else {
        return FaultOutcome::GiveUp;
    };
    let mut guard = CONNECTION.lock().unwrap_or_else(|e| e.into_inner());
    // 1回だけ張り直す。**張り直しを繰り返さない**のは、受付が閉じた後
    // （＝準備が完走した後）に毎回の失敗openが接続を試みるのを避けるため。
    for attempt in 0..2 {
        if guard.is_none() {
            match connect(pipe_name) {
                Some(handle) => *guard = Some(handle.0 as isize),
                // パイプが無い＝準備が終わって受付が閉じた可能性が高い。
                None => return FaultOutcome::RetryAnyway,
            }
        }
        let handle = HANDLE(guard.unwrap() as *mut _);
        match roundtrip(handle, request.as_bytes(), timeout_ms) {
            Some(reply) => return parse_outcome(&reply),
            None => {
                // 切れていた。ハンドルを捨てて、**1度だけ**張り直す。
                unsafe {
                    let _ = CloseHandle(handle);
                }
                *guard = None;
                if attempt == 1 {
                    return FaultOutcome::RetryAnyway;
                }
            }
        }
    }
    FaultOutcome::RetryAnyway
}

/// 応答JSONから結論だけを取り出す。
///
/// **3つの答えを3つのまま運ぶ**（受付側`FaultResponse`と1対1）。
/// `unavailable`を`GiveUp`へ畳むと、**準備が終わっただけの状況で開けるはずのファイルを
/// 諦める**ことになる（[`FaultOutcome::RetryAnyway`]のdoc）。
///
/// **知らない綴りは`GiveUp`**——受付が将来新しい応答を足したときに、子が勝手にやり直さない
/// 側へ倒す。
pub(crate) fn parse_outcome(reply: &[u8]) -> FaultOutcome {
    let text = String::from_utf8_lossy(reply);
    if text.contains("\"kind\":\"retry\"") {
        FaultOutcome::Retry
    } else if text.contains("\"kind\":\"unavailable\"") {
        FaultOutcome::RetryAnyway
    } else {
        FaultOutcome::GiveUp
    }
}

/// JSON文字列リテラルへ変換する（`\`と`"`と制御文字だけを逃がす）。
///
/// **Windowsのパスは`\`を含む**ので、ここを素通しにすると受付側のJSON解析が壊れる
/// ——壊れると要求が1件も通らず、しかも症状は「なぜかfault-inが効かない」という静かな形になる。
pub(crate) fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn connect(pipe_name: &str) -> Option<HANDLE> {
    unsafe {
        // NUL終端のUTF-16へ（`ledger.rs`の`nt_path_wide`と同じ作り方）。
        let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        CreateFileW(
            PCWSTR(name_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        .ok()
    }
}

/// 1フレーム書いて1フレーム読む。`None`は「この接続はもう使えない」。
fn roundtrip(pipe: HANDLE, payload: &[u8], timeout_ms: u32) -> Option<Vec<u8>> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &len, timeout_ms)?;
    write_all(pipe, payload, timeout_ms)?;
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf, timeout_ms)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    // 受付の応答は短い。**上限を置く**のは、壊れた長さで巨大な確保をしないため。
    if len > 64 * 1024 {
        return None;
    }
    let mut reply = vec![0u8; len];
    if len > 0 {
        read_exact(pipe, &mut reply, timeout_ms)?;
    }
    Some(reply)
}

fn write_all(pipe: HANDLE, buf: &[u8], timeout_ms: u32) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let chunk = &buf[done..];
        let n = overlapped(pipe, timeout_ms, |ov| unsafe { WriteFile(pipe, Some(chunk), None, Some(ov)) })?;
        if n == 0 {
            return None;
        }
        done += n as usize;
    }
    Some(())
}

fn read_exact(pipe: HANDLE, buf: &mut [u8], timeout_ms: u32) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let chunk = &mut buf[done..];
        let n = overlapped(pipe, timeout_ms, |ov| unsafe { ReadFile(pipe, Some(chunk), None, Some(ov)) })?;
        if n == 0 {
            return None;
        }
        done += n as usize;
    }
    Some(())
}

/// オーバーラップドI/Oを[`ROUNDTRIP_TIMEOUT_MS`]付きで回す。
///
/// タイムアウトしたら`CancelIoEx`で取り消し、**取り消しの完了まで待ってから**返る
/// （`bWait=true`）——待たずに返ると、この関数のスタックにある`OVERLAPPED`をカーネルが
/// まだ見ている状態でスタックが巻き戻る。`harness-sandbox`の`run_overlapped`が
/// 同じ理由で同じことをしている。
fn overlapped<F>(pipe: HANDLE, timeout_ms: u32, start: F) -> Option<u32>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    unsafe {
        let event = CreateEventW(None, true, false, None).ok()?;
        let mut ov = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };
        let started = start(&mut ov as *mut _);
        let pending = match started {
            Ok(()) => false,
            Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => true,
            Err(_) => {
                let _ = CloseHandle(event);
                return None;
            }
        };
        if pending && WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0 {
            let _ = CancelIoEx(pipe, Some(&ov as *const _));
            let mut discarded = 0u32;
            let _ = GetOverlappedResult(pipe, &ov, &mut discarded, true);
            let _ = CloseHandle(event);
            return None;
        }
        let mut transferred = 0u32;
        let ok = GetOverlappedResult(pipe, &ov, &mut transferred, true).is_ok();
        let _ = CloseHandle(event);
        ok.then_some(transferred)
    }
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    /// **ワイヤ形式を固定する。** 受付側（`harness-sandbox`）とは別クレート・別プロセスで、
    /// **どちらかだけを直してもコンパイルは通る**（モジュールdoc）。ここが両端を繋ぐ唯一の錨である。
    #[test]
    fn the_request_is_a_json_object_with_the_kind_and_the_path() {
        let request = format!(
            "{{\"kind\":\"grant\",\"path\":{}}}",
            json_string(r"C:\ws\src\lib.rs")
        );
        assert_eq!(
            request,
            r#"{"kind":"grant","path":"C:\\ws\\src\\lib.rs"}"#,
            "this must match harness-sandbox's FaultRequest wire format byte for byte"
        );
    }

    /// **バックスラッシュを逃がさないと要求が1件も通らない。** Windowsのパスは`\`だらけで、
    /// 素通しにすると受付側のJSON解析が落ちる——しかも症状は「なぜか効かない」だけである。
    #[test]
    fn windows_separators_and_quotes_are_escaped() {
        assert_eq!(json_string(r"C:\a\b"), r#""C:\\a\\b""#);
        assert_eq!(json_string("say \"hi\""), r#""say \"hi\"""#);
        assert_eq!(json_string("tab\there"), r#""tab\there""#);
    }

    /// **3つの答えを3つのまま運ぶ。**
    ///
    /// 対で見る（`B-35`）——`denied`と`unavailable`を両方測らないと、片方に畳んだ実装でも
    /// 片側のassertだけは通る。畳むとどちらの向きでも壊れる: `unavailable`を`GiveUp`にすると
    /// **準備が終わっただけのファイルを諦め**、`denied`を`RetryAnyway`にすると
    /// **workspace外への拒否を毎回2回叩く**。
    #[test]
    fn the_three_answers_stay_three() {
        assert_eq!(parse_outcome(br#"{"kind":"retry"}"#), FaultOutcome::Retry);
        assert_eq!(
            parse_outcome(br#"{"kind":"unavailable","reason":"later"}"#),
            FaultOutcome::RetryAnyway
        );
        assert_eq!(
            parse_outcome(br#"{"kind":"denied","reason":"outside"}"#),
            FaultOutcome::GiveUp
        );
        // 知らない綴り・空は**やり直さない側**へ倒す。
        assert_eq!(parse_outcome(b""), FaultOutcome::GiveUp);
        assert_eq!(parse_outcome(br#"{"kind":"something-new"}"#), FaultOutcome::GiveUp);
    }
}
