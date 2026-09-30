//! 【使い捨て——複製を消すコミットでこのファイルごと消す】
//!
//! 昇格ランナーの`win`（名前付きパイプIPCの下回りの複製）と、`harness_sandbox::win_pipe_ipc`
//! （privhelper・netfilterd・vmsandboxdが共有するモジュール）が、同じ入力に対して
//! **同じDACLと同じワイヤ上のバイト列**を作ることを、複製を消す前に固定する
//! （`docs/CODE-STRUCTURE-RULES.md`規則6）。
//!
//! 比べる相手の複製ごと消えるので、切り替えのコミットでこのテストも消す（同規則2「判定が出た
//! 使い捨ての実験は残さない」）。切り替え後にワイヤ形式とDACLを固定し続けるのは
//! `harness_sandbox::tier2a::privhelper`の`pipe_ipc_characterization`である。
//!
//! フレームの受け渡しは**両方向**で見る。切り替えの前後で、古い常駐役（複製）と新しい依頼役
//! （共有モジュール）が同じパイプで会話し得るためである。
//!
//! 端の形は実物に合わせる——サーバ端は常駐役（`server.rs`）と同じオーバーラップド、
//! クライアント端は依頼役（`client.rs`）と同じ`FILE_FLAG_OVERLAPPED`なしで開く。

use crate::win as copy;
use harness_sandbox::win_common::wide as shared_wide;
use harness_sandbox::win_pipe_ipc as shared;
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

const TIMEOUT: Duration = Duration::from_secs(5);

/// 接続済みのパイプ1本。`server`は常駐役と同じ形、`client`は依頼役と同じ形で開く。
struct Pair {
    server: HANDLE,
    client: Option<HANDLE>,
}

impl Pair {
    fn connect() -> Self {
        let name = shared::unique_pipe_name("dev-elevated-runner-equivalence");
        let sid = shared::current_user_sid_string().expect("current_user_sid_string");
        let mut sa = shared::user_only_security_attributes(&sid).expect("security attributes");
        let name_w = shared_wide(&name);
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            )
        };
        unsafe {
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        }
        assert!(!server.is_invalid(), "CreateNamedPipeW failed");

        let client_thread = std::thread::spawn(move || unsafe {
            let name_w = shared_wide(&name);
            CreateFileW(
                PCWSTR(name_w.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )
            .expect("client CreateFileW")
            .0 as usize
        });
        shared::connect_with_timeout(server, TIMEOUT).expect("connect_with_timeout");
        let client = HANDLE(client_thread.join().unwrap() as *mut _);
        Pair {
            server,
            client: Some(client),
        }
    }

    fn client(&self) -> HANDLE {
        self.client.expect("client end is still open")
    }

    fn close_client(&mut self) {
        if let Some(client) = self.client.take() {
            unsafe {
                let _ = CloseHandle(client);
            }
        }
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        self.close_client();
        unsafe {
            let _ = DisconnectNamedPipe(self.server);
            let _ = CloseHandle(self.server);
        }
    }
}

/// 読み書きする側の実装。エラー型が2つで違うので、比べるために文字列へ揃える。
#[derive(Clone, Copy)]
struct Side {
    name: &'static str,
    write: fn(HANDLE, &[u8]) -> Result<(), String>,
    read: fn(HANDLE) -> Result<Vec<u8>, String>,
}

const COPY: Side = Side {
    name: "copy",
    write: |h, p| copy::write_framed_timeout(h, p, TIMEOUT).map_err(|e| e.to_string()),
    read: |h| copy::read_framed_timeout(h, TIMEOUT).map_err(|e| e.to_string()),
};

const SHARED: Side = Side {
    name: "shared",
    write: |h, p| shared::write_framed_timeout(h, p, TIMEOUT).map_err(|e| e.to_string()),
    read: |h| shared::read_framed_timeout(h, TIMEOUT).map_err(|e| e.to_string()),
};

/// 依頼役の端は同期ハンドルなので、`ReadFile`は相手が書くまで待ち続けてタイムアウトしない。
/// 書き手が失敗したときにテストごと固まらないよう、全体を別スレッドで回して待ち時間を区切る。
fn within_deadline<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(60))
        .expect("the exchange panicked or did not finish within 60s")
}

/// 依頼（依頼役→常駐役）と応答（常駐役→依頼役）を1往復させ、両方向で中身が一致することを見る。
/// 書き手は別スレッドに置く——パイプのバッファ（4096バイト）を超えるフレームは、
/// 読み手が読むまで書き終わらないため。
fn round_trip(client_side: Side, server_side: Side, payload: Vec<u8>) {
    within_deadline(move || {
        let pair = Pair::connect();
        let label = format!(
            "client={} server={} len={}",
            client_side.name,
            server_side.name,
            payload.len()
        );

        let client = pair.client().0 as usize;
        let request = payload.clone();
        let writer =
            std::thread::spawn(move || (client_side.write)(HANDLE(client as *mut _), &request));
        let received = (server_side.read)(pair.server).unwrap_or_else(|e| panic!("{label}: {e}"));
        writer
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(received == payload, "{label}: request differs");

        let server = pair.server.0 as usize;
        let response = payload.clone();
        let writer =
            std::thread::spawn(move || (server_side.write)(HANDLE(server as *mut _), &response));
        let received = (client_side.read)(pair.client()).unwrap_or_else(|e| panic!("{label}: {e}"));
        writer
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(received == payload, "{label}: response differs");
    });
}

fn dacl_sddl(sa: SECURITY_ATTRIBUTES) -> String {
    let mut out = windows::core::PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(sa.lpSecurityDescriptor),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut out,
            None,
        )
        .expect("ConvertSecurityDescriptorToStringSecurityDescriptorW");
        let sddl = out.to_string().expect("SDDL is valid UTF-16");
        let _ = LocalFree(HLOCAL(out.0 as *mut _));
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        sddl
    }
}

#[test]
fn both_produce_the_same_wide_strings_and_the_same_caller_sid() {
    for s in ["", "runas", r"\\.\pipe\dev-elevated-runner-S-1-5-21-1", "日本語"] {
        assert_eq!(copy::wide(s), shared_wide(s), "{s:?}");
    }
    let copy_sid = copy::current_user_sid_string().expect("copy sid");
    let shared_sid = shared::current_user_sid_string().expect("shared sid");
    assert_eq!(copy_sid, shared_sid);
    assert!(copy_sid.starts_with("S-1-5-"), "{copy_sid}");
}

/// 両者とも「呼び出しユーザー1人にだけ全権」のDACLを作る。互いの一致だけでなく絶対値も見る
/// ——両方が同じ壊れ方をしていても落ちるように。
#[test]
fn both_build_a_dacl_that_names_only_the_calling_user() {
    let sid = shared::current_user_sid_string().expect("sid");
    let copy_sa = copy::user_only_security_attributes(&sid).expect("copy sa");
    let shared_sa = shared::user_only_security_attributes(&sid).expect("shared sa");

    assert_eq!(copy_sa.nLength, shared_sa.nLength);
    assert_eq!(copy_sa.bInheritHandle.0, 0, "copy: handle must not be inheritable");
    assert_eq!(shared_sa.bInheritHandle.0, 0, "shared: handle must not be inheritable");

    let copy_sddl = dacl_sddl(copy_sa);
    let shared_sddl = dacl_sddl(shared_sa);
    assert_eq!(copy_sddl, shared_sddl);
    assert_eq!(copy_sddl, format!("D:(A;;GA;;;{sid})"));
}

/// ワイヤ上のバイト列そのものが同じ（`[4バイトLE長][ペイロード]`）。往復だけでは、書き手と
/// 読み手が同じ向きにずれたときに気付けないので、生のバイトを読む。
#[test]
fn both_put_the_same_bytes_on_the_wire() {
    for side in [COPY, SHARED] {
        let pair = Pair::connect();
        (side.write)(pair.client(), b"hi").expect("write hi");
        (side.write)(pair.client(), b"").expect("write empty");

        let mut raw = [0u8; 10];
        shared::read_exact_timeout(pair.server, &mut raw, TIMEOUT).expect("read raw");
        assert_eq!(raw, [2, 0, 0, 0, b'h', b'i', 0, 0, 0, 0], "{}", side.name);

        // 余計なバイトを書いていない（続けて読むと何も来ずに時間切れになる）。
        let mut extra = [0u8; 1];
        assert!(
            shared::read_exact_timeout(pair.server, &mut extra, Duration::from_millis(200))
                .is_err(),
            "{}: wrote bytes beyond the frames",
            side.name
        );
    }
}

/// 古い常駐役×新しい依頼役、新しい常駐役×古い依頼役のどちらでも会話が成り立つ。
#[test]
fn frames_cross_between_the_copy_and_the_shared_module_in_both_directions() {
    let large: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    for payload in [Vec::new(), b"hi".to_vec(), large] {
        round_trip(SHARED, COPY, payload.clone());
        round_trip(COPY, SHARED, payload);
    }
}

/// 何も届かなければ、両者とも指定の時間で諦めて`Err`を返す（無限に待たない）。
#[test]
fn both_give_up_when_nothing_arrives() {
    for side in ["copy", "shared"] {
        let pair = Pair::connect();
        let started = Instant::now();
        let short = Duration::from_millis(300);
        let failed = match side {
            "copy" => copy::read_framed_timeout(pair.server, short).is_err(),
            _ => shared::read_framed_timeout(pair.server, short).is_err(),
        };
        assert!(failed, "{side}: expected a timeout error");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{side}: did not return promptly after the timeout"
        );
    }
}

/// 相手がパイプを閉じたら、両者とも`Err`を返す（空のフレームを成功として返さない）。
#[test]
fn both_fail_when_the_peer_has_closed_the_pipe() {
    for side in ["copy", "shared"] {
        let mut pair = Pair::connect();
        pair.close_client();
        let failed = match side {
            "copy" => copy::read_framed_timeout(pair.server, TIMEOUT).is_err(),
            _ => shared::read_framed_timeout(pair.server, TIMEOUT).is_err(),
        };
        assert!(failed, "{side}: expected an error after the peer closed");
    }
}
