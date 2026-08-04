//! 上流TCPへの接続（Happy Eyeballs風の並行試行）。
//!
//! `TcpStream::connect((host, port))`は、名前解決で得たアドレスを**先頭から順に**試し、
//! 失敗したら次へ進む。これは「先頭のアドレス族が到達不能」な環境で、1接続ごとにその族の
//! 失敗待ち時間を丸ごと支払うことを意味する。
//!
//! この開発機の実測（2026-08-04）:
//!
//! | 接続先 | 所要時間 |
//! |---|---|
//! | `lookup_host("localhost")` の結果 | `["[::1]:p", "127.0.0.1:p"]`（**IPv6が先**） |
//! | `connect(("localhost", p))`（listenerは127.0.0.1のみ） | **約2,030ms** |
//! | `connect(("127.0.0.1", p))` | 約0.4ms |
//! | 閉じたポートへの接続（v4/v6とも） | 約2,050msで`ConnectionRefused` |
//!
//! つまりこのマシンではloopbackの接続失敗の判明に約2秒かかり、`localhost`宛の上流接続は
//! **毎回**その2秒を払っていた。協調プロキシ（[`crate::net_proxy`]）はリクエストのたびに
//! この経路を通るため、テストが不定期にタイムアウトで落ちる原因になっていた
//! （`docs/STATUS.md` Tier2a残課題#6、[BUG-054](../../../docs/bugs/BUG-054.md)）。
//! 本番でも、IPv6のAAAAを返すのにIPv6経路が死んでいるネットワーク（珍しくない）で同じ遅延が出る。
//!
//! RFC 8305（Happy Eyeballs v2）と同じ考え方で解決する。**アドレス族を交互に並べ替え、
//! 少しずつずらして並行に接続を張り、最初に成功したものを採用する**。片方の族が死んでいても
//! 支払うのはstagger分だけになる。
//!
//! ブラウザやcurlが同じ問題に対して同じ解を採っているのは偶然ではない——「解決結果の先頭
//! アドレスが必ず生きている」という前提が現実には成り立たないため。

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;

/// 次のアドレスへ接続を開始するまでの待ち時間（RFC 8305 §5 の Connection Attempt Delay。
/// 推奨250ms、上限2秒）。短くしすぎると常に全アドレスへ同時にSYNを送ることになり、
/// 長くしすぎると本来の目的（死んだ族を素早く見限る）を達成できない。
const ATTEMPT_STAGGER: Duration = Duration::from_millis(250);

/// アドレス族が交互になるよう並べ替える（RFC 8305 §4）。解決結果が
/// `[v6a, v6b, v4a]`なら`[v6a, v4a, v6b]`にする。先頭の族は解決結果の順序を尊重する
/// （OSのアドレス選択ポリシーを覆さない）。
fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6());
    let (mut first, mut second) = (v6.into_iter(), v4.into_iter());
    let mut out = Vec::new();
    // 解決結果の先頭がv4だった場合は、v4を先に出す。
    let mut take_first = true;
    loop {
        let next = if take_first {
            first.next().or_else(|| second.next())
        } else {
            second.next().or_else(|| first.next())
        };
        match next {
            Some(a) => out.push(a),
            None => break,
        }
        take_first = !take_first;
    }
    out
}

/// `host:port`へ接続する。[`TcpStream::connect`]と違い、解決した全アドレスへ
/// [`ATTEMPT_STAGGER`]ずつずらして並行に接続を試み、**最初に成功したもの**を返す。
///
/// 全て失敗した場合は最後のエラーを返す（アドレスが1つも解決できなければ`AddrNotAvailable`）。
pub async fn connect_upstream(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    connect_any(interleave_families(addrs)).await
}

async fn connect_any(addrs: Vec<SocketAddr>) -> std::io::Result<TcpStream> {
    connect_any_with(addrs, TcpStream::connect).await
}

/// [`connect_any`]の本体。実ソケットを開く部分を`connect`として受け取る。
///
/// **注入点を設けた理由**: 「先頭が失敗したら待たずに次へ進む」「決まらなければstagger後に
/// 並行して次を張る」という時間依存の分岐は、実ソケットでは環境に左右されて検証できない
/// （この開発機は接続失敗の判明自体に約2秒かかるため、そもそも“速く失敗するアドレス”を
/// 用意できない）。`docs/CODE-STRUCTURE-RULES.md`規則6の「テストを書くために必要なら注入を
/// 追加する」に従う。
async fn connect_any_with<C, F, S>(addrs: Vec<SocketAddr>, connect: C) -> std::io::Result<S>
where
    C: Fn(SocketAddr) -> F,
    F: std::future::Future<Output = std::io::Result<S>>,
{
    let mut remaining = addrs.into_iter();
    let Some(first) = remaining.next() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "host did not resolve to any address",
        ));
    };

    let mut attempts = FuturesUnordered::new();
    attempts.push(connect(first));

    loop {
        let stagger = tokio::time::sleep(ATTEMPT_STAGGER);
        tokio::pin!(stagger);
        tokio::select! {
            // 一定時間で決まらなければ、次のアドレスも**並行して**試す。
            _ = &mut stagger => {
                if let Some(addr) = remaining.next() {
                    attempts.push(connect(addr));
                }
            }
            // 先に結果が出た場合。失敗なら待たずに次を始める（RFC 8305 §5——
            // 失敗が判明した時点でstaggerを待つ理由は無い。素の`TcpStream::connect`と
            // 同じ速さを正常な環境でも保つために重要）。
            Some(result) = attempts.next(), if !attempts.is_empty() => {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(e) => match remaining.next() {
                        Some(addr) => attempts.push(connect(addr)),
                        // 走っている試行がもう無い＝これが最後の失敗。そのエラーを返す。
                        None if attempts.is_empty() => return Err(e),
                        None => {}
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn families_are_interleaved_starting_with_the_resolvers_first_family() {
        let out = interleave_families(vec![
            sa("[::1]:80"),
            sa("[::2]:80"),
            sa("127.0.0.1:80"),
            sa("127.0.0.2:80"),
        ]);
        assert_eq!(
            out,
            vec![
                sa("[::1]:80"),
                sa("127.0.0.1:80"),
                sa("[::2]:80"),
                sa("127.0.0.2:80")
            ]
        );
    }

    #[test]
    fn a_single_family_keeps_its_original_order() {
        let out = interleave_families(vec![sa("127.0.0.1:80"), sa("127.0.0.2:80")]);
        assert_eq!(out, vec![sa("127.0.0.1:80"), sa("127.0.0.2:80")]);
    }

    #[tokio::test]
    async fn empty_address_list_is_an_error_not_a_hang() {
        let err = connect_any(Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    }

    /// 接続の中身を差し替えるフェイク。`delay`後に`ok`に応じた結果を返し、呼ばれた順序を記録する。
    /// `#[tokio::test(start_paused = true)]`と組み合わせると、待ち時間は仮想時間で進むので
    /// 実時間を1msも消費せずにstaggerの挙動を確定できる。
    fn fake_connector(
        plan: Vec<(SocketAddr, Duration, bool)>,
        log: std::sync::Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    ) -> impl Fn(SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<SocketAddr>>>>
    {
        move |addr: SocketAddr| {
            let entry = plan
                .iter()
                .find(|(a, _, _)| *a == addr)
                .copied()
                .unwrap_or((addr, Duration::ZERO, false));
            log.lock().unwrap().push(addr);
            Box::pin(async move {
                let (addr, delay, ok) = entry;
                tokio::time::sleep(delay).await;
                if ok {
                    Ok(addr)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "fake refused",
                    ))
                }
            })
        }
    }

    /// **これが本題**: 先頭アドレスが決まらないまま固まっても、staggerぶんだけ待って
    /// 2番目を並行に張り、そちらで接続できる。素の`TcpStream::connect`は先頭が返るまで
    /// 一切次へ進まない（この開発機では約2秒、モジュールdoc参照）。
    #[tokio::test(start_paused = true)]
    async fn a_stalled_first_address_falls_back_after_the_stagger() {
        let stalled = sa("[::1]:80");
        let live = sa("127.0.0.1:80");
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let connect = fake_connector(
            vec![
                (stalled, Duration::from_secs(30), false),
                (live, Duration::from_millis(1), true),
            ],
            log.clone(),
        );

        let started = tokio::time::Instant::now();
        let got = connect_any_with(vec![stalled, live], connect).await.unwrap();
        let elapsed = started.elapsed();

        assert_eq!(got, live);
        assert_eq!(*log.lock().unwrap(), vec![stalled, live], "先頭→staggerで2番目");
        assert!(
            elapsed >= ATTEMPT_STAGGER && elapsed < ATTEMPT_STAGGER * 2,
            "staggerぶんだけ待つこと: {elapsed:?}"
        );
    }

    /// 失敗が**速く**判明する正常な環境では、staggerを待たずに次のアドレスへ進む
    /// （RFC 8305 §5）。素の`TcpStream::connect`より遅くならないことの保証。
    #[tokio::test(start_paused = true)]
    async fn a_fast_failure_moves_to_the_next_address_without_waiting_for_the_stagger() {
        let refused = sa("[::1]:80");
        let live = sa("127.0.0.1:80");
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let connect = fake_connector(
            vec![
                (refused, Duration::from_millis(1), false),
                (live, Duration::from_millis(1), true),
            ],
            log.clone(),
        );

        let started = tokio::time::Instant::now();
        let got = connect_any_with(vec![refused, live], connect).await.unwrap();
        let elapsed = started.elapsed();

        assert_eq!(got, live);
        assert!(
            elapsed < ATTEMPT_STAGGER,
            "速い失敗のあとはstaggerを待たない: {elapsed:?}"
        );
    }

    /// 生きているアドレスへ実ソケットで到達できること（フェイクではなく本物の経路の煙試験）。
    #[tokio::test]
    async fn a_dead_first_address_still_reaches_the_live_one_over_real_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    return;
                }
            }
        });
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            drop(l);
            addr
        };

        let stream = connect_any(vec![dead, live]).await.expect("connect");
        assert_eq!(stream.peer_addr().unwrap(), live);
    }

    #[tokio::test]
    async fn the_last_error_is_returned_when_every_address_fails() {
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            drop(l);
            addr
        };
        let err = connect_any(vec![dead]).await.unwrap_err();
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            ),
            "unexpected: {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_upstream_resolves_and_connects_by_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    return;
                }
            }
        });
        let stream = connect_upstream("localhost", port).await.expect("connect");
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }
}
