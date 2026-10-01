//! 自分自身のプロセスへ掛ける緩和策（起動直後に1回だけ呼ぶ）。
//!
//! # 何のためにあるのか
//!
//! サンドボックスの中のコードは、既定のモードではワークスペースの中にジャンクション
//! （別の場所を指すディレクトリ）を作れる（`plans/mac-spike/RESULTS.md` §S81で実測）。
//! 一方、**管理者権限で動くハーネスの補助プロセス**は、サンドボックスより強い権限で
//! ワークスペース配下のパスを開く。そこへジャンクションを置かれると、本来触るはずのない場所を
//! 強い権限で書き換えることになり得る。
//!
//! 今もパスを実体へ解決して封じ込めを確かめる検査（`elevated_launch::validate_sink_under`）が
//! 1枚入っているが、**新しい書込経路を足した人がその検査を呼び忘れると、守りが1枚も無くなる**。
//! ここで足すのは、呼び忘れても効く2枚目である——OSの側でリンクを辿らせない。
//!
//! # 掛ける相手（`docs/STATUS.md`の残課題 サンドボックス周辺 #68）
//!
//! | プロセス | 掛けるか | 理由 |
//! |---|---|---|
//! | `harness-netfilterd.exe` | **掛ける** | 開くのはハーネスが置き場所を決めた監査ログだけで、ユーザーのリンクを読まない |
//! | `harness-policy-learnd.exe` | **掛ける** | 同上 |
//! | `harness-vmsandboxd.exe` | **掛ける** | 同上 |
//! | `harness-privhelper.exe` | **掛けない** | **ユーザーが`--fs-allow`で指定したパス**へアクセス制御リストを書く。リンクを通過するパスを指定されたとき、この緩和策が`ERROR_UNTRUSTED_MOUNT_POINT`（448）で断るので動かなくなる（§S82の測定2で実測） |
//! | `harness.exe`・`harness-spawnd.exe`・`harness-policy-editor.exe` | **掛けない** | ユーザーのワークスペースのファイルを読む。ユーザー自身が張ったリンク（パッケージ管理ツールが作る`node_modules`の中のリンク等）を読めなくなる |
//!
//! # この緩和策が守らないもの
//!
//! - **ハードリンク**には効かない（1つのファイル実体に付いた名前はどれも対等なので、
//!   パスをどう解決しても見つからない）。ただしサンドボックスの子は、許可されていないファイルへ
//!   ハードリンクを張れないことを実測してある（§S81・§S82）
//! - **管理者が作ったリンク**は通る（Windowsがインストール時に作った`C:\Documents and Settings`等）。
//!   断るのは管理者でないユーザーが作ったものだけである
//! - **掛けたプロセス1つにしか効かない。** 子プロセスへは引き継がれないので、
//!   新しく管理者権限のプロセスを足すときは、そのプロセスでも呼ぶこと

/// 自分自身へ「管理者でないユーザーが作ったリンクを辿らない」を掛ける。
///
/// **一度掛けると、そのプロセスが終わるまで外せない。** だから起動直後に1回だけ呼ぶ。
///
/// # 失敗しても止めない
///
/// 掛けられないのは、この版のWindowsが対応していないときである。**掛からなかったことを
/// 理由に起動を止めない**——守りが1枚減るだけで、既存の検査
/// （`elevated_launch::validate_sink_under`）は変わらず効いている。
/// ただし**黙らない**（`B-09`: 成功に見える失敗を作らない）——呼び出し側が結果を記録できるよう、
/// 掛かったかどうかを返す。
#[cfg(windows)]
pub fn refuse_untrusted_links() -> Result<(), String> {
    use windows::Win32::System::SystemServices::PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetProcessMitigationPolicy, ProcessRedirectionTrustPolicy,
        SetProcessMitigationPolicy,
    };

    /// `PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY`の`EnforceRedirectionTrust`ビット（`winnt.h`）。
    const ENFORCE_REDIRECTION_TRUST: u32 = 0x1;

    unsafe {
        let mut policy = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
        policy.Anonymous.Flags = ENFORCE_REDIRECTION_TRUST;
        SetProcessMitigationPolicy(
            ProcessRedirectionTrustPolicy,
            &policy as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        )
        .map_err(|e| format!("SetProcessMitigationPolicy(RedirectionTrust): {e}"))?;

        // **掛かったことを別の口で確かめる**（`SetProcessMitigationPolicy`が成功を返しても、
        // 実際に有効になっていなければ守りは無い。`B-29`: 前提を1つ測る）。
        let mut readback = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessRedirectionTrustPolicy,
            &mut readback as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        )
        .map_err(|e| format!("GetProcessMitigationPolicy(RedirectionTrust): {e}"))?;
        if readback.Anonymous.Flags & ENFORCE_REDIRECTION_TRUST == 0 {
            return Err(format!(
                "the mitigation did not take effect (flags read back as {:#x})",
                readback.Anonymous.Flags
            ));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn refuse_untrusted_links() -> Result<(), String> {
    Err("windows only".to_string())
}

/// 補助プロセスの起動引数で「この緩和策を掛けない」と伝える綴り。
///
/// # なぜ起動引数なのか
///
/// **設定ファイルの値を、コマンドラインのフラグが上書きできるようにするため**である。
/// 補助プロセスが設定ファイルを自分で読む形だと、`harness.exe`がフラグで上書きした結果は
/// そのプロセスへ届かない——フラグで切ったつもりが補助プロセスには効かない、という食い違いが残る。
///
/// **起こす側が最終的な値を渡し、補助プロセスは設定ファイルを読まない。** これで
/// 「読む場所は`harness.exe`とポリシーエディタだけ、効かせる値は渡されたもの1つ」になる。
///
/// # 渡さなかったときは掛ける
///
/// この綴りが引数に無ければ掛ける。**既定を緩い側に倒すと、渡し忘れた経路だけが黙って守りを失う**
/// ——実際、環境変数で運ぶ版ではポリシーエディタ経由の起動に届いておらず、実機で初めて分かった
/// （`B-06`: 同じ状態を作り得る経路を全部数える）。倒れる向きを「守る」側にしておけば、
/// 配線漏れは「切ったのに切れない」として現れ、守りが消える側には倒れない。
pub const NO_LINK_MITIGATION_ARG: &str = "--no-refuse-untrusted-links";

/// 起こす側のプロセスが、起動時に1度だけ決める「補助プロセスへ掛けるか」。
///
/// # なぜプロセスに1つ持つのか
///
/// 補助プロセスを起こす箇所は3つ（netfilterd・policy-learnd・vmsandboxd）あり、
/// どれも`harness.exe`やポリシーエディタの奥から呼ばれる。**値を引数で引き回すと、
/// 途中の関数すべてに欄が1つ増える**——そして増やし忘れた経路だけが既定で動く。
/// 起動時に1度決まって以後変わらない値なので、プロセスに1つ持たせて取りに行く形にする。
///
/// **設定されていなければ掛ける。** 倒れる向きを「守る」側にしておけば、
/// 呼び忘れは「切ったのに切れない」として現れ、守りが消える側には倒れない。
static LINK_MITIGATION: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// 起こす側が、設定ファイルとコマンドラインのフラグを解決した結果を置く。
///
/// **起動時に1度だけ呼ぶ。** 2度目以降は無視される（`OnceLock`）——
/// 途中で変わる値ではないし、変えられると「どの時点の値で起こしたか」が追えなくなる。
pub fn set_link_mitigation(refuse_untrusted_links: bool) {
    let _ = LINK_MITIGATION.set(refuse_untrusted_links);
}

/// 補助プロセスの起動引数の末尾へ足す綴り。
///
/// 掛けるなら空、掛けないなら[`NO_LINK_MITIGATION_ARG`]（前に空白を1つ付ける）。
/// **3つの起こす箇所が同じ関数を通る**ので、綴りが片方だけずれることがない（`B-05`）。
pub fn link_mitigation_arg_suffix() -> &'static str {
    if *LINK_MITIGATION.get().unwrap_or(&true) {
        ""
    } else {
        concat!(" ", "--no-refuse-untrusted-links")
    }
}

/// 自分の起動引数に「掛けない」の綴りがあるか。
///
/// **純粋な判定にしてあるのは、切る側と掛ける側を対で測れるようにするため**である
/// （Win32を1行も呼ばないので、普通の`cargo test`で回る）。
pub fn args_disable_link_mitigation<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|a| a.as_ref() == NO_LINK_MITIGATION_ARG)
}

/// [`refuse_untrusted_links`]を呼び、結果を標準エラーへ1行書く。
///
/// 管理者権限で動く3つの補助プロセスが**同じ1行**を出すための共通の入口である
/// （各`main`で文面を書くと、いつか片方だけ古くなる。`B-05`）。
///
/// # 切るかどうかは起こす側が決める
///
/// 判断の材料は`cli-defaults.toml`の`security.refuse_untrusted_links`と、それを上書きする
/// コマンドラインのフラグで、**どちらも起こす側（`harness.exe`・ポリシーエディタ）が解決し、
/// 結果だけが起動引数で届く**（[`NO_LINK_MITIGATION_ARG`]）。このプロセスは設定ファイルを読まない。
///
/// **切った起動では診断ログへ1行残す**——守りが1枚減ったことが、後から障害を追う人に
/// 見えないまま流れないようにする。
pub fn harden_elevated_helper(process_name: &str) {
    if args_disable_link_mitigation(std::env::args()) {
        let message = format!(
            "[{process_name}] mitigation disabled by the caller \
             (security.refuse_untrusted_links = false, or the matching command-line flag): \
             this process may follow links created by non-administrators; \
             the path checks before each write still apply"
        );
        eprintln!("{message}");
        // **切ったことは必ず残す。** このプロセスの標準エラーはどこにも繋がらないので、
        // ここへ書かないと「守りを1枚外して動いている」ことの記録が1つも無くなる。
        log_to_privhelper_diagnostics(&message);
        return;
    }
    match refuse_untrusted_links() {
        Ok(()) => eprintln!(
            "[{process_name}] mitigation: refusing to follow links created by non-administrators"
        ),
        Err(e) => {
            let message = format!(
                "[{process_name}] warning: could not refuse links created by non-administrators \
                 ({e}); the path checks before each write still apply"
            );
            eprintln!("{message}");
            // **失敗したときだけ、消えないところへも書く。**
            //
            // この3つのプロセスは`runas`で起こされるので、**標準エラーはどこにも繋がらない**
            // ——上の`eprintln!`は実運用では誰にも届かない。掛からなかったこと（＝守りが1枚減った
            // こと）が無言で流れるのは、成功に見える失敗そのものである（`B-09`）。
            //
            // 書き先は特権ヘルパーの診断ログと同じファイルにする。新しい置き場を作ると、
            // 障害のときに読む人が2つのファイルを知っていなければならなくなる。
            // **成功したときは書かない**——普段から行が増えると、異常の行が埋もれる。
            log_to_privhelper_diagnostics(&message);
        }
    }
}

/// 特権ヘルパーの診断ログ（`%APPDATA%\harness\config\privhelper.log`）へ1行追記する。
///
/// **台帳ファイルには一切触れない**（`CLAUDE.md`の台帳誤削除防止の規約と同じ理由で、
/// 台帳の読み書きとは独立させる）。書けなくても呼び出し側の処理は止めない——
/// 診断の副次経路であり、ここの失敗が緩和策の成否を左右してはならない。
fn log_to_privhelper_diagnostics(message: &str) {
    use std::io::Write;

    let Some(dirs) = directories::ProjectDirs::from("", "", "harness") else {
        return;
    };
    let path = dirs.config_dir().join("privhelper.log");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "[{now_ms}] pid={} {message}", std::process::id());
    }
}

#[cfg(all(windows, test))]
mod tests {
    /// **この関数は、呼んだプロセスに後戻りできない変更を加える。** だから製品の関数を
    /// テストプロセスで呼ばず、**別プロセス**（テスト用のプローブ）で確かめる
    /// ——`tier2a-proc-probe --redirection-trust enforce` が同じWin32呼び出しを行い、
    /// 掛かったことを読み戻しで確かめる（`plans/mac-spike/RESULTS.md` §S81・§S82）。
    ///
    /// ここで測れるのは、**呼び出しの形が壊れていないこと**だけである——
    /// 掛けてしまうとこのテストプロセスの以後の全テストに効くので、呼ばない。
    #[test]
    fn the_mitigation_struct_has_the_size_the_api_expects() {
        use windows::Win32::System::SystemServices::PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
        // `SetProcessMitigationPolicy`は大きさで版を見分ける。構造体が1つの`u32`の共用体より
        // 大きくなったら、渡す大きさが合わなくなって`ERROR_INVALID_PARAMETER`で落ちる。
        assert_eq!(
            core::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
            4,
            "the policy struct changed size; the call would be rejected"
        );
    }
}

#[cfg(test)]
mod toggle_tests {
    /// **設定の既定は「守る」側である。**
    ///
    /// ここで測れるのは既定値だけで、**実際に掛かるかはこのテストプロセスでは測れない**
    /// ——緩和策は一度掛けると外せないので、製品の関数をテストプロセスで呼べない
    /// （実機の確認は`plans/mac-spike/RESULTS.md` §S83、計器は`tier2a-proc-probe`）。
    ///
    /// 設定ファイルの読み取り（壊れていたら拒否する・誤字を無視しない等）は
    /// `harness-user-config`の単体テストが固定している。
    /// **禁止側**: 「掛けない」の綴りが引数にあれば切ると読む。
    #[test]
    fn the_disable_argument_is_recognised() {
        assert!(super::args_disable_link_mitigation([
            "harness-netfilterd.exe",
            "a-pipe-name",
            super::NO_LINK_MITIGATION_ARG,
        ]));
    }

    /// **許可側（対）**: 綴りが無ければ掛ける。似た綴りにも反応しない。
    ///
    /// これが無いと「常に切る」実装でも上のテストが緑になる（`B-35`）。
    #[test]
    fn anything_else_keeps_the_mitigation_on() {
        assert!(!super::args_disable_link_mitigation([
            "harness-netfilterd.exe",
            "a-pipe-name",
        ]));
        assert!(!super::args_disable_link_mitigation([
            "harness-vmsandboxd.exe",
            "--owner-sid",
            "S-1-5-21-0",
            "--refuse-untrusted-links",
        ]));
    }

    /// 起こす側が足す綴りと、受ける側が探す綴りが**同じ**である。
    ///
    /// 別々に書くと、片方だけ直したときに「切ったのに切れない」が無言で成立する（`B-05`）。
    #[test]
    fn the_suffix_the_launcher_appends_is_what_the_helper_looks_for() {
        // 既定（まだ`set_link_mitigation`を呼んでいない）は掛ける側なので空。
        assert_eq!(super::link_mitigation_arg_suffix(), "");
        // 切る側の綴りは、受ける側が探すものと一致する。
        assert_eq!(
            concat!(" ", "--no-refuse-untrusted-links").trim(),
            super::NO_LINK_MITIGATION_ARG
        );
    }

    #[test]
    fn the_default_configuration_keeps_the_mitigation_on() {
        assert!(
            harness_user_config::UserConfig::default()
                .security
                .refuse_untrusted_links,
            "既定を緩い側に置くと、設定ファイルを消しただけで守りが外れる"
        );
    }
}
