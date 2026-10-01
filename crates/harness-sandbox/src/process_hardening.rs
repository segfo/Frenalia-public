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

/// この緩和策を掛けるかどうかを、ユーザー単位の設定から読む。
///
/// # なぜ起こす側から渡さず、このプロセスが自分で読むのか
///
/// **補助プロセスを起こす経路が1つではないからである。** `harness.exe`だけでなく
/// `harness-policy-editor.exe`も同じ補助プロセス（netfilterd・policy-learnd）を起こす。
/// 起こす側が値を運ぶ形にすると、**運ぶ処理を書いた経路でしか設定が効かない**
/// ——実際、`harness.exe`側にだけ配線した版を実機で撃ったところ、ポリシーエディタ経由の起動では
/// 設定が無視されていた（`B-06`: 同じ状態を作り得る経路を全部数える）。
///
/// **読む規則は`harness_user_config::load`ただ1つ**なので、読む場所が複数でも正本は1つである。
/// `harness.exe`も起動時に同じ関数を呼ぶが、あちらの目的は**壊れていたら早く止める**ことで、
/// 掛けるかどうかの判断はここで行う。
///
/// # 読めないときは掛ける
///
/// 設定ファイルを読めない（置き場を決められない・壊れている）ときは**掛ける側へ倒す**。
/// 倒れる向きが「守る」側になるのが要点で、設定を読めなかったことを理由に守りを外さない。
/// **ただし黙らない**——読めなかったことを診断ログへ1行書く。
fn user_wants_the_mitigation() -> (bool, Option<String>) {
    match harness_user_config::load() {
        Ok(config) => (config.security.refuse_untrusted_links, None),
        Err(e) => (
            true,
            Some(format!(
                "could not read the user configuration ({e}); keeping the mitigation on"
            )),
        ),
    }
}

/// [`refuse_untrusted_links`]を呼び、結果を標準エラーへ1行書く。
///
/// 管理者権限で動く3つの補助プロセスが**同じ1行**を出すための共通の入口である
/// （各`main`で文面を書くと、いつか片方だけ古くなる。`B-05`）。
///
/// # ユーザーが切っているときは掛けない
///
/// 判断の材料は`cli-defaults.toml`の`security.refuse_untrusted_links`で、
/// **このプロセス自身が読む**（[`user_wants_the_mitigation`]）。
/// **切った起動では診断ログへ1行残す**——守りが1枚減ったことが、後から障害を追う人に
/// 見えないまま流れないようにする。
pub fn harden_elevated_helper(process_name: &str) {
    let (wanted, warning) = user_wants_the_mitigation();
    if let Some(warning) = warning {
        let message = format!("[{process_name}] warning: {warning}");
        eprintln!("{message}");
        log_to_privhelper_diagnostics(&message);
    }
    if !wanted {
        let message = format!(
            "[{process_name}] mitigation disabled by the user configuration \
             (security.refuse_untrusted_links = false in cli-defaults.toml): this process may \
             follow links created by non-administrators; the path checks before each write still apply"
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
