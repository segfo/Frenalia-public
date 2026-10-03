//! [BUG-208] Tier1が作業フォルダへ低ILラベルを付けられなかったときに、**利用者とモデルへ言う文**。
//!
//! # 何が起きているか
//!
//! Tier1の子は低い整合性レベル（低IL）で走り、低ILの印（必須ラベル）を付けたフォルダにしか書けない。
//! 印を付けるのは`run_shell`のたびに`harness_sandbox::tier1::win_restricted::set_low_integrity_label`で、
//! 付けるには、そのフォルダに対する`WRITE_OWNER`（「所有権の取得」）がこのアカウントに要る。
//! ドライブ直下に一般ユーザーが作ったフォルダは「変更」までしか持たないので付けられず、
//! そのときは**作業フォルダの中にも1つも書けない**（範囲外への書込の拒否はそのまま効く）。
//!
//! # 文が言うこと（B-32）
//!
//! 何が足りないか（このフォルダに対する「所有権の取得」）・何が起きるか（`run_shell`の子はこのフォルダに
//! 書けない。読むのと`write_file`/`edit_file`は影響を受けない）・どうすればよいか（フル コントロールを持つ
//! 場所を作業フォルダにする／所有者なら自分に権限を足す）。**同じ文を利用者（stderr）とモデル（結果の
//! フッタ）の両方へ出す**——綴りを2つ持つと片方だけ直る（B-05）。
//!
//! # 起動時に1度だけ言わないのはなぜか
//!
//! 印は`run_shell`の`cwd`へ付ける。`cwd`はコマンドごとにワークスペースの中のどこでもよい（`resolve_cwd`）ので、
//! 起動時にワークスペースの根だけを調べても、実際に付けるフォルダと別のものを調べることになる（B-21）。
//! だから付けるその場で判定し、**同じフォルダのアクセス拒否は利用者へ1回だけ**言う（[`should_tell_the_user`]）。
//! モデルへは毎回フッタで言う（モデルは前の結果を読み返さずに同じ書込を試すので）。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use harness_sandbox::tier1::win_restricted::LabelError;

/// 直し方の文に埋める、このアカウントの名前とユーザープロファイルの場所。
///
/// 試験で決まった値を渡せるよう、環境から読むのは[`Remedy::from_env`]だけにしてある。
pub(crate) struct Remedy {
    /// `DOMAIN\user`。分からなければ`None`（コマンドを示さず、言葉だけで言う）。
    pub(crate) account: Option<String>,
    /// `%USERPROFILE%`の実際の値。分からなければ`None`。
    pub(crate) profile: Option<String>,
}

impl Remedy {
    pub(crate) fn from_env() -> Self {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let account = match (get("USERDOMAIN"), get("USERNAME")) {
            (Some(domain), Some(user)) => Some(format!("{domain}\\{user}")),
            (None, Some(user)) => Some(user),
            _ => None,
        };
        Self {
            account,
            profile: get("USERPROFILE"),
        }
    }
}

/// 低ILラベルを付けられなかったことを言う1つの文（先頭の`warning:`や括弧は付けない）。
pub(crate) fn label_failure_text(cwd: &Path, e: &LabelError, remedy: &Remedy) -> String {
    let cwd = cwd.display();
    let consequence = "Without the label, commands run by run_shell cannot create or change any \
                       file in this folder (reading still works, and write_file/edit_file are not \
                       affected)";
    match e {
        LabelError::AccessDenied { .. } => {
            let place = match &remedy.profile {
                Some(profile) => format!("for example a folder under {profile}"),
                None => "for example a folder under your user profile".to_string(),
            };
            let grant = match &remedy.account {
                Some(account) => format!(
                    "or, if you own this folder, grant yourself that permission without \
                     administrator rights: icacls \"{cwd}\" /grant \"{account}:(WO)\""
                ),
                None => "or, if you own this folder, grant your account the \"Take ownership\" \
                         permission on it (no administrator rights are needed for the owner)"
                    .to_string(),
            };
            format!(
                "Tier1 could not apply the low-integrity label to its working folder {cwd}: this \
                 account does not have the \"Take ownership\" (WRITE_OWNER) permission on that \
                 folder, which writing the label requires (\"Modify\" does not include it). \
                 {consequence}. To fix it, use a working folder where your account has Full \
                 control ({place}), {grant}."
            )
        }
        LabelError::Other(_) => format!(
            "Tier1 could not apply the low-integrity label to its working folder {cwd} ({e}). \
             {consequence}."
        ),
    }
}

/// 利用者へ言うか。**同じフォルダのアクセス拒否は、プロセスの間で1回だけ**言う。
///
/// アクセス拒否はフォルダのACLの性質で、コマンドのたびに変わらない。ほかの失敗は理由が分からないので
/// 毎回言う（まとめると、2回目以降に別の理由で落ちたことが見えなくなる）。
pub(crate) fn should_tell_the_user(cwd: &Path, e: &LabelError) -> bool {
    static TOLD: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    match e {
        LabelError::AccessDenied { .. } => first_time(TOLD.get_or_init(Default::default), cwd),
        LabelError::Other(_) => true,
    }
}

/// `seen`に`dir`が無ければ入れて`true`を返す。錠が壊れていたら言う側へ倒す（黙らない）。
fn first_time(seen: &Mutex<HashSet<PathBuf>>, dir: &Path) -> bool {
    match seen.lock() {
        Ok(mut seen) => seen.insert(dir.to_path_buf()),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(dir: &str) -> LabelError {
        LabelError::AccessDenied {
            dir: PathBuf::from(dir),
        }
    }

    fn remedy() -> Remedy {
        Remedy {
            account: Some("EVO-X2\\segfo".to_string()),
            profile: Some("C:\\Users\\segfo".to_string()),
        }
    }

    /// 実機で出た場面（ドライブ直下のフォルダ）の文が、**何が足りないか・何が起きるか・どうすればよいか**を
    /// 言うこと（B-32）。直す前の文は「Mandatory Controlが拒否する」としか言わず、理由も直し方も無かった。
    #[test]
    fn the_access_denied_text_says_what_is_missing_what_happens_and_what_to_do() {
        let cwd = Path::new("C:\\harness-e2e\\tui-check");
        let text = label_failure_text(cwd, &denied("C:\\harness-e2e\\tui-check"), &remedy());

        // 何が足りないか
        assert!(text.contains("\"Take ownership\" (WRITE_OWNER)"), "{text}");
        assert!(text.contains("\"Modify\" does not include it"), "{text}");
        // 何が起きるか（書けないもの・影響を受けないもの）
        assert!(
            text.contains("cannot create or change any file in this folder"),
            "{text}"
        );
        assert!(
            text.contains("write_file/edit_file are not affected"),
            "{text}"
        );
        // どうすればよいか（場所を変える・所有者なら自分に足す）
        assert!(text.contains("Full control"), "{text}");
        assert!(text.contains("C:\\Users\\segfo"), "{text}");
        assert!(
            text.contains("icacls \"C:\\harness-e2e\\tui-check\" /grant \"EVO-X2\\segfo:(WO)\""),
            "{text}"
        );
        // どのフォルダの話か
        assert!(text.contains("C:\\harness-e2e\\tui-check"), "{text}");
    }

    /// アカウント名が分からないときは、**打てないコマンドを示さない**（言葉で言う）。
    #[test]
    fn without_an_account_name_the_text_does_not_show_a_broken_command() {
        let text = label_failure_text(
            Path::new("C:\\w"),
            &denied("C:\\w"),
            &Remedy {
                account: None,
                profile: None,
            },
        );
        assert!(!text.contains("icacls"), "{text}");
        assert!(text.contains("\"Take ownership\" permission"), "{text}");
        assert!(text.contains("your user profile"), "{text}");
    }

    /// アクセス拒否以外の失敗は、理由をそのまま出し、直し方を**推測で書かない**（B-32）。
    #[test]
    fn other_failures_keep_the_reason_and_do_not_guess_a_fix() {
        let e = LabelError::Other(
            harness_sandbox::tier1::win_restricted::RestrictedError::Win32(
                "SetNamedSecurityInfoW failed: WIN32_ERROR(1336)".to_string(),
            ),
        );
        let text = label_failure_text(Path::new("C:\\w"), &e, &remedy());
        assert!(text.contains("WIN32_ERROR(1336)"), "{text}");
        assert!(text.contains("cannot create or change any file"), "{text}");
        assert!(!text.contains("WRITE_OWNER"), "{text}");
        assert!(!text.contains("icacls"), "{text}");
    }

    /// 同じフォルダのアクセス拒否は1回だけ利用者へ言い、**別のフォルダ**は別に言う。
    #[test]
    fn the_user_is_told_once_per_folder() {
        let seen = Mutex::new(HashSet::new());
        assert!(first_time(&seen, Path::new("C:\\a")));
        assert!(
            !first_time(&seen, Path::new("C:\\a")),
            "同じフォルダは2度言わない"
        );
        assert!(first_time(&seen, Path::new("C:\\b")), "別のフォルダは言う");

        // 入口（`run_windows_tier1`が呼ぶもの）がこの覚え方を通っていること。プロセスの間で共有される
        // 覚えなので、他の試験と重ならない名前で測る。
        let dir = Path::new("C:\\the-user-is-told-once-per-folder");
        assert!(should_tell_the_user(dir, &denied("C:\\x")));
        assert!(
            !should_tell_the_user(dir, &denied("C:\\x")),
            "同じフォルダのアクセス拒否は2度言わない"
        );
    }

    /// アクセス拒否以外は毎回言う（まとめると、別の理由で落ちたことが見えなくなる）。
    #[test]
    fn other_failures_are_told_every_time() {
        let e = || {
            LabelError::Other(
                harness_sandbox::tier1::win_restricted::RestrictedError::Win32("x".to_string()),
            )
        };
        let dir = Path::new("C:\\other-failures-are-told-every-time");
        assert!(should_tell_the_user(dir, &e()));
        assert!(should_tell_the_user(dir, &e()));
    }
}
