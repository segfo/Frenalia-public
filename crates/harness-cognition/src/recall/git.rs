//! Recallの記憶ディレクトリのgit履歴化。`plans/PLAN-RECALL-MEMORY.md`「git履歴化」。
//!
//! **ここで起動するgitは必ず[`harness_core::git::hardening_env`]を経由する**
//! （設計変更A）。記憶ディレクトリは`data_dir()`配下（ワークスペース外）にあるが、
//! Tier0/Tier1（隔離なし）では`run_shell`の子プロセスがharnessと同一ユーザー権限で動くため、
//! ワークスペース内に`.git/hooks/post-commit`を仕込まれたリポジトリをモデルに操作させれば
//! （あるいは記憶ディレクトリへ直接到達できれば）、次のcheckpoint書込みのたびに任意コードが
//! 実行される経路になり得る。ハードニングenvは**フック経由の**この経路を塞ぐ。
//!
//! **ハードニングenvだけでは足りない**（[BUG-150](../../../../docs/bugs/BUG-150.md)）。
//! 2026-09-04の実測で、envを全部載せても外部プログラムを起動できるgitの設定キーが14件あり、
//! そのうち`filter.<名前>.clean`は**下の[`commit_all`]が呼ぶ`git add -A`で発火する**ことを
//! 確認した（記憶ディレクトリの`.git/config`と`.gitattributes`を1度書ければ、
//! 以後のcheckpointごとに無人で起動する）。
//!
//! このモジュールのdocが以前「構造的に塞ぐ」と書いていたのは誤りで、
//! 実際に塞げていたのは`core.hooksPath`だけだった。
//!
//! # いま塞いでいるもの（2026-09-20、BUG-150の案E）
//!
//! [`commit_all`]は**gitを起こす前に`.git/config`を手つかずへ戻す**。
//! 記憶ディレクトリのリポジトリは**harnessが自分で作り自分だけが使う**ので、
//! 「`git init`が書くものだけを許す」というallowlistで言い切れる
//! ——deny listでは原理的に列挙できない（キーの真ん中が任意の文字列になる形が7件ある）。
//!
//! **塞いだのはこの無人の経路だけである。** ワークスペース側の`.git/config`は
//! `D-06`の射程を変える決定（BUG-150の案C・案D）が要るので、そちらは手つかずのまま。

use std::path::Path;
use std::process::Command;

/// このマシンに`git`があるか（`PATH`解決）。
pub(crate) fn git_available() -> bool {
    which::which("git").is_ok()
}

/// `dir`が`.git/`を持たなければ`git init`する。
pub(crate) fn ensure_repo(dir: &Path) -> Result<(), String> {
    if dir.join(".git").exists() {
        return Ok(());
    }
    run(dir, &["init", "--quiet"])
}

/// [BUG-150 案E] このリポジトリの`.git/config`に、`git init`が書いたもの以外が混ざっていないか。
///
/// # なぜdeny listではなくallowlistなのか
///
/// 外部プログラムを起動できるgitの設定キーは**14件あり、うち7件はキーの真ん中が任意の文字列**
/// （`filter.<名前>.clean`・`diff.<名前>.command`等）なので、**完全一致のdeny listでは
/// 原理的に列挙できない**。さらにdeny listはgitの版が上がってキーが増えるたびに黙って弱くなる。
///
/// **記憶ディレクトリのリポジトリはharnessが自分で作り自分だけが使う**ので、
/// そこに正当なユーザー設定は1つも無い。だから「`git init`が書くものだけを許す」と言い切れる。
/// この形なら、gitに新しいキーが増えても自動的に閉じる。
///
/// # 許すものは実測から取った
///
/// 一覧は`git init --quiet`が実際に書いた`[core]`の6キー（2026-09-20、git for Windows）。
/// **推測ではない。** ここに無いものが1つでも在れば、`Some(その行)`を返す。
///
/// 戻り値は**最初に見つかった行**（人へ見せる用）。`None`なら手つかずである。
fn first_unexpected_config_line(text: &str) -> Option<String> {
    /// `git init`が書く唯一のセクション。
    const ALLOWED_SECTION: &str = "core";
    /// そのセクションで`git init`が書くキー（小文字で比較する）。
    const ALLOWED_KEYS: &[&str] = &[
        "repositoryformatversion",
        "filemode",
        "bare",
        "logallrefupdates",
        "symlinks",
        "ignorecase",
        // 実測には出なかったが、環境によっては`git init`が書く。**危険側ではない**
        // （どれも外部プログラムを起動しない）ので許す。
        "precomposeunicode",
        "hidedotfiles",
    ];

    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // `[filter "x"]`のようなサブセクション付きも、先頭の語だけ見れば足りる。
            section = inner
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_ascii_lowercase();
            if section != ALLOWED_SECTION {
                return Some(raw.to_string());
            }
            continue;
        }
        let key = line
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        // セクション宣言の外に出た値（壊れたconfig）も想定外として扱う。
        if section != ALLOWED_SECTION || !ALLOWED_KEYS.contains(&key.as_str()) {
            return Some(raw.to_string());
        }
    }
    None
}

/// [BUG-150 案E] 記憶ディレクトリの`.git/config`を、**gitを起こす前に**手つかずの状態へ戻す。
///
/// 想定外のキーが1つでも在れば`config`を消して`git init`し直す。**内容を手で書き戻さない**のは、
/// 正しい既定がこの環境の`git`にしか分からないため（`ignorecase`等はファイルシステム依存）。
///
/// # 限界（**同じ場所に書く**）
///
/// - **ワークスペース側の穴は塞がない。** ここで守るのは記憶ディレクトリだけである
///   （[BUG-150](../../../../docs/bugs/BUG-150.md)の案C・案Dの代わりにはならない）。
/// - **`.gitattributes`は見ない。** 発火の定義は`.git/config`側にあるので、
///   そちらを手つかずに保てば`.gitattributes`だけでは何も起こらない。
/// - **時間差は残る。** 検査してから`git`が読むまでの隙に書き換えられる可能性は消えない。
///   ただしこの経路を踏めるのは**harnessと同一権限で動く子**（Tier0/Tier1）だけで、
///   そこまで来ている相手には他の手段もある。**塞ぐ機構ではなく、無人で踏む経路を消すもの。**
fn ensure_pristine_config(dir: &Path) -> Result<(), String> {
    let config = dir.join(".git").join("config");
    let text = match std::fs::read_to_string(&config) {
        Ok(text) => text,
        // 読めない＝形が想定と違う。**無言で続けない**（`B-10`）。作り直しに任せる。
        Err(_) => String::from("<unreadable>"),
    };
    let Some(offending) = first_unexpected_config_line(&text) else {
        return Ok(());
    };
    // **黙って直さない。** 記憶ディレクトリのconfigは harness しか書かないので、
    // 想定外の行が在ること自体が運用者の知るべき事実である。
    eprintln!(
        "warning: the recall memory repository's .git/config carried a line harness did not put \
         there; rewriting it from scratch before running git (BUG-150). offending line: \
         {offending}"
    );
    let _ = std::fs::remove_file(&config);
    // `git init`は既存リポジトリに対しても走り、欠けている`config`をこの環境の既定で書き戻す。
    run(dir, &["init", "--quiet"])
}

/// `git add -A && git commit`。**変更が無い場合は成功扱い**（初回オープン直後の空リポジトリ等）。
pub(crate) fn commit_all(dir: &Path, message: &str) -> Result<(), String> {
    // [BUG-150 案E] **`git add`より前に置く。** `filter.<名前>.clean`が発火するのは
    // `git add`であって`git commit`ではない。
    ensure_pristine_config(dir)?;
    run(dir, &["add", "-A"])?;
    match run(dir, &["commit", "--quiet", "-m", message]) {
        Ok(()) => Ok(()),
        Err(e) if e.contains("nothing to commit") => Ok(()),
        Err(e) => Err(e),
    }
}

fn run(dir: &Path, args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).args(args);
    // allowlist方式のクリーンenv + gitハードニング（設計変更A）。`run_shell`のモデル実行・
    // `resolve.rs`の内部`git merge-file`と同じ定義を共有する（`harness_core::git`のdoc参照）。
    for (k, v) in harness_core::git::hardening_env() {
        cmd.env(k, v);
    }
    cmd.env(
        "GIT_AUTHOR_NAME",
        std::env::var("GIT_AUTHOR_NAME").unwrap_or_else(|_| "harness".to_string()),
    );
    cmd.env(
        "GIT_AUTHOR_EMAIL",
        std::env::var("GIT_AUTHOR_EMAIL").unwrap_or_else(|_| "harness@localhost".to_string()),
    );
    cmd.env("GIT_COMMITTER_NAME", "harness");
    cmd.env("GIT_COMMITTER_EMAIL", "harness@localhost");

    let output = cmd
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "git {} failed: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skip_if_no_git() -> bool {
        if !git_available() {
            eprintln!("skipping: git not found in PATH");
            return true;
        }
        false
    }

    #[test]
    fn ensure_repo_is_idempotent() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        assert!(dir.path().join(".git").exists());
        // 2回目も成功する（既に`.git`があれば何もしない）。
        ensure_repo(dir.path()).unwrap();
    }

    /// [BUG-150 案E] **禁止側**: `git init`が書いたままのconfigは手つかずと判定する。
    ///
    /// これが無いと「常に作り直す」実装でも許可側のテストは通る。常に作り直すと、
    /// 毎回のcheckpointでgitをもう1回起こすことになる（費用が静かに増える）。
    #[test]
    fn a_freshly_initialised_config_is_left_alone() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join(".git").join("config")).unwrap();
        assert_eq!(
            first_unexpected_config_line(&text),
            None,
            "`git init`が書いた内容を想定外と判定している。許可一覧が実体からずれた: {text}"
        );
    }

    /// [BUG-150 案E] **許可側**: 外部プログラムを起動できるキーを見つける。
    ///
    /// 実測（2026-09-04）で`git add`が発火させることを確認した形をそのまま使う。
    /// **キーの真ん中が任意の文字列**なので、完全一致のdeny listでは列挙できない——
    /// だからこの判定はallowlistでなければならない。
    #[test]
    fn a_poisoned_filter_section_is_detected() {
        let poisoned = "[core]\n\trepositoryformatversion = 0\n\
             [filter \"pwn\"]\n\tclean = /usr/bin/echo PWNED\n";
        let found = first_unexpected_config_line(poisoned)
            .expect("`filter.<名前>.clean`を見逃した。これは`git add`で発火する");
        assert!(found.contains("filter"), "{found}");
    }

    /// [BUG-150 案E] `[core]`の中に紛れ込んだ危険なキーも見つける。
    ///
    /// セクション名だけを見る実装だと、ここが素通りする——`core.pager`・`core.sshCommand`は
    /// どちらも外部プログラムを起動する。
    #[test]
    fn a_dangerous_key_inside_core_is_detected() {
        for key in ["pager", "sshCommand", "hooksPath", "editor", "worktree"] {
            let text = format!("[core]\n\trepositoryformatversion = 0\n\t{key} = /bin/pwn\n");
            assert!(
                first_unexpected_config_line(&text).is_some(),
                "core.{key} を見逃した: {text}"
            );
        }
    }

    /// [BUG-150 案E] **無人の経路が実際に閉じるか**——毒を仕込んでからcheckpointを走らせる。
    ///
    /// 記憶ディレクトリのcheckpointは、ユーザーがgitを打たなくてもharnessが自分の都合で走らせる。
    /// **仕込んだあとは放置でよい**というのが、この経路がとくに重い理由だった。
    #[test]
    fn a_checkpoint_rewrites_a_poisoned_config_before_running_git() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        let config = dir.path().join(".git").join("config");

        // `git add`が発火点になる形（実測済み）。あわせて`.gitattributes`も置く——
        // **これだけでは何も起きない**ことも同時に確かめる（発火の定義はconfig側にある）。
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("[filter \"pwn\"]\n\tclean = /usr/bin/echo PWNED\n");
        std::fs::write(&config, &text).unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "* filter=pwn\n").unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();

        commit_all(dir.path(), "checkpoint: poisoned").expect("checkpoint must still succeed");

        let after = std::fs::read_to_string(&config).unwrap();
        assert!(
            !after.contains("filter"),
            "[BUG-150] checkpointの後も毒入りの設定が残っている。次のcheckpointで無人のまま\
             発火する: {after}"
        );
        assert_eq!(
            first_unexpected_config_line(&after),
            None,
            "作り直した後のconfigがまだ手つかずでない: {after}"
        );
    }

    #[test]
    fn commit_all_records_a_new_file() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        commit_all(dir.path(), "checkpoint: test").unwrap();

        let log = Command::new("git")
            .current_dir(dir.path())
            .args(["log", "--oneline"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&log.stdout).contains("checkpoint: test"));
    }

    /// commit対象が無いとき（2回連続で同じ状態でcommit）もエラーにしない。
    #[test]
    fn commit_all_is_a_no_op_when_there_is_nothing_to_commit() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        commit_all(dir.path(), "first").unwrap();
        commit_all(dir.path(), "second").unwrap();
    }

    /// `.git/hooks/post-commit`を仕込んでも実行されない（設計変更A、`core.hooksPath`を
    /// 存在しないパスへ向けるハードニング）。
    #[test]
    fn hooks_do_not_fire() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let marker = dir.path().join("HOOK_FIRED");
        #[cfg(windows)]
        let hook_body = format!(
            "#!/bin/sh\necho fired > \"{}\"\n",
            marker.to_string_lossy().replace('\\', "/")
        );
        #[cfg(not(windows))]
        let hook_body = format!("#!/bin/sh\necho fired > '{}'\n", marker.display());
        let hook_path = hooks_dir.join("post-commit");
        std::fs::write(&hook_path, hook_body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&hook_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&hook_path, perms).unwrap();
        }

        std::fs::write(dir.path().join("b.txt"), "x").unwrap();
        commit_all(dir.path(), "checkpoint: hook test").unwrap();

        assert!(
            !marker.exists(),
            "post-commit hook fired despite hardening env"
        );
    }
}
