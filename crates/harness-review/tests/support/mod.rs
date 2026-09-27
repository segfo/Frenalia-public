//! 結合テストの器: 一時フォルダの本物の git で「本物のリポジトリ」と「CoW セッションの差分層」を作る。
//!
//! 差分層は Redirector を通さずに**終わった後の形**だけを再現する——エージェントの見え方
//! （本物の複製）で git を回し、本物と比べて増えた・変わったファイルを差分層の同じ相対パスへ
//! 写し、消えたファイルを操作台帳の `delete` 行にする。段5の実セッションの記録
//! （`plans/cow-default-spike/raw/…ops-ledger.jsonl`）と同じ形である: 新しいゆるい ref、
//! `HEAD` の書換、ゆるいオブジェクト、ファイルとしては残らない削除。本体層の pack が
//! バイト同一でコピーされる形（net-spike N8-M1-i）も [`SimOptions::copy_up_base_packs`] で作れる。
//!
//! **実マシンのものには触れない。** 置き場の根・`HOME`（利用者のグローバル設定）・git の
//! 作業ディレクトリはすべてこの器の一時フォルダの中にある。

#![allow(dead_code)]
// 器はエージェントの役（とテストの検算）として素の git を回す。ハーネスの起動器を通すと、
// 「ハーネスの git が読まないこと」を測る相手まで同じ起動器で動かすことになり、対照にならない。
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;

use harness_review::GitLauncher;

pub struct Fixture {
    _root: tempfile::TempDir,
    pub base: PathBuf,
    pub home: PathBuf,
    pub ws: PathBuf,
    pub review_root: PathBuf,
    pub scratch: PathBuf,
    pub cow_root: PathBuf,
    pub launcher: GitLauncher,
}

#[derive(Default, Clone, Copy)]
pub struct SimOptions {
    /// 本体層の pack を、差分層へバイト同一で写す（実セッションで起きる copy-up の形）。
    pub copy_up_base_packs: bool,
}

pub fn git_exe() -> PathBuf {
    which::which("git").expect("these tests need git on PATH")
}

impl Fixture {
    /// 本物のリポジトリ（`main` に2コミット、`old` 枝、`v0` タグ。`gc` 済みで本体層は pack）を作る。
    /// 置き場のパスには日本語と空白を含める（alternates・worktree がそれで壊れないことも測る）。
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("レビュー 試験");
        let home = base.join("home");
        let ws = base.join("ws").join("repo");
        let review_root = base.join("review");
        let scratch = base.join("scratch");
        let cow_root = base.join("cow");
        for d in [&home, &ws, &review_root, &scratch, &cow_root] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = t\n\temail = t@example.com\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let launcher = GitLauncher::new(git_exe(), test_env(&home), scratch.clone());
        let fx = Self {
            _root: root,
            base,
            home,
            ws,
            review_root,
            scratch,
            cow_root,
            launcher,
        };
        fx.git(&fx.ws, &["init", "-q"]);
        write(&fx.ws.join("README.md"), "hello\n");
        write(&fx.ws.join("src/lib.txt"), "fn original() {}\n");
        fx.git(&fx.ws, &["add", "-A"]);
        fx.git(&fx.ws, &["commit", "-q", "-m", "c1"]);
        fx.git(&fx.ws, &["branch", "old"]);
        fx.git(&fx.ws, &["tag", "v0"]);
        write(&fx.ws.join("docs/guide.txt"), "guide\n");
        fx.git(&fx.ws, &["add", "-A"]);
        fx.git(&fx.ws, &["commit", "-q", "-m", "c2"]);
        fx.git(&fx.ws, &["gc", "-q"]);
        fx
    }

    /// 器を組むための素の git（ハーネスの起動器ではない）。失敗したら panic する。
    pub fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = self.git_raw(dir, args);
        assert!(
            out.status.success(),
            "git {args:?} in {} failed: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// stdin を渡す版（`hash-object --stdin` など）。
    pub fn git_stdin(&self, dir: &Path, args: &[&str], input: &[u8]) -> String {
        use std::io::Write;
        let mut child = Command::new(git_exe())
            .args(args)
            .current_dir(dir)
            .env_clear()
            .envs(test_env(&self.home))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// 発火したら記録を残す仕掛けの置き場。
    pub fn markers(&self) -> Markers {
        let dir = self.base.join("markers");
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("fired.log");
        let script = dir.join("log.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$1\" >> \"{}\"\ncat\n", sh_path(&log)),
        )
        .unwrap();
        Markers { log, script }
    }

    pub fn git_raw(&self, dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new(git_exe())
            .args(args)
            .current_dir(dir)
            .env_clear()
            .envs(test_env(&self.home))
            .output()
            .unwrap()
    }

    /// セッション1本を再現する。`script` はエージェントの見え方（本物の複製）で git を回す。
    /// 戻り値は差分層のフォルダ（`<cow_root>/<sid>`）とエージェントの見え方のフォルダ。
    pub fn session(
        &self,
        sid: &str,
        opts: SimOptions,
        script: impl FnOnce(&Path),
    ) -> (PathBuf, PathBuf) {
        let agent = self.base.join(format!("agent-{sid}"));
        copy_tree(&self.ws, &agent);
        script(&agent);
        let dl = self.cow_root.join(sid);
        std::fs::create_dir_all(&dl).unwrap();
        let mut ledger = String::new();
        let mut op = |kind: &str, rel: &str| {
            ledger.push_str(&format!(
                "{{\"op\":\"{kind}\",\"path\":\"{rel}\",\"baseline_hash\":null,\"ts_unix_millis\":1}}\n"
            ));
        };
        for rel in files_under(&agent) {
            let real = self.ws.join(&rel);
            let theirs = std::fs::read(agent.join(&rel)).unwrap();
            match std::fs::read(&real) {
                Ok(ours) if ours == theirs => continue,
                Ok(_) => op("modify", &rel),
                Err(_) => op("create", &rel),
            }
            let dest = dl.join(&rel);
            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            std::fs::write(dest, theirs).unwrap();
        }
        for rel in files_under(&self.ws) {
            if !agent.join(&rel).exists() {
                op("delete", &rel);
            }
        }
        if opts.copy_up_base_packs {
            for rel in files_under(&self.ws) {
                if rel.starts_with(".git/objects/pack/") && rel.ends_with(".pack") {
                    let dest = dl.join(&rel);
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::copy(self.ws.join(&rel), dest).unwrap();
                    op("modify", &rel);
                }
            }
        }
        std::fs::write(dl.join(".harness-cow-ops.jsonl"), ledger).unwrap();
        #[cfg(windows)]
        harness_sandbox::tier2a::workspace_ledger::write_cow_session_meta(&dl, &self.ws, sid);
        (dl, agent)
    }

    pub fn request<'a>(&'a self, dl: &'a Path) -> harness_review::ReviewRequest<'a> {
        harness_review::ReviewRequest {
            workspace_root: &self.ws,
            diff_layer_dir: dl,
            review_root: &self.review_root,
            scratch_parent: &self.scratch,
        }
    }

    /// 本物の ref（名前 → 値）。
    pub fn real_refs(&self) -> Vec<(String, String)> {
        self.git(
            &self.ws,
            &["for-each-ref", "--format=%(refname) %(objectname)"],
        )
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(n, o)| (n.to_string(), o.to_string()))
        .collect()
    }
}

/// テストの git に渡す環境。`HOME` をこの器の中へ向け、利用者の実際のグローバル設定を読まない。
pub fn test_env(home: &Path) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            matches!(
                k.to_ascii_uppercase().as_str(),
                "PATH"
                    | "SYSTEMROOT"
                    | "WINDIR"
                    | "COMSPEC"
                    | "PATHEXT"
                    | "TEMP"
                    | "TMP"
                    | "SYSTEMDRIVE"
                    | "PROGRAMFILES"
                    | "PROGRAMDATA"
                    | "APPDATA"
                    | "LOCALAPPDATA"
            )
        })
        .collect();
    let home = home.to_string_lossy().into_owned();
    env.push(("HOME".into(), home.clone()));
    env.push(("USERPROFILE".into(), home));
    env.push(("GIT_CONFIG_NOSYSTEM".into(), "1".into()));
    env
}

/// 書く。git が読み取り専用で作ったファイル（ゆるいオブジェクト・commit-graph）も上書きする
/// ——子はそれらの所有者なので書き換えられる。測る側が書き換えられないまま測ると、
/// 攻撃者にできることを測れていない（net-spike N8-M1補の「踏んだ罠」と同じ形）。
pub fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    make_writable(path);
    std::fs::write(path, text).unwrap();
}

pub fn make_writable(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

/// `/` 区切りの相対パスで、`dir` の下のファイルを全部返す。
pub fn files_under(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

/// ディレクトリごと写す（空のディレクトリも。gc の後の `.git/refs/heads` は空で、git は
/// `refs` が無いとリポジトリと認めない）。
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// 発火すると `fired.log` に名前を1行書く仕掛け（フィルタとしても使えるよう、stdin を
/// そのまま stdout へ流す）。
pub struct Markers {
    pub log: PathBuf,
    pub script: PathBuf,
}

impl Markers {
    /// フィルタ・外部 diff として設定に書くコマンド。
    pub fn command(&self, name: &str) -> String {
        format!("sh \\\"{}\\\" {name}", sh_path(&self.script))
    }

    /// フックとして置くスクリプトの中身。
    pub fn hook(&self, name: &str) -> String {
        format!(
            "#!/bin/sh\nsh \"{}\" {name} < /dev/null > /dev/null\n",
            sh_path(&self.script)
        )
    }

    pub fn fired(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// シェルから見たパス（`/` 区切り）。フックやフィルタのコマンド文字列に埋める。
pub fn sh_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
