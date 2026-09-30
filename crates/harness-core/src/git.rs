//! harnessが起動する全`git`が共有するハードニングenv。
//!
//! 元は`harness-sandbox`の`secret_env`にあったが、`harness-cognition`（Recall機構、
//! `plans/PLAN-RECALL-MEMORY.md`）が独自にgitを起動する必要があり、`harness-cognition`は
//! `harness-sandbox`（Win32/ACL/AppContainerを抱える重いクレート）へ依存しない設計のため、
//! 依存が軽い`harness-core`へ移した。`harness-sandbox`は再エクスポートで既存呼び出し元
//! （`shell.rs`のモデル実行・`resolve.rs`の内部`git merge-file`）を無改造のまま保つ。

/// harnessが起動する全`git`（`run_shell`経由のモデル実行・`resolve.rs`の内部`git merge-file`・
/// Recallのcheckpoint git履歴化・`harness-review`のレビュー経路の4経路）へ適用する、
/// 自動発火経路だけを潰すenv（D-06/D-14b、
/// `plans/DESIGN-SANDBOX-APPPOLICY.md` §5.2）。`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/
/// `GIT_CONFIG_VALUE_n`（git 2.31+）は`-c`と同じ最高優先度の設定として扱われ、攻撃者が書き換える
/// `.git/config`では上書きできない。
///
/// global config（`user.name`・credential helper・`safe.directory`）は意図的に生かす——
/// `GIT_CONFIG_GLOBAL`/`SYSTEM`を空へ向ける旧`hardened_git_command`方式は、モデル実行`git commit`が
/// `Author identity unknown`で即死する副作用を持つため採用しない。system config
/// （`GIT_CONFIG_NOSYSTEM=1`）のみ無効化する。`core.hooksPath`は存在しないパスでよい
/// （gitは不在のhookを黙ってスキップする）。
///
/// **この機構の限界（`docs/bugs/BUG-150.md`）**: ここで固定しているのは`core.hooksPath`・
/// `core.fsmonitor`・`core.pager`の3項目だけで、**外部プログラムを起動できるgitの設定キーは
/// 他に14件ある**（2026-09-04にgit 2.51.1.windows.1で全件実測）。うち7件は
/// `diff.<名前>.command`・`filter.<名前>.clean`のようにキーの真ん中が攻撃者の決める
/// 任意文字列なので、完全一致でしか固定できない`GIT_CONFIG_KEY_n`では**原理的に潰せない**。
/// `.git/config`へ書ける構成（＝CoWモード以外）では、これは許可リストの内側のRCE経路になる。
/// **ここへキーを足す形は完成しないので、足す前にBUG-150の案A〜Eを読むこと。**
///
/// **Recallのようにこの機構の外側で新しくgitを起動する経路を追加するときは、必ずここを通す**
/// （`bug-pattern-rules` B-06「不変条件を変えたなら全経路を数えたか」——「harnessが起動する
/// git全てがハードニング済み」という不変条件を成立させる呼び出し元は現在4箇所。
/// 4箇所目の`harness-review`（`launcher.rs`）は、このenvに加えて**エージェントの`.git`を
/// git dirとして一度も渡さない**構造で D-110 (vi) を守っている——このenvだけでは
/// `.git/config`を無効にできないため）。
pub fn hardening_env() -> Vec<(String, String)> {
    vec![
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_CONFIG_COUNT".to_string(), "2".to_string()),
        ("GIT_CONFIG_KEY_0".to_string(), "core.hooksPath".to_string()),
        (
            "GIT_CONFIG_VALUE_0".to_string(),
            "harness-empty-git-hooks-dir-does-not-exist".to_string(),
        ),
        ("GIT_CONFIG_KEY_1".to_string(), "core.fsmonitor".to_string()),
        ("GIT_CONFIG_VALUE_1".to_string(), "false".to_string()),
        ("GIT_PAGER".to_string(), "cat".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_env_disables_hooks_fsmonitor_and_pager() {
        let env = hardening_env();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("GIT_CONFIG_NOSYSTEM"), Some("1"));
        assert_eq!(get("GIT_CONFIG_COUNT"), Some("2"));
        assert_eq!(get("GIT_CONFIG_KEY_0"), Some("core.hooksPath"));
        assert_eq!(get("GIT_CONFIG_KEY_1"), Some("core.fsmonitor"));
        assert_eq!(get("GIT_CONFIG_VALUE_1"), Some("false"));
        assert_eq!(get("GIT_PAGER"), Some("cat"));
    }
}
