//! 子プロセスへ渡す`PATH`の合成と、ツール出力のバイト上限。
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則3の軸1で`shell.rs`から切り出した。ここも純粋関数だけで、
//! 実際に子へenvを積むのは`super::runner`（`apply_common_command_settings`・
//! `spawn_with_workspace`）である。envのallowlist自体は`harness_sandbox::build_child_env`
//! （D-07）が持ち、この module はそこへ追記する形しか扱わない。

/// 出力バイト上限（層5・T-13、Tier0/Tier1/Tier2bいずれでも適用する保険）。
pub(crate) const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

pub(crate) fn truncate_to_limit(mut s: String) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        s.truncate(MAX_OUTPUT_BYTES);
        s.push_str("\n[output truncated at 10MiB]");
    }
    s
}

/// 既存の`PATH`エントリへ`path_extra`を追記する。`env`は要素を増減させず既存の`PATH`値だけを
/// 書き換えるため、`&mut Vec`ではなくスライスで受ける（`Vec`からは自動で型強制される）。
pub(crate) fn append_path_extra(env: &mut [(String, String)], path_extra: &[String]) {
    if path_extra.is_empty() {
        return;
    }
    let Some((_, path)) = env
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
    else {
        return;
    };
    for entry in path_extra {
        append_path_entry(path, entry);
    }
}

fn append_path_entry(path: &mut String, entry: &str) {
    let entry = entry.trim();
    if entry.is_empty() {
        return;
    }
    if path
        .split(path_separator())
        .any(|existing| path_entries_equal(existing, entry))
    {
        return;
    }
    if !path.is_empty() && !path.ends_with(path_separator()) {
        path.push(path_separator());
    }
    path.push_str(entry);
}

pub(crate) fn path_separator() -> char {
    if cfg!(windows) {
        ';'
    } else {
        ':'
    }
}

pub(crate) fn path_entries_equal(a: &str, b: &str) -> bool {
    let a = a.trim().trim_end_matches(['\\', '/']);
    let b = b.trim().trim_end_matches(['\\', '/']);
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}
