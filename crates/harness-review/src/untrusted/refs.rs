//! 差分層の ref を読むための**純粋な解析**（FS も git も触らない）。
//!
//! 入力はすべてサンドボックスの子が書けたバイト列である。**git が書く形だけを受け付け、
//! それ以外は拒否する**（寛容に読むと、子が git の解釈の隙間を使って別の意味を運べる）。
//! symref（`ref: …`）は `HEAD` 以外では受け付けない。

use harness_change_ledger::path_rules::validate_relative_path;

/// SHA-1 のオブジェクト名の長さ（16進）。SHA-256 のリポジトリは扱わない（`lifecycle` が断る）。
pub(crate) const OID_HEX_LEN: usize = 40;

/// 小文字16進でちょうど40桁か。
pub(crate) fn is_oid_hex(s: &str) -> bool {
    s.len() == OID_HEX_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// ゆるい ref ファイルの中身: `<40桁>` と、あれば改行1つだけ。
pub(crate) fn parse_loose_ref(bytes: &[u8]) -> Result<String, String> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|_| "not UTF-8".to_string())?;
    if text.starts_with("ref:") {
        return Err("symbolic refs are not accepted outside HEAD".into());
    }
    if is_oid_hex(text) {
        Ok(text.to_string())
    } else {
        Err("not exactly one 40-digit lowercase object name".into())
    }
}

/// `HEAD` の中身。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeadState {
    /// `ref: refs/heads/<枝>`。
    Branch(String),
    /// 切り離された `HEAD`。
    Detached(String),
}

impl HeadState {
    pub(crate) fn describe(&self) -> String {
        match self {
            HeadState::Branch(name) => name.clone(),
            HeadState::Detached(oid) => format!("detached at {oid}"),
        }
    }
}

pub(crate) fn parse_head(bytes: &[u8]) -> Result<HeadState, String> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|_| "HEAD is not UTF-8".to_string())?;
    if let Some(target) = text.strip_prefix("ref: ") {
        if !target.starts_with("refs/heads/") {
            return Err(format!("HEAD points outside refs/heads/: {target}"));
        }
        check_ref_name(target)?;
        return Ok(HeadState::Branch(target.to_string()));
    }
    if is_oid_hex(text) {
        return Ok(HeadState::Detached(text.to_string()));
    }
    Err("HEAD is neither `ref: refs/heads/<name>` nor a 40-digit object name".into())
}

/// `packed-refs` の中身を解析する。**1行でも崩れていれば全体を拒否する**——どの行が
/// 意図したものか判断できないので、一部だけ採るより全体を「読めない」にするほうが安全側。
///
/// 受け付ける行は3種: 先頭の `# pack-refs with: …`、`<40桁> <ref名>`、直前の ref の剥いた値
/// `^<40桁>`（注釈付きタグの指す先。取り込みには使わないが、形は検査する）。
pub(crate) fn parse_packed_refs(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "packed-refs is not UTF-8".to_string())?;
    let mut refs: Vec<(String, String)> = Vec::new();
    let mut previous_was_ref = false;
    for (index, line) in text.split_terminator('\n').enumerate() {
        let lineno = index + 1;
        if index == 0 && line.starts_with("# pack-refs with:") {
            previous_was_ref = false;
            continue;
        }
        if let Some(peeled) = line.strip_prefix('^') {
            if !previous_was_ref || !is_oid_hex(peeled) {
                return Err(format!("packed-refs line {lineno}: malformed peeled line"));
            }
            previous_was_ref = false;
            continue;
        }
        let Some((oid, name)) = line.split_once(' ') else {
            return Err(format!(
                "packed-refs line {lineno}: expected `<oid> <refname>`"
            ));
        };
        if !is_oid_hex(oid) {
            return Err(format!("packed-refs line {lineno}: malformed object name"));
        }
        check_ref_name(name).map_err(|why| format!("packed-refs line {lineno}: {why}"))?;
        if refs.iter().any(|(n, _)| n == name) {
            return Err(format!("packed-refs line {lineno}: {name} appears twice"));
        }
        refs.push((name.to_string(), oid.to_string()));
        previous_was_ref = true;
    }
    Ok(refs)
}

/// ref の完全名（`refs/…`）が git の規則（`check-ref-format`）と、Windows のパスとしての
/// 規則の両方を満たすか。
///
/// git の規則: 成分が空でない・`.` で始まらない・`.lock` で終わらない・`..` を含まない・
/// 制御文字と ` ~^:?*[\` を含まない・`@{` を含まない・`.` で終わらない・`@` だけではない。
/// Windows: 予約デバイス名・成分末尾の空白（[`validate_relative_path`] を流用）。
/// 大小だけが違う名前の衝突と、`a` と `a/b` の衝突は、集合を見る
/// [`find_ambiguous_names`] が扱う。
pub(crate) fn check_ref_name(name: &str) -> Result<(), String> {
    const MAX_LEN: usize = 1024;
    if name.len() > MAX_LEN {
        return Err(format!("ref name longer than {MAX_LEN} bytes"));
    }
    if !name.starts_with("refs/") {
        return Err(format!("{name}: not under refs/"));
    }
    if name.contains("..") || name.contains("@{") || name == "@" {
        return Err(format!("{name}: contains `..` or `@{{`"));
    }
    if name.ends_with('/') || name.ends_with('.') {
        return Err(format!("{name}: ends with `/` or `.`"));
    }
    for component in name.split('/') {
        if component.is_empty() {
            return Err(format!("{name}: empty component"));
        }
        if component.starts_with('.') {
            return Err(format!("{name}: a component starts with `.`"));
        }
        if component.ends_with(".lock") {
            return Err(format!("{name}: a component ends with `.lock`"));
        }
    }
    if let Some(bad) = name
        .chars()
        .find(|c| c.is_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return Err(format!("{name}: contains {bad:?}"));
    }
    validate_relative_path(name).map_err(|why| format!("{name}: {why:?}"))?;
    Ok(())
}

/// Windows で同じファイルに落ちる名前の組（大小だけの違い）と、ファイルとディレクトリが
/// ぶつかる組（`refs/heads/a` と `refs/heads/a/b`）を探す。**どちらも、どちらが本物か
/// 決められない**ので、該当する名前は全部取り込まない。
pub(crate) fn find_ambiguous_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut lowered: Vec<(String, &str)> = names
        .into_iter()
        .map(|n| (n.to_ascii_lowercase(), n))
        .collect();
    lowered.sort();
    let mut ambiguous = std::collections::BTreeSet::new();
    for (i, (low, original)) in lowered.iter().enumerate() {
        for (other_low, other) in &lowered[i + 1..] {
            let same = other_low == low;
            let nested = other_low.starts_with(low.as_str())
                && other_low.as_bytes().get(low.len()) == Some(&b'/');
            if same || nested {
                ambiguous.insert(original.to_string());
                ambiguous.insert(other.to_string());
            }
        }
    }
    ambiguous.into_iter().collect()
}

/// ref がどの名前空間にあるか。取り込むのは `Heads` と `Tags` だけ（D-110 (vi)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefScope {
    Heads,
    Tags,
    Other,
}

pub(crate) fn ref_scope(name: &str) -> RefScope {
    if name.starts_with("refs/heads/") {
        RefScope::Heads
    } else if name.starts_with("refs/tags/") {
        RefScope::Tags
    } else {
        RefScope::Other
    }
}

#[cfg(test)]
#[path = "refs_tests.rs"]
mod refs_tests;
