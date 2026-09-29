//! 一時リポジトリから本物のレビュー用 ref（`refs/harness/review/<session-id>/…`）へ fetch する。
//!
//! fetch の側（本物）では `transfer.fsckObjects` が立っている（`launcher::PINNED_CONFIG`）。
//! pack を受け取る側の `index-pack --strict` が、運ばれた全オブジェクトの名前を中身から
//! 計算し直し、形式を検査する——**偽装したオブジェクトはここで構造的に落ちる**
//! （net-spike N8-M1補: E3 の形は偽装を必ず捕まえた）。
//!
//! 本物の名前空間を汚さないためのフラグ: `--no-tags`（タグの自動追従で本物の `refs/tags/*` を
//! 書かない）・`--no-write-fetch-head`・`--no-recurse-submodules`・`--no-auto-maintenance`・
//! `--no-auto-gc`。`--atomic` で、取り込む ref は全部か無しかにする。
//!
//! **終了コードを信じない。** git は壊れた alternates などに出会っても `error:` を出して
//! 終了コード0で続けることがある（N8-M1-i）。fetch の後に `for-each-ref` で読み返し、
//! 頼んだ組と**完全に一致する**ことを確かめる。
//!
//! **限界**: fetch には隔離の置き場が無いので、接続性の検査で落ちた場合でも、どこからも
//! 参照されないオブジェクトが本物に残り得る。無害で、本物の gc が回収する。

use std::collections::BTreeMap;

use crate::assemble::AssembledSource;
use crate::launcher::{GitAt, GitLauncher, RealRepo};
use crate::lifecycle::SessionId;
use crate::ReviewError;

/// 取り込む。戻り値は（エージェントから見えていた名前 → 作ったレビュー用 ref）。
pub(crate) fn fetch_into_review_refs(
    launcher: &GitLauncher,
    real: &RealRepo,
    source: &AssembledSource,
    sid: &SessionId,
    placed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ReviewError> {
    if placed.is_empty() {
        return Ok(BTreeMap::new());
    }
    let prefix = sid.review_ref_prefix();
    let mut args: Vec<std::ffi::OsString> = [
        "fetch",
        "--quiet",
        "--atomic",
        "--no-tags",
        "--no-write-fetch-head",
        "--no-recurse-submodules",
        "--no-auto-maintenance",
        "--no-auto-gc",
        "--no-show-forced-updates",
    ]
    .iter()
    .map(|s| std::ffi::OsString::from(*s))
    .collect();
    args.push(source.git_dir().as_os_str().to_os_string());
    args.push(format!("+refs/heads/*:{prefix}heads/*").into());
    args.push(format!("+refs/tags/*:{prefix}tags/*").into());
    launcher.run_ok(GitAt::Real(real), &args, None)?;

    let expected: BTreeMap<String, String> = placed
        .iter()
        .map(|(name, oid)| (sid.review_ref_for(name), oid.clone()))
        .collect();
    let actual = review_refs(launcher, real, sid)?;
    if actual != expected {
        return Err(ReviewError::Mismatch(format!(
            "after fetching, {prefix}* holds {actual:?}, but {expected:?} was requested"
        )));
    }
    Ok(placed
        .keys()
        .map(|name| (name.clone(), sid.review_ref_for(name)))
        .collect())
}

/// 本物にある、このセッションのレビュー用 ref の全部（名前 → 値）。
///
/// 名前の組み立てはセッション ID からだけ行う（セッションメタの `review_ref` は子が書ける
/// ので読まない）。`for-each-ref` の接頭辞一致は「`/` までの一致」なので `session-a` が
/// `session-ab` を拾うことは無いが、念のためこちらでも末尾 `/` 付きで絞る。
pub(crate) fn review_refs(
    launcher: &GitLauncher,
    real: &RealRepo,
    sid: &SessionId,
) -> Result<BTreeMap<String, String>, ReviewError> {
    let prefix = sid.review_ref_prefix();
    let out = launcher.run_ok(
        GitAt::Real(real),
        &[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            prefix.trim_end_matches('/'),
        ],
        None,
    )?;
    Ok(out
        .stdout_text()
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(_, name)| name.starts_with(&prefix))
        .map(|(oid, name)| (name.to_string(), oid.to_string()))
        .collect())
}

/// このセッションのレビュー用 ref を全部消す。消した名前を返す。
pub(crate) fn delete_review_refs(
    launcher: &GitLauncher,
    real: &RealRepo,
    sid: &SessionId,
) -> Result<Vec<String>, ReviewError> {
    let existing = review_refs(launcher, real, sid)?;
    if existing.is_empty() {
        return Ok(Vec::new());
    }
    let transaction: String = existing
        .iter()
        .map(|(name, oid)| format!("delete {name} {oid}\n"))
        .collect();
    launcher.run_ok(
        GitAt::Real(real),
        &["update-ref", "--stdin"],
        Some(transaction.as_bytes()),
    )?;
    let left = review_refs(launcher, real, sid)?;
    if !left.is_empty() {
        return Err(ReviewError::Mismatch(format!(
            "review refs are still present after deleting them: {left:?}"
        )));
    }
    Ok(existing.into_keys().collect())
}
