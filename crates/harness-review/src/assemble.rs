//! 取り込み元の一時 bare リポジトリを組む（D-110 (vi)）。
//!
//! 中身を**全部ハーネスが決める**ことがこの段の要点である。ローカル fetch の相手側
//! （ここで動く upload-pack）には `-c` も `GIT_CONFIG_*` も届かない（`launcher` の doc）ので、
//! 相手側が読むものを限る手段は「この一時リポジトリに何を置くか」しか無い。置くのは3つだけ:
//!
//! 1. **検算を通ったオブジェクト**——ゆるいオブジェクトは名前と中身の一致を確かめたバイト列、
//!    pack はここで `index-pack` し直したもの（差分層の索引は使わない）
//! 2. **厳格に解析した ref**（`refs/heads/*`・`refs/tags/*` で、本物と値が違うものだけ）
//! 3. **ハーネスが書いた alternates**（本物の `objects` だけを指す）
//!
//! `init` は `--template=`（空）で行う——利用者のグローバル設定の `init.templateDir` が
//! フックなどを持ち込まないようにするため。置き場は `%TEMP%` の下で、ボリュームのルート
//! （他のユーザーが書ける継承を持ち得る）には置かない。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::launcher::{GitAt, GitLauncher, RealRepo, SourceRepo};
use crate::untrusted::objects::verify_loose_object;
use crate::untrusted::refs::{ref_scope, RefScope};
use crate::untrusted::{DiffLayerGit, ObjectInventory, ReadOutcome};
use crate::{ObjectTally, ReviewError, SkippedRef};

/// ゆるいオブジェクト1つの圧縮後の大きさの上限。
const LOOSE_OBJECT_COMPRESSED_MAX: u64 = 256 * 1024 * 1024;

/// 組み上がった一時リポジトリ。捨てるときは [`AssembledSource::close`] を呼ぶ（消せなかったことを
/// 黙らせないため。`Drop` でも消えるが、そちらは失敗を報告できない）。
pub(crate) struct AssembledSource {
    dir: tempfile::TempDir,
    repo: SourceRepo,
}

impl AssembledSource {
    pub(crate) fn repo(&self) -> &SourceRepo {
        &self.repo
    }

    pub(crate) fn git_dir(&self) -> &Path {
        &self.repo.git_dir
    }

    pub(crate) fn close(self) -> Result<(), ReviewError> {
        let path = self.dir.path().to_path_buf();
        self.dir.close().map_err(|e| ReviewError::io(path, e))
    }
}

/// 一時リポジトリに置けた ref と、置けなかった ref。
pub(crate) struct PlacedRefs {
    pub(crate) placed: BTreeMap<String, String>,
    pub(crate) unplaced: Vec<SkippedRef>,
}

pub(crate) fn assemble(
    launcher: &GitLauncher,
    real: &RealRepo,
    dl: &DiffLayerGit,
    inventory: &ObjectInventory,
    wanted: &BTreeMap<String, String>,
    scratch_parent: &Path,
    tally: &mut ObjectTally,
) -> Result<(AssembledSource, PlacedRefs), ReviewError> {
    std::fs::create_dir_all(scratch_parent).map_err(|e| ReviewError::io(scratch_parent, e))?;
    let dir = tempfile::Builder::new()
        .prefix("harness-review-src-")
        .tempdir_in(scratch_parent)
        .map_err(|e| ReviewError::io(scratch_parent, e))?;
    let git_dir = dir.path().join("src.git");
    let mut init_args: Vec<std::ffi::OsString> = vec![
        "init".into(),
        "--quiet".into(),
        "--bare".into(),
        "--template=".into(),
        "--object-format=sha1".into(),
        "--ref-format=files".into(),
    ];
    init_args.push(git_dir.clone().into_os_string());
    launcher.run_ok(GitAt::Nowhere, &init_args, None)?;
    let source = AssembledSource {
        dir,
        repo: SourceRepo::assembled_at(git_dir.clone()),
    };

    write_alternates(&git_dir, &real.objects_dir())?;
    copy_loose_objects(dl, inventory, &git_dir, tally)?;
    index_packs(launcher, real, dl, inventory, &source, tally)?;
    let placed = place_refs(launcher, source.repo(), wanted)?;
    Ok((source, placed))
}

/// alternates には本物の `objects` の絶対パスだけを書く。区切りは `/` にする
/// （`\` をシェルで書いて1つ潰れ、UNC が「届かない」と誤読した前例がある。net-spike N8-M1-③）。
fn write_alternates(git_dir: &Path, real_objects: &Path) -> Result<(), ReviewError> {
    let Some(text) = real_objects.to_str() else {
        return Err(ReviewError::Unsupported(format!(
            "{}: the repository path is not valid Unicode",
            real_objects.display()
        )));
    };
    let text = text
        .strip_prefix(r"\\?\")
        .unwrap_or(text)
        .replace('\\', "/");
    let info = git_dir.join("objects").join("info");
    std::fs::create_dir_all(&info).map_err(|e| ReviewError::io(&info, e))?;
    let path = info.join("alternates");
    std::fs::write(&path, format!("{text}\n")).map_err(|e| ReviewError::io(path, e))
}

fn copy_loose_objects(
    dl: &DiffLayerGit,
    inventory: &ObjectInventory,
    git_dir: &Path,
    tally: &mut ObjectTally,
) -> Result<(), ReviewError> {
    for (oid, rel) in &inventory.loose {
        let bytes = match dl.read(rel, LOOSE_OBJECT_COMPRESSED_MAX)? {
            ReadOutcome::Bytes(bytes) => bytes,
            ReadOutcome::TooLarge => {
                tally
                    .loose_rejected
                    .push((oid.clone(), "larger than the limit".into()));
                continue;
            }
            ReadOutcome::Absent | ReadOutcome::NotAFile => {
                tally
                    .loose_rejected
                    .push((oid.clone(), "not a regular file".into()));
                continue;
            }
        };
        if let Err(why) = verify_loose_object(oid, &bytes) {
            tally.loose_rejected.push((oid.clone(), why));
            continue;
        }
        // 検算したバイト列そのものを書く（読み直さない）。
        let dest_dir = git_dir.join("objects").join(&oid[..2]);
        std::fs::create_dir_all(&dest_dir).map_err(|e| ReviewError::io(&dest_dir, e))?;
        let dest = dest_dir.join(&oid[2..]);
        std::fs::write(&dest, &bytes).map_err(|e| ReviewError::io(dest, e))?;
        tally.loose_copied += 1;
    }
    Ok(())
}

/// pack を写して、ここで索引を作り直す。**2段**で行う: 1段目で全部の索引を作り（ハッシュは
/// ここで全部検算される）、2段目で `--strict` の検査を掛ける。`--strict` はリンク先の存在まで
/// 確かめるので、pack 同士が参照し合っていても1段目で全部が見えている必要がある。
fn index_packs(
    launcher: &GitLauncher,
    real: &RealRepo,
    dl: &DiffLayerGit,
    inventory: &ObjectInventory,
    source: &AssembledSource,
    tally: &mut ObjectTally,
) -> Result<(), ReviewError> {
    let pack_dir = source.git_dir().join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir).map_err(|e| ReviewError::io(&pack_dir, e))?;
    let checks = source.dir.path().join("strict-checks");
    std::fs::create_dir_all(&checks).map_err(|e| ReviewError::io(&checks, e))?;

    let mut indexed: Vec<(String, PathBuf)> = Vec::new();
    for (stem, rel) in &inventory.packs {
        // 本物に同じ名前の pack があれば、中身は alternates で届く（本体層のコピー。N8-M1-i）。
        // 差分層の側が書き換えられていても、こちらを使わないので読まずに省く。
        if real
            .objects_dir()
            .join("pack")
            .join(format!("{stem}.pack"))
            .is_file()
        {
            tally.packs_already_present += 1;
            continue;
        }
        let dest = pack_dir.join(format!("{stem}.pack"));
        if !dl.copy_file(rel, &dest)? {
            tally
                .packs_rejected
                .push((stem.clone(), "not a regular file".into()));
            continue;
        }
        let args: Vec<std::ffi::OsString> =
            vec!["index-pack".into(), dest.clone().into_os_string()];
        let out = launcher.run(GitAt::Source(source.repo()), &args, None)?;
        let printed = out.stdout_text();
        let expected = stem.trim_start_matches("pack-");
        if !out.success || printed.trim() != expected {
            remove_pack(&pack_dir, stem);
            let why = if out.success {
                format!("its content hashes to {}, not to its name", printed.trim())
            } else {
                out.stderr_text()
            };
            tally.packs_rejected.push((stem.clone(), why));
            continue;
        }
        indexed.push((stem.clone(), dest));
    }

    for (stem, dest) in indexed {
        let check_idx = checks.join(format!("{stem}.idx"));
        let mut args: Vec<std::ffi::OsString> =
            vec!["index-pack".into(), "--strict".into(), "-o".into()];
        args.push(check_idx.into_os_string());
        args.push(dest.into_os_string());
        let out = launcher.run(GitAt::Source(source.repo()), &args, None)?;
        if out.success {
            tally.packs_indexed += 1;
        } else {
            remove_pack(&pack_dir, &stem);
            tally.packs_rejected.push((stem, out.stderr_text()));
        }
    }
    Ok(())
}

fn remove_pack(pack_dir: &Path, stem: &str) {
    for ext in ["pack", "idx", "rev"] {
        let _ = std::fs::remove_file(pack_dir.join(format!("{stem}.{ext}")));
    }
}

/// 取り込む ref を一時リポジトリに置く。先端が無い（検算で落ちた・どこにも無い）ものと、
/// 枝なのにコミットでないものは置かずに理由を返す。`update-ref --stdin` は1本でも失敗すると
/// 全部を戻すので、先に確かめて除いておく。
fn place_refs(
    launcher: &GitLauncher,
    source: &SourceRepo,
    wanted: &BTreeMap<String, String>,
) -> Result<PlacedRefs, ReviewError> {
    let mut placed = BTreeMap::new();
    let mut unplaced = Vec::new();
    if wanted.is_empty() {
        return Ok(PlacedRefs { placed, unplaced });
    }
    let oids: BTreeSet<&String> = wanted.values().collect();
    let mut query = String::new();
    for oid in &oids {
        query.push_str(oid);
        query.push('\n');
    }
    let out = launcher.run_ok(
        GitAt::Source(source),
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        Some(query.as_bytes()),
    )?;
    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    for line in out.stdout_text().lines() {
        if let Some((oid, kind)) = line.split_once(' ') {
            kinds.insert(oid.to_string(), kind.to_string());
        }
    }
    for (name, oid) in wanted {
        let reason = match (kinds.get(oid).map(String::as_str), ref_scope(name)) {
            (None | Some("missing"), _) => Some(
                "its object is neither among the verified objects nor in the real repository"
                    .to_string(),
            ),
            (Some(kind), RefScope::Heads) if kind != "commit" => {
                Some(format!("a branch must point at a commit, not a {kind}"))
            }
            _ => None,
        };
        match reason {
            Some(reason) => unplaced.push(SkippedRef {
                name: name.clone(),
                oid: Some(oid.clone()),
                reason,
            }),
            None => {
                placed.insert(name.clone(), oid.clone());
            }
        }
    }

    let transaction: String = placed
        .iter()
        .map(|(name, oid)| format!("create {name} {oid}\n"))
        .collect();
    let out = launcher.run(
        GitAt::Source(source),
        &["update-ref", "--stdin"],
        Some(transaction.as_bytes()),
    )?;
    if !out.success {
        // どれが原因かを1本ずつ確かめる（全体の失敗を、全部の失敗として扱わない）。
        let mut still_placed = BTreeMap::new();
        for (name, oid) in placed {
            let one = format!("create {name} {oid}\n");
            let out = launcher.run(
                GitAt::Source(source),
                &["update-ref", "--stdin"],
                Some(one.as_bytes()),
            )?;
            if out.success {
                still_placed.insert(name, oid);
            } else {
                unplaced.push(SkippedRef {
                    name,
                    oid: Some(oid),
                    reason: out.stderr_text(),
                });
            }
        }
        placed = still_placed;
    }
    Ok(PlacedRefs { placed, unplaced })
}
