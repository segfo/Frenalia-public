//! 差分層の `.git` を**辿らずに**読む。差分層に触れるのはこのファイルだけである。
//!
//! 差分層は子が書けるので、junction・シンボリックリンクを置いてハーネスに別の場所を
//! 読ませることができる。そこで `harness-sandbox` のジェイル（`WorkspaceJail::walk_dir`）と
//! 同じ道具を使う——差分層に根を置いた cap-std の `Dir` から、ハンドルに相対で1段ずつ開く。
//! 根の外へ出る経路は cap-std が拒否し（`overlay.rs` の
//! `apply_does_not_follow_a_junction_planted_in_the_overlay` で実測済み）、根の内側を指す
//! リンクもここで飛ばす。**`.git` そのものがリンクなら拒否する**ので、差分層に根を置く
//! （`.git` に根を置くと、`.git` を junction にされたとき気付けない）。
//!
//! **読むのは1回だけ**。検算は呼び出し側がメモリ上のバイト列に対して行い、一時リポジトリへは
//! そのバイト列を書く（読み直さない）。pack は大きいので [`DiffLayerGit::copy_file`] で
//! 一時リポジトリへ写し、**写した側を**検査する。どちらも「検査したものと使うものが同じ」
//! を守るためである。
//!
//! **この機構の限界**: 1段ずつ「リンクでないか」を確かめてから開くので、確かめてから
//! 開くまでの間に子が差し替えると検査をすり抜け得る。レビューは動いているセッションには
//! 掛けない（`lifecycle` が断る）ので、その間に書く子は居ない。

use std::io::Read;
use std::path::Path;

use cap_std::fs::Dir;

use crate::ReviewError;

/// 1回の走査で拾うファイルの上限。これを超える差分層は「読み切れない」として断る。
const WALK_FILE_LIMIT: usize = 200_000;
/// 走査の深さの上限（根の内側を指すリンクで輪を作られても止まる保険）。
const WALK_DEPTH_LIMIT: usize = 32;

/// 読み取りの結果。
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    Bytes(Vec<u8>),
    Absent,
    /// ファイルでない（ディレクトリ・リンク・その他）。
    NotAFile,
    TooLarge,
}

/// 差分層の `.git`（開いたハンドル）。
pub(crate) struct DiffLayerGit {
    git: Dir,
}

impl DiffLayerGit {
    /// 差分層の `.git` を開く。`Ok(None)` は「差分層に `.git` が無い」＝エージェントが git に
    /// 書き込んでいない。`.git` がリンクやファイルなら断る。
    pub(crate) fn open(diff_layer_dir: &Path) -> Result<Option<Self>, ReviewError> {
        let root = Dir::open_ambient_dir(diff_layer_dir, cap_std::ambient_authority())
            .map_err(|e| ReviewError::io(diff_layer_dir, e))?;
        match root.symlink_metadata(".git") {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ReviewError::io(diff_layer_dir.join(".git"), e)),
            Ok(m) if m.file_type().is_symlink() => Err(ReviewError::Refused(
                ".git in the diff layer is a link; it is not read".into(),
            )),
            Ok(m) if !m.is_dir() => Err(ReviewError::Refused(
                ".git in the diff layer is not a directory; it is not read".into(),
            )),
            Ok(_) => {
                let git = root
                    .open_dir(".git")
                    .map_err(|e| ReviewError::io(diff_layer_dir.join(".git"), e))?;
                Ok(Some(Self { git }))
            }
        }
    }

    /// `rel`（`.git` からの相対、`/` 区切り）のディレクトリを、各段でリンクを拒否しながら開く。
    fn open_dir(&self, rel: &str) -> Result<Option<Dir>, ReviewError> {
        let mut dir = self.git.try_clone().map_err(|e| ReviewError::io(rel, e))?;
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            match dir.symlink_metadata(part) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(ReviewError::io(rel, e)),
                Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return Ok(None),
                Ok(_) => {}
            }
            dir = dir.open_dir(part).map_err(|e| ReviewError::io(rel, e))?;
        }
        Ok(Some(dir))
    }

    /// ファイルを1回だけ読む。`max` バイトを超えたら [`ReadOutcome::TooLarge`]。
    pub(crate) fn read(&self, rel: &str, max: u64) -> Result<ReadOutcome, ReviewError> {
        let (parent, name) = split_parent(rel);
        let Some(dir) = self.open_dir(parent)? else {
            return Ok(ReadOutcome::Absent);
        };
        match dir.symlink_metadata(name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ReadOutcome::Absent),
            Err(e) => return Err(ReviewError::io(rel, e)),
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
                return Ok(ReadOutcome::NotAFile)
            }
            Ok(m) if m.len() > max => return Ok(ReadOutcome::TooLarge),
            Ok(_) => {}
        }
        let file = dir.open(name).map_err(|e| ReviewError::io(rel, e))?;
        let mut bytes = Vec::new();
        file.take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| ReviewError::io(rel, e))?;
        if bytes.len() as u64 > max {
            return Ok(ReadOutcome::TooLarge);
        }
        Ok(ReadOutcome::Bytes(bytes))
    }

    /// ファイルを `dest`（ハーネスの一時リポジトリの中）へ写す。リンクなら写さず `false`。
    pub(crate) fn copy_file(&self, rel: &str, dest: &Path) -> Result<bool, ReviewError> {
        let (parent, name) = split_parent(rel);
        let Some(dir) = self.open_dir(parent)? else {
            return Ok(false);
        };
        match dir.symlink_metadata(name) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() => {}
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(ReviewError::io(rel, e)),
        }
        let mut src = dir.open(name).map_err(|e| ReviewError::io(rel, e))?;
        let mut out = std::fs::File::create(dest).map_err(|e| ReviewError::io(dest, e))?;
        std::io::copy(&mut src, &mut out).map_err(|e| ReviewError::io(dest, e))?;
        Ok(true)
    }

    /// `rel_dir` の下のファイルを再帰で列挙する（`.git` からの相対パス、`/` 区切り）。
    /// リンクは辿らず、2つ目の戻り値に数える。
    pub(crate) fn walk(&self, rel_dir: &str) -> Result<(Vec<String>, Vec<String>), ReviewError> {
        let mut files = Vec::new();
        let mut links = Vec::new();
        if let Some(dir) = self.open_dir(rel_dir)? {
            walk_dir(
                &dir,
                rel_dir.trim_end_matches('/'),
                0,
                &mut files,
                &mut links,
            )?;
        }
        Ok((files, links))
    }
}

fn walk_dir(
    dir: &Dir,
    prefix: &str,
    depth: usize,
    files: &mut Vec<String>,
    links: &mut Vec<String>,
) -> Result<(), ReviewError> {
    if depth > WALK_DEPTH_LIMIT {
        return Err(ReviewError::Refused(format!(
            "{prefix}: nested deeper than {WALK_DEPTH_LIMIT} levels"
        )));
    }
    for entry in dir.entries().map_err(|e| ReviewError::io(prefix, e))? {
        let entry = entry.map_err(|e| ReviewError::io(prefix, e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            links.push(format!("{prefix}/{}", name.to_string_lossy()));
            continue;
        };
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let file_type = entry.file_type().map_err(|e| ReviewError::io(&rel, e))?;
        if file_type.is_symlink() {
            links.push(rel);
        } else if file_type.is_dir() {
            let sub = entry.open_dir().map_err(|e| ReviewError::io(&rel, e))?;
            walk_dir(&sub, &rel, depth + 1, files, links)?;
        } else if file_type.is_file() {
            if files.len() >= WALK_FILE_LIMIT {
                return Err(ReviewError::Refused(format!(
                    "the diff layer's .git holds more than {WALK_FILE_LIMIT} files"
                )));
            }
            files.push(rel);
        } else {
            links.push(rel);
        }
    }
    Ok(())
}

fn split_parent(rel: &str) -> (&str, &str) {
    match rel.rsplit_once('/') {
        Some((parent, name)) => (parent, name),
        None => ("", rel),
    }
}
