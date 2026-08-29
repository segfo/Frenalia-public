//! ツリーを**streaming列挙**する走査器（設計書§5.1.3「背景walkとオンデマンド付与の直列化」の
//! `scanner`）。
//!
//! # 既存の救済walkと何が違うのか
//!
//! [`super::super::fix_descendants_missing_aces`]は、まず
//! [`super::super::acl_grant::collect_dirs_and_files`]で**全パスを`Vec`へ集めてから**回る。
//! 26万ノードのツリーでは、1件目のDACLを触る前に列挙が終わるまで待つことになり、
//! **その間は割り込みも受けられない**。ここでは1ノードずつ writer へ渡して進む。
//!
//! # ディレクトリは自分のACEが確定してから子を列挙する
//!
//! 設計書がこの順を指定しているのは費用のためではなく、**以後そのディレクトリに作られる
//! 新規の子がOS継承で同じACEを受ける**ようにするためである。逆順にすると、走査中に
//! 生まれたファイルが継承元の無い状態で置かれ、**1回目のビルドが作ったファイルが
//! 2回目も fault する**（着手条件1の後半）。
//!
//! # ここが**やらない**こと
//!
//! - **symlink／リパースポイントを辿らない。** [`collect_dirs_and_files`]の同じガードを
//!   引き継ぐ——辿るとworkspace外へACEを配る（スコープ逸脱）。
//! - **消えたノードで打ち切らない**（[`super::super::acl_grant::OnVanished::Skip`]相当）。
//!   打ち切ると**残り全部**が未処理のまま「成功」になる（BUG-084と同型）。
//!   代わりに数えて[`ScanReport`]へ載せる。

use std::path::{Path, PathBuf};

use crate::tier2a::win_appcontainer::acl_grant::path_is_within;

use super::writer::{Node, NodeOutcome, WriterHandle, WriterUnavailable};

/// 走査の結果。**件数を返すのは事後確認のため**である——「打ち切ったのか全部やったのか」を
/// 呼び出し側が区別できないと、部分適用が成功に見える（`B-10`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanReport {
    /// writerへ渡したノード数。
    pub(crate) submitted: usize,
    /// `skip`配下として対象外にした数。
    pub(crate) skipped: usize,
    /// 実際に明示ACEが書かれた数。
    pub(crate) granted: usize,
    /// 列挙中に消えていた／読めなかったディレクトリの数。
    pub(crate) unreadable_dirs: usize,
    /// 安全点で止められた（[`ScanControl::should_stop`]が真を返した）。
    pub(crate) stopped_early: bool,
}

/// 走査を外から止めるための口。fallback controllerとツールのキャンセルが使う。
pub(crate) trait ScanControl {
    /// **ノード境界でだけ**問われる。真を返すと走査は安全点で止まる。
    fn should_stop(&self) -> bool;
    /// 1ノード進むごとに呼ばれる（`submitted`の累計）。表示用。
    fn progress(&self, submitted: usize);
}

/// 何も止めず何も報告しない[`ScanControl`]。**テスト専用**——製品は必ず進捗を出す
/// （`grant_job`の`ScanProgress`）。出さない選択肢を製品から見える場所に置くと、
/// 「背景で何が起きているか分からない」状態を作れてしまう（`B-10`）。
#[cfg(test)]
pub(crate) struct RunToCompletion;

#[cfg(test)]
impl ScanControl for RunToCompletion {
    fn should_stop(&self) -> bool {
        false
    }
    fn progress(&self, _submitted: usize) {}
}

/// `root`配下を streaming で歩き、1ノードずつ`writer`へ渡す。
///
/// **writerが受け付けなくなったら即座に止める**（[`WriterUnavailable`]）。走査だけ進めても
/// 誰もACEを書かないので、進んだぶんが「処理済み」に見えるだけ有害である。
pub(crate) fn scan(
    root: &Path,
    skip: &[PathBuf],
    writer: &WriterHandle,
    control: &dyn ScanControl,
) -> Result<ScanReport, WriterUnavailable> {
    let mut report = ScanReport::default();
    // 明示スタックで持つ（再帰にすると深いツリーで自分のスタックを溢れさせる。
    // `collect_dirs_and_files`は再帰だが、あちらは列挙だけで1フレームが軽い）。
    let mut pending_dirs: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = pending_dirs.pop() {
        if control.should_stop() {
            report.stopped_early = true;
            return Ok(report);
        }
        if skip.iter().any(|s| path_is_within(&dir, s)) {
            report.skipped += 1;
            continue;
        }
        // **自分のACEが確定してから子を列挙する**（モジュールdoc）。
        if !submit(writer, Node::dir(&dir), &mut report, control)? {
            // 消えていたディレクトリの子は存在しないので、列挙へ進まない。
            continue;
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // 消えた／読めないディレクトリは「配下に対象が1件も無い」のと同じ扱いで**続行する**。
            Err(_) => {
                report.unreadable_dirs += 1;
                continue;
            }
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            // リパースポイントは辿らない（モジュールdoc。辿るとworkspace外へ配る）。
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                pending_dirs.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if control.should_stop() {
                report.stopped_early = true;
                return Ok(report);
            }
            if skip.iter().any(|s| path_is_within(&path, s)) {
                report.skipped += 1;
                continue;
            }
            submit(writer, Node::file(path), &mut report, control)?;
        }
    }
    Ok(report)
}

/// 1ノードをwriterへ渡し、結果を[`ScanReport`]へ積む。戻り値は「このノードは在ったか」
/// （偽なら消えていたので、ディレクトリなら列挙へ進まない）。
///
/// **書込の失敗で走査全体を止めない。** 1ノードのDACLが書けないのは（ACL不足・共有違反等で）
/// 起こり得て、そこで打ち切ると残り全部が未処理のまま終わる。数えて先へ進み、
/// 足りないぶんは fallback の全walkが拾う。
fn submit(
    writer: &WriterHandle,
    node: Node,
    report: &mut ScanReport,
    control: &dyn ScanControl,
) -> Result<bool, WriterUnavailable> {
    let outcome = writer.grant_background(node)?;
    report.submitted += 1;
    control.progress(report.submitted);
    match outcome {
        Ok(NodeOutcome::Granted) => {
            report.granted += 1;
            Ok(true)
        }
        Ok(NodeOutcome::AlreadyReached) => Ok(true),
        Ok(NodeOutcome::Vanished) => Ok(false),
        Err(_) => Ok(true),
    }
}

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod scanner_tests;
