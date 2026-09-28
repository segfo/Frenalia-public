//! 名前の変更の経路（[`route_rename`]）の試験。
//!
//! フックは実プロセスへ注入しないと動かないので、本当の`NtSetInformationFile`の代わりに偽物を渡し、
//! 「本当の呼び出しをしたか」「何を返したか」「台帳に何が残ったか」を見る。
//! パス名とハンドルの値は試験ごとに別にする——ハンドル対応表と削除済みの集合はプロセスに1つしか無い。

use super::*;
use crate::test_support::{cow_fixture, ledger_ops};
use std::cell::Cell;
use windows::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION_0;
use windows::Win32::Foundation::{BOOLEAN, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS};

/// 移動先`target`へ向けた名前の変更のバッファを、情報クラス`class`の形で作る。
fn rename_info(class: FILE_INFORMATION_CLASS, target: &Path, replace_if_exists: bool) -> Vec<u8> {
    let anonymous = if class == FileRenameInformationEx {
        FILE_RENAME_INFORMATION_0 {
            Flags: if replace_if_exists {
                FILE_RENAME_REPLACE_IF_EXISTS
            } else {
                0
            },
        }
    } else {
        FILE_RENAME_INFORMATION_0 {
            ReplaceIfExists: BOOLEAN(replace_if_exists as u8),
        }
    };
    build_rename_info_buffer(anonymous, target).0
}

/// `src`（差分層に在る、このセッションで開いたファイル）を`dst`へ名前の変更する。
/// 本当の呼び出しは偽物で、呼ばれたら`real_status`を返す。戻り値は（フックが返した状態, 本当の呼び出しの回数）。
fn rename_through_the_hook(
    cfg: &Config,
    handle_key: isize,
    class: FILE_INFORMATION_CLASS,
    src: &str,
    dst: &Path,
    replace_if_exists: bool,
    real_status: NTSTATUS,
) -> (Option<NTSTATUS>, u32) {
    handle_paths()
        .lock()
        .unwrap()
        .insert(handle_key, src.to_string());
    let info = rename_info(class, dst, replace_if_exists);
    let calls = Cell::new(0);
    let real = |_: *const c_void, _: u32| {
        calls.set(calls.get() + 1);
        real_status
    };
    let status = unsafe {
        route_rename(
            cfg,
            handle_key,
            info.as_ptr() as *const c_void,
            class,
            &real,
        )
    };
    handle_paths().lock().unwrap().remove(&handle_key);
    (status, calls.get())
}

/// BUG-176: 上書きを許さない名前の変更は、移動先が**ワークスペースにだけ**在っても衝突で失敗する。
/// 以前は移動先を差分層へ書き換えた結果そこには何も無いので成功し、ワークスペースの`dst`を
/// 論理的に上書きしていた（台帳に`Delete src`と`Modify dst`が残る）。
#[test]
fn a_rename_that_must_not_replace_collides_with_a_file_that_is_only_in_the_workspace() {
    for (key, class, name) in [
        (0x0176_0001, FileRenameInformation, "plain"),
        (0x0176_0003, FileRenameInformationEx, "ex"),
    ] {
        let (_ws, _diff_layer, cfg) = cow_fixture();
        let src = format!("bug176-{name}-src.txt");
        let dst = format!("bug176-{name}-dst.txt");
        std::fs::write(cfg.workspace_root.join(&dst), "original").unwrap();
        std::fs::write(cfg.diff_layer_dir.join(&src), "moved").unwrap();

        let (status, calls) = rename_through_the_hook(
            &cfg,
            key,
            class,
            &src,
            &cfg.workspace_root.join(&dst),
            false,
            STATUS_SUCCESS,
        );

        assert_eq!(
            status,
            Some(STATUS_OBJECT_NAME_COLLISION),
            "BUG-176 ({name}): the workspace already has {dst}, so a rename that must not \
             replace it has to collide"
        );
        assert_eq!(calls, 0, "({name}) the real rename must not run");
        assert!(ledger_ops(&cfg, &src).is_empty(), "({name}) nothing moved");
        assert!(
            ledger_ops(&cfg, &dst).is_empty(),
            "({name}) nothing replaced"
        );
    }
}

/// 許可側: 上書きを許すなら、ワークスペースに在る移動先を置き換える（台帳は`Delete src`と、
/// 元が在ったので`Modify dst`）。移動先がどこにも無ければ上書き不可でも通る（`Create dst`）。
#[test]
fn a_rename_that_may_replace_or_goes_to_a_new_name_runs_and_is_recorded() {
    for (key, class, name) in [
        (0x0176_0005, FileRenameInformation, "plain"),
        (0x0176_0007, FileRenameInformationEx, "ex"),
    ] {
        let (_ws, _diff_layer, cfg) = cow_fixture();
        let src = format!("bug176-{name}-replace-src.txt");
        let dst = format!("bug176-{name}-replace-dst.txt");
        std::fs::write(cfg.workspace_root.join(&dst), "original").unwrap();
        std::fs::write(cfg.diff_layer_dir.join(&src), "moved").unwrap();
        let (status, calls) = rename_through_the_hook(
            &cfg,
            key,
            class,
            &src,
            &cfg.workspace_root.join(&dst),
            true,
            STATUS_SUCCESS,
        );
        assert_eq!(status, Some(STATUS_SUCCESS), "({name})");
        assert_eq!(calls, 1, "({name})");
        assert_eq!(ledger_ops(&cfg, &src), [ChangeOp::Delete], "({name})");
        assert_eq!(ledger_ops(&cfg, &dst), [ChangeOp::Modify], "({name})");

        let src = format!("bug176-{name}-new-src.txt");
        let dst = format!("bug176-{name}-new-dst.txt");
        std::fs::write(cfg.diff_layer_dir.join(&src), "moved").unwrap();
        let (status, calls) = rename_through_the_hook(
            &cfg,
            key + 0x100,
            class,
            &src,
            &cfg.workspace_root.join(&dst),
            false,
            STATUS_SUCCESS,
        );
        assert_eq!(status, Some(STATUS_SUCCESS), "({name})");
        assert_eq!(calls, 1, "({name})");
        assert_eq!(ledger_ops(&cfg, &dst), [ChangeOp::Create], "({name})");
    }
}

/// 本物のファイルシステムと同じく、上書きを許してもディレクトリはファイルで置き換えられない。
/// 移動先のディレクトリがワークスペースにだけ在ると、差分層に何も無いので本当の呼び出しは通ってしまう。
#[test]
fn a_rename_onto_a_directory_that_is_only_in_the_workspace_is_denied_even_when_replacing() {
    let (_ws, _diff_layer, cfg) = cow_fixture();
    let src = "bug176-dir-src.txt";
    let dst = "bug176-dir-dst";
    std::fs::create_dir(cfg.workspace_root.join(dst)).unwrap();
    std::fs::write(cfg.diff_layer_dir.join(src), "moved").unwrap();
    let (status, calls) = rename_through_the_hook(
        &cfg,
        0x0176_0009,
        FileRenameInformation,
        src,
        &cfg.workspace_root.join(dst),
        true,
        STATUS_SUCCESS,
    );
    assert_eq!(status, Some(STATUS_ACCESS_DENIED));
    assert_eq!(calls, 0);
    assert!(ledger_ops(&cfg, src).is_empty());
}

/// 判定の表。移動先が論理削除済みなら、ワークスペースに元が残っていても断らない
/// （論理的には無い）。差分層に在るなら判定しない——本当の呼び出しが自分で衝突・拒否を返す。
#[test]
fn rename_refusal_follows_the_logical_view_of_the_destination() {
    struct Facts {
        diff_layer: bool,
        workspace: bool,
        dir: bool,
        deleted: bool,
    }
    impl RenameTargetFacts for Facts {
        fn in_diff_layer(&self) -> bool {
            self.diff_layer
        }
        fn in_workspace(&self) -> bool {
            self.workspace
        }
        fn workspace_is_dir(&self) -> bool {
            self.dir
        }
        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }
    const COLLIDE: Option<NTSTATUS> = Some(STATUS_OBJECT_NAME_COLLISION);
    const DENY: Option<NTSTATUS> = Some(STATUS_ACCESS_DENIED);
    let rows = [
        // (説明, 上書き可, 差分層, ワークスペース, ディレクトリ, 論理削除済み, 答え)
        (
            "a file only in the workspace (BUG-176)",
            false,
            false,
            true,
            false,
            false,
            COLLIDE,
        ),
        (
            "a directory only in the workspace",
            false,
            false,
            true,
            true,
            false,
            COLLIDE,
        ),
        (
            "a file only in the workspace, replacing",
            true,
            false,
            true,
            false,
            false,
            None,
        ),
        (
            "a directory only in the workspace, replacing",
            true,
            false,
            true,
            true,
            false,
            DENY,
        ),
        (
            "only in the workspace but logically deleted",
            false,
            false,
            true,
            false,
            true,
            None,
        ),
        (
            "in the diff layer: the real rename decides",
            false,
            true,
            true,
            false,
            false,
            None,
        ),
        (
            "nowhere: a new name",
            false,
            false,
            false,
            false,
            false,
            None,
        ),
    ];
    for (what, replace, diff_layer, workspace, dir, deleted, want) in rows {
        let facts = Facts {
            diff_layer,
            workspace,
            dir,
            deleted,
        };
        assert_eq!(rename_refusal(replace, &facts), want, "{what}");
    }
}

/// BUG-177: 名前の変更の移動先の親がどこにも無ければ、差分層にも作らない（本物と同じく
/// 本当の呼び出しが「パスが無い」で失敗する）。在る親（ワークスペースの`sub/`）は写す。
#[test]
fn a_rename_does_not_create_a_destination_parent_that_does_not_exist_anywhere() {
    let (_ws, _diff_layer, cfg) = cow_fixture();
    let src = "bug177-rename-src.txt";
    std::fs::write(cfg.diff_layer_dir.join(src), "moved").unwrap();
    let dst = cfg
        .workspace_root
        .join("bug177-rename-newdir")
        .join("x.txt");
    let (_, calls) = rename_through_the_hook(
        &cfg,
        0x0177_0001,
        FileRenameInformation,
        src,
        &dst,
        false,
        STATUS_OBJECT_PATH_NOT_FOUND,
    );
    assert_eq!(calls, 1, "the real rename answers the missing path itself");
    assert!(
        !cfg.diff_layer_dir.join("bug177-rename-newdir").exists(),
        "BUG-177: the rename must not create a parent that does not exist logically"
    );

    std::fs::create_dir(cfg.workspace_root.join("bug177-rename-sub")).unwrap();
    let src = "bug177-rename-src2.txt";
    std::fs::write(cfg.diff_layer_dir.join(src), "moved").unwrap();
    let dst = cfg.workspace_root.join("bug177-rename-sub").join("x.txt");
    let (status, _) = rename_through_the_hook(
        &cfg,
        0x0177_0003,
        FileRenameInformation,
        src,
        &dst,
        false,
        STATUS_SUCCESS,
    );
    assert_eq!(status, Some(STATUS_SUCCESS));
    assert!(cfg.diff_layer_dir.join("bug177-rename-sub").is_dir());
}
