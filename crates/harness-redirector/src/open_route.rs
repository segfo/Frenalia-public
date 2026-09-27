//! `NtCreateFile`・`NtOpenFile`の2つの入口が共有する「このopenをどこへ向けるか」の判断と実行。
//!
//! **2つのフックは同じ分岐の並びを別々に書いていた**（差分層を直接指す → 論理削除済み → 書込の誘導 →
//! 差分層の版を読む → 差分層にしか無いディレクトリを読む → 素通し）。Windowsの削除・名前の変更は
//! `NtOpenFile`を、書込の多くは`NtCreateFile`を通るので、**片方にだけ直しを入れると、もう片方の経路に
//! 同じ穴が残る**（`B-06`）。判断を[`decide_open_route`]1つに、実行を[`route_open`]1つに置き、
//! 2つのフックは引数を[`OpenRequest`]へ詰めて本当の呼び出しを渡すだけにした。
//!
//! 判断は純粋関数である。差分層・削除済みの集合を見に行く問い合わせは[`OpenFacts`]越しに
//! **必要になった枝でだけ**行う（以前の分岐と同じ順序・同じ回数。書込の誘導に入るopenで
//! 差分層の版の有無を見に行かない、等）。

use super::*;

/// 1回のopenの要求。2つの入口の違い（`CreateDisposition`の有無）をここで吸収する。
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenRequest {
    pub(crate) desired_access: u32,
    /// `NtCreateFile`だけが持つ。`NtOpenFile`は`None`（常に`FILE_OPEN`相当）。
    pub(crate) create_disposition: Option<u32>,
    /// `NtCreateFile`の`CreateOptions`／`NtOpenFile`の`OpenOptions`。
    pub(crate) options: u32,
}

impl OpenRequest {
    pub(crate) fn write_intent(&self) -> bool {
        is_write_intent(self.desired_access, self.create_disposition)
    }

    fn redirects_write(&self) -> bool {
        should_redirect_write(self.write_intent(), self.options, self.create_disposition)
    }

    /// 論理削除済みのパスを作り直せる開き方か（設計書§19.7）。`NtOpenFile`は作り直せない。
    fn can_recreate(&self) -> bool {
        self.create_disposition
            .is_some_and(is_create_capable_disposition)
    }
}

/// openをどこへ向けるか（[`decide_open_route`]の答え）。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// 差分層の実体を直接指している（BUG-066）。誘導せずに素通しし、`record`なら台帳へ書く予定を持つ。
    DiffLayerAlias { record: bool },
    /// 論理削除済み（設計書§19.7）。本当のopenをせずにこの状態を返す。
    Refuse(NTSTATUS),
    /// 差分層へ誘導して書く（copy-up）。`source`はworkspaceの元の中身を写すか（BUG-172）。
    RedirectWrite { source: CopySource },
    /// 差分層の版を読む（read-through、設計書§19.3/§19.7）。
    ReadThrough(PathBuf),
    /// 差分層にしか無いディレクトリを読む（BUG-128）。
    DirReadThrough(PathBuf),
    /// 差分層にも版が無い。そのまま開かせる。
    Passthrough,
}

/// [`decide_open_route`]が必要になった枝でだけ問い合わせる事実。
pub(crate) trait OpenFacts {
    /// このパスは論理削除済みか（兄弟プロセスが台帳へ書いた削除も取り込んだうえで）。
    fn is_deleted(&self) -> bool;
    /// 差分層にこのパスの版（ファイル）があれば、そのパス。
    fn diff_layer_file(&self) -> Option<PathBuf>;
    /// 差分層にだけディレクトリとして在れば、そのパス。
    fn diff_layer_only_dir(&self) -> Option<PathBuf>;
}

/// openをどこへ向けるかを決める。
pub(crate) fn decide_open_route(
    kind: TargetKind,
    req: &OpenRequest,
    facts: &impl OpenFacts,
) -> Route {
    // BUG-066: 差分層配下の実体を直接開いている＝**既にCoWの行き先**。誘導は一切せず
    // （差分層の差分層は作らない）、書込意図のときだけ台帳へ記録する。削除済みの判定も掛けない
    // ——あれは「workspaceをどう見せるか」の論理であって、行き先の実体への直接アクセスに
    // 被せると、削除済みパスの差分層実体を消すことすらできなくなる。
    if kind == TargetKind::DiffLayerAlias {
        return Route::DiffLayerAlias {
            record: req.redirects_write(),
        };
    }
    let deleted = facts.is_deleted();
    if deleted {
        // **作り直せない開き方なら「無い」。** 設計書§19.7の優先順位（削除済み＞差分層＞workspace）。
        if !req.can_recreate() {
            return Route::Refuse(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        // **作り直せる開き方は、書込目的があるかを問わず差分層へ誘導する。**
        //
        // ここを`redirects_write()`で絞っていたのが穴だった（行列のケースY）。
        // `FILE_OPEN_IF`＋読み取りだけ（`.NET`の`FileMode.OpenOrCreate`）は書込目的が立たないので
        // 素通しになり、**読取専用のworkspaceに在る元のファイルが開けていた**——同じとき
        // `Test-Path`（属性照会のフック）は「無い」と答えるので、セッションの中の見え方が
        // 入口ごとに食い違う。論理削除は「無い」を意味するのだから、
        // **読む側も「無いところに作る」へ落ちなければならない。**
        //
        // BUG-172: 作り直しなので、workspaceの元の中身は写さない。
        return Route::RedirectWrite {
            source: CopySource::Nothing,
        };
    }
    if req.redirects_write() {
        return Route::RedirectWrite {
            source: CopySource::Workspace,
        };
    }
    if let Some(path) = facts.diff_layer_file() {
        return Route::ReadThrough(path);
    }
    // BUG-128: 差分層にしか無いディレクトリ。**`FILE_DIRECTORY_FILE`フラグでは絞らない**
    // ——git/Cygwinの`lstat`は種別が未確定のままフラグ無しで開いて存在と種別を確かめる。
    // ファイルの版は直前で見ているので、ここに来る時点で対象はファイルではない。
    if let Some(path) = facts.diff_layer_only_dir() {
        return Route::DirReadThrough(path);
    }
    Route::Passthrough
}

/// 実際のフック状態から事実を引く[`OpenFacts`]。
struct LiveFacts<'a> {
    cfg: &'a Config,
    rel: &'a Path,
    ledger_key: &'a str,
}

impl OpenFacts for LiveFacts<'_> {
    fn is_deleted(&self) -> bool {
        is_deleted_after_refresh(self.cfg, self.ledger_key)
    }

    fn diff_layer_file(&self) -> Option<PathBuf> {
        diff_layer_version_path(self.cfg, self.rel)
    }

    fn diff_layer_only_dir(&self) -> Option<PathBuf> {
        diff_layer_only_dir_path(self.cfg, self.rel)
    }
}

/// 本当のopen（フックを外した元の関数）を、`object_attributes`をそのまま渡して呼ぶ手順。
pub(crate) type RealOpen<'a> = &'a dyn Fn(*const OBJECT_ATTRIBUTES) -> NTSTATUS;

/// `object_attributes`の名前だけを`target`へ差し替えて本当のopenを呼ぶ。
///
/// 差し替えた`OBJECT_ATTRIBUTES`は名前のバッファを指すので、両方をこの関数の中で生かしたまま
/// 呼ぶ（`build_redirected_oa`のdocの約束を、ここに閉じる）。
unsafe fn call_at(
    object_attributes: *const OBJECT_ATTRIBUTES,
    target: &Path,
    real: RealOpen<'_>,
) -> NTSTATUS {
    let wide: Vec<u16> = nt_path_wide(target);
    let (mut redirected_oa, mut redirected_name) =
        unsafe { build_redirected_oa(object_attributes, &wide) };
    redirected_oa.ObjectName = &mut redirected_name;
    real(&redirected_oa)
}

/// 2つのopenフックの本体。`real`は元の関数を呼ぶ手順（`OBJECT_ATTRIBUTES`だけを差し替えられる）。
///
/// # Safety
/// `file_handle`・`object_attributes`はフックが受け取ったものをそのまま渡すこと。
pub(crate) unsafe fn route_open(
    label: &str,
    file_handle: *mut HANDLE,
    object_attributes: *const OBJECT_ATTRIBUTES,
    req: OpenRequest,
    real: RealOpen<'_>,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let Some(status) =
            unsafe { route_open_guarded(label, file_handle, object_attributes, &req, real) }
        {
            return status;
        }
    }
    real(object_attributes)
}

/// 再入防止ガードの内側の本体。`None`は「何もせず素通しする」（呼び出し側がガードの外で呼ぶ）。
unsafe fn route_open_guarded(
    label: &str,
    file_handle: *mut HANDLE,
    object_attributes: *const OBJECT_ATTRIBUTES,
    req: &OpenRequest,
    real: RealOpen<'_>,
) -> Option<NTSTATUS> {
    let cfg = CONFIG.get()?;
    // [D-88] DirectRwのlazyレーン: **本来のopenを先に呼び、拒否されてから初めて分類する。**
    // 分類を前に置くと1 openあたり+28.3 µs（§S25、`file_hooks`のモジュールdoc）。
    if !cfg.cow_enabled {
        let status = real(object_attributes);
        if status != STATUS_ACCESS_DENIED {
            return Some(status);
        }
        return Some(
            retry_once_after_fault_in(cfg, object_attributes, || real(object_attributes))
                .unwrap_or(status),
        );
    }
    let path = unsafe { object_attributes_path(object_attributes) }?;
    let Some(Classified {
        rel,
        ledger_key,
        kind,
    }) = classify_target(cfg, &path)
    else {
        // Phase 4（設計書§19.8）: workspace内でもext capture root配下でもない絶対パスへの
        // 書込意図。素通しさせ、実際にACLで拒否された（`STATUS_ACCESS_DENIED`）場合のみ
        // 監査台帳へ記録する（境界自体はACLが既に保証しているので、ここでは何も遮断/
        // 誘導しない——フックは境界にしない、D-01）。
        if !req.write_intent() {
            return None;
        }
        let status = real(object_attributes);
        if status == STATUS_ACCESS_DENIED {
            record_denied_attempt(cfg, &path, req.desired_access);
        }
        return Some(status);
    };

    let rel_lower = ledger_key.to_ascii_lowercase();
    let is_probe = rel_lower.contains("test.txt") || rel_lower.contains("grandchild");
    if is_probe {
        debug_log(&format!(
            "{label}: rel={ledger_key:?} kind={kind:?} desired_access={:#x} \
             disposition={:?} options={:#x} is_dir={} write_intent={} diff_layer_exists={}",
            req.desired_access,
            req.create_disposition,
            req.options,
            req.options & FILE_DIRECTORY_FILE.0 != 0,
            req.write_intent(),
            cfg.diff_layer_dir.join(&rel).is_file(),
        ));
    }

    let facts = LiveFacts {
        cfg,
        rel: &rel,
        ledger_key: &ledger_key,
    };
    let route = decide_open_route(kind, req, &facts);
    let status = match &route {
        Route::DiffLayerAlias { record } => {
            // BUG-171: 台帳へ書くのは本当のopenが成功した後。
            let planned = record
                .then(|| plan_diff_layer_alias_write(cfg, &ledger_key))
                .flatten();
            let status = real(object_attributes);
            finish_diff_layer_alias_write(cfg, planned, status.is_ok());
            status
        }
        Route::Refuse(status) => {
            if is_probe {
                debug_log(&format!(
                    "{label}: rel={ledger_key:?} check_deleted short-circuit status={status:?}"
                ));
            }
            return Some(*status);
        }
        Route::RedirectWrite { source } => {
            // BUG-171: 写すのはopenの前（写さないと既存ファイルを開けない）、
            // 台帳へ書くのはopenが成功した後。
            let diff_layer_path = cfg.diff_layer_dir.join(&rel);
            let copied = copy_up(cfg, &ledger_key, &path, &diff_layer_path, *source);
            let status = unsafe { call_at(object_attributes, &diff_layer_path, real) };
            finish_copy_up(cfg, copied, status.is_ok());
            status
        }
        Route::ReadThrough(target) | Route::DirReadThrough(target) => unsafe {
            call_at(object_attributes, target, real)
        },
        Route::Passthrough => real(object_attributes),
    };
    if is_probe {
        debug_log(&format!(
            "{label}: rel={ledger_key:?} route={route:?} status={status:?}"
        ));
    }
    // 差分層にも版が無い素通しでも、ハンドル→パス対応表には載せる（`FILE_DELETE_ON_CLOSE`の
    // 追跡と、NtClose側での取り除き漏れを防ぐため）。
    track_new_handle(file_handle, status, &ledger_key, req.options);
    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const FILE_OVERWRITE_IF: u32 = 5;

    const DIR: u32 = 0x0000_0001; // FILE_DIRECTORY_FILE

    /// 問い合わせに固定の答えを返し、**何回問い合わせられたか**を数える。
    #[derive(Default)]
    struct Fake {
        deleted: bool,
        file: Option<&'static str>,
        dir: Option<&'static str>,
        asked_deleted: Cell<u32>,
        asked_file: Cell<u32>,
        asked_dir: Cell<u32>,
    }

    impl OpenFacts for Fake {
        fn is_deleted(&self) -> bool {
            self.asked_deleted.set(self.asked_deleted.get() + 1);
            self.deleted
        }
        fn diff_layer_file(&self) -> Option<PathBuf> {
            self.asked_file.set(self.asked_file.get() + 1);
            self.file.map(PathBuf::from)
        }
        fn diff_layer_only_dir(&self) -> Option<PathBuf> {
            self.asked_dir.set(self.asked_dir.get() + 1);
            self.dir.map(PathBuf::from)
        }
    }

    fn create(desired_access: u32, disposition: u32, options: u32) -> OpenRequest {
        OpenRequest {
            desired_access,
            create_disposition: Some(disposition),
            options,
        }
    }

    fn open(desired_access: u32, options: u32) -> OpenRequest {
        OpenRequest {
            desired_access,
            create_disposition: None,
            options,
        }
    }

    /// 1行: (説明, 種別, 要求, 事実) → (答え, 問い合わせた回数 [削除済み, 版, ディレクトリ])。
    type Row = (&'static str, TargetKind, OpenRequest, Fake, Route, [u32; 3]);

    fn rows() -> Vec<Row> {
        use TargetKind::{DiffLayerAlias as Alias, Ext, Workspace as Ws};
        let fake = |deleted, file, dir| Fake {
            deleted,
            file,
            dir,
            ..Fake::default()
        };
        vec![
            (
                "alias write is recorded, and no facts are asked",
                Alias,
                create(FILE_WRITE_DATA, FILE_OPEN_IF, 0),
                fake(true, Some("x"), None),
                Route::DiffLayerAlias { record: true },
                [0, 0, 0],
            ),
            (
                "alias read is not recorded",
                Alias,
                open(FILE_READ_DATA | SYNCHRONIZE, 0),
                fake(false, None, None),
                Route::DiffLayerAlias { record: false },
                [0, 0, 0],
            ),
            (
                "alias directory open with DELETE is not recorded (BUG-048)",
                Alias,
                open(DELETE | SYNCHRONIZE, DIR),
                fake(false, None, None),
                Route::DiffLayerAlias { record: false },
                [0, 0, 0],
            ),
            (
                "deleted path opened by NtOpenFile is refused",
                Ws,
                open(DELETE | FILE_READ_ATTRIBUTES, 0),
                fake(true, None, None),
                Route::Refuse(STATUS_OBJECT_NAME_NOT_FOUND),
                [1, 0, 0],
            ),
            (
                "deleted path read with FILE_OPEN is refused",
                Ws,
                create(FILE_READ_DATA, FILE_OPEN, 0),
                fake(true, None, None),
                Route::Refuse(STATUS_OBJECT_NAME_NOT_FOUND),
                [1, 0, 0],
            ),
            (
                "deleted path recreated with FILE_CREATE is redirected without copying (BUG-172)",
                Ws,
                create(FILE_WRITE_DATA, FILE_CREATE, 0),
                fake(true, None, None),
                Route::RedirectWrite {
                    source: CopySource::Nothing,
                },
                [1, 0, 0],
            ),
            (
                "deleted path opened with FILE_OPEN_IF for reading only is redirected to the diff \
                 layer, so the workspace original stays invisible (case Y)",
                Ws,
                create(FILE_READ_DATA | SYNCHRONIZE, FILE_OPEN_IF, 0),
                fake(true, None, None),
                Route::RedirectWrite {
                    source: CopySource::Nothing,
                },
                [1, 0, 0],
            ),
            (
                "deleted path opened with FILE_SUPERSEDE is also a recreate",
                Ws,
                create(FILE_READ_DATA, 0, 0),
                fake(true, None, None),
                Route::RedirectWrite {
                    source: CopySource::Nothing,
                },
                [1, 0, 0],
            ),
            (
                "write to an existing file copies it up, without asking for the diff layer version",
                Ws,
                create(FILE_WRITE_DATA, FILE_OPEN, 0),
                fake(false, Some("x"), None),
                Route::RedirectWrite {
                    source: CopySource::Workspace,
                },
                [1, 0, 0],
            ),
            (
                "NtOpenFile with DELETE only is a write (the start of a Windows delete or rename)",
                Ws,
                open(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0),
                fake(false, None, None),
                Route::RedirectWrite {
                    source: CopySource::Workspace,
                },
                [1, 0, 0],
            ),
            (
                "truncating disposition is a write even with read access only",
                Ws,
                create(FILE_READ_DATA, FILE_OVERWRITE_IF, 0),
                fake(false, None, None),
                Route::RedirectWrite {
                    source: CopySource::Workspace,
                },
                [1, 0, 0],
            ),
            (
                "read with a diff layer version reads it, without asking for the directory",
                Ws,
                create(FILE_READ_DATA | SYNCHRONIZE, FILE_OPEN, 0),
                fake(false, Some("v"), Some("d")),
                Route::ReadThrough(PathBuf::from("v")),
                [1, 1, 0],
            ),
            (
                "read of a diff-layer-only directory reads it (BUG-128)",
                Ws,
                open(FILE_LIST_DIRECTORY | SYNCHRONIZE, DIR),
                fake(false, None, Some("d")),
                Route::DirReadThrough(PathBuf::from("d")),
                [1, 1, 1],
            ),
            (
                "existing directory opened with DELETE is not a redirected write (BUG-048)",
                Ws,
                open(DELETE | SYNCHRONIZE, DIR),
                fake(false, None, Some("d")),
                Route::DirReadThrough(PathBuf::from("d")),
                [1, 1, 1],
            ),
            (
                "directory created with FILE_CREATE and list access only is not a write intent \
                 (only truncating dispositions count), so it passes through",
                Ws,
                create(FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_CREATE, DIR),
                fake(false, None, None),
                Route::Passthrough,
                [1, 1, 1],
            ),
            (
                "directory created with FILE_CREATE and write access is a redirected write",
                Ws,
                create(FILE_WRITE_DATA | SYNCHRONIZE, FILE_CREATE, DIR),
                fake(false, None, None),
                Route::RedirectWrite {
                    source: CopySource::Workspace,
                },
                [1, 0, 0],
            ),
            (
                "read of an untouched file passes through",
                Ws,
                create(FILE_READ_DATA | SYNCHRONIZE, FILE_OPEN, 0),
                fake(false, None, None),
                Route::Passthrough,
                [1, 1, 1],
            ),
            (
                "ext capture roots follow the same table",
                Ext,
                create(FILE_WRITE_DATA, FILE_OPEN_IF, 0),
                fake(false, None, None),
                Route::RedirectWrite {
                    source: CopySource::Workspace,
                },
                [1, 0, 0],
            ),
        ]
    }

    #[test]
    fn open_routes_match_the_table() {
        let rows = rows();
        assert!(rows.len() >= 16, "the table must not silently shrink");
        for (what, kind, req, facts, want, asked) in rows {
            let got = decide_open_route(kind, &req, &facts);
            assert_eq!(got, want, "{what}");
            assert_eq!(
                [
                    facts.asked_deleted.get(),
                    facts.asked_file.get(),
                    facts.asked_dir.get()
                ],
                asked,
                "{what}: facts must be asked only on the branches that need them"
            );
        }
    }
}
