//! FS検査（workspace内のcreate/modify/delete/rename）と脱走試行（workspace外への書込・読取）。
//!
//! 2026-10-06 に`main.rs`からそのまま移した——`main.rs`は本体1,000行を超えており、
//! `--spawn-stdin`（`plans/position-domains/P5.md` の P5.4b）を足す行数以上を外へ出すため。

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

fn fs_op(op: &str, path: &Path, result: std::io::Result<()>) -> Value {
    match result {
        Ok(()) => {
            json!({"op": op, "path": path.display().to_string(), "ok": true, "os_error": null})
        }
        Err(e) => json!({
            "op": op,
            "path": path.display().to_string(),
            "ok": false,
            "os_error": e.raw_os_error(),
            "error": e.to_string(),
        }),
    }
}

pub(crate) fn run_fs_checks(tag: &str) -> Vec<Value> {
    let mut out = Vec::new();

    let new_path = PathBuf::from(format!("{tag}-new.txt"));
    out.push(fs_op(
        "create",
        &new_path,
        fs::write(&new_path, format!("created-by-{tag}")),
    ));

    let seed_path = PathBuf::from(format!("{tag}-seed.txt"));
    out.push(fs_op(
        "modify",
        &seed_path,
        fs::write(&seed_path, format!("modified-by-{tag}")),
    ));

    let del_path = PathBuf::from(format!("{tag}-del.txt"));
    out.push(fs_op("delete", &del_path, fs::remove_file(&del_path)));

    let ren_from = PathBuf::from(format!("{tag}-ren.txt"));
    let ren_to = PathBuf::from(format!("{tag}-ren2.txt"));
    out.push(fs_op("rename", &ren_from, fs::rename(&ren_from, &ren_to)));

    out
}

pub(crate) fn run_escape_checks(tag: &str, outside_read: Option<&Path>) -> Vec<Value> {
    let mut out = Vec::new();

    let windows_target = PathBuf::from(format!("C:\\Windows\\harness-escape-{tag}.txt"));
    out.push(fs_op(
        "escape-write-windows",
        &windows_target,
        fs::write(&windows_target, "should-not-be-writable"),
    ));

    if let Some(profile) = env::var_os("USERPROFILE") {
        let profile_target = PathBuf::from(profile).join(format!("harness-escape-{tag}.txt"));
        out.push(fs_op(
            "escape-write-userprofile",
            &profile_target,
            fs::write(&profile_target, "should-not-be-writable"),
        ));
    } else {
        out.push(json!({
            "op": "escape-write-userprofile", "path": null, "ok": false,
            "os_error": null, "error": "USERPROFILE not set",
        }));
    }

    if let Ok(cwd) = env::current_dir() {
        if let Some(parent) = cwd.parent() {
            let parent_target = parent.join(format!("harness-escape-{tag}.txt"));
            out.push(fs_op(
                "escape-write-parent",
                &parent_target,
                fs::write(&parent_target, "should-not-be-writable"),
            ));
        }
    }

    let win_ini = PathBuf::from("C:\\Windows\\win.ini");
    out.push(fs_op(
        "escape-read-baseline",
        &win_ini,
        fs::read(&win_ini).map(|_| ()),
    ));

    if let Some(outside) = outside_read {
        out.push(fs_op(
            "escape-read-outside",
            outside,
            fs::read(outside).map(|_| ()),
        ));
    }

    out
}
