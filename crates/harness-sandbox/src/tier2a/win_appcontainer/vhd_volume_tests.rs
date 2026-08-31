//! **D-81（差分層はワークスペースと同じボリュームへ置く）を、本物の別ボリュームで検証する。**
//!
//! この開発機には「C: 以外で CoW が通るボリューム」が1本も無い——`G:`は Google Drive の
//! 仮想ドライブ（FAT32 と申告）、`X:`/`Z:`はネットワーク共有、`E:`は DACL の書込を拒否する
//! 暗号化ファイルシステム。そのため D-81 の per-volume 配置は**規則を純関数で検算しただけ**で、
//! 実際に `<ボリューム>\.harness-cow\` へ差分層が落ちる経路を一度も通していなかった。
//!
//! そこで検証用の NTFS ボリュームを VHD（仮想ハードディスク）として作る。
//!
//! ## 作成と撤収を別テストに分けてある理由
//!
//! 実マシンに残る資源（マウントされたボリューム・VHD ファイル）を作るので、**撤収を
//! 同じ変更で用意する**（`bug-pattern-rules` B-01）。さらに `n2_loopback_exemption_add`／
//! `_remove` と同じく**別テストに分ける**——昇格側プロセスへ呼び出し元の環境変数が
//! 引き継がれる保証が無く、引き継がれなければ「撤収したつもりで作成していた」という
//! 無言の取り違えになる。
//!
//! ```text
//! target\debug\dev-elevated-run.exe vhd-ntfs-create   # 作る（UACが1回出る）
//! target\debug\dev-elevated-run.exe vhd-ntfs-remove   # 消す（必ず打つこと）
//! ```
//!
//! ## **この作成経路は現状使えない**（2026-08-24 実測）
//!
//! 上の`vhd-ntfs-create`を実際に撃ったところ、**仮想ディスクファイルの作成までは成功し、
//! 接続（`attach vdisk`）の段で22分かけて失敗した**。ボリュームは1つも増えず、しかも
//! **`System`がそのファイルを掴んだまま**になり、再起動するまで削除できなくなった
//! （`Get-DiskImage`は`Attached: False`を返す半端な状態）。
//!
//! 見立ては「昇格側デーモンが対話デスクトップから切り離された文脈で動いており、
//! 仮想ディスクサービスを介する接続がそこでは通らない」だが、**これは推測で測っていない**。
//! 再挑戦するなら`Mount-DiskImage`経路を試す価値がある。
//!
//! **当面はボリュームを人が用意すること**（ディスクの管理からVHDを作ってNTFSでフォーマットし、
//! ドライブ文字を割り当てる）。**検証本体[`d81_per_volume_placement`]は昇格が要らない**ので、
//! ドライブ文字さえ分かればそのまま回る——実際、D-81の最後の未検証部分はこの形で通した
//! （`T:`、2026-08-25）。手順は`docs/DEV-ENVIRONMENT.md`。

use std::path::{Path, PathBuf};

/// 検証用 VHD の置き場。既存の実機E2E置き場と同じ`C:\harness-e2e`配下に置く。
fn vhd_path() -> PathBuf {
    PathBuf::from(r"C:\harness-e2e\d81-ntfs-probe.vhdx")
}

/// 割り当てるドライブ文字を決める。**既に使われている文字を避ける**——決め打ちにすると、
/// この機の割り当て（C/E/G/X/Z）が変わった日に既存ボリュームを掴みに行く。
fn pick_free_drive_letter() -> Option<char> {
    let used: Vec<char> = crate::win_common::logical_drive_roots()
        .iter()
        .filter_map(|r| r.to_string_lossy().chars().next())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    // A/B はフロッピー用に予約されている慣習があるので避ける。後ろから探すのは、
    // ネットワークドライブが後方の文字を使う慣習と衝突しにくい中間帯を狙うため。
    ('M'..='V').rev().find(|c| !used.contains(c))
}

/// `diskpart`へスクリプトを流す。**戻り値ではなく出力も返す**——`diskpart`は失敗しても
/// 終了コード0を返すことがあるので、呼び出し側が本文を見て判断できるようにする
/// （`bug-pattern-rules` B-10: 外部コマンドの終了コードだけを信じない）。
fn run_diskpart(script: &str) -> (bool, String) {
    let dir = std::env::temp_dir();
    let script_path = dir.join(format!("harness-diskpart-{}.txt", std::process::id()));
    if let Err(e) = std::fs::write(&script_path, script) {
        return (false, format!("could not write the diskpart script: {e}"));
    }
    let output = std::process::Command::new("diskpart")
        .arg("/s")
        .arg(&script_path)
        .output();
    let _ = std::fs::remove_file(&script_path);
    match output {
        Ok(o) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            (o.status.success(), text)
        }
        Err(e) => (false, format!("could not run diskpart: {e}")),
    }
}

/// 検証用の NTFS ボリュームを作ってマウントする（**要管理者**）。
#[test]
#[ignore = "要管理者。`dev-elevated-run.exe vhd-ntfs-create`から回すこと"]
fn vhd_ntfs_create() {
    let vhd = vhd_path();
    if let Some(parent) = vhd.parent() {
        std::fs::create_dir_all(parent).expect("検証用VHDの置き場を作れること");
    }
    assert!(
        !vhd.exists(),
        "{} が既にある。先に `dev-elevated-run.exe vhd-ntfs-remove` で撤収すること",
        vhd.display()
    );
    let letter = pick_free_drive_letter().expect("空きドライブ文字が1つも無い");

    // 256MBあれば足りる（差分層をいくつか置くだけ）。`expandable`なので実消費はさらに小さい。
    let script = format!(
        "create vdisk file=\"{}\" maximum=256 type=expandable\n\
         select vdisk file=\"{}\"\n\
         attach vdisk\n\
         create partition primary\n\
         format fs=ntfs quick label=HARNESSD81\n\
         assign letter={letter}\n",
        vhd.display(),
        vhd.display()
    );
    let (ok, text) = run_diskpart(&script);
    println!("--- diskpart (create) ---\n{text}");
    assert!(ok, "diskpartが失敗した");

    let root = PathBuf::from(format!("{letter}:\\"));
    // **作れたと言われたことを信じない。実際に見て確かめる**（B-25）。
    let cap = crate::win_common::volume_capability(&root);
    println!("mounted {} -> {cap:?}", root.display());
    assert!(
        matches!(&cap, Some(c) if c.persistent_acls && !c.is_remote && c.filesystem == "NTFS"),
        "作った検証用ボリュームがローカルNTFSとして見えていない: {cap:?}"
    );
    println!(
        "\n次はこれを非昇格で回す:\n  HARNESS_TEST_D81_PROBE_DRIVE={letter} cargo test -p harness-sandbox \
         --lib d81_per_volume_placement -- --ignored --nocapture\n終わったら必ず \
         `dev-elevated-run.exe vhd-ntfs-remove` を打つこと。"
    );
}

/// 検証用ボリュームを外して VHD ファイルを消す（**要管理者**。作成と対）。
#[test]
#[ignore = "要管理者。`dev-elevated-run.exe vhd-ntfs-remove`から回すこと"]
fn vhd_ntfs_remove() {
    let vhd = vhd_path();
    if !vhd.exists() {
        println!("{} は既に無い（撤収済み）", vhd.display());
        return;
    }
    let script = format!(
        "select vdisk file=\"{}\"\ndetach vdisk\n",
        vhd.display()
    );
    let (ok, text) = run_diskpart(&script);
    println!("--- diskpart (detach) ---\n{text}");
    // detachが失敗してもファイル削除は試す——**片方だけ残る形を作らない**。
    let removed = std::fs::remove_file(&vhd);
    println!("VHDファイルの削除: {removed:?}");
    assert!(ok, "diskpartのdetachが失敗した");
    removed.expect("VHDファイルを消せること");
    assert!(!vhd.exists(), "撤収したのにVHDファイルが残っている");
}

/// **D-81 の per-volume 配置を、本物の別ボリュームで通す**（昇格不要）。
///
/// `HARNESS_TEST_D81_PROBE_DRIVE`（1文字）で対象ドライブを渡す。`vhd-ntfs-create`が印字する。
#[test]
#[ignore = "検証用ボリュームが要る。先に `dev-elevated-run.exe vhd-ntfs-create` を回すこと"]
fn d81_per_volume_placement() {
    let Ok(letter) = std::env::var("HARNESS_TEST_D81_PROBE_DRIVE") else {
        println!("set HARNESS_TEST_D81_PROBE_DRIVE to the drive letter printed by vhd-ntfs-create");
        return;
    };
    let letter = letter.trim().to_ascii_uppercase();
    let root = PathBuf::from(format!("{letter}:\\"));
    assert!(root.exists(), "{} が見えない", root.display());

    // ワークスペースはボリューム直下ではなく1段下に置く——直下だと差分層がワークスペースの
    // 中に入るのでD-81が拒否する（その拒否も規則としてテスト済み）。
    let workspace = root.join("proj");
    std::fs::create_dir_all(workspace.join("src")).expect("検証用ワークスペースを作れること");
    std::fs::write(workspace.join("README.md"), b"d81 probe\n").expect("ファイルを置けること");

    // (1) ゲートが通ること。**C:と同じ扱いになるはず**（ローカルNTFS・DACL書込可）。
    let cap = crate::win_common::volume_capability(&root);
    let gate = crate::session_scope::cow_volume_gate("workspace", &workspace, cap.clone(), &|| {
        Some(crate::win_common::can_write_dacl(&workspace))
    });
    println!("gate({}) -> {gate:?}", workspace.display());
    assert!(gate.is_ok(), "検証用NTFSボリュームがゲートを通らない: {gate:?}");

    // (2) 差分層の根が**そのボリュームの直下**になること（D-81の本体）。
    let chosen = crate::session_scope::cow_diff_layer_root_for_workspace(&workspace)
        .expect("置き場を決められること");
    println!(
        "cow_diff_layer_root_for_workspace -> {} (fell_back={:?})",
        chosen.root.display(),
        chosen.fell_back
    );
    assert!(
        chosen.fell_back.is_none(),
        "別ボリュームなのに%LOCALAPPDATA%へ降格した: {:?}",
        chosen.fell_back
    );
    let expected = root.join(crate::session_scope::PER_VOLUME_COW_DIRNAME);
    assert_eq!(
        chosen.root, expected,
        "差分層の根がそのボリュームの直下になっていない"
    );
    assert!(
        chosen.root.is_dir(),
        "根の実体が作られていない: {}",
        chosen.root.display()
    );

    // (3) セッションの置き場がその下に来ること。
    let diff_layer = crate::session_scope::cow_diff_layer_dir_in(&chosen.root, "session-d81-probe");
    assert!(diff_layer.starts_with(&expected), "{}", diff_layer.display());
    println!("session diff layer -> {}", diff_layer.display());

    // (4) **AppContainerのACEが実際に載ること**（C:と同じ挙動か。共有では載らなかった）。
    std::fs::create_dir_all(&diff_layer).expect("差分層を作れること");
    let sid = crate::tier2a::win_appcontainer::derive_profile_sid("harness.acl-probe.diagnostic")
        .expect("package SIDを導出できること");
    crate::tier2a::win_appcontainer::grant_ace_inheritable_rw(&diff_layer, sid.as_psid())
        .expect("差分層へACEを付けられること");
    let sid_text = crate::win_common::sid_to_string(sid.as_psid()).unwrap_or_default();
    let readback = std::process::Command::new("icacls")
        .arg(&diff_layer)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    println!("--- icacls {} ---\n{readback}", diff_layer.display());
    assert!(
        readback.contains(sid_text.trim_start_matches('*')),
        "ACEを付けたのに読み返しで見つからない（共有と同じ無言の失敗）"
    );

    // 後始末: このテストが作ったものだけ消す。ボリューム自体は`vhd-ntfs-remove`が畳む。
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&expected);
    println!("\n検証用ワークスペースと差分層を削除した。ボリュームは `dev-elevated-run.exe vhd-ntfs-remove` で撤収すること。");
}

/// 使っていない引数への警告を避けるための参照（`Path`はシグネチャで使う）。
#[allow(dead_code)]
fn _unused(_: &Path) {}
