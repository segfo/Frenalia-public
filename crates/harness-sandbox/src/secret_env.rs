//! secret env allowlist（D-07）。`plans/DESIGN-SANDBOX.md` §7 D-07参照。
//!
//! 子の環境はallowlist方式で構築する: 通す既定はPATH/HOME等toolchain安全集合のみ。
//! さらにallowlist内であっても変数名が秘密っぽいパターン
//! （`KEY`/`SECRET`/`TOKEN`/`PASSWORD`/`CREDENTIAL`）を含む場合は二重ガードとして除外する。
//! 全spawn（`run_shell`の子・`resolve.rs`の内部git）に適用する（Tier0限定機能ではない）。

/// 素通しを許す変数名（大小無視で比較）。
const ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "LANG",
    "APPDATA",
    "LOCALAPPDATA",
    "COMSPEC",
    "CARGO_HOME",
    "RUSTUP_HOME",
    // **`PROGRAMDATA`が無いとMSVCリンカが見つからず、rustcが別物の`link`を掴む。**
    // rustcはVisual Studioの位置をVS Setup Configuration API経由で解決し、その実体は
    // `%ProgramData%\Microsoft\VisualStudio\Packages\_Instances`のインスタンスストアを読む。
    // この変数が無いと列挙が0件になり、rustcはPATHへフォールバックする——そこにGit for
    // Windows（MSYS）が同梱する**GNU coreutilsの`link`**があると、それを起動して
    // `link: extra operand ...` で失敗する。エラー文面がMSVCの話をしないので、
    // 「ビルドツールが入っていない」という誤った結論へ誘導される。
    //
    // 実測（2026-08-10、1差分×1ケース）: allowlistのみの環境で`cargo build --release`が失敗し、
    // `PROGRAMDATA`を1つ足すと成功する。`ProgramFiles`・`ProgramFiles(x86)`・`ProgramW6432`・
    // `windir`を足しても直らない（＝この変数が原因であって「環境が薄いから」ではない）。
    // 公開のシステムパスであり秘密を含まないのでallowlistの趣旨（D-07）と矛盾しない。
    //
    // AppContainer（Tier2a）で同じ症状が出たのが[BUG-014]で、あちらの原因は同じ検出機構への
    // **ACL拒否**だった。原因は違うが壊れ方は同一である。
    "PROGRAMDATA",
    // `PATHEXT`が無いとWindows PowerShell/pwshは外部ネイティブexeの起動に**サイレントに
    // 失敗する**（出力無し・終了コード未設定・エラーも出ない）。既存テストがPowerShell
    // 組み込みコマンドレット（Write-Output等）のみを使っていたため長らく露呈しなかった
    // （協調プロキシE2Eテストでcurl.exeを初めて外部起動して発覚、bug-catalog参照）。
    "PATHEXT",
    // --- 以下6件: OSが`REG_EXPAND_SZ`を**子プロセスのenvに対して**展開するために要る -----
    //
    // 落ちていると`ExpandEnvironmentStringsW`が`%...%`を**そのまま返す**（未定義の変数は
    // 展開されずリテラルとして残る、というWindowsの仕様）。`%`始まりの文字列は**絶対パスでは
    // ない**ため、その後のファイル操作は**CWD（＝workspace root）相対**として解決され、
    // workspace直下に実体ができる。[BUG-104]がまさにこれで、リポジトリ直下に
    // `%SystemDrive%\ProgramData\Microsoft\Windows\Caches\`（約1MB）が実際に作られた
    // ——`HKLM\...\CurrentVersion\ProfileList`の`ProgramData`が`%SystemDrive%\ProgramData`
    // というREG_EXPAND_SZで、既知フォルダ解決がそれを子のenvで展開しようとしたため。
    //
    // 対象はレジストリ実測で決めた（`the_registry_expand_sz_variables_survive_the_allowlist`
    // が同じ走査をテストとして行う）。**実測に出ない変数は足さない**——`PROGRAMW6432`等は
    // どのREG_EXPAND_SZからも参照されていないので入れていない。
    //
    // いずれも公開のシステムパスで、ユーザ名も秘密も含まない（`USERPROFILE`が既に通って
    // いる以上、新たに漏れる情報も無い）。D-07の趣旨＝**秘密を隔離先へ流さない**とは
    // 矛盾しない。
    //
    // 既知フォルダ面（`ProfileList`・`User Shell Folders`）が参照するもの:
    "SYSTEMDRIVE",
    "PUBLIC",
    // COM登録面（`HKLM\SOFTWARE\Classes\[WOW6432Node\]CLSID\*\{Inproc,Local}Server32`）が
    // 参照するもの。`harness-redirector`の`ntpath.rs`が記録しているMpOav.dll（AMSI）系の
    // 未展開パスもこの面から来る。
    "COMMONPROGRAMFILES",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "WINDIR",
];

/// allowlistに載っていても除去する秘密っぽい名前パターン（大小無視の部分一致）。
const SECRET_PATTERNS: &[&str] = &["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"];

fn looks_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_PATTERNS.iter().any(|p| upper.contains(p))
}

fn is_allowlisted(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ALLOWLIST.iter().any(|a| *a == upper)
}

/// 子プロセスへ渡すクリーンなenvを、現在プロセスの環境から構築する。
pub fn build_child_env() -> Vec<(String, String)> {
    build_child_env_from(std::env::vars())
}

/// テスト用: 任意の環境イテレータからクリーンなenvを構築する。
pub fn build_child_env_from(
    vars: impl IntoIterator<Item = (String, String)>,
) -> Vec<(String, String)> {
    vars.into_iter()
        .filter(|(name, _)| is_allowlisted(name) && !looks_secret(name))
        .collect()
}

/// `harness_core::git::hardening_env`の再エクスポート。定義自体はそちらへ移した
/// （`harness-cognition`のRecall機構が`harness-sandbox`へ依存せずに同じハードニングを使うため。
/// `harness_core::git`のモジュールdoc参照）。既存呼び出し元（`shell.rs`・`resolve.rs`）は
/// この再エクスポートにより無改造のまま動く。
pub use harness_core::git::hardening_env as git_hardening_env;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_non_allowlisted_and_secret_looking_vars() {
        let env = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("ANTHROPIC_API_KEY".to_string(), "sk-secret".to_string()),
            ("OPENAI_API_KEY".to_string(), "sk-secret2".to_string()),
            ("HOME".to_string(), "/home/u".to_string()),
            ("SOME_RANDOM_VAR".to_string(), "x".to_string()),
        ];
        let cleaned = build_child_env_from(env);
        let names: Vec<&str> = cleaned.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"HOME"));
        assert!(!names.contains(&"ANTHROPIC_API_KEY"));
        assert!(!names.contains(&"OPENAI_API_KEY"));
        assert!(!names.contains(&"SOME_RANDOM_VAR"));
    }

    /// **MSVCツールチェーンの検出に要る変数が落ちていないこと。**
    ///
    /// `PROGRAMDATA`が無いとrustcはVisual Studioを見つけられず、PATH上のGNU `link`
    /// （Git for Windows同梱）を掴んで`link: extra operand ...`で失敗する。
    /// エラーがMSVCの話をしないため「ビルドツールが未インストール」と誤診されやすい
    /// （実測とBUG-014との関係はALLOWLIST側のコメント参照）。
    ///
    /// **綴りは実際の環境変数名と一致していなければ意味が無い**ので、
    /// 判定関数`is_allowlisted`を通す（定数配列を直接見ない。大小の扱いまで含めて検証する）。
    #[test]
    fn the_msvc_toolchain_lookup_variables_survive_the_allowlist() {
        for name in ["ProgramData", "PROGRAMDATA", "programdata"] {
            assert!(
                is_allowlisted(name),
                "{name} must pass the allowlist, otherwise rustc cannot locate the MSVC linker \
                 and silently falls back to an unrelated `link` on PATH"
            );
        }
        // 実際に構築しても残ることを確認する（`looks_secret`に巻き込まれていないこと）。
        let cleaned = build_child_env_from(vec![(
            "ProgramData".to_string(),
            r"C:\ProgramData".to_string(),
        )]);
        assert_eq!(
            cleaned.len(),
            1,
            "ProgramData must survive build_child_env_from"
        );
    }

    #[test]
    fn allowlisted_name_that_looks_secret_is_still_dropped() {
        // 現実には無いが、二重ガードの意図（allowlist内でも秘密パターンなら除外）を確認。
        let env = vec![("CARGO_HOME".to_string(), "/home/u/.cargo".to_string())];
        let cleaned = build_child_env_from(env);
        assert_eq!(cleaned.len(), 1);

        let env2 = vec![("HOME_API_KEY".to_string(), "x".to_string())];
        assert!(build_child_env_from(env2).is_empty());
    }
}

/// **OSが子のenvに対して展開する`%VAR%`が、allowlistを通ること**（BUG-104）。
///
/// 変数名を並べるだけのテストは`ALLOWLIST`の写経にしかならず、「その集合が正しいのか」を
/// 何も検証しない。ここでは**実際のレジストリを走査**して、Windowsが`REG_EXPAND_SZ`で
/// 参照している変数名そのものを取り出し、それがallowlistを通ることを見る。
/// OS側が新しい変数を参照し始めたら、こちらのテストが落ちて気付ける。
#[cfg(all(test, windows))]
mod registry_expand_sz_tests {
    use super::*;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_EXPAND_SZ,
    };

    /// 走査対象。**OSが所有する既知フォルダ面だけ**にする。
    ///
    /// ここが`%VAR%`を落としたときに「CWD相対で実体が作られる」面そのものである。
    /// CLSID面（COM登録）は第三者アプリが`%MYAPP%`のような独自変数を登録し得て、
    /// 他マシンでフレーキーになるため走査しない（下の静的テストで測定値を固定する）。
    const KNOWN_FOLDER_KEYS: &[(HKEY, &str)] = &[
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ),
    ];

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// `%NAME%`の`NAME`だけを拾う（大文字化）。`C:\%foo`のような閉じない`%`は無視する。
    fn variable_names_in(value: &str) -> Vec<String> {
        let chars: Vec<char> = value.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '%' {
                // `find`はレンジの**要素**（＝chars上の添字そのもの）を返す。`position`は
                // 反復内の相対位置を返すので取り違えると添字が壊れる。
                if let Some(end) = (i + 1..chars.len()).find(|&j| chars[j] == '%') {
                    let name: String = chars[i + 1..end].iter().collect();
                    // パス区切りを含むものは変数名ではない（`%`が単体で現れただけ）。
                    if !name.is_empty() && !name.contains('\\') && !name.contains('/') {
                        out.push(name.to_ascii_uppercase());
                    }
                    i = end + 1;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// 1キーの`REG_EXPAND_SZ`値を列挙して、参照されている変数名を集める。
    ///
    /// `RegEnumValueW`は`REG_EXPAND_SZ`を**展開せずに**返す（`RegGetValueW`と違って
    /// `RRF_NOEXPAND`相当が既定）。展開された値を見てしまうと`%VAR%`が消えて
    /// このテストは何も測れなくなるので、APIの選択はここが要点である。
    fn expand_sz_variable_names(root: HKEY, subkey: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut hkey = HKEY::default();
        // ワイド文字列は**呼び出しより長く生きる変数へ束縛する**。`PCWSTR(wide(..).as_ptr())`と
        // 一時値のまま書いても現状は文末まで生きて健全だが、後の整形や式の分割で
        // 静かにダングリングへ変わり得るので、寿命をコードの形で固定しておく。
        let subkey_w = wide(subkey);
        let status =
            unsafe { RegOpenKeyExW(root, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hkey) };
        if status != ERROR_SUCCESS {
            // 開けないキーは走査対象から外れるだけ。**全キーが開けなければ**下の対照群
            // assertが落ちるので、無言で「合格」にはならない。
            return names;
        }
        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 512];
            let mut name_len = name_buf.len() as u32;
            let mut value_type: u32 = 0;
            let mut data_buf = [0u8; 8192];
            let mut data_len = data_buf.len() as u32;
            let status = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_SUCCESS && value_type == REG_EXPAND_SZ.0 {
                let units = (data_len as usize) / 2;
                let mut wide_value = vec![0u16; units];
                for (k, slot) in wide_value.iter_mut().enumerate() {
                    *slot = u16::from_le_bytes([data_buf[k * 2], data_buf[k * 2 + 1]]);
                }
                while wide_value.last() == Some(&0) {
                    wide_value.pop();
                }
                names.extend(variable_names_in(&String::from_utf16_lossy(&wide_value)));
            }
            // 値が1つ読めなくても（バッファ不足等）走査は続ける——1件の取りこぼしで
            // テスト全体が黙って通らないよう、判定は集めた総数に対して行う。
            index += 1;
        }
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        names
    }

    #[test]
    fn the_registry_expand_sz_variables_survive_the_allowlist() {
        let mut found: Vec<String> = Vec::new();
        for (root, subkey) in KNOWN_FOLDER_KEYS {
            found.extend(expand_sz_variable_names(*root, subkey));
        }
        found.sort();
        found.dedup();

        // **対照群**（B-35）: 1件も拾えていないなら、このテストは何も検証していない。
        // レジストリが読めない・キー名が変わった等をここで落とす。
        assert!(
            !found.is_empty(),
            "control: no REG_EXPAND_SZ variable was collected from {} known-folder keys; \
             the scan itself is broken, so the assertions below would be vacuous",
            KNOWN_FOLDER_KEYS.len()
        );

        for name in &found {
            assert!(
                is_allowlisted(name),
                "%{name}% is referenced by a known-folder REG_EXPAND_SZ value but does not pass \
                 the allowlist. A child spawned with build_child_env() cannot expand it, so \
                 ExpandEnvironmentStringsW returns the literal `%{name}%\\...` — which is not an \
                 absolute path and therefore gets created **relative to the child's CWD \
                 (= workspace root)**. That is BUG-104: `%SystemDrive%\\ProgramData\\...` was \
                 actually created in the repository root. Add {name} to ALLOWLIST. \
                 (collected: {found:?})"
            );
        }
    }

    /// COM登録面（CLSID）の測定値を固定する。
    ///
    /// 走査ではなく静的リストなのは上の`KNOWN_FOLDER_KEYS`のdocのとおり（第三者COM登録で
    /// フレーキーになるため）。2026-08-12の実測での参照数は
    /// `SYSTEMROOT`=5794 / `COMMONPROGRAMFILES`=217 / `PROGRAMFILES`=49 / `WINDIR`=14 /
    /// `PROGRAMFILES(X86)`=8 / `PROGRAMDATA`=4（`HKLM\SOFTWARE\Classes\[WOW6432Node\]CLSID\*\
    /// {Inproc,Local}Server32`の`REG_EXPAND_SZ`）。
    #[test]
    fn the_measured_com_registration_variables_survive_the_allowlist() {
        for name in [
            "SYSTEMROOT",
            "COMMONPROGRAMFILES",
            "PROGRAMFILES",
            "WINDIR",
            "PROGRAMFILES(X86)",
            "PROGRAMDATA",
        ] {
            assert!(
                is_allowlisted(name),
                "%{name}% is referenced by COM server registrations (REG_EXPAND_SZ under CLSID). \
                 Dropping it makes those DLL/EXE paths resolve relative to the child's CWD \
                 instead of failing loudly (BUG-104の同型)"
            );
        }
        // 綴りの揺れで素通りしないこと（`is_allowlisted`は大小を吸収する契約）。
        assert!(is_allowlisted("ProgramFiles(x86)"));
    }
}
