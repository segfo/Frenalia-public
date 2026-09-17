//! [段階6f-2] 変換の単体テスト。**昇格もDaemonも要らない**ものだけをここに置く。
//!
//! # 一番大事なのは「OSに聞く」テストである
//!
//! 実行ファイルの解決は**OSの規則を自前で書き直したもの**なので、期待値を手で書くと
//! 「規則を取り違えたまま緑になる」形を固定してしまう（[BUG-158](../../../docs/bugs/BUG-158.md)で
//! 実際にやった）。だから[`resolution_tests`]は、同じコマンドラインを
//! **こちらの解決器**と**本物の`CreateProcessW`**の両方へ通し、
//! `QueryFullProcessImageNameW`が答えた実体と突き合わせる。

use super::*;

mod candidate_tests {
    use super::*;

    /// 引用符で始まるなら、閉じ引用符までが実行ファイルで**候補は1つ**。
    #[test]
    fn a_quoted_image_is_the_only_candidate() {
        assert_eq!(
            image_candidates(r#""C:\Program Files\x\app.exe" --flag a b"#),
            vec![r"C:\Program Files\x\app.exe".to_string()],
            "引用符で囲まれていれば曖昧さは無い。候補を増やすと、OSが見ないものを試すことになる"
        );
    }

    /// 引用符が無ければ、**空白で区切った前置を順に**試す（OSの規則）。
    #[test]
    fn an_unquoted_path_with_spaces_yields_every_prefix_in_order() {
        assert_eq!(
            image_candidates(r"C:\Program Files\sub dir\app name --flag"),
            vec![
                r"C:\Program".to_string(),
                r"C:\Program Files\sub".to_string(),
                r"C:\Program Files\sub dir\app".to_string(),
                r"C:\Program Files\sub dir\app name".to_string(),
                r"C:\Program Files\sub dir\app name --flag".to_string(),
            ],
            "順序が命である。**前から**試すのがOSの規則で、逆にすると\
             `C:\\Program.exe`を置いた攻撃者ではなく本来の実行ファイルが起きてしまい、\
             判定した値と起きる値が食い違う"
        );
    }

    /// 前後の空白と重複の扱い。**空の候補を作らない**——空文字で`SearchPathW`を呼ぶと
    /// 「見つからない」ではなく未定義の答えが返り得る。
    #[test]
    fn leading_whitespace_and_empty_candidates_are_dropped() {
        assert_eq!(
            image_candidates("   cmd.exe  /c  echo"),
            vec![
                "cmd.exe".to_string(),
                "cmd.exe  /c".to_string(),
                "cmd.exe  /c  echo".to_string(),
            ]
        );
        assert!(image_candidates("   ").is_empty());
        assert!(image_candidates(r#""""#).is_empty());
    }
}

mod console_tests {
    use super::*;

    /// **対で見る**（`B-35`）。片側だけだと「常に`required`」「常に`not_needed`」の
    /// どちらの実装でも半分は緑になる。取り違えると、片側は起動失敗、
    /// もう片側は**終了コード0の無言失敗**になる。
    #[test]
    fn a_caller_that_asks_for_no_window_does_not_need_a_console_and_a_plain_caller_does() {
        assert_eq!(console_need_from_flags(0), "required");
        assert_eq!(console_need_from_flags(CREATE_NO_WINDOW), "not_needed");
        assert_eq!(console_need_from_flags(DETACHED_PROCESS), "not_needed");
        // 一時停止と組み合わさっても、コンソールの答えは変わらない。
        assert_eq!(
            console_need_from_flags(CREATE_SUSPENDED_FLAG),
            "required",
            "一時停止はコンソールと無関係の軸である"
        );
        // 新しいコンソールが欲しい呼び出し元は「要る」側（モジュールdoc）。
        assert_eq!(console_need_from_flags(0x0000_0010), "required");
    }
}

mod environment_tests {
    use super::*;

    fn block(entries: &[&str]) -> Vec<u16> {
        let mut out = Vec::new();
        for entry in entries {
            out.extend(entry.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    #[test]
    fn a_utf16_block_becomes_name_value_pairs() {
        assert_eq!(
            parse_env_block_utf16(&block(&["PATH=C:\\bin", "FOO=bar=baz"])),
            vec![
                ("PATH".to_string(), "C:\\bin".to_string()),
                ("FOO".to_string(), "bar=baz".to_string()),
            ],
            "値に`=`が含まれても、名前は**最初の`=`まで**である"
        );
    }

    /// 先頭が`=`の項目（ドライブごとのカレントディレクトリ）は落とす。
    ///
    /// **落とさないと名前が空の変数をDaemonへ送ることになる**——受け取った側が
    /// `=値`という綴りで環境ブロックを組み直すので、意味の違うものが生える。
    #[test]
    fn the_hidden_per_drive_entries_are_dropped() {
        let parsed = parse_env_block_utf16(&block(&["=C:=C:\\work", "PATH=C:\\bin"]));
        assert_eq!(parsed, vec![("PATH".to_string(), "C:\\bin".to_string())]);
    }

    /// **空のブロックは空の一覧になる**（`P-11`: 「空だと申告した」は「申告していない」とは別で、
    /// こちらは前者である。電文では`[]`として運ばれる）。
    #[test]
    fn an_empty_block_is_an_empty_declaration_not_a_missing_one() {
        assert!(parse_env_block_utf16(&[0u16]).is_empty());
        assert!(parse_env_block_utf16(&[]).is_empty());
    }

    /// **ANSIのブロックも読めること。** `CreateProcessW`でも
    /// `CREATE_UNICODE_ENVIRONMENT`が無ければ環境ブロックはANSIである
    /// ——取り違えると1項目目の途中で切れ、環境が丸ごと消える。
    #[test]
    fn an_ansi_block_is_converted_before_parsing() {
        let mut bytes: Vec<u8> = Vec::new();
        for entry in ["PATH=C:\\bin", "FOO=bar"] {
            bytes.extend(entry.as_bytes());
            bytes.push(0);
        }
        bytes.push(0);
        assert_eq!(
            parse_env_block_utf16(&ansi_to_wide(&bytes)),
            vec![
                ("PATH".to_string(), "C:\\bin".to_string()),
                ("FOO".to_string(), "bar".to_string()),
            ]
        );
    }
}

mod request_tests {
    use super::*;

    /// **電文のバイト列を固定する。**
    ///
    /// `harness-sandbox`側は別クレート・別プロセスで、**どちらかだけを直しても
    /// コンパイルは通る**（モジュールdoc）。あちらの`spawnd::wire_tests`に
    /// **同じ文字列を`SpawnRequest`として読む守り**があり、2つで1組である。
    #[test]
    fn the_request_is_the_wire_the_daemon_expects() {
        let payload = build_request(
            r"C:\Windows\System32\cmd.exe",
            r#""C:\Windows\System32\cmd.exe" /c echo hi"#,
            r"C:\ws",
            &[("PATH".to_string(), r"C:\bin".to_string())],
            None,
            Some(123),
            Some(456),
            "required",
            false,
        );
        assert_eq!(
            payload,
            r#"{"command_line":"\"C:\\Windows\\System32\\cmd.exe\" /c echo hi","console":"required","cwd":"C:\\ws","env":[["PATH","C:\\bin"]],"handles":{"stderr":456,"stdin":null,"stdout":123},"image":"C:\\Windows\\System32\\cmd.exe","kind":"spawn","suspended":false}"#,
            "これは harness-sandbox の SpawnRequest::Spawn として読めなければならない"
        );
    }

    /// **知らない綴り・壊れた応答は「起きた」にしない。**
    ///
    /// 対で見る（`B-35`）——成功側だけだと「常に成功と読む」実装で緑になり、
    /// そのとき呼び出し元は**空のハンドルで待つ**ことになる。
    #[test]
    fn only_a_well_formed_spawned_reply_counts_as_started() {
        assert_eq!(
            parse_reply(br#"{"kind":"spawned","pid":4242,"process":16,"thread":24}"#),
            Reply::Spawned(Spawned {
                pid: 4242,
                process: 16,
                thread: 24
            })
        );
        assert_eq!(
            parse_reply(br#"{"kind":"denied","reason":{"kind":"no_matching_edge"}}"#),
            Reply::Denied
        );
        assert_eq!(parse_reply(br#"{"kind":"something-new"}"#), Reply::Denied);
        assert_eq!(parse_reply(b""), Reply::Denied);
        // ハンドルが0の「成功」は成功ではない。
        assert_eq!(
            parse_reply(br#"{"kind":"spawned","pid":1,"process":0,"thread":24}"#),
            Reply::Denied
        );
    }
}

/// **OSに聞いて検算する**（決定4）。
///
/// 期待値を手で書くのではなく、同じコマンドラインを本物の`CreateProcessW`へ
/// `lpApplicationName = NULL`で渡し、`QueryFullProcessImageNameW`が答えた実体と比べる。
/// 起こすのは**一時停止したまま**で、比べたら即座に終了させるので副作用は無い。
mod resolution_tests {
    use super::*;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, QueryFullProcessImageNameW, TerminateProcess, CREATE_SUSPENDED,
        PROCESS_INFORMATION, PROCESS_NAME_FORMAT, STARTUPINFOW,
    };

    /// そのコマンドラインでOSが実際に起こす実行ファイル。起こせなければ`None`。
    fn what_the_os_actually_starts(command_line: &str) -> Option<String> {
        let mut wide: Vec<u16> = command_line
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessW(
                None,
                PWSTR(wide.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &startup,
                &mut info,
            )
            .ok()?;
            let mut buffer = vec![0u16; 1024];
            let mut size = buffer.len() as u32;
            let queried = QueryFullProcessImageNameW(
                info.hProcess,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );
            let _ = TerminateProcess(info.hProcess, 1);
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(info.hProcess);
            queried.ok()?;
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }

    fn assert_same_as_the_os(command_line: &str) {
        let ours = resolve_image(None, Some(command_line));
        let theirs = what_the_os_actually_starts(command_line);
        match (&ours, &theirs) {
            (Some(ours), Some(theirs)) => assert!(
                ours.eq_ignore_ascii_case(theirs),
                "解決がOSとずれた。判定した実行ファイルと起きる実行ファイルが\
                 別物になる（§8.2が禁じている形）\n  command line: {command_line}\n  \
                 ours:  {ours}\n  OS:    {theirs}"
            ),
            (None, None) => {}
            _ => panic!(
                "片方だけが解決した。\n  command line: {command_line}\n  \
                 ours: {ours:?}\n  OS:   {theirs:?}"
            ),
        }
    }

    /// 起こしても何もしない実行ファイルを2つ置く。**このテストバイナリ自身を写す**
    /// ——有効なPEであれば中身は何でもよく（一時停止のまま終了させるので1行も走らない）、
    /// 外部のツールに依存しないで済む。
    fn stage_two_executables(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let me = std::env::current_exe().expect("the test binary has a path");
        let short = dir.join("amb.exe");
        let long = dir.join("amb sub.exe");
        std::fs::copy(&me, &short).expect("copy the short-named executable");
        std::fs::copy(&me, &long).expect("copy the long-named executable");
        (short, long)
    }

    /// 引用符つき・引用符なし・`PATH`から引く・拡張子なし の4つの形が、
    /// **どれもOSと同じ実行ファイルへ落ちる**こと。
    #[test]
    fn the_resolver_agrees_with_the_operating_system() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (short, long) = stage_two_executables(dir.path());

        // (1) 引用符つき——空白入りでも曖昧さは無い。
        assert_same_as_the_os(&format!("\"{}\" --flag", long.display()));
        // (2) **引用符なしで空白入り**。短い名前が在るので、OSはそちらを先に掴む。
        assert_same_as_the_os(&format!("{} --flag", long.display()));
        // (3) `PATH`から引く。
        assert_same_as_the_os("cmd.exe /c exit");
        // (4) 拡張子なし——`.exe`が補われる。
        assert_same_as_the_os("cmd /c exit");

        // (2)が本当に「短い側」を掴んでいることまで見る。**これを見ないと、
        // 両方とも同じ答えを返す壊れた実装でも「一致した」ことになる**（計器を疑う）。
        let ambiguous = format!("{} --flag", long.display());
        assert_eq!(
            resolve_image(None, Some(&ambiguous))
                .map(|p| p.to_ascii_lowercase()),
            Some(short.to_string_lossy().to_ascii_lowercase()),
            "空白入りの未引用は、**前の候補**から試すのがOSの規則である"
        );
    }

    /// 短い側が無ければ、長い側が選ばれる（上のテストの対）。
    #[test]
    fn without_the_shorter_neighbour_the_full_name_is_used() {
        let dir = tempfile::tempdir().expect("temp dir");
        let me = std::env::current_exe().expect("the test binary has a path");
        let long = dir.path().join("only sub.exe");
        std::fs::copy(&me, &long).expect("copy");

        let command_line = format!("{} --flag", long.display());
        assert_same_as_the_os(&command_line);
        assert_eq!(
            resolve_image(None, Some(&command_line)).map(|p| p.to_ascii_lowercase()),
            Some(long.to_string_lossy().to_ascii_lowercase())
        );
    }

    /// `lpApplicationName`が在るときは**それだけを見る**。
    /// 存在しなければ`None`——「Daemonが断った」の顔で返さないため。
    #[test]
    fn an_explicit_application_name_wins_and_must_exist() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (short, _long) = stage_two_executables(dir.path());
        let resolved = resolve_image(
            Some(&short.to_string_lossy()),
            Some(r"totally\different\command line"),
        );
        assert_eq!(
            resolved.map(|p| p.to_ascii_lowercase()),
            Some(short.to_string_lossy().to_ascii_lowercase())
        );
        assert_eq!(
            resolve_image(Some(&dir.path().join("missing.exe").to_string_lossy()), None),
            None,
            "在りもしない実行ファイルを電文へ載せると、拒否の理由が実物と食い違う"
        );
    }
}
