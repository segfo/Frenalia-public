//! [`super`]（子の PowerShell が書いた CLIXML を文字へ戻す）のテスト。
//!
//! 実物の固定入力は、2026-10-07 にユーザーが Tier2a の TUI で見た結果欄（BUG-238）を
//! セッション記録（`.harness/sessions/*.jsonl`）からそのまま切り出したもの。
//! **手で書き写していない**——1文字でも違えば、それは PowerShell が書いたものではなくなる。

use super::*;

/// BUG-238 の発端。`powershell -NoP -Enc {{val:1}}`（中身は `pwsh --enc …`）の標準エラー。
/// 内側の PowerShell の起動時警告・進行表示3件・`pwsh` が見つからないエラーが入っている。
const SESSION_PWSH_NOT_FOUND: &str = concat!(
    "#< CLIXML\r\n",
    r##"<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">'FileSystem' プロバイダーで InitializeDefaultDrives 操作を実行しようとして失敗しました。_x000D__x000A_</S><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">2</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="2"><TNRef RefId="0" /><MS><I64 N="SourceId">2</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><S S="Error">pwsh : The term 'pwsh' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the_x000D__x000A_</S><S S="Error"> spelling of the name, or if a path was included, verify that the path is correct and try again._x000D__x000A_</S><S S="Error">At line:1 char:1_x000D__x000A_</S><S S="Error">+ pwsh --enc cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAQQBCADMAQQBIAE0AQQBhAEEAQQ ..._x000D__x000A_</S><S S="Error">+ ~~~~_x000D__x000A_</S><S S="Error">    + CategoryInfo          : ObjectNotFound: (pwsh:String) [], CommandNotFoundException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : CommandNotFoundException_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs>"##
);

/// 同じセッションの1回目。`Write-Host hello` を `-Enc` で撃ったときの標準エラー
/// （標準出力には `hello` が出ている）。
const SESSION_WRITE_HOST: &str = concat!(
    "#< CLIXML\r\n",
    r##"<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">'FileSystem' プロバイダーで InitializeDefaultDrives 操作を実行しようとして失敗しました。_x000D__x000A_</S><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="information" RefId="1"><TN RefId="1"><T>System.Management.Automation.InformationRecord</T><T>System.Object</T></TN><ToString>hello</ToString><Props><Obj N="MessageData" RefId="2"><TN RefId="2"><T>System.Management.Automation.HostInformationMessage</T><T>System.Object</T></TN><ToString>hello</ToString><Props><S N="Message">hello</S><B N="NoNewLine">false</B><S N="ForegroundColor">Gray</S><S N="BackgroundColor">Black</S></Props></Obj><S N="Source">Write-Host</S><DT N="TimeGenerated">2026-10-07T09:04:31.426482+09:00</DT><Obj N="Tags" RefId="3"><TN RefId="3"><T>System.Collections.Generic.List`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T><T>System.Object</T></TN><LST><S>PSHOST</S></LST></Obj><S N="User">EVO-X2\segfo</S><S N="Computer">EVO-X2</S><U32 N="ProcessId">33348</U32><U32 N="NativeThreadId">39168</U32><U32 N="ManagedThreadId">13</U32></Props></Obj></Objs>"##
);

const OBJS_OPEN: &str =
    r#"<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">"#;

fn block(children: &str) -> String {
    format!("#< CLIXML\r\n{OBJS_OPEN}{children}</Objs>")
}

/// 発端の結果欄で起きたことを、そのまま裏返して固定する。TUI は先頭400文字しか出さない
/// （`harness-tui` の `MAX_OUTPUT_PREVIEW`）ので、**本当のエラーがその範囲に入る**ことまで見る。
#[test]
fn the_real_error_comes_out_of_the_xml_and_into_the_first_400_chars() {
    let restored = restore(SESSION_PWSH_NOT_FOUND.to_string());

    assert!(!restored.text.contains("#< CLIXML"), "{}", restored.text);
    assert!(!restored.text.contains("<Objs"), "{}", restored.text);
    let head: String = restored.text.chars().take(400).collect();
    assert!(
        head.contains("pwsh : The term 'pwsh' is not recognized"),
        "本当のエラーが先頭400文字に入っていない:\n{head}"
    );
    // 内側の PowerShell の起動時警告は本文に残る（文言で外すことはしない。B-33）。
    assert!(restored
        .text
        .starts_with("'FileSystem' プロバイダーで InitializeDefaultDrives 操作を実行しようとして失敗しました。\r\npwsh : "));
    // エラーの最後の行まで欠けずに戻っている。
    assert!(restored
        .text
        .ends_with("    + FullyQualifiedErrorId : CommandNotFoundException\r\n \r\n"));
    assert_eq!(restored.restored_blocks, 1);
    assert_eq!(restored.raw_blocks, 0);
}

/// 進行表示は本文から外すが、捨てずに件数ごと持つ（B-10）。
#[test]
fn progress_records_leave_the_body_but_are_counted() {
    let restored = restore(SESSION_PWSH_NOT_FOUND.to_string());

    assert!(
        !restored.text.contains("Preparing modules"),
        "{}",
        restored.text
    );
    assert_eq!(
        restored.progress,
        vec![("Preparing modules for first use.".to_string(), 3)]
    );
}

/// `Write-Host` の情報レコード（Tags に `PSHOST`）は、同じ文字が標準出力に既に出ているので
/// 本文に重ねない。重ねると `hello` が2回出る。
#[test]
fn write_host_is_not_repeated_on_top_of_stdout() {
    let restored = restore(SESSION_WRITE_HOST.to_string());

    assert_eq!(
        restored.text,
        "'FileSystem' プロバイダーで InitializeDefaultDrives 操作を実行しようとして失敗しました。\r\n"
    );
    assert_eq!(restored.restored_blocks, 1);
}

/// `PSHOST` の付かない情報レコード（`Write-Information`）は標準出力に出ないので、本文に残す。
#[test]
fn information_without_pshost_is_kept() {
    let restored = restore(block(
        r#"<Obj S="information" RefId="1"><TN RefId="1"><T>System.Management.Automation.InformationRecord</T><T>System.Object</T></TN><ToString>i1</ToString><Props><S N="MessageData">i1</S><S N="Source">Write-Information</S><Obj N="Tags" RefId="2"><TN RefId="2"><T>System.Collections.Generic.List`1</T></TN><LST /></Obj></Props></Obj>"#,
    ));

    assert_eq!(restored.text, "i1\n");
}

/// 警告・詳細・デバッグはコンソールと同じ前置きを付ける（無いと普通の出力と区別が付かない）。
#[test]
fn warning_verbose_and_debug_get_the_console_prefix() {
    let restored = restore(block(
        r#"<S S="warning">w1</S><S S="verbose">v1</S><S S="debug">d1</S>"#,
    ));

    assert_eq!(restored.text, "WARNING: w1\nVERBOSE: v1\nDEBUG: d1\n");
}

/// 前置きを付ける行は、改行で終わっていないエラーの断片の後ろでも行頭から始まる。
#[test]
fn a_prefixed_line_starts_on_its_own_line() {
    let restored = restore(block(r#"<S S="Error">partial</S><S S="warning">w</S>"#));

    assert_eq!(restored.text, "partial\nWARNING: w\n");
}

#[test]
fn powershell_and_xml_escapes_are_decoded() {
    let restored = restore(block(concat!(
        r#"<S S="Error">a&lt;b&gt; &amp; &quot;q&quot; &apos;s&apos; &#65;&#x42;_x000D__x000A_</S>"#,
        // `_x005F_` は `_` 自身。続く `x0041_` は文字の並びのまま残る（もう一度解かない）。
        r#"<S S="Error">_x005F_x0041_ _xZZ _x00_x000A_</S>"#,
        // UTF-16 のサロゲート対は1文字へ。片割れは置換文字へ。
        r#"<S S="Error">_xD83D__xDE00_ _xD83D_!_x000A_</S>"#,
    )));

    assert_eq!(
        restored.text,
        "a<b> & \"q\" 's' AB\r\n_x0041_ _xZZ _x00\n\u{1F600} \u{FFFD}!\n"
    );
}

/// 子が時間切れで殺されると `</Objs>` が来ない。読めた要素までは戻し、残りは元のまま。
#[test]
fn a_block_cut_off_before_objs_closes_keeps_what_was_read() {
    let cut_at = SESSION_PWSH_NOT_FOUND
        .find("<S S=\"Error\">At line:1")
        .expect("固定入力にある要素")
        + 6;
    let truncated = &SESSION_PWSH_NOT_FOUND[..cut_at];

    let restored = restore(truncated.to_string());

    assert!(
        restored.text.contains("pwsh : The term 'pwsh'"),
        "{}",
        restored.text
    );
    assert!(
        restored.text.ends_with("<S S=\""),
        "読めなかった残りが元のまま残っていない: {}",
        restored.text
    );
    assert_eq!(restored.progress.len(), 1);
    assert_eq!((restored.restored_blocks, restored.raw_blocks), (0, 1));
}

/// 知らない要素に当たったら、そこから区画の終わりまでは元の文字列のまま残す（隠さない側）。
#[test]
fn an_unknown_element_keeps_the_rest_of_the_block_as_is() {
    let stream = format!(
        "{}after\n",
        block(r#"<S S="Error">a_x000A_</S><Foo>bar</Foo><S S="Error">b</S>"#)
    );

    let restored = restore(stream);

    assert_eq!(
        restored.text,
        "a\n<Foo>bar</Foo><S S=\"Error\">b</S></Objs>after\n"
    );
    assert_eq!((restored.restored_blocks, restored.raw_blocks), (0, 1));
}

/// 知らない種類のストリームも同じ扱い（読み違えて別のストリームとして見せない）。
#[test]
fn an_unknown_stream_kind_is_left_as_is() {
    let restored = restore(block(r#"<S S="Unknown">x</S>"#));

    assert_eq!(restored.text, "<S S=\"Unknown\">x</S></Objs>");
    assert_eq!(restored.raw_blocks, 1);
}

/// CLIXML が無い出力は1バイトも変えない。行の途中に印があっても区画とは見なさない。
#[test]
fn output_without_a_block_is_returned_unchanged() {
    for stream in [
        "",
        "hello\r\n",
        "say #< CLIXML here\n",
        "#< CLIXML\nnot xml at all\n",
    ] {
        let restored = restore(stream.to_string());
        assert_eq!(restored.text, stream);
        assert_eq!((restored.restored_blocks, restored.raw_blocks), (0, 0));
        assert!(restored.progress.is_empty());
    }
}

/// 区画の前後にある普通の出力は、その位置のまま残す。区画が2つあっても両方戻す。
#[test]
fn text_around_and_between_blocks_stays_in_place() {
    let stream = format!(
        "before\n{}\nmiddle\n{}\nafter\n",
        block(r#"<S S="Error">e1_x000D__x000A_</S>"#),
        block(r#"<S S="Error">e2_x000D__x000A_</S>"#),
    );

    let restored = restore(stream);

    assert_eq!(restored.text, "before\ne1\r\n\nmiddle\ne2\r\n\nafter\n");
    assert_eq!(restored.restored_blocks, 2);
}

#[test]
fn the_footer_note_is_absent_when_nothing_was_restored() {
    let plain = restore("hello\n".to_string());
    assert_eq!(footer_note(&[&plain, &plain]), None);
}

/// 注記は標準出力と標準エラーの両方を1行にまとめ、進行表示を件数ごと出す。
#[test]
fn the_footer_note_names_the_cause_and_counts_progress() {
    let err = restore(SESSION_PWSH_NOT_FOUND.to_string());
    let out = restore(block(
        r#"<Obj S="progress" RefId="0"><MS><PR N="Record"><AV>Preparing modules for first use.</AV></PR></MS></Obj>"#,
    ));

    let note = footer_note(&[&out, &err]).expect("戻した区画がある");

    assert!(note.starts_with("[powershell-clixml: "), "{note}");
    assert!(note.contains("-EncodedCommand"), "{note}");
    assert!(
        note.contains("\"Preparing modules for first use.\" ×4"),
        "{note}"
    );
    assert!(!note.contains("元のXMLのまま"), "{note}");
    assert!(note.ends_with(']'), "{note}");
    assert!(!note.contains('\n'), "フッタは1行: {note}");
}

/// 元のまま残した区画があれば、そう言う（言わないと、XMLが残っている理由が読めない）。
#[test]
fn the_footer_note_says_when_xml_was_left_as_is() {
    let raw = restore(block(r#"<Foo/>"#));

    let note = footer_note(&[&raw]).expect("元のまま残した区画がある");

    assert!(note.contains("元のXMLのまま"), "{note}");
}

/// 活動名が多くても注記は伸び続けない。
#[test]
fn the_footer_note_caps_the_progress_list() {
    let children: String = (0..20)
        .map(|i| format!(r#"<Obj S="progress" RefId="{i}"><MS><PR N="Record"><AV>activity-{i}</AV></PR></MS></Obj>"#))
        .collect();
    let restored = restore(block(&children));

    let note = footer_note(&[&restored]).expect("戻した区画がある");

    assert!(note.contains("activity-0"), "{note}");
    assert!(!note.contains("activity-19"), "{note}");
    assert!(note.contains("ほか15種"), "{note}");
}
