//! [BUG-206] 会話TUIが預かった標準エラーの行（`harness_term::stderr_capture`）を transcript へ出す。
//!
//! 預かる部品そのもの（`SetStdHandle`での差し替え・読み残しの書き戻し）はポリシーエディタと共有で、
//! ここが持つのは「引き取った行を画面のどこへ出すか」だけである。**預かるのは`crate::run`の間だけ**
//! なので、ヘッドレス（`-p`）の実行ではこれまでどおり標準エラーへそのまま出る（標準出力の契約、B-24）。
//!
//! [BUG-206]: ../../../../docs/bugs/BUG-206.md

use super::{AppState, TranscriptItem};

impl AppState {
    /// 引き取った標準エラーの行を、書かれた順に transcript へ積む。
    ///
    /// **捨てない**（B-10）。ライブラリの警告（`run_shell`のTier1が作業フォルダへ低ILラベルを
    /// 付けられなかった等）は、端末へ直接書かれると画面が崩れるので預かっているだけで、
    /// 内容はユーザーが次に何をするかを決める材料そのものである。
    ///
    /// 誰が言ったかが分かるよう、ポリシーエディタと同じ印を付ける（`stderr_capture::shown`）。
    /// **エラーの見た目にはしない**——中身は`note:`も`warning:`もあり、他人の文言を読んで
    /// 色分けするとロケールや書き方の違いで外れる（B-33）。
    pub fn note_stderr_lines(&mut self, lines: Vec<String>) {
        for line in lines {
            self.transcript
                .push(TranscriptItem::Info(harness_term::stderr_capture::shown(
                    &line,
                )));
        }
    }

    /// 標準エラーを預かれなかったことを1度だけ出す（黙ると、崩れた画面の理由がどこにも無い）。
    pub fn note_stderr_capture_failure(&mut self, reason: &str) {
        self.transcript.push(TranscriptItem::Error(
            harness_term::stderr_capture::start_failure_notice(reason),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::DrawFeedback;

    /// 画面全体を製品と同じ描画関数で1フレーム描き、行ごとの文字列にする。
    fn screen_rows(app: &AppState, width: u16, height: u16) -> Vec<String> {
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height))
            .expect("terminal");
        let mut feedback = DrawFeedback::default();
        term.draw(|f| feedback = crate::ui::render(f, app))
            .expect("draw");
        let buffer = term.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect()
    }

    /// 引き取った行は**全部・書かれた順に**、印付きで transcript に入る（1行も落とさない）。
    #[test]
    fn captured_stderr_lines_go_into_the_transcript_in_order_with_the_mark() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.note_stderr_lines(vec![
            "warning: first".to_string(),
            "note: second".to_string(),
        ]);

        let shown: Vec<&str> = app
            .transcript
            .iter()
            .map(|item| match item {
                TranscriptItem::Info(text) => text.as_str(),
                other => panic!("預かった行は付随的な通知として出す: {other:?}"),
            })
            .collect();
        assert_eq!(
            shown,
            vec!["[stderr] warning: first", "[stderr] note: second"]
        );
    }

    /// **画面の中に描かれる**こと——transcript に積んだだけで描かれない形（BUG-192の形）を防ぐ。
    /// 実機で崩れた警告と同じ文面を入れ、製品の描画関数で描いた画面に、印と文面の頭が出ることを見る。
    #[test]
    fn a_captured_stderr_line_is_drawn_inside_the_conversation_screen() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.note_stderr_lines(vec![
            "warning: failed to apply the low-integrity label to the Tier1 cwd".to_string(),
        ]);

        let rows = screen_rows(&app, 120, 20);
        let hit = rows
            .iter()
            .position(|row| row.contains("[stderr] warning: failed to apply"))
            .unwrap_or_else(|| panic!("預かった行が画面に描かれていない:\n{}", rows.join("\n")));
        // transcript の枠の中であって、画面の最下部（入力欄とステータスバー）ではない。
        assert!(
            hit < rows.len() - 3,
            "transcript の枠の中に出る（{hit}行目）:\n{}",
            rows.join("\n")
        );
    }

    /// 預かれなかったときは理由と「画面が崩れたら端末の大きさを変える」を1行で出す。
    #[test]
    fn a_failed_capture_is_reported_once_with_what_to_do() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.note_stderr_capture_failure("SetStdHandle(STD_ERROR_HANDLE) failed: x");

        assert_eq!(app.transcript.len(), 1);
        match &app.transcript[0] {
            TranscriptItem::Error(text) => {
                assert!(text.contains("SetStdHandle"), "{text}");
                assert!(text.contains("resize the terminal"), "{text}");
            }
            other => panic!("預かれなかったことはエラーとして出す: {other:?}"),
        }
    }
}
