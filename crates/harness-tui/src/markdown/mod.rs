//! assistantの返答を、流れ込むそばから描く部品（`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4）。
//!
//! # 何のためにあるのか
//!
//! 返答は少しずつ流れ込んでくる（ストリーミング）。届いた分をその都度描き直すのに要る能力は4つしかない——
//! 「末尾へ文章を足す」「流入の終わりを伝える」「空に戻す」「この幅で描く」。この4つだけを[`StreamingMarkdown`]
//! （Port）として決め、Markdownの解析器・描画部品といった実装（Adapter）はその裏に隠す。使用側（`crate::ui`・
//! `crate::app`）が知るのは[`MarkdownView`]（Facade）だけなので、実装を差し替えても使用側は1行も変わらない。
//!
//! | 部品 | 役割 |
//! |---|---|
//! | [`StreamingMarkdown`] | Port。表示に要る能力だけ |
//! | [`MarkdownView`] | Facade。**どの実装を使うかと、描く幅をどう決めるかを、ここ1か所で決める** |
//! | [`plain::PlainText`] | 原文を1行ずつそのまま描く実装（整形しない。付け替える前のtranscriptと同じ見た目）。feature `markdown-codewandler`を切ったビルドの実装で、整形する実装が落ちた（panicした）ときの受け皿でもある |
//! | `codewandler`（feature `markdown-codewandler`。既定で有効） | codewandlerで整形して描く実装（Adapter`codewandler::CodewandlerMarkdown`と写した描画部品）の置き場。**既定のビルドはこれで描く**（計画書のT9で切り替えた） |
//!
//! # 限界
//!
//! - どの実装で描くかはビルドで決まる（[`Engine`]を`cfg`で選ぶ。`cfg`を書くのは、このファイルの実装の選択・
//!   Adapterのモジュールの宣言・試験を選ぶ口`formatting_only`と`plain_only`（試験のビルドだけ）だけ）。実行中には切り替えない。
//! - codewandlerの名前は`codewandler/`と、実装を選ぶこのファイルの外には書かない。ソースを読んで数える試験
//!   （`leak_tests`）が止める。
//! - 対象はassistantの返答だけ。thinking・ツール出力・ユーザー入力は今までどおり`crate::ui`がそのまま描く。

#[cfg(feature = "markdown-codewandler")]
mod codewandler;
mod plain;

use harness_term::select::LineJoin;
use ratatui::style::Style;
use ratatui::text::Line;

#[cfg(test)]
#[path = "contract_tests.rs"]
mod contract_tests;
#[cfg(test)]
#[path = "leak_tests.rs"]
mod leak_tests;
#[cfg(test)]
#[path = "view_tests.rs"]
mod view_tests;

/// 試験の項目（`#[test]`の関数・試験のモジュール）を、**整形する実装を選んだビルドでだけ**置く。画面の試験のうち、
/// 整形した見た目（太字・見出し・継続インデント等）を確かめるものに使う。
///
/// 実装を選ぶのはこのファイルだけなので、試験が実装の名前（featureの名前）を書かずに済むよう、ここで選ぶ
/// （`leak_tests`——実装を差し替えるときに、使用側の試験まで直さずに済む）。整形しない実装を選んだビルドで
/// 同じ場面を確かめる試験は[`plain_only`]に入れる。
#[cfg(all(test, feature = "markdown-codewandler"))]
macro_rules! formatting_only {
    ($($item:item)*) => { $($item)* };
}
#[cfg(all(test, not(feature = "markdown-codewandler")))]
macro_rules! formatting_only {
    ($($item:item)*) => {};
}
#[cfg(test)]
pub(crate) use formatting_only;

/// [`formatting_only`]の逆。**整形しない実装を選んだビルドでだけ**置く（原文のまま描く見た目を確かめる試験）。
#[cfg(all(test, feature = "markdown-codewandler"))]
macro_rules! plain_only {
    ($($item:item)*) => {};
}
#[cfg(all(test, not(feature = "markdown-codewandler")))]
macro_rules! plain_only {
    ($($item:item)*) => { $($item)* };
}
#[cfg(test)]
pub(crate) use plain_only;

/// Port: 流れ込む返答を描くのに要る能力だけ（モジュールdoc）。
///
/// **失敗を返さない。** エラー型を置かないのは、中身の無い抽象を作らないため——codewandlerは解析も描画も失敗を
/// 返さない。それに描画の経路は失敗してはいけない（描けないと会話そのものが見えなくなる）。将来の実装が失敗し得る
/// なら、**その実装の中で原文をそのまま描く形へ落とす**ことを、この契約に含める。
///
/// どの実装も通すべき性質は`contract_tests::port_contract`が持つ（実装を差し替えるときの合格条件）。
pub(crate) trait StreamingMarkdown {
    /// 末尾へ文章を足す。区切りはどこでもよい（`&str`なので文字の途中にはならない）——同じ文章をどう区切って
    /// 足しても、描く結果は同じでなければならない。
    fn push(&mut self, chunk: &str);
    /// 流入の終わり。未確定の部分を確定させる。何度呼んでも1回と同じ。終わった後に[`Self::push`]されたら、
    /// 流入を再開する。
    fn finish(&mut self);
    /// 空に戻す。解析の設定は保つ（戻した後は、作ったばかりのものと同じに描く）。
    fn reset(&mut self);
    /// `width`桁（折り返しに使える桁数）で描く。**幅は状態として持たない**——別の幅で描いた後に元の幅で描けば、
    /// 最初と同じ結果になる（端末の幅を変えても、正しく描き直せるように）。
    fn render(&mut self, width: u16) -> Rendered;
}

/// 描いた結果。行と、行ごとの「前の行の続きか」と、リンクの文字が描かれた場所。
///
/// **`lines`と`joins`は同じ長さで、`links`の区間はどれも指す行の文字の中に収まる**（不変条件）。実装はそう作り、
/// [`MarkdownView::render`]が確かめる。
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Rendered {
    pub lines: Vec<Line<'static>>,
    /// `lines`と同じ長さ。実装が幅に合わせて自分で分けた続きの行は`Continues`（コピーでは元の1行に戻す。
    /// `harness_term::select::LineJoin`）。それ以外は`Break`。
    pub joins: Vec<LineJoin>,
    /// リンクの文字が描かれた場所とURL（[`LinkSpan`]。行の順、同じ行では左から）。文中にURLを出さない代わりに、
    /// マウスが指した文字がどのリンクかを引くのに使う（計画書§3。使う側はT11）。整形しない実装は返さない。
    pub links: Vec<LinkSpan>,
}

/// リンクの文字が描かれた場所と、そのURL（計画書§1.5の6・§3）。
///
/// 場所は`lines[line]`の中の文字（書記素）の半開区間`start..end`。**数え方は範囲選択の位置
/// （`harness_term::select`の`Pos.offset`）と同じ**——`Line::styled_graphemes`が返す書記素で数え、描かれない
/// 制御文字は数えない。範囲選択の地図が返す「何行目の何文字目」をそのまま当てて、指した文字がリンクかを引けるように
/// するため。折り返しをまたぐリンクは、行ごとに1つずつ分かれる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkSpan {
    pub line: usize,
    pub start: usize,
    pub end: usize,
    /// リンク先。**製品で読むところはまだ無い**——吹き出しに出して開くのは計画書のT11で、それまでは試験だけが読む。
    /// 試験でないビルドの「使われていない」の警告を止める（[`MarkdownView::reset`]と同じ扱い）。T11で読んだら外す。
    #[cfg_attr(not(test), allow(dead_code))]
    pub url: String,
}

/// どの実装で描くか。**ここ1か所で決める**（モジュールdoc）。feature `markdown-codewandler`（既定で有効）なら整形する
/// 実装、切ったビルドでは原文をそのまま描く実装。
#[cfg(feature = "markdown-codewandler")]
type Engine = codewandler::CodewandlerMarkdown;
#[cfg(not(feature = "markdown-codewandler"))]
type Engine = plain::PlainText;

/// Facade: 使用側から見える唯一の入口（モジュールdoc）。
#[derive(Debug, Default)]
pub(crate) struct MarkdownView {
    /// 選んだ実装。**`Box`に入れてあるのは、整形する実装が結果の置き場をいくつも持って大きく（約500バイト）、
    /// transcriptの項目（`crate::app::TranscriptItem`）のうちassistantの返答だけが桁違いに大きくなるため**
    /// （`clippy::large_enum_variant`。項目の列は、どの種類の項目も一番大きい種類の大きさを取る）。項目の側で包むと
    /// 使用側の全部の箇所が変わるので、ここで包む。
    engine: Box<Engine>,
}

impl MarkdownView {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 末尾へ文章を足す（[`StreamingMarkdown::push`]）。
    pub(crate) fn push(&mut self, chunk: &str) {
        self.engine.push(chunk);
    }

    /// 流入の終わり（[`StreamingMarkdown::finish`]）。
    pub(crate) fn finish(&mut self) {
        self.engine.finish();
    }

    /// 空に戻す（[`StreamingMarkdown::reset`]）。
    ///
    /// **製品からの呼び出しはまだ無い**——transcriptの項目は、切り詰め・全消去・セッションの復元のどれでも項目ごと
    /// 作り直すか捨てるので、同じ項目を空に戻す使い道が今は無い。それでも口を置くのは、使用側が知る能力として
    /// ユーザーが挙げた4つ（計画書§1.2）の1つだからで、Portの契約（戻した後は作ったばかりと同じ）は試験で先に
    /// 固定しておく——使い道ができたときに規則を決め直さないため。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reset(&mut self) {
        self.engine.reset();
    }

    /// transcriptの枠の**内側の幅**`inner_width`で描く（実装へ渡す幅は[`render_in`]が決める）。
    pub(crate) fn render(&mut self, inner_width: u16) -> Rendered {
        render_in(self.engine.as_mut(), inner_width)
    }
}

/// `engine`を、枠の内側の幅`inner_width`の場所へ描く。
///
/// **実装へ渡す幅は`harness_term::wrap::text_width`で狭めた幅**——数える幅と描く幅を決める場所を1か所に保つため
/// （`harness_term::wrap`のモジュールdoc。行末の全角文字が右の枠線を覆わないよう、右端の1桁を空ける）。
/// 実装が折り返さないときも同じ幅を渡す。
///
/// 戻す前に[`Rendered`]の不変条件を確かめる。デバッグビルドでは食い違いで止まり、リリースでは直して渡す——描画の
/// 経路は止めない。
///
/// - `lines`と`joins`の長さ: 足りない印を`Break`で埋め、余る印を捨てる（`harness_term::select`が短い印の並びを
///   `Break`とみなすのと同じ扱い）
/// - `links`の区間: 行の文字の中に収まらない区間（[`link_fits`]）を捨てる（使う側が位置から引いたときに、別の文字を
///   リンクと取り違えないように）
///
/// **実装が1行も描かなかったら、空の1行にして渡す**（印は`Break`）。空の返答や、Markdownとしては何も描かない返答
/// （参照リンクの定義だけ等）でも、返答の場所を画面に残すため——0行にすると、そこに返答があったことが画面から消える。
/// 付け替える前のtranscriptが空の返答を空の1行で描いていたのに倣い、どの実装でも同じになるようにここで決める。
fn render_in(engine: &mut impl StreamingMarkdown, inner_width: u16) -> Rendered {
    let mut rendered = engine.render(harness_term::wrap::text_width(inner_width));
    debug_assert_eq!(
        rendered.lines.len(),
        rendered.joins.len(),
        "Markdownの実装が、行と印の数が違う結果を返した"
    );
    rendered.joins.resize(rendered.lines.len(), LineJoin::Break);
    if rendered.lines.is_empty() {
        rendered.lines.push(Line::from(""));
        rendered.joins.push(LineJoin::Break);
    }
    let returned = rendered.links.len();
    let lines = &rendered.lines;
    rendered.links.retain(|link| link_fits(lines, link));
    debug_assert_eq!(
        rendered.links.len(),
        returned,
        "Markdownの実装が返したリンクの区間が行の文字の外を指す"
    );
    rendered
}

/// `link`の区間が、指す行の文字（`Line::styled_graphemes`で数えた書記素。[`LinkSpan`]）の中に収まり、空でないか。
fn link_fits(lines: &[Line<'_>], link: &LinkSpan) -> bool {
    lines.get(link.line).is_some_and(|line| {
        link.start < link.end && link.end <= line.styled_graphemes(Style::default()).count()
    })
}
