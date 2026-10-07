//! codewandler（`codewandler-markdown-stream`の解析器と、`codewandler-markdown-ratatui`の描画部品）で
//! Markdownを整形して描く実装の置き場（`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4）。
//!
//! # 何のためにあるのか
//!
//! assistantの返答を整形して描く実装（Adapter）を、ここ1か所に閉じ込める。codewandlerは**急場しのぎの依存**で
//! （計画書§1.2・§1.6）、別の実装へ差し替えるときはこのディレクトリを消し、`markdown/mod.rs`の実装の選択と
//! `Cargo.toml`の依存を直すだけで済むようにする。codewandlerの名前がこの外に出ないことは`super::leak_tests`が数える。
//!
//! | 部品 | 役割 |
//! |---|---|
//! | [`CodewandlerMarkdown`] | Adapter。流れ込む文章を確定した部分と書きかけの末尾に分けて解析し、幅ごとに描いた結果を持つ（計画書のT8） |
//! | `seal` | 確定の境界の候補を、文章の字面だけで探す |
//! | `guard` | 解析器が落ちる（panicする）形の行を、渡す前に無害な形へ書き換える（解析器の不具合の回避。暫定） |
//! | `render` | 写した描画部品（`codewandler-markdown-ratatui` 0.2.1。出典とライセンス表記と、写した後に変えたものの一覧はファイルの冒頭）。行を幅に合わせて分けるところは計画書のT7aで直した（`render/wrap.rs`）。構造の不具合（入れ子のリスト・リストの中のブロック・タスクリスト・HTMLブロック・コードの字下げ）とリンクの区間はT7bで直した。既に描いた文書の続きとして描く口と、描いた結果をつなぐ口はT8で足した |
//!
//! # 確定した部分と書きかけの末尾（計画書§1.4(3)）
//!
//! 返答は少しずつ届く。届くたびに全文を解析し直すと、長い返答ほど1フレームが重くなる（計画書§1.2「毎回全文を
//! 解析し直さない」）。解析器の増分の口（`write`）は、段落やリストが閉じるまで出来事を出さず、途中を見るには
//! `flush`するしかなく、`flush`した解析器は二度と使えない（計画書§1.3）——だから増分の口は表示に使えない。
//! そこで、文章を次の2つに分ける。
//!
//! - **確定した部分**: 先頭から、最後に採った境界まで。境界と境界の間（塊）は、採ったときに1回だけ解析し、
//!   出来事を持ち続ける。以後は解析し直さない
//! - **書きかけの末尾**: 残り。文章の長さが変わったときだけ、新しい解析器で解析し直して`flush`する
//!
//! 境界は2段で決める。
//!
//! 1. **候補**（`seal`）: コードフェンスの外の空行の次の、行頭（字下げなし）から始まる、改行まで届いた行
//! 2. **確かめる**: 塊（確定していない部分の頭から候補の行の前まで）に候補の行を続けて解析した出来事が、
//!    塊と候補の行を別々に解析してつないだものと同じときだけ、境界として採る（[`sealable`]）
//!
//! 2段目を置くのは、字面だけでは決まらない所があるからである。空行を挟んで次の項目が来るリストは1つのリストのまま
//! 続き（項目の番号・ゆるいリストかが前の項目に左右される）、空行を含むHTMLのコメントやリストの項目の中のフェンスは、
//! 入れ物を数えない字面の規則では開閉を取り違える。**区切ってよいかを解析器そのものに尋ねる**ので、候補の規則が
//! 外しすぎても外さなすぎても、描く結果は変わらない（変わるのは速さだけ。`seal`の限界）。
//!
//! 確かめるのに、塊を余分に1回（候補の行を続けたものとして）解析する。退けた候補があると、次の候補では確定していない
//! 部分が長くなっている（退けた候補の前も含めて解析し直す）。
//!
//! # 原文の持ち方
//!
//! **足された文章の全部を、この型でも写しとして持つ**（[`CodewandlerMarkdown`]の`source`）。transcriptの項目
//! （`crate::app::AssistantText`）も原文を持つので、返答の文章はメモリに2つある。持たずに済ませるには、Portに
//! 「原文を貸す」口を足すか、描くたびに原文を渡す形へPortを変えることになる——どちらもユーザーが挙げた4つの能力
//! （計画書§1.2）の外で、整形しない実装（`super::plain::PlainText`）が既に写しを持つのと同じ扱いにした。
//! 写しが要るのは、末尾の解析（確定していない部分の文章）・境界を確かめる解析・`finish`での全文の解析のため。
//! 2つの写しがずれないことは、追記が`AssistantText::push_str`の1つの口を通る（型で強制した）ことで保つ。
//!
//! 写しのほかに、解析の結果（出来事の列）と描いた結果（行）も持つ。どちらも文章より大きい（測っていない）。
//!
//! # 落ちたとき（解析器・描画部品のpanic）
//!
//! 解析器はある入力で落ちる（panicする）ことが分かっている（知っている形は`guard`が渡す前に避ける）。ほかの入力で
//! 落ちない保証は無く、写した描画部品も同じである。描画の経路で落ちると会話そのものが見えなくなるので、Portの約束
//! （描画の経路は失敗しない。`super::StreamingMarkdown`）を守るために、`finish`と`render`の中身を
//! `harness_term::contain_panic`の中で呼ぶ。その範囲の中では、panicのフックが端末を戻さない——`catch_unwind`だけ
//! では、受け止める前にフックが端末を戻し、TUIの画面が壊れる。
//!
//! 落ちたら、**その返答は以後ずっと原文のまま描く**（原文を整形しない実装`super::plain::PlainText`へ移し、それに
//! 描かせる。`reset`で整形する形へ戻る）。持っていた結果（確定した塊・描いた行・末尾・全文）は途中まで更新されている
//! かもしれないので、全部捨てる。解析し直さないのは、同じ文章ではまた落ちるからで、描くたびに（約30回/秒）落ちて
//! 報告を積まないため。
//!
//! 黙らない形は2つ。
//!
//! - panicの報告（文面と場所）は、今までどおり標準エラーへ出る。会話TUIは画面を握っている間、標準エラーを預かって
//!   `[stderr]`の行としてtranscriptに出す（`harness_term::stderr_capture`）。流れ込んでいる途中なら、その行の後に
//!   届いた文章は新しい返答の項目として始まり、そちらは整形して描く（BUG-232の直し方）
//! - 原文のまま描く形へ落ちたことを、ログ（会話TUIではログファイル）へ警告として1回書く
//!
//! # 持っている結果と、捨てる条件
//!
//! どの結果も、**それを作った材料が変わったら使わない**——材料を鍵として一緒に持ち、使う前に比べる。
//!
//! | 結果 | 作った材料（鍵） | 捨てる・作り直すとき |
//! |---|---|---|
//! | 確定した塊ごとの出来事 | 境界の間の文章 | 作り直さない（文章は末尾へ足すだけなので、境界の前は変わらない）。`finish`・`reset`で捨てる |
//! | 確定した部分を描いた行 | 幅と、先頭から何個目の塊まで描いたか | 幅が違えば全部描き直す。塊が増えたら、増えた塊だけ描いて後ろへつなぐ |
//! | 末尾の出来事 | 末尾の文章の範囲（確定した部分の終わりから文章の終わりまで） | 範囲が変われば解析し直す |
//! | 末尾を描いた行 | 幅と、末尾の出来事と、確定した部分の続きとして描いたか（前に描いた行があれば、最初のブロックの前に空行を置く。`render::render_lines_following`） | どれかが違えば描き直す |
//! | 全文の出来事（`finish`） | 文章の長さ | 足せば捨てる（長さも比べる）。2回目以降の`finish`は、長さが同じなら何もしない |
//! | 全文を描いた行 | 幅と、全文の出来事 | 幅が違えば描き直す |
//!
//! 文章も幅も変わらないフレームの手間は、持っている行を写して返すことだけ（Portの`render`が行を所有して返す形
//! なので、写す手間は行の数に比例する）。
//!
//! # 限界
//!
//! - **参照リンクの定義と使う所が、間に別の塊を挟んで離れていると、流入中は定義が見えない**——リンクにならず
//!   `[文字][label]`のまま描き、`finish`で全文を解析し直すとリンクになる（計画書§1.7。隣の塊なら、境界を確かめる
//!   解析が退けるので、流入中からリンクになる）。
//! - 長いコードブロック・空行を挟んで続く長いリスト・長い引用が流れ込んでいる間は、そこに境界が無いので末尾が長く、
//!   末尾の解析の手間がその長さに比例する（計画書§1.7）。
//! - `finish`は流入中の結果（確定した塊と末尾）を捨てる（終えた返答は多く、二重に持たないため）。終えた後に足すと、
//!   次の描画で文章の頭から境界を探し直して塊を作り直す（その1回だけ、文章の長さに比例する）。
//! - 解析器は、表の区切り行として読む行のセルが`:`だけだと落ちる（表を流している途中の`|:`で起きる）。落ちる形の行は
//!   渡す前に`\:`へ書き換える（`guard`。描く文字は`:`のまま）。ほかの入力で落ちたら、その返答は原文のまま描く
//!   （上の「落ちたとき」）。
//! - 空の文章・空行だけの文章は0行で描く（描画部品が何も描かない）。画面では、Facade（`super::MarkdownView`）が
//!   空の1行にする（どの実装でも同じ規則）。
//! - 写した描画部品は、**元の出力が幅に左右されず、T7bで直した構造を含まない入力では、今も元と1文字も違わない**
//!   （`equivalence_tests`）。行の分け方（`wrap_tests`）・構造（`characterization_tests`・`structure_tests`）・
//!   リンクの区間（`link_tests`）はそれぞれの試験が固定する。
//! - 画像は、代わりの文字（alt）をリンクと同じ書式で描き、画像のURLへのリンクとして区間を返す（リンクの中の画像は
//!   外側のリンク先。`link_tests`のモジュールdoc）。画像そのものは描かない。

use std::any::Any;
use std::ops::Range;

use markdown_stream::{BlockKind, Event, Parser, StreamParser};

use super::plain::PlainText;
use super::{Rendered, StreamingMarkdown};

/// 解析器が落ちる形の行を、渡す前に書き換える（モジュールdoc）。
mod guard;
/// 写した描画部品（モジュールdoc）。Adapterが使う。製品が使わない口（試験だけが使うもの・構文の色付け用に予約された
/// 書式）には、項目ごとに「使われていない」の警告を止める印と理由がある（T7bまではこのモジュール全体に付けていた）。
mod render;
mod seal;

use guard::Guard;
use render::Theme;
use seal::Scanner;

#[cfg(test)]
#[path = "characterization_tests.rs"]
mod characterization_tests;
#[cfg(test)]
#[path = "equivalence_tests.rs"]
mod equivalence_tests;
#[cfg(test)]
#[path = "fallback_tests.rs"]
mod fallback_tests;
#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod fuzz_tests;
#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
#[cfg(test)]
#[path = "stream_tests.rs"]
mod stream_tests;
#[cfg(test)]
#[path = "structure_tests.rs"]
mod structure_tests;
#[cfg(test)]
#[path = "wrap_tests.rs"]
mod wrap_tests;

/// codewandlerで整形して描くAdapter（モジュールdoc）。feature `markdown-codewandler`のビルドでは、Facade
/// （`super::MarkdownView`）がこれで描く。
#[derive(Debug, Default)]
pub(crate) struct CodewandlerMarkdown {
    /// 足された文章の全部（原文の写し。モジュールdocの「原文の持ち方」）。
    source: String,
    /// 確定の境界の候補を探す走査（読み終えた所を覚えている）。
    scanner: Scanner,
    /// 確定した部分の終わり（最後に採った境界。バイト位置）。
    sealed_end: usize,
    /// 確定した塊ごとの出来事（文章の順）。
    sealed: Vec<Vec<Event>>,
    /// 確定した部分を描いた行。
    sealed_view: Option<SealedView>,
    /// 書きかけの末尾の出来事と、それを描いた行。
    tail: Option<Tail>,
    /// `finish`で全文を解析した出来事と、それを描いた行。
    whole: Option<Whole>,
    /// 解析器か描画部品が落ちた後に、原文をそのまま描く実装（モジュールdocの「落ちたとき」）。`Some`の間は、原文は
    /// こちらだけが持ち（`source`は空）、ほかの結果も持たない。`reset`で`None`に戻る。
    fallen: Option<PlainText>,
    /// 解析と描画の回数（試験だけが数える）。
    #[cfg(test)]
    counts: Counts,
}

/// 確定した部分のうち先頭から`chunks`個の塊を、`width`桁で描いてつないだもの。
#[derive(Debug)]
struct SealedView {
    width: u16,
    chunks: usize,
    rendered: Rendered,
}

/// 書きかけの末尾（文章の`range`）を解析した出来事と、それを描いた行。
#[derive(Debug)]
struct Tail {
    range: Range<usize>,
    events: Vec<Event>,
    view: Option<TailView>,
}

/// 書きかけの末尾を描いた行と、描いたときの幅と「確定した部分の続きとして描いたか」（鍵）。
#[derive(Debug)]
struct TailView {
    key: (u16, bool),
    rendered: Rendered,
}

/// 文章の先頭から`len`バイト（`finish`のときの全文）を解析した出来事と、それを描いた行（幅と一緒に持つ）。
#[derive(Debug)]
struct Whole {
    len: usize,
    events: Vec<Event>,
    view: Option<(u16, Rendered)>,
}

/// 解析と描画の回数（試験だけが数える。確定した塊を解析し直していないこと等を、回数で確かめるため）。
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Counts {
    /// 境界の候補を解析器で確かめた回数。
    pub(super) checks: usize,
    /// 確定した塊として出来事を持ち始めた回数（確かめた解析の結果をそのまま持つ）。
    pub(super) sealed_parses: usize,
    /// 書きかけの末尾を解析した回数。
    pub(super) tail_parses: usize,
    /// 全文を解析した回数（`finish`）。
    pub(super) whole_parses: usize,
    /// 確定した塊を描いた回数。
    pub(super) chunk_renders: usize,
    /// 書きかけの末尾を描いた回数。
    pub(super) tail_renders: usize,
    /// 全文の出来事を描いた回数。
    pub(super) whole_renders: usize,
}

#[cfg(test)]
impl CodewandlerMarkdown {
    /// 解析と描画の回数。
    pub(super) fn counts(&self) -> Counts {
        self.counts
    }

    /// 確定した塊の数。
    pub(super) fn sealed_chunks(&self) -> usize {
        self.sealed.len()
    }

    /// 解析器か描画部品が落ちて、原文のまま描く形へ落ちたか。
    pub(super) fn has_fallen_back(&self) -> bool {
        self.fallen.is_some()
    }
}

impl CodewandlerMarkdown {
    /// 新しく改行まで届いた行から境界の候補を探し、解析器で確かめて採った境界までを、確定した塊にする
    /// （モジュールdocの「確定した部分と書きかけの末尾」）。
    fn seal(&mut self) {
        for line in self.scanner.advance(&self.source) {
            #[cfg(test)]
            {
                self.counts.checks += 1;
            }
            let chunk = &self.source[self.sealed_end..line.start];
            if let Some(events) = sealable(chunk, &self.source[line.clone()]) {
                #[cfg(test)]
                {
                    self.counts.sealed_parses += 1;
                }
                self.sealed.push(events);
                self.sealed_end = line.start;
            }
        }
    }

    /// 確定した部分を`width`桁で描いた行。幅が前と同じなら、前に描いた行の後ろへ増えた塊だけを描いてつなぐ。
    fn sealed_view(&mut self, width: u16) -> &Rendered {
        if self
            .sealed_view
            .as_ref()
            .is_some_and(|view| view.width != width)
        {
            self.sealed_view = None;
        }
        let view = self.sealed_view.get_or_insert_with(|| SealedView {
            width,
            chunks: 0,
            rendered: Rendered::default(),
        });
        for events in &self.sealed[view.chunks..] {
            #[cfg(test)]
            {
                self.counts.chunk_renders += 1;
            }
            let follows = !view.rendered.lines.is_empty();
            render::append(&mut view.rendered, &draw(events, width, follows));
        }
        view.chunks = self.sealed.len();
        &view.rendered
    }

    /// 書きかけの末尾を`width`桁で描いた行。末尾の範囲が前と同じなら解析し直さず、幅と「確定した部分の続きか」
    /// （`follows`。`render::render_lines_following`）も同じなら描き直さない。
    fn tail_view(&mut self, width: u16, follows: bool) -> &Rendered {
        let range = self.sealed_end..self.source.len();
        if self.tail.as_ref().is_none_or(|tail| tail.range != range) {
            #[cfg(test)]
            {
                self.counts.tail_parses += 1;
            }
            let events = parse(&[&self.source[range.clone()]]);
            self.tail = Some(Tail {
                range,
                events,
                view: None,
            });
        }
        let tail = self.tail.as_mut().expect("直前に作った");
        if tail
            .view
            .as_ref()
            .is_none_or(|view| view.key != (width, follows))
        {
            #[cfg(test)]
            {
                self.counts.tail_renders += 1;
            }
            tail.view = Some(TailView {
                key: (width, follows),
                rendered: draw(&tail.events, width, follows),
            });
        }
        &tail.view.as_ref().expect("直前に描いた").rendered
    }
}

impl CodewandlerMarkdown {
    /// 全文を1回だけ解析し直す（[`StreamingMarkdown::finish`]の中身。落ちたら呼び出し側が受け止める）。
    fn finish_formatting(&mut self) {
        if self
            .whole
            .as_ref()
            .is_some_and(|whole| whole.len == self.source.len())
        {
            return;
        }
        #[cfg(test)]
        {
            self.counts.whole_parses += 1;
        }
        let events = parse(&[&self.source]);
        self.whole = Some(Whole {
            len: self.source.len(),
            events,
            view: None,
        });
        self.scanner = Scanner::default();
        self.sealed_end = 0;
        self.sealed = Vec::new();
        self.sealed_view = None;
        self.tail = None;
    }

    /// `width`桁で整形して描く（[`StreamingMarkdown::render`]の中身。落ちたら呼び出し側が受け止める）。
    fn render_formatted(&mut self, width: u16) -> Rendered {
        if let Some(whole) = self
            .whole
            .as_mut()
            .filter(|whole| whole.len == self.source.len())
        {
            if whole.view.as_ref().is_none_or(|(at, _)| *at != width) {
                #[cfg(test)]
                {
                    self.counts.whole_renders += 1;
                }
                whole.view = Some((width, draw(&whole.events, width, false)));
            }
            return whole.view.as_ref().expect("直前に描いた").1.clone();
        }
        self.seal();
        let mut rendered = self.sealed_view(width).clone();
        let follows = !rendered.lines.is_empty();
        render::append(&mut rendered, self.tail_view(width, follows));
        rendered
    }

    /// 落ちた（panicした）ことをログへ書き、持っている結果を全部捨てて、原文を整形しない実装へ移す。以後はそれが
    /// 描く（モジュールdocの「落ちたとき」）。
    fn fall_back(&mut self, payload: &(dyn Any + Send)) -> &mut PlainText {
        tracing::warn!(
            panic = panic_message(payload),
            bytes = self.source.len(),
            "the Markdown parser or renderer panicked; this reply is drawn as plain text from now on"
        );
        let source = std::mem::take(&mut self.source);
        *self = Self::default();
        let plain = self.fallen.insert(PlainText::default());
        plain.push(&source);
        plain
    }
}

impl StreamingMarkdown for CodewandlerMarkdown {
    /// 写しへ足す。解析は描くときまで待つ（描くまでに何回足されても、解析は1回で済む）。終えた後なら、全文の結果を
    /// 捨てて流入へ戻る（流入中の結果は`finish`が捨てたので、次の描画で文章の頭から作り直す）。落ちた後は、原文の
    /// まま描く実装へ足す。
    fn push(&mut self, chunk: &str) {
        if let Some(plain) = &mut self.fallen {
            plain.push(chunk);
            return;
        }
        self.source.push_str(chunk);
        self.whole = None;
    }

    /// 全文を1回だけ解析し直す（塊に分けて解析したことによる違いを正す。計画書§1.4(3)の4）。文章が前の`finish`から
    /// 変わっていなければ何もしない——画面は流入中でない返答の全部へ、描くたびに呼ぶ（計画書§0のT8の条件）。
    /// 流入中の結果は捨てる（モジュールdocの限界）。解析器が落ちたら、原文のまま描く形へ落ちる（モジュールdocの
    /// 「落ちたとき」）。落ちた後は何もしない。
    fn finish(&mut self) {
        if self.fallen.is_some() {
            return;
        }
        if let Err(payload) = harness_term::contain_panic(|| self.finish_formatting()) {
            self.fall_back(payload.as_ref());
        }
    }

    /// 作ったばかりの状態に戻す（落ちた後なら、整形して描く形へも戻る）。解析器は解析のたびに
    /// `StreamParser::new_gfm`で作るので、GFMの設定は失われない（解析器の`reset`はGFMの設定まで消すので使わない。
    /// 計画書§1.3）。
    fn reset(&mut self) {
        *self = Self::default();
    }

    /// 整形して描く。解析器か描画部品が落ちたら、原文のまま描く形へ落ちて、その形で描いた結果を返す（モジュールdocの
    /// 「落ちたとき」）。
    fn render(&mut self, width: u16) -> Rendered {
        if let Some(plain) = &mut self.fallen {
            return plain.render(width);
        }
        match harness_term::contain_panic(|| self.render_formatted(width)) {
            Ok(rendered) => rendered,
            Err(payload) => self.fall_back(payload.as_ref()).render(width),
        }
    }
}

/// panicの中身の文面（`panic!`へ渡した文字列）。文字列でなければその旨。
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(the panic payload is not a string)")
}

/// 確定していない部分の頭から候補の行の前までの文章`chunk`を、塊として区切ってよいかを解析器で確かめる。
/// 区切ってよければ、`chunk`を解析した出来事を返す（モジュールdocの「確定した部分と書きかけの末尾」の2段目）。
///
/// 区切ってよいのは、`chunk`に候補の行`next`を続けて解析した出来事が、`chunk`と`next`を別々に解析してつないだものと
/// 同じとき——`next`が新しい文書の始まりと同じに読まれ、`chunk`の中身も`next`に左右されないとき。解析器が
/// 次の行へ持ち越すもの（開いている入れ物・コードブロック・HTMLブロック・リストのゆるさと番号・参照リンクの定義）が
/// `next`の読まれ方を変えるなら、出来事が違ってくる。出来事の位置（`Span`）は解析器が埋めない（いつも既定値）ので、
/// 比べてよい。
fn sealable(chunk: &str, next: &str) -> Option<Vec<Event>> {
    let alone = parse(&[chunk]);
    let joined = parse(&[chunk, next]);
    let next_alone = parse(&[next]);
    body(&joined)
        .eq(body(&alone).chain(body(&next_alone)))
        .then_some(alone)
}

/// 文書の出入り（`Document`）を除いた出来事（空の文章では、解析器は文書の出入りも出さない）。
fn body(events: &[Event]) -> impl Iterator<Item = &Event> {
    events.iter().filter(|event| {
        !matches!(
            event,
            Event::EnterBlock {
                block: BlockKind::Document,
                ..
            } | Event::ExitBlock {
                block: BlockKind::Document,
                ..
            }
        )
    })
}

/// `parts`を続けた文章を解析する。解析器は毎回`StreamParser::new_gfm`で作り（`reset`はGFMの設定を消すため使わない）、
/// **1行ずつ渡す**——解析器の`write`はバッファの頭から1行ずつ切り出すので、長い文章を1回で渡すと手間が長さの2乗に
/// 近くなる（計画書§1.3）。渡す前に、解析器が落ちる形の行を書き換える（`guard`）。最後に`flush`して、書きかけの行と
/// 開いているブロックを閉じる。
///
/// 文章は文書の頭か確定の境界から始まり、`parts`の境目は行の境目である（最後の部分だけが改行で終わらなくてよい）——
/// `guard`が行を1行ずつ順に見るため。
fn parse(parts: &[&str]) -> Vec<Event> {
    #[cfg(test)]
    if parts
        .iter()
        .any(|part| part.contains(fallback_tests::PARSER_BOMB))
    {
        fallback_tests::explode("解析器");
    }
    let mut parser = StreamParser::new_gfm();
    let mut guard = Guard::default();
    let mut events = Vec::new();
    for part in parts {
        for line in part.split_inclusive('\n') {
            events.extend(parser.write(guard.line(line).as_bytes()));
        }
    }
    events.extend(parser.flush());
    events
}

/// 出来事を、既定の書式で`width`桁で描く。`follows`なら、既に何か描いた文書の続きとして描く（最初のブロックの前にも
/// ブロックの間の空行を置く。`render::render_lines_following`）。
fn draw(events: &[Event], width: u16, follows: bool) -> Rendered {
    #[cfg(test)]
    if events.iter().any(
        |event| matches!(event, Event::Text { text, .. } if text.contains(fallback_tests::DRAW_BOMB)),
    ) {
        fallback_tests::explode("描画部品");
    }
    render::render_lines_following(events, &Theme::default(), usize::from(width), follows)
}
