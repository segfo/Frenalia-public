//! ユーザーが書いた長い値を、モデルに**書き写させず参照させる**仕組み。
//!
//! # 何のためにあるのか
//!
//! モデルは、ユーザーの文を読んで自分でコマンドを組み立て直す。そのとき長い値（符号化された塊・ハッシュ・鍵）を
//! **書き写すと、1文字でも違えば別のものが走る**。実測（2026-10-04、ローカルの`qwen3.6-35b`・4回）では、308文字の
//! base64 を4回とも写し損じた——1文字違いが2回、64文字短いものが2回。1文字違った値は`systeminfo`ではなく
//! `sDsteminfo`を走らせる命令になっていた。
//!
//! だから**書き写させない**。モデルが書くのは「ユーザーの文の何番目の長い値か」だけで、**その値を取り出して
//! 差し込むのはハーネス**である。
//!
//! ```text
//! ユーザー: pwsh --enc cAB3AHMAaAAg……（308文字）
//! モデル:   run_shell { command: "pwsh --enc {{val:1}}" }
//! ハーネス: pwsh --enc cAB3AHMAaAAg……（ユーザーの文から取り出してそのまま差し込む）
//! ```
//!
//! # 差し込んだ後の文字列が、判定にも実行にも使われる
//!
//! 差し込みは**判定の材料を作るより前**に1か所で行う（`harness_engine::turn`）。だから承認画面に出る文字列・
//! 判定器が照合する文字列・実際に走る文字列は同じものである（D-101「判定器が見る材料」を崩さない）。
//!
//! # 書き写した値は走らせない
//!
//! モデルは決まりを守らないことがある（実測: 2026-10-04、決まりを伝えた状態でも`qwen3.6-35b`は書き写した）。
//! そこで、**モデルが書いた長い値がユーザーの文の値を写したものだと分かったら、損じている限り実行しない**
//! （[`review`]）。断ったことはツールの結果としてモデルへ返し、番号で書き直させる。
//!
//! | モデルが書いたもの | ハーネスの動き |
//! |---|---|
//! | ユーザーの値と**一字一句同じ** | そのまま走らせる（会話の記録に1行残す） |
//! | 値を写したが**損じている** | **走らせない。** ツールの結果でモデルへ理由を返す |
//! | どの値とも**似ていない** | そのまま走らせる（モデルが自分で作った値） |
//!
//! **「損じを直して走らせる」という扱いは採らない**（2026-10-04に一度入れて外した）。直す側に回すと
//! 「どこからが別物か」の線引きが残り、線の外側——実測では308文字のうち64文字（20.8%）が落ちた形——が
//! 黙って走る。**断る側に倒すと、壊れた写しが走らないことが機構として成り立つ。**
//!
//! # 候補にする語の絞り方（形フィルタ）
//!
//! 「空白なしで40字以上」だけでは**散文を候補から外せない**。日本語は空白で区切られないので、
//! 普通の一文（話題がかぶっている文）がまるごと1つの「語」として入り、ファイル編集ツールの`old_string`等と
//! Levenshtein 距離（文字を足す・消す・書き換える回数の合計）で近く見えて拒否が連発する。
//! 実測（2026-10-06）で、ユーザーが書いた日本語の文と、モデルが`edit_file`に渡した Markdown の切り貼りが
//! 「46文字／16文字分違う」で引っ掛かり、拒否と再試行が無限に続いた。
//!
//! そこで**形フィルタ**（[`looks_like_payload`]）を候補抽出の段に足す——残すのは
//!
//! - **Base64形**: 文字が`[A-Za-z0-9+/=]`のみ、かつ数字か記号を1字以上含む
//! - **hex形**: 文字が`[0-9a-fA-F]`のみ、かつ長さ[`MIN_HEX_SHAPE_CHARS`]以上
//!
//! のどちらかに合うものだけ。これで**仮名漢字の文・ハイフン付き英識別子・URL・パスは候補から外れ**、
//! 本来 D-115 が守りたかった Base64・hex・鍵・ハッシュだけが残る。
//!
//! # ここが守らないもの
//!
//! - **差し込めなかったときは、書いた綴りがそのまま残る**（勝手に消さない）。承認画面にも`{{user:1}}`が見えるので、
//!   人は「モデルが指した値が無い」と分かって断れる。黙って空文字へ畳むと、別のコマンドが静かに走る
//! - **`{{val:N}}`で参照できるのは、人が書いた直近の文1つだけ**（値が無ければ何も指せない）。
//!   それより前の人の文の値は`{{back:K:N}}`で指す（D-127。綴りの読み方は[`crate::reference_syntax`]）。
//!   ツールの出力・ファイルの中身は参照できない（モデルはそれらを書き写すしかなく、この仕組みでは守れない）
//! - **差し込む中身はユーザー自身が書いたもの**である。中身がコマンドの意味を変えること（`; rm -rf /`）は
//!   止めない——止めるのは承認画面と判定器の仕事で、人は差し込んだ後の文字列を見て決める
//! - **形フィルタに合わない Payload**（空白を含む生スクリプト・Base64 文字集合に収まる長い純英単語）は
//!   候補にならない。前者はユーザーがコードフェンスで囲むしかなく、後者は実務ではほぼ無い

use serde_json::Value;

use crate::reference_syntax::ValueRef;
use crate::Message;

/// モデルが書いた語を「ユーザーの値を写したもの」とみなす、違いの割合の上限
/// （ユーザーの値の長さに対して）。
///
/// 違いの数え方は**文字を足す・消す・書き換える回数の合計**（レーベンシュタイン距離）で、
/// **長さが変わる損じも数えられる**。実測（2026-10-04）の2つの損じは2回（0.6%）と64回（20.8%）で、
/// どちらもこの内側に入る。
///
/// **これを超える違いは写しとみなさない**——モデルが自分で作った別の値として素通りさせる。
/// 無関係な値がここへ入ることは実質無い: 40文字の16進の値を2つ並べても違いは37回前後（92%）になる。
pub const MAX_TRANSCRIPTION_RATIO: f32 = 0.5;

/// 審査の対象として見る、空白で区切った1語の長さの上限（文字）。
///
/// 探す費用は「語の長さ × 値の長さ」で増えるので、際限なく長い語は見ない。モデルの出力は1回の応答の
/// 上限で頭打ちになるため、**実際にここへ当たることはほぼ無い**（当たった語は審査せずそのまま走る）。
const MAX_SCANNED_WORD_CHARS: usize = 65_536;

/// 参照できる「長い値」とみなす最短の長さ（文字）。空白を含まない連なりで数える。
///
/// **短い値は対象にしない**——`-Force`のような普通の語まで参照の対象にすると、モデルが番号を数え間違える余地が増える。
/// 書き写しで事故が起きるのは、人が目で照合できない長さの値である。
pub const MIN_REFERENCE_CHARS: usize = 40;

/// 「hex形」とみなす最短の長さ（文字）。SHA-1=40、SHA-256=64、MD5=32を拾う下限。
///
/// **実装の下限は[`MIN_REFERENCE_CHARS`]に押さえられている**（長さ40未満の語はそもそも候補にならない）が、
/// hex形は32文字から意味を持つことを宣言しておく。
pub const MIN_HEX_SHAPE_CHARS: usize = 32;

/// モデルへ伝える書き方（システムプロンプトと、ここの取り出しが同じ綴りを見る）。
pub const SYNTAX_EXAMPLE: &str = "{{val:1}}";

/// 書き写しを断った文（[`Transcription::refusal_ja`]）の頭。会話に残ったツールの結果を後から読む側
/// （`harness_engine::RecordedOutcome`）が「断った」と見分けるのに使うので、綴りはここにだけ置く（B-05）。
pub const TRANSCRIPTION_REFUSAL_PREFIX: &str = "書き写した値は実行しませんでした。";

/// `messages`から、モデルが参照できる値を取り出す（並び順が番号になる。1つ目が`{{val:1}}`）。
///
/// **人が書いた直近の文1つ**だけを見る（[`crate::human_turns`]。ツールの結果を運ぶ文と、会話を畳んだ
/// 要約の文は「直近」にならない）。**その文に長い値が無ければ空**で、前の文へは遡らない（D-127）
/// ——遡ると、新しい文に値が無いときに前の文の値が今の番号で指せてしまい、モデルは前に貼られた値を
/// 走らせようとした（BUG-234、2026-10-06 のユーザーの実機。「実行しないで」と書いて渡した値も同じ形で指せた）。
pub fn values_in(messages: &[Message]) -> Vec<String> {
    crate::human_turns::nth_back(messages, 0)
        .map(|turn| long_values(turn.text))
        .unwrap_or_default()
}

/// 1つの文に出てくる長い値（出てきた順）。
///
/// **長さだけでは散文を落とせない。** 日本語は空白で区切られないので「空白なしで40字以上の語」の網には
/// 普通の一文（話題がかぶっている文）が丸ごと入り、ファイル編集ツールの`old_string`等と Levenshtein 距離
/// （文字を足す・消す・書き換える回数の合計）で類似してしまう。実測（2026-10-06）で日本語の一文と
/// Markdown 編集の切り貼りが「46文字／16文字分違う」で引っ掛かり、拒否と再試行が無限に続いた。
///
/// そこで**形フィルタ**を足す——候補にするのは、1文字変えると実行が狂う値の形（Base64形か hex形）に
/// 合うものだけ。[`looks_like_payload`]で判定する。
///
/// 置き場は人の文ごとに作る（D-127）ので、組み立てる側（`harness_engine::references`）が文1つずつ呼ぶ。
pub fn long_values(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|word| word.chars().count() >= MIN_REFERENCE_CHARS)
        .filter(|word| looks_like_payload(word))
        .map(str::to_string)
        .collect()
}

/// その語が「写し間違いで意味が変わる値」の形をしているかを判定する。
///
/// **目的**: 日本語散文・英識別子・URL・パスのような、1文字違っても意味が壊れない語を候補から外す。
/// Base64・hex・鍵・ハッシュのように、1文字違うと別のものを指す語だけを残す。
///
/// # 判定
///
/// 次のどちらかに合致したら合格:
///
/// - **Base64形**: 文字が`[A-Za-z0-9+/=]`のみで構成され、かつ**数字か`+`／`/`／`=`を1字以上含む**。
///   数字や記号を要求するのは、純英単語（`UltraSuperAwesomeProductName`のような長い識別子）を外すため
///   ——実際の Base64 payload はほぼ必ず数字と記号を含むが、英識別子は含まないことが多い。
/// - **hex形**: 文字が`[0-9a-fA-F]`のみで構成され、長さが[`MIN_HEX_SHAPE_CHARS`]以上。
///
/// # 落ちるもの（意図した通り）
///
/// - 仮名漢字を含む日本語の文（どちらの文字集合にも入らない）
/// - `premise-first-explanation`のようなハイフン付き英識別子（Base64 文字集合に無い`-`があるので脱落）
/// - URL（`:`・`/`・`.`がある。`/`は Base64 だが、URL は数字も記号も使いながら英単語を長く並べる形で、
///   実務上は Base64 払いで事故を起こさない）
/// - 純英単語の長い識別子（Base64 の数字／記号要件で脱落）
///
/// # 残るもの（意図した通り）
///
/// - UTF-16 BOM付き Base64（PowerShell `-enc` の実測形。`cABwAHMAaAAg…`）
/// - 標準 Base64（数字と`+/=`が混ざる）
/// - Git ハッシュ・SHA ハッシュ・MD5
/// - トークン・API キー（hex形または Base64形の長い塊として渡されるもの）
pub fn looks_like_payload(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() < MIN_REFERENCE_CHARS {
        return false;
    }
    looks_like_base64(&chars) || looks_like_hex(&chars)
}

/// Base64形か（[`looks_like_payload`]の片翼）。
fn looks_like_base64(chars: &[char]) -> bool {
    let mut has_digit_or_symbol = false;
    for &c in chars {
        let is_base64_alpha = c.is_ascii_alphabetic();
        let is_base64_digit = c.is_ascii_digit();
        let is_base64_symbol = matches!(c, '+' | '/' | '=');
        if !(is_base64_alpha || is_base64_digit || is_base64_symbol) {
            return false;
        }
        if is_base64_digit || is_base64_symbol {
            has_digit_or_symbol = true;
        }
    }
    has_digit_or_symbol
}

/// hex形か（[`looks_like_payload`]の片翼）。
fn looks_like_hex(chars: &[char]) -> bool {
    if chars.len() < MIN_HEX_SHAPE_CHARS {
        return false;
    }
    chars.iter().all(|c| c.is_ascii_hexdigit())
}

/// ツールの入力の**すべての文字列**の中の`{{val:N}}`（と古い別名`{{user:N}}`）を、
/// `values`のN番目（1始まり）へ置き換える。`values`は直近の文の値だけなので、`{{back:K:N}}`は置き換えない。
///
/// 置き換えるのは番号が在るものだけで、**無い番号はそのまま残す**（モジュールdoc「守らないもの」）。
/// 綴りの読み方は[`crate::reference_syntax`]の1か所が持つ（前の文も引ける置き場で置き換えるなら、
/// そちらの[`crate::reference_syntax::substitute`]を直接使う）。
pub fn substitute(input: &Value, values: &[String]) -> Value {
    crate::reference_syntax::substitute(input, &mut |r| {
        if r.back == 0 {
            values.get(r.number - 1).cloned()
        } else {
            None
        }
    })
}

/// モデルがユーザーの値を**書き写していた**という審査の結果1件（[`review`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcription {
    /// 何個前の人の文の値を写したか（0 が直近の文。`{{back:K:N}}`のK）。
    pub back: usize,
    /// その文の何番目の値を写したか（1始まり。`{{val:N}}`・`{{back:K:N}}`のN）。
    pub number: usize,
    /// モデルが書いた部分の長さ（文字）。
    pub written_chars: usize,
    /// ユーザーの値の長さ（文字）。
    pub value_chars: usize,
    /// 違いの回数（足す・消す・書き換えるの合計）。**0なら一字一句同じ。**
    pub differences: usize,
}

impl Transcription {
    /// 一字一句同じか。`false`なら**そのツール呼び出しを実行してはいけない**。
    pub fn is_exact(&self) -> bool {
        self.differences == 0
    }

    /// 参照の書き方（直近の文なら`{{val:N}}`、それより前なら`{{back:K:N}}`）。
    pub fn reference(&self) -> String {
        ValueRef {
            back: self.back,
            number: self.number,
        }
        .spelling()
    }

    /// 実行を断ったことを**モデルへ**伝える文（ツールの結果として返す）。`menu`には
    /// [`crate::ValueStore::render`]（前の文の値を写したときは[`crate::value_store::ReferenceBook::render_for`]）が
    /// 組んだ値の一覧をそのまま渡す。
    ///
    /// **どの番号を指すべきかはハーネスが決めない。** 「どれに近いか」までしか言えないからである
    /// ——実測（2026-10-04）では、ユーザーの値を途中まで書き写した語が、**その値を解読して得た
    /// 別の値の方に近く**出た（どちらも同じ文字の並びで始まるため）。1つに決めて返したところ、
    /// モデルはその番号を素直に使い、`pwsh --enc pwsh --enc …` という走らない行を組み立てた。
    /// だから**一覧をそのまま渡して、どれを指すかはモデルに選ばせる**。
    ///
    /// 何文字分違ったかは言うが、**文字を数え直させない**——実測ではモデルが数を合わせようとして
    /// 手で数え始め、1往復をまるごと使った。だから「数え直す必要はない」と明示する。
    pub fn refusal_ja(&self, menu: &str) -> String {
        format!(
            "{TRANSCRIPTION_REFUSAL_PREFIX}あなたが書いた{written}文字の値は、ハーネスが持っている値のどれかを写したものに見えますが、{differences}文字分違います（足す・消す・書き換えるの合計）。1文字でも違えば別のものが走ります。\n\n値を書き写さず、番号で指し直してください。文字を数え直す必要はありません。\n{menu}",
            written = self.written_chars,
            differences = self.differences,
        )
    }
}

/// ツールの入力の中に、ユーザーの値を**書き写した**跡が無いかを調べる。
///
/// **[`substitute`]より前に通すこと。** 差し込んだ後では、参照の書き方を正しく使った呼び出しにも
/// 値が入っているので、「モデルが書き写した」と区別できなくなる。
///
/// [`Transcription::is_exact`]が`false`のものが1つでもあれば、呼び出し側は**そのツール呼び出しを
/// 実行してはいけない**。一字一句同じものは走らせてよい（記録には残す）。
///
/// `values`は直近の文の値（`{{val:N}}`）だけを相手にする。前の文の値も相手にするなら[`review_against`]。
pub fn review(input: &Value, values: &[String]) -> Vec<Transcription> {
    let candidates: Vec<(ValueRef, &str)> = values
        .iter()
        .enumerate()
        .map(|(index, value)| (ValueRef::current(index + 1), value.as_str()))
        .collect();
    review_against(input, &candidates)
}

/// [`review`]を、指せる値**全部**（`{{val:N}}`と`{{back:K:N}}`。D-127 の4）を相手に掛ける。
///
/// `candidates`の並びは、違いの回数が同じ候補が2つあったときの勝ち順になる（前にあるものが勝つ）。
/// 置き場（`ReferenceBook::all_values`）は直近の文を先に並べるので、同じ値が今の文と前の文の両方に
/// あれば今の文の番号で報告する。
pub fn review_against(input: &Value, candidates: &[(ValueRef, &str)]) -> Vec<Transcription> {
    let mut found = Vec::new();
    review_value(input, candidates, &mut found);
    found
}

fn review_value(input: &Value, candidates: &[(ValueRef, &str)], found: &mut Vec<Transcription>) {
    match input {
        Value::String(text) => {
            for word in text.split_whitespace() {
                if let Some(t) = transcription_of(word, candidates) {
                    found.push(t);
                }
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|v| review_value(v, candidates, found)),
        Value::Object(fields) => fields
            .values()
            .for_each(|v| review_value(v, candidates, found)),
        _ => {}
    }
}

/// `word`がどのユーザーの値を写したものか。写していないなら`None`。
///
/// **語まるごとを比べてはいけない。** モデルは値の前後に自分で飾りを付ける（`payload=`・引用符・
/// `--enc=`）ので、まるごと比べると飾りの分まで違いに数え、短い値では写しを見落とす。
/// だから[`closest_region`]で**語の中の、値に当たる部分だけ**を見る。
fn transcription_of(word: &str, candidates: &[(ValueRef, &str)]) -> Option<Transcription> {
    let written: Vec<char> = word.chars().collect();
    if written.len() > MAX_SCANNED_WORD_CHARS {
        return None;
    }
    let mut best: Option<Transcription> = None;
    for &(reference, value) in candidates {
        let user_value: Vec<char> = value.chars().collect();
        // **上限はユーザーの値の長さで決める。** モデルが短く切り詰めても基準が動かない。
        let limit = (user_value.len() as f32 * MAX_TRANSCRIPTION_RATIO) as usize;
        if user_value.len() < MIN_REFERENCE_CHARS || written.len() + limit < user_value.len() {
            continue; // 短すぎて入らない
        }
        let Some((differences, start, end)) = closest_region(&written, &user_value, limit) else {
            continue;
        };
        if best.as_ref().is_none_or(|b| differences < b.differences) {
            best = Some(Transcription {
                back: reference.back,
                number: reference.number,
                written_chars: end - start,
                value_chars: user_value.len(),
                differences,
            });
        }
    }
    best
}

/// `word`の中で`value`に最も近い部分を探し、`(違いの回数, 始まり, 終わり)`を返す。
/// `limit`を超えると分かった時点で`None`。
///
/// 違いの数え方は**文字を足す・消す・書き換える回数の合計**（レーベンシュタイン距離）である。
/// **書き換えだけを数えると、1文字消す損じを拾えない**——消すと以降が1つずつずれるので、
/// 残り全部が「違う文字」に見えて上限を大きく超える（実測で実際にこれが起きた）。
///
/// `value`は全部使い、`word`は**前後を自由に飛ばせる**（飾りの分）。表を1行ずつ進め、
/// 各マスに「その並べ方が`word`の何文字目から始まったか」を一緒に持ち回る。
fn closest_region(word: &[char], value: &[char], limit: usize) -> Option<(usize, usize, usize)> {
    let n = word.len();
    // `value`を0文字使った段は、`word`のどこから始めても違い0（前の飾りは飛ばしてよい）。
    let mut prev_cost: Vec<usize> = vec![0; n + 1];
    let mut prev_start: Vec<usize> = (0..=n).collect();
    let (mut cost, mut start) = (vec![0usize; n + 1], vec![0usize; n + 1]);
    for (i, cv) in value.iter().enumerate() {
        cost[0] = i + 1;
        start[0] = 0;
        for (j, cw) in word.iter().enumerate() {
            let same = prev_cost[j] + usize::from(cv != cw); // 書き換えるか、一致
            let drop_value = prev_cost[j + 1] + 1; // `value`の文字が`word`から消えている
            let drop_word = cost[j] + 1; // `word`に余計な文字がある
            if same <= drop_value && same <= drop_word {
                (cost[j + 1], start[j + 1]) = (same, prev_start[j]);
            } else if drop_value <= drop_word {
                (cost[j + 1], start[j + 1]) = (drop_value, prev_start[j + 1]);
            } else {
                (cost[j + 1], start[j + 1]) = (drop_word, start[j]);
            }
        }
        // 違いは段をまたいで減らないので、この段の最小が上限を超えたら以降も超える。
        if cost.iter().min().is_some_and(|m| *m > limit) {
            return None;
        }
        std::mem::swap(&mut prev_cost, &mut cost);
        std::mem::swap(&mut prev_start, &mut start);
    }
    // 違いが同じなら**`word`を長く使う方**を採る。`a`が並んだだけの値では「末尾の1文字を書き換えた」と
    // 「末尾の1文字を余らせた」が同じ違いの回数になり、後者を採ると余った文字が語に残る。
    (0..=n)
        .map(|j| (prev_cost[j], prev_start[j], j))
        .filter(|(differences, ..)| *differences <= limit)
        .min_by_key(|(differences, _, j)| (*differences, std::cmp::Reverse(*j)))
}

#[cfg(test)]
#[path = "user_reference_tests.rs"]
mod tests;
