//! 承認画面の要約を書かせる言語（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-100 の「要約の言語」）。
//!
//! # 固定の表から選ぶ
//!
//! 要約の呼び出しは会話と切り離してある（system は固定文・道具なし）。言語を伝えるには system へ
//! 1行足すしかないが、**自由な文字列を system へ混ぜると、その文字列を作れる者が指示を足せる**。
//! だから言語は[`SummaryLanguage`]の表から選び、送るのは表に書いた英語の綴り（[`SummaryLanguage::english_name`]）だけにする。
//!
//! # ユーザーの文そのものは渡さない
//!
//! 決めるのに使うのはユーザーが最後に入力した文だが、要約の呼び出しへ渡るのは**言語の名前1つ**だけである。
//! 要約は会話と別のプロバイダへ送れる（`approval.summary_provider`）ので、会話の中身をそこへ出さない。
//! 会話から要約の側へ漏れるのは「ユーザーがどの言語で書いたか」という表の1行ぶんの情報に限られる。
//!
//! # 決め方（[`SummaryLanguage::for_user`]）
//!
//! 1. 平仮名・片仮名が1文字でもあれば日本語、ハングルが1文字でもあれば韓国語（その言語でしか使わない文字）
//! 2. それ以外で、ラテン文字でない文字（漢字・キリル文字・アラビア文字・ヘブライ文字・タイ文字）があれば、
//!    いちばん多い種類で決める。**1つの文字が複数の言語で使われる**もの——漢字（中国語・日本語）・
//!    キリル文字（ロシア語・ウクライナ語・ブルガリア語）・アラビア文字（アラビア語・ペルシア語・ウルドゥー語）——は、
//!    表示言語がその中にあれば表示言語、無ければ代表の言語（中国語・ロシア語・アラビア語）にする
//! 3. ラテン文字だけ・入力がまだ無いときは、Windows の表示言語（[`SummaryLanguage::from_windows_langid`]）。
//!    それも表に無ければ決めない（`None`。要約の要求は言語を足さない今までの形になる）
//!
//! # ここが守らないもの
//!
//! - **ラテン文字の言語どうし（英語・フランス語・ドイツ語…）は文の文字では区別しない。** 表示言語に倒す
//! - **ギリシャ文字は数えない。** 英語の技術文書でも記号として使う（π・Δ・λ・μ）ので、文字の種類で言語が決まらない
//! - **文の中に1文字でもあればその文字で決める。** 英語の文に漢字を1文字引いただけでも中国語になる
//! - **モデルが指定の言語に従う保証は無い。** 要約は補助で、中身と差分を必ず見るという画面の文言は変えない

/// 要約を書かせる言語。**ここに無い言語は指定しない**（system へ自由な文字列を混ぜないため）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SummaryLanguage {
    Arabic,
    Bulgarian,
    /// 簡体と繁体を決められなかったとき（漢字だけの文で、表示言語が中国語でも日本語でもない）。
    Chinese,
    SimplifiedChinese,
    TraditionalChinese,
    Czech,
    Danish,
    Dutch,
    English,
    Finnish,
    French,
    German,
    Greek,
    Hebrew,
    Hungarian,
    Indonesian,
    Italian,
    Japanese,
    Korean,
    Norwegian,
    Persian,
    Polish,
    Portuguese,
    Romanian,
    Russian,
    Spanish,
    Swedish,
    Thai,
    Turkish,
    Ukrainian,
    Urdu,
    Vietnamese,
}

impl SummaryLanguage {
    /// system に書く綴り（「Write the summary in {これ}.」）。
    pub fn english_name(self) -> &'static str {
        match self {
            Self::Arabic => "Arabic",
            Self::Bulgarian => "Bulgarian",
            Self::Chinese => "Chinese",
            Self::SimplifiedChinese => "Simplified Chinese",
            Self::TraditionalChinese => "Traditional Chinese",
            Self::Czech => "Czech",
            Self::Danish => "Danish",
            Self::Dutch => "Dutch",
            Self::English => "English",
            Self::Finnish => "Finnish",
            Self::French => "French",
            Self::German => "German",
            Self::Greek => "Greek",
            Self::Hebrew => "Hebrew",
            Self::Hungarian => "Hungarian",
            Self::Indonesian => "Indonesian",
            Self::Italian => "Italian",
            Self::Japanese => "Japanese",
            Self::Korean => "Korean",
            Self::Norwegian => "Norwegian",
            Self::Persian => "Persian",
            Self::Polish => "Polish",
            Self::Portuguese => "Portuguese",
            Self::Romanian => "Romanian",
            Self::Russian => "Russian",
            Self::Spanish => "Spanish",
            Self::Swedish => "Swedish",
            Self::Thai => "Thai",
            Self::Turkish => "Turkish",
            Self::Ukrainian => "Ukrainian",
            Self::Urdu => "Urdu",
            Self::Vietnamese => "Vietnamese",
        }
    }

    /// Windows の LANGID（`GetUserDefaultUILanguage`の戻り値。下位10ビットが主言語、上位6ビットが副言語）から。
    /// 表に無い言語は`None`（クロアチア語・セルビア語・ボスニア語のように主言語の番号を共有するものも含む）。
    pub fn from_windows_langid(langid: u16) -> Option<Self> {
        let primary = langid & 0x03FF;
        let sub = langid >> 10;
        Some(match primary {
            0x01 => Self::Arabic,
            0x02 => Self::Bulgarian,
            // 副言語: 1=台湾・3=香港・5=マカオ・0x1F=zh-Hant が繁体。2=中国・4=シンガポール・0=zh-Hans が簡体。
            0x04 => match sub {
                0x01 | 0x03 | 0x05 | 0x1F => Self::TraditionalChinese,
                _ => Self::SimplifiedChinese,
            },
            0x05 => Self::Czech,
            0x06 => Self::Danish,
            0x07 => Self::German,
            0x08 => Self::Greek,
            0x09 => Self::English,
            0x0A => Self::Spanish,
            0x0B => Self::Finnish,
            0x0C => Self::French,
            0x0D => Self::Hebrew,
            0x0E => Self::Hungarian,
            0x10 => Self::Italian,
            0x11 => Self::Japanese,
            0x12 => Self::Korean,
            0x13 => Self::Dutch,
            0x14 => Self::Norwegian,
            0x15 => Self::Polish,
            0x16 => Self::Portuguese,
            0x18 => Self::Romanian,
            0x19 => Self::Russian,
            0x1D => Self::Swedish,
            0x1E => Self::Thai,
            0x1F => Self::Turkish,
            0x20 => Self::Urdu,
            0x21 => Self::Indonesian,
            0x22 => Self::Ukrainian,
            0x29 => Self::Persian,
            0x2A => Self::Vietnamese,
            _ => return None,
        })
    }

    /// ユーザーが最後に入力した文（無ければ`None`）と表示言語から、要約の言語を決める（モジュールdocの「決め方」）。
    /// **表示言語は呼び出し側が渡す**——ここは OS を読まない（試験が実物の OS に左右されないように）。
    pub fn for_user(last_input: Option<&str>, display: Option<Self>) -> Option<Self> {
        match last_input.and_then(Script::deciding) {
            Some(script) => Some(script.language(display)),
            None => display,
        }
    }
}

/// 言語を決められる文字の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Kana,
    Hangul,
    Han,
    Cyrillic,
    Arabic,
    Hebrew,
    Thai,
}

impl Script {
    /// 数で比べる種類（平仮名・片仮名とハングルは1文字で決まるので入れない）。同数なら先のもの。
    const COUNTED: [Script; 5] = [
        Script::Han,
        Script::Cyrillic,
        Script::Arabic,
        Script::Hebrew,
        Script::Thai,
    ];

    fn of(c: char) -> Option<Self> {
        Some(match c as u32 {
            // 中黒（U+30FB）は中国語の文でも使うので数えない。
            0x3041..=0x309F
            | 0x30A0..=0x30FA
            | 0x30FC..=0x30FF
            | 0x31F0..=0x31FF
            | 0xFF66..=0xFF9F => Self::Kana,
            0x1100..=0x11FF
            | 0x3130..=0x318F
            | 0xA960..=0xA97F
            | 0xAC00..=0xD7FF
            | 0xFFA0..=0xFFDC => Self::Hangul,
            0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x323AF => Self::Han,
            0x0400..=0x052F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Self::Cyrillic,
            0x0600..=0x06FF
            | 0x0750..=0x077F
            | 0x08A0..=0x08FF
            | 0xFB50..=0xFDFF
            | 0xFE70..=0xFEFF => Self::Arabic,
            0x0590..=0x05FF | 0xFB1D..=0xFB4F => Self::Hebrew,
            0x0E00..=0x0E7F => Self::Thai,
            _ => return None,
        })
    }

    /// 文から言語を決める文字の種類を選ぶ。決まらなければ（ラテン文字だけ・空）`None`。
    fn deciding(text: &str) -> Option<Self> {
        let mut counts = [0usize; Self::COUNTED.len()];
        let mut hangul = false;
        for c in text.chars() {
            match Self::of(c) {
                // 平仮名・片仮名は日本語でしか使わないので、見つけた時点で決まる。
                Some(Self::Kana) => return Some(Self::Kana),
                Some(Self::Hangul) => hangul = true,
                Some(script) => {
                    if let Some(i) = Self::COUNTED.iter().position(|s| *s == script) {
                        counts[i] += 1;
                    }
                }
                None => {}
            }
        }
        if hangul {
            // 韓国語の文は漢字を混ぜることがある。ハングルがあれば韓国語。
            return Some(Self::Hangul);
        }
        let (best, &count) = counts
            .iter()
            .enumerate()
            .rev()
            .max_by_key(|(_, count)| **count)?;
        (count > 0).then_some(Self::COUNTED[best])
    }

    /// 文字の種類と表示言語から言語を決める。複数の言語で使う文字は、表示言語がその中にあれば表示言語。
    fn language(self, display: Option<SummaryLanguage>) -> SummaryLanguage {
        use SummaryLanguage as L;
        match (self, display) {
            (Self::Kana, _) => L::Japanese,
            (Self::Hangul, _) => L::Korean,
            (Self::Han, Some(l @ (L::Japanese | L::SimplifiedChinese | L::TraditionalChinese))) => {
                l
            }
            (Self::Han, _) => L::Chinese,
            (Self::Cyrillic, Some(l @ (L::Russian | L::Ukrainian | L::Bulgarian))) => l,
            (Self::Cyrillic, _) => L::Russian,
            (Self::Arabic, Some(l @ (L::Arabic | L::Persian | L::Urdu))) => l,
            (Self::Arabic, _) => L::Arabic,
            (Self::Hebrew, _) => L::Hebrew,
            (Self::Thai, _) => L::Thai,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SummaryLanguage as L;

    /// 表示言語を英語にした場合（どの文字の種類でも「表示言語に倒さない」側を見る）。
    const EN: Option<L> = Some(L::English);

    /// 平仮名・片仮名が入っていれば日本語。漢字やラテン文字が多くても変わらない（コードを貼った日本語の依頼）。
    #[test]
    fn kana_means_japanese() {
        assert_eq!(L::for_user(Some("この関数を直して"), EN), Some(L::Japanese));
        assert_eq!(L::for_user(Some("テスト"), EN), Some(L::Japanese));
        assert_eq!(
            L::for_user(
                Some("fn main() { println!(\"hello world\"); } を実行して"),
                EN
            ),
            Some(L::Japanese)
        );
        // 半角片仮名も。
        assert_eq!(L::for_user(Some("ﾃｽﾄ"), EN), Some(L::Japanese));
    }

    /// ハングルなら韓国語（漢字が混ざっていても）。
    #[test]
    fn hangul_means_korean() {
        assert_eq!(
            L::for_user(Some("이 함수를 고쳐 주세요"), EN),
            Some(L::Korean)
        );
        assert_eq!(L::for_user(Some("大韓民國 만세"), EN), Some(L::Korean));
    }

    /// 漢字だけなら中国語。**表示言語が日本語なら日本語、中国語なら簡体／繁体**——漢字は日本語でも使うので、
    /// 「続行」「修正」のような漢字だけの短い依頼を中国語と決めつけない。
    #[test]
    fn han_only_is_chinese_unless_the_display_language_says_which() {
        assert_eq!(L::for_user(Some("修复这个函数"), EN), Some(L::Chinese));
        assert_eq!(L::for_user(Some("修复这个函数"), None), Some(L::Chinese));
        assert_eq!(
            L::for_user(Some("続行"), Some(L::Japanese)),
            Some(L::Japanese)
        );
        assert_eq!(
            L::for_user(Some("修复"), Some(L::SimplifiedChinese)),
            Some(L::SimplifiedChinese)
        );
        assert_eq!(
            L::for_user(Some("修復"), Some(L::TraditionalChinese)),
            Some(L::TraditionalChinese)
        );
        // 韓国語の表示言語でも漢字だけなら中国語（韓国語の文はハングルを含む）。
        assert_eq!(L::for_user(Some("修復"), Some(L::Korean)), Some(L::Chinese));
    }

    /// キリル文字はロシア語。表示言語がウクライナ語・ブルガリア語ならそちら。
    #[test]
    fn cyrillic_is_russian_unless_the_display_language_says_which() {
        assert_eq!(L::for_user(Some("исправь функцию"), EN), Some(L::Russian));
        assert_eq!(
            L::for_user(Some("виправ функцію"), Some(L::Ukrainian)),
            Some(L::Ukrainian)
        );
        assert_eq!(
            L::for_user(Some("поправи"), Some(L::Bulgarian)),
            Some(L::Bulgarian)
        );
    }

    /// アラビア文字・ヘブライ文字・タイ文字。
    #[test]
    fn other_scripts_that_decide_a_language() {
        assert_eq!(L::for_user(Some("أصلح الدالة"), EN), Some(L::Arabic));
        assert_eq!(
            L::for_user(Some("تابع را درست کن"), Some(L::Persian)),
            Some(L::Persian)
        );
        assert_eq!(L::for_user(Some("תקן את הפונקציה"), EN), Some(L::Hebrew));
        assert_eq!(L::for_user(Some("แก้ไขฟังก์ชัน"), EN), Some(L::Thai));
    }

    /// **ラテン文字だけ・入力が無いときは表示言語に倒す。** 表示言語も無ければ決めない。
    #[test]
    fn latin_only_or_no_input_falls_back_to_the_display_language() {
        assert_eq!(
            L::for_user(Some("fix the function"), Some(L::Japanese)),
            Some(L::Japanese)
        );
        assert_eq!(
            L::for_user(Some("corrige la fonction"), Some(L::French)),
            Some(L::French)
        );
        assert_eq!(L::for_user(None, Some(L::German)), Some(L::German));
        assert_eq!(L::for_user(Some(""), Some(L::German)), Some(L::German));
        assert_eq!(L::for_user(Some("fix it"), None), None);
        assert_eq!(L::for_user(None, None), None);
    }

    /// **ギリシャ文字は数えない**（英語の技術文書でも記号として使う）。中黒・全角の句読点も数えない。
    #[test]
    fn symbols_shared_across_languages_do_not_decide() {
        assert_eq!(
            L::for_user(Some("compute Δx = π r² with λ = 0.5"), Some(L::English)),
            Some(L::English)
        );
        assert_eq!(
            L::for_user(Some("a・b、c。"), Some(L::English)),
            Some(L::English)
        );
    }

    /// 種類が混ざっていれば多いほう。
    #[test]
    fn the_more_frequent_script_wins() {
        assert_eq!(
            L::for_user(Some("исправь функцию 中"), EN),
            Some(L::Russian)
        );
        assert_eq!(L::for_user(Some("修复这个函数 и"), EN), Some(L::Chinese));
    }

    /// 表示言語の LANGID。主言語の番号で引き、中国語だけは副言語で簡体／繁体を分ける。
    #[test]
    fn windows_langids_map_to_the_table() {
        assert_eq!(L::from_windows_langid(0x0411), Some(L::Japanese)); // ja-JP
        assert_eq!(L::from_windows_langid(0x0409), Some(L::English)); // en-US
        assert_eq!(L::from_windows_langid(0x0809), Some(L::English)); // en-GB
        assert_eq!(L::from_windows_langid(0x0412), Some(L::Korean)); // ko-KR
        assert_eq!(L::from_windows_langid(0x0804), Some(L::SimplifiedChinese)); // zh-CN
        assert_eq!(L::from_windows_langid(0x0404), Some(L::TraditionalChinese)); // zh-TW
        assert_eq!(L::from_windows_langid(0x0C04), Some(L::TraditionalChinese)); // zh-HK
        assert_eq!(L::from_windows_langid(0x1004), Some(L::SimplifiedChinese)); // zh-SG
        assert_eq!(L::from_windows_langid(0x0419), Some(L::Russian)); // ru-RU
        assert_eq!(L::from_windows_langid(0x0422), Some(L::Ukrainian)); // uk-UA
        assert_eq!(L::from_windows_langid(0x041A), None); // hr-HR（セルビア語・ボスニア語と番号を共有）
        assert_eq!(L::from_windows_langid(0), None);
    }

    /// 送る綴りは英字と空白だけ（system へ混ぜても指示や区切りにならない）。
    #[test]
    fn every_name_is_plain_english_words() {
        for langid in 0..=u16::MAX {
            if let Some(l) = L::from_windows_langid(langid) {
                let name = l.english_name();
                assert!(
                    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphabetic() || c == ' '),
                    "{name:?}"
                );
            }
        }
        assert_eq!(L::Chinese.english_name(), "Chinese");
    }
}
