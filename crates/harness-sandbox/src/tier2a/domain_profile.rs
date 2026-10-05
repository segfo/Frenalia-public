//! [段階⑦→#55] **遷移先ドメインごとの**AppContainerプロファイル名
//! （`plans/DESIGN-MAC-BROKER.md` §22.9）。
//!
//! # 何のためにあるのか
//!
//! ドメインのセキュリティコンテキストは`(package SID, capability SIDの組)`である（§22.1）。
//! このうち**package SIDはプロファイル名から一方向に導出される**ので、
//! 「ドメインDの入れ物」を作るとは「Dの名前でプロファイルを作る」ことに等しい。
//!
//! **分ける理由は、同一package SID内では閉じないものがあるから**である。案A
//! （トークンの既定DACLの差し替え）でコード注入は塞いだが、**名前付きカーネルオブジェクト
//! 経由のデータ交換・妨害は閉じられない**——AppContainerの名前付きオブジェクトは
//! package SIDごとの専用ディレクトリに作られるためである（§22.9）。
//!
//! # 3つ目の族である（セッション単位・MCPサーバ単位に続く）
//!
//! | 族 | 接頭辞 | 単位 |
//! |---|---|---|
//! | [`crate::tier2a::session_profile`] | `harness.shell.sandbox` | セッション（D-37） |
//! | [`crate::tier2a::mcp_profile`] | `harness.mcp` | MCPサーバ（D-38） |
//! | **ここ** | `harness.domain` | **遷移先ドメイン**（§22.9） |
//!
//! **形はMCPサーバ用と同じ**（`<接頭辞>.<セッションの印>.<id>`）。写したのは意図であって
//! 偶然ではない——生存管理・台帳・接頭辞による孤児回収が、あちらと同じ枠にそのまま乗る。
//!
//! > §22.9は「3つ目を足すのではなく**ドメインを鍵にした1つのアロケータへ一般化する**」と
//! > 書いている。**一般化はこの回では行っていない**——台帳の欄の形を変えることになり、
//! > 変えた瞬間に**古い台帳が読めなくなって、そこに記録された回収対象が孤児になる**。
//! > 骨格を通す目的に対して釣り合わないので、一般化は**挙動を変えない別の回**に行う。
//!
//! # セッションの印を名前に入れる理由
//!
//! 入れ物の寿命は**そのセッション**である。印が無いと、別のharnessが同じドメイン名で
//! 作った入れ物と区別できず、**走行中の他セッションの入れ物を回収する**（BUG-053と同じ形）。

/// 遷移先ドメインのプロファイル名の接頭辞。
///
/// **GCがこの接頭辞だけを頼りに孤児を列挙する**ため、変更するとそれ以前のセッションが
/// 作った入れ物を回収できなくなる（`mcp_profile`の同じ定数と同じ理由）。
pub const DOMAIN_PROFILE_PREFIX: &str = "harness.domain";

/// `<セッションの印>.<ドメイン名>`部分の長さ上限。
///
/// `CreateAppContainerProfile`の名前は64文字までで、接頭辞`harness.domain.`が15文字を使う。
/// **`mcp_profile`の50とは値が違う**——接頭辞の長さが違うので、同じ数にすると
/// 片方が64文字を超える。
const MAX_SUFFIX_LEN: usize = 49;

/// `token`のセッションで動くドメイン`domain`の入れ物の名前。
pub fn domain_profile_name_for(token: &str, domain: &str) -> String {
    format!("{DOMAIN_PROFILE_PREFIX}.{token}.{domain}")
}

/// このプロセスのセッションにおけるドメイン`domain`の入れ物の名前。
pub fn current_domain_profile_name(domain: &str) -> String {
    domain_profile_name_for(crate::tier2a::session_profile::session_token(), domain)
}

/// harnessの遷移先ドメインのプロファイル名か。
///
/// **信頼境界を越えて受け取った名前の検証に使う**——昇格側（`privhelper`・`netfilterd`）は、
/// 渡された名前がこの形であることを確認してからSIDを導出する。これを緩めると、非特権側が
/// 任意のAppContainerへACEやWFPフィルタを張らせられる。
/// `session_profile::is_session_profile_name`・`mcp_profile::is_mcp_profile_name`と
/// **同じ文字種**（英数字・ハイフン・ドット）だけを許す。
pub fn is_domain_profile_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(&format!("{DOMAIN_PROFILE_PREFIX}.")) else {
        return false;
    };
    // `<印>.<ドメイン名>`の2つの部分が両方とも非空であること。区切りのドットが無い
    // （＝ドメイン名が無い）名前は、セッション全体を指す別物なので受け付けない。
    // ドメイン名は`.`を含み得るので、切るのは最初の`.`である（BUG-189）。
    if crate::tier2a::mcp_profile::split_session_token(suffix).is_none() {
        return false;
    }
    suffix.len() <= MAX_SUFFIX_LEN
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// プロファイル名から**セッションの印**を取り出す（GCが持ち主を判定するのに使う）。
///
/// **`None`は「この族の名前ではない」**。形が違うものへ推測で印を当てない——
/// 当てると、他人の入れ物を自分のものとして回収することになる。
///
/// 呼ぶのは持ち主の判定の唯一の入口（`session_profile::token_of_profile`）だけである。
/// 2026-09-30まではそこから呼ばれておらず、この族は回収と「残す側」の名簿から漏れていた
/// （`docs/STATUS.md`「サンドボックス周辺 #63」）。
///
/// **印は最初の`.`まで**である（[BUG-189](../../../../docs/bugs/BUG-189.md)。切り方の正本は
/// `mcp_profile::split_session_token`）。2026-10-01までは最後の`.`で切っていたので、
/// `.`を含むドメイン名では自分の入れ物を「別のセッションのもの」と答え、`ensure_profile`が
/// 作成を拒んでいた。
pub fn token_of_domain_profile(name: &str) -> Option<&str> {
    if !is_domain_profile_name(name) {
        return None;
    }
    let suffix = name.strip_prefix(&format!("{DOMAIN_PROFILE_PREFIX}."))?;
    crate::tier2a::mcp_profile::split_session_token(suffix).map(|(token, _domain)| token)
}

// ---------------------------------------------------------------------------
// 遷移先の名前の検査（書く前に断るためのもの。2026-10-05 にポリシーエディタから移した）
// ---------------------------------------------------------------------------

/// `harness.exe`のセッションの印（`<pid>-<unix秒>`）が**最も長くなる形**。pidは`u32`の最大桁。
///
/// 印の形の正本は[`crate::tier2a::session_profile::session_token`]で、
/// 試験`the_longest_session_token_still_has_the_shape_of_a_real_one`がこのプロセスの本物の印と
/// 形を突き合わせる（形が変わったらその試験が赤くなる）。
const LONGEST_SESSION_TOKEN: &str = "4294967295-9999999999";

/// 遷移先ドメイン`domain`が、`harness.exe`の入れ物の名前として**どのセッションでも使えるか**。
/// 使えなければ理由を返す。
///
/// # 判定は持ち主の判定そのものに聞く
///
/// 最も長いセッションの印で入れ物の名前を組み（[`domain_profile_name_for`]）、
/// `session_profile::token_of_profile`（GCと「生きている他セッション」の名簿が使う唯一の入口）が
/// **同じ印を読み戻せるか**を見る。読み戻せないのは、名前に使えない文字がある・長すぎる
/// （入れ物の名前は64文字まで。`harness.exe`は起動時にその遷移先を用意できない）ときである。
///
/// `.`はかつて暫定で断っていた——持ち主の判定が名前の**最後の**`.`で印を切っていたので、
/// `a.b`の`a`を印の一部と読み違えたためである。2026-10-01に判定が最初の`.`で切るよう直った
/// （[BUG-189](../../../../docs/bugs/BUG-189.md)）ので、**この関数は何も変えずに通すようになった**
/// （判定を写さずに聞いているため）。
///
/// 編集時検査（`harness_policy::transition`の`check_domain_name`）は50文字で通すので、
/// 長さはそれより厳しい。**決定63が「自動生成名の検証を『あれば良い』に落とさない——検証が無いと
/// 承認は通るのにプロファイル生成が実行時に落ちる」と決めた**のと同じ理由で、書く前に断る。
///
/// # 誰が呼ぶか
///
/// ポリシーエディタ（遷移を書く前の検査・遷移先の欄の表示）。**`harness-policy`（純粋クレート）は
/// このクレートに依存できない**（依存は逆向き）ので、位置ごとのドメインの割り当て
/// （`plans/position-domains/P3.md` Task 4）はこの関数をクロージャで受け取る。
///
/// かつてはエディタが接頭辞（[`DOMAIN_PROFILE_PREFIX`]）を写して同じ組み立てをしていた。
/// 写しは片方だけ変わる（`bug-pattern-rules` B-05）ので、組み立てごとここへ移した。
pub fn domain_profile_name_problem(domain: &str) -> Option<String> {
    if name_round_trips(domain) {
        return None;
    }
    Some(format!(
        "harness.exe の入れ物（AppContainerプロファイル）の名前にできません——\
         使えるのは英数字と「-」「.」だけで、長さは {}文字までです",
        longest_destination_name_len()
    ))
}

fn name_round_trips(domain: &str) -> bool {
    let name = domain_profile_name_for(LONGEST_SESSION_TOKEN, domain);
    crate::tier2a::session_profile::token_of_profile(&name) == Some(LONGEST_SESSION_TOKEN)
}

/// どのセッションでも入れ物の名前にできる最長の名前の長さ（**持ち主の判定に聞いて数える**。
/// 上限の値をここへ写さない）。
fn longest_destination_name_len() -> usize {
    (1..=64)
        .take_while(|n| name_round_trips(&"x".repeat(*n)))
        .last()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2a::mcp_profile::{is_harness_profile_name, mcp_profile_name_for};
    use crate::tier2a::session_profile::profile_name_for;

    #[test]
    fn profile_names_carry_the_prefix_so_gc_can_find_them_without_the_ledger() {
        let name = domain_profile_name_for("1234-99", "cargo");
        assert_eq!(name, "harness.domain.1234-99.cargo");
        assert!(name.starts_with(DOMAIN_PROFILE_PREFIX));
        assert!(is_domain_profile_name(&name));
        assert_eq!(token_of_domain_profile(&name), Some("1234-99"));
    }

    /// **[BUG-189] 禁止側。** ドメイン名に`.`があっても、印は**最初の**`.`までである。
    ///
    /// 最後の`.`で切ると`a.b`の`a`を印の一部と読み、持ち主を「別のセッション`1234-99.a`」と
    /// 答える。`.`入りの名前は手で書かなくても現れる——`policy.json`の編集時検査が`.`を許し
    /// （`harness_policy`の`check_domain_name`）、既定のドメイン名は`python3.11.exe`から
    /// `python3.11`を作る（`harness_policy::policy_file::default_domain_name`）。
    ///
    /// 許可側（`.`を含まない名前）は上の`profile_names_carry_the_prefix_…`が見ている。
    #[test]
    fn a_dotted_domain_name_does_not_leak_into_the_session_token() {
        for domain in ["a.b", "python3.11", "x.y.z"] {
            let name = domain_profile_name_for("1234-99", domain);
            assert!(is_domain_profile_name(&name), "{name}");
            assert_eq!(
                token_of_domain_profile(&name),
                Some("1234-99"),
                "the session token of {name}"
            );
        }
    }

    /// **信頼境界の検証**: 昇格側が受け取る名前として妥当なものだけを通す。
    #[test]
    fn only_well_formed_domain_profile_names_are_accepted() {
        assert!(is_domain_profile_name("harness.domain.1234-5678.cargo"));
        assert!(is_domain_profile_name("harness.domain.1234-5678.a-b-c"));

        for bad in [
            // ドメイン名が無い（セッション全体を指す形）。
            "harness.domain.1234-5678",
            "harness.domain.",
            "harness.domain",
            // 空の要素。
            "harness.domain..cargo",
            "harness.domain.1234-5678.",
            // 別の族。
            "harness.shell.sandbox.1234-5678",
            "harness.mcp.1234-5678.docs",
            "other.container.1234.cargo",
            // パス・ワイルドカード等の混入。
            "harness.domain.1234.../evil",
            "harness.domain.1234.a b",
            "harness.domain.1234.a\\b",
            "harness.domain.1234.a*",
        ] {
            assert!(!is_domain_profile_name(bad), "should reject {bad:?}");
            assert_eq!(token_of_domain_profile(bad), None, "no token for {bad:?}");
        }

        // 名前の長さ上限（AppContainerプロファイル名の64文字制限）。
        let too_long = domain_profile_name_for("1234-5678", &"x".repeat(MAX_SUFFIX_LEN));
        assert!(!is_domain_profile_name(&too_long));
        assert!(
            domain_profile_name_for("1234-5678", &"x".repeat(MAX_SUFFIX_LEN)).len() > 64,
            "上限を超える名前は64文字を超えていなければ、この上限は何も守っていない"
        );
    }

    /// **信頼境界が見る統合判定へ通っている**（`is_harness_profile_name`）。
    ///
    /// 通っていないと、昇格側は遷移先ドメインの入れ物を「harness由来ではない」と見なす
    /// ——ACEもWFPフィルタも張れず、**そのドメインは何もできない**。
    /// 逆に、判定を2つに割って呼び分ける形にすると、片方の呼び出しを足し忘れた経路が
    /// **検証をすり抜ける**（`mcp_profile::is_harness_profile_name`のdocが宣言している）。
    #[test]
    fn the_trust_boundary_predicate_accepts_the_domain_family_too() {
        let domain = domain_profile_name_for("1234-5678", "cargo");
        assert!(
            is_harness_profile_name(&domain),
            "信頼境界の判定が遷移先ドメインの入れ物を通していない: {domain}"
        );
        // 既存の2族も通り続けること（足したことで壊していない）。
        assert!(is_harness_profile_name(&profile_name_for("1234-5678")));
        assert!(is_harness_profile_name(&mcp_profile_name_for(
            "1234-5678",
            "docs"
        )));
    }

    /// 3つの族は互いに相手の形を受け付けない（SIDの導出先を取り違えないことの担保）。
    #[test]
    fn the_three_profile_families_do_not_overlap() {
        let session = profile_name_for("1234-5678");
        let mcp = mcp_profile_name_for("1234-5678", "docs");
        let domain = domain_profile_name_for("1234-5678", "cargo");

        assert!(!is_domain_profile_name(&session));
        assert!(!is_domain_profile_name(&mcp));
        assert!(!crate::tier2a::mcp_profile::is_mcp_profile_name(&domain));
        assert!(!crate::tier2a::session_profile::is_session_profile_name(
            &domain
        ));
    }

    // --- 遷移先の名前の検査（2026-10-05 にポリシーエディタから移した） -------------

    /// **許可側**: 英数字と`-`の短い名前は使える（組み立てがずれた日にはここが赤くなる——
    /// そのとき検査は全部の名前を断る側へ外れている）。
    #[test]
    fn a_short_plain_name_can_be_a_destination() {
        for good in ["iso", "cargo-build", "a1"] {
            assert_eq!(
                domain_profile_name_problem(good),
                None,
                "{good:?} が断られた"
            );
        }
    }

    /// **許可側**: `.`を含む名前も使える（[BUG-189](../../../../docs/bugs/BUG-189.md)）。
    ///
    /// 持ち主の判定が名前の最後の`.`で印を切っていた間は、ここを暫定で断っていた。既定のドメイン名は
    /// `python3.11.exe`から`python3.11`を作る（`harness_policy::policy_file::default_domain_name`）ので、
    /// 断ると、記録した名前のままでは遷移先にできない。判定が最後の`.`で切る形へ戻ると、ここが赤くなる。
    #[test]
    fn a_dotted_name_can_be_a_destination() {
        for good in ["a.b", "python3.11"] {
            assert_eq!(
                domain_profile_name_problem(good),
                None,
                "{good:?} が断られた"
            );
        }
    }

    /// **禁止側**: 入れ物の名前にできない名前は断る。長さの上限は持ち主の判定に聞いて数えるので、
    /// 上限ちょうどは通り、1文字超えると断られる。
    #[test]
    fn names_that_cannot_become_a_profile_name_are_refused() {
        let longest = longest_destination_name_len();
        assert!(
            longest >= 16,
            "上限が短すぎる（印の形が変わった？）: {longest}"
        );
        assert_eq!(domain_profile_name_problem(&"x".repeat(longest)), None);
        assert!(domain_profile_name_problem(&"x".repeat(longest + 1)).is_some());
        for bad in ["", "bad name", "a/b", "a*"] {
            assert!(
                domain_profile_name_problem(bad).is_some(),
                "{bad:?} が通った"
            );
        }
    }

    /// 最も長い印の形が、**このプロセスの本物の印と同じ形**（数字-数字）で、それより長くないこと。
    ///
    /// 印の形（`session_profile::session_token`）が変わったら赤くなる——`LONGEST_SESSION_TOKEN`を直すこと。
    #[test]
    fn the_longest_session_token_still_has_the_shape_of_a_real_one() {
        let real = crate::tier2a::session_profile::session_token();
        let shape = |token: &str| {
            let (pid, secs) = token.split_once('-').expect("印に「-」が無い");
            !pid.is_empty()
                && !secs.is_empty()
                && pid.chars().all(|c| c.is_ascii_digit())
                && secs.chars().all(|c| c.is_ascii_digit())
        };
        assert!(shape(real), "本物の印の形が変わった: {real}");
        assert!(shape(LONGEST_SESSION_TOKEN));
        assert!(
            real.len() <= LONGEST_SESSION_TOKEN.len(),
            "本物の印が最長の想定より長い: {real}"
        );
    }

    /// 決定65の細目9（提案するドメイン名は27文字以内。`plans/POLICY-EDITOR-TOMOYO-DIG.md`）の27は、
    /// **この検査が数えた値**である。
    ///
    /// 印の形か上限（`MAX_SUFFIX_LEN`）が変わってここが赤くなったら、決定65の細目9の数字と、
    /// 位置ごとのドメインの割り当ての試験（`harness_policy::position_domains`。27文字の偽の検査を
    /// 渡している）を直すこと。
    #[test]
    fn the_longest_destination_name_is_the_27_of_decision_65() {
        assert_eq!(longest_destination_name_len(), 27);
    }
}
