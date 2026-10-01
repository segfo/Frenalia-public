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
}
