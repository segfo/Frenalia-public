//! MCPサーバごとのAppContainerプロファイル（D-38、`plans/DESIGN-MCP.md` §3.1）。
//!
//! `run_shell`の子はセッション単位の1プロファイル（[`crate::tier2a::session_profile`]、D-37）で
//! 動くが、MCPサーバは**サーバごとに別のプロファイル＝別のpackage SID**を持つ。
//!
//! ## なぜサーバごとに分けるのか
//!
//! D-37が「共有された1つの主体」を欠陥クラスの根として廃した判断の直接の帰結である。信頼度も
//! 用途も異なる複数のMCPサーバを1つのSIDへ相乗りさせると、ACL・WFPフィルタ・capabilityが
//! **全サーバの要求の和集合**になり、最も緩いサーバが全体の権限を決めてしまう。
//! `run_shell`の子とも共有しない——AppContainerのcapabilityはトークン属性でプロセスツリー全体が
//! 継承する（T-15）ため、MCPサーバへnetworkを与えると同じSIDの`run_shell`子孫すべてが通信可能に
//! なり、D-11「信頼付与は狭く保つ」と正面から衝突する。
//!
//! ## 生存管理はセッション側の枠に相乗りする
//!
//! 生存マーカー・台帳・孤児回収は`session_profile`の枠をそのまま使う。MCPプロファイルは
//! セッションの台帳エントリ（`SessionEntry::mcp`）へぶら下がり、セッションが死ねば一緒に
//! 回収される。**プロファイル名の接頭辞だけを頼りにした台帳非依存の回収経路**（`session_profile`の
//! モジュールdoc）もそのまま効く。

/// MCPサーバプロファイル名の接頭辞。**GCがこの接頭辞だけを頼りに孤児を列挙する**ため、
/// 変更するとそれ以前のセッションが作ったプロファイルを回収できなくなる。
pub const MCP_PROFILE_PREFIX: &str = "harness.mcp";

/// `<session-token>.<server-id>`部分の長さ上限。`CreateAppContainerProfile`の名前は64文字までで、
/// 接頭辞`harness.mcp.`が12文字を使う。
const MAX_SUFFIX_LEN: usize = 50;

/// `token`のセッションで動く`server_id`のプロファイル名。
pub fn mcp_profile_name_for(token: &str, server_id: &str) -> String {
    format!("{MCP_PROFILE_PREFIX}.{token}.{server_id}")
}

/// このプロセスのセッションにおける`server_id`のプロファイル名。
pub fn current_mcp_profile_name(server_id: &str) -> String {
    mcp_profile_name_for(crate::tier2a::session_profile::session_token(), server_id)
}

/// harnessのMCPサーバプロファイル名か。
///
/// **信頼境界を越えて受け取った名前の検証に使う**——昇格側（`privhelper`・`netfilterd`）は、
/// 渡された名前がこの形であることを確認してからSIDを導出する。これを緩めると、非特権側が
/// 任意のAppContainerへACEやWFPフィルタを張らせられる。`session_profile::is_session_profile_name`
/// と同じ文字種（英数字・ハイフン・ドット）だけを許す。
pub fn is_mcp_profile_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(&format!("{MCP_PROFILE_PREFIX}.")) else {
        return false;
    };
    // `<token>.<server-id>`の2つの部分が両方とも非空であること。区切りのドットが無い
    // （＝サーバidが無い）名前は、セッション全体を指す別物なので受け付けない。
    let Some((token, server_id)) = suffix.rsplit_once('.') else {
        return false;
    };
    !token.is_empty()
        && !server_id.is_empty()
        && suffix.len() <= MAX_SUFFIX_LEN
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// harness由来のAppContainerプロファイル名か（`run_shell`セッション用またはMCPサーバ用）。
///
/// **信頼境界（`privhelper`・`netfilterd`）はこの関数だけを見る。** 2つの検証関数を別々に
/// 呼び分ける形にすると、片方の呼び出し箇所を足し忘れたときに「MCPプロファイルには
/// フィルタを張れない」あるいは逆に「検証をすり抜ける」経路が生まれる。
pub fn is_harness_profile_name(name: &str) -> bool {
    crate::tier2a::session_profile::is_session_profile_name(name) || is_mcp_profile_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2a::session_profile::profile_name_for;

    #[test]
    fn profile_names_carry_the_prefix_so_gc_can_find_them_without_the_ledger() {
        let name = mcp_profile_name_for("1234-99", "company-docs");
        assert_eq!(name, "harness.mcp.1234-99.company-docs");
        assert!(name.starts_with(MCP_PROFILE_PREFIX));
        assert!(is_mcp_profile_name(&name));
    }

    /// **信頼境界の検証**: 昇格側が受け取る名前として妥当なものだけを通す。
    #[test]
    fn only_well_formed_mcp_profile_names_are_accepted() {
        assert!(is_mcp_profile_name("harness.mcp.1234-5678.docs"));
        assert!(is_mcp_profile_name("harness.mcp.1234-5678.a-b-c"));

        for bad in [
            // サーバid部分が無い（セッション全体を指す形）。
            "harness.mcp.1234-5678",
            "harness.mcp.",
            "harness.mcp",
            // 空の要素。
            "harness.mcp..docs",
            "harness.mcp.1234-5678.",
            // 別の主体。
            "harness.shell.sandbox.1234-5678",
            "other.container.1234.docs",
            // パス・ワイルドカード等の混入。
            "harness.mcp.1234.../evil",
            "harness.mcp.1234.a b",
            "harness.mcp.1234.a\\b",
            "harness.mcp.1234.a*",
        ] {
            assert!(!is_mcp_profile_name(bad), "should reject {bad:?}");
        }

        // 名前の長さ上限（AppContainerプロファイル名の64文字制限）。
        let too_long = mcp_profile_name_for("1234-5678", &"x".repeat(MAX_SUFFIX_LEN));
        assert!(!is_mcp_profile_name(&too_long));
    }

    /// 信頼境界が見る統合判定は、両系統を通し、それ以外を通さない。
    #[test]
    fn the_trust_boundary_predicate_accepts_both_harness_profile_families_only() {
        assert!(is_harness_profile_name(&profile_name_for("1234-5678")));
        assert!(is_harness_profile_name(&mcp_profile_name_for(
            "1234-5678",
            "docs"
        )));

        for bad in [
            "harness.shell.sandbox",
            "harness.mcp",
            "microsoft.windowsterminal",
            "",
        ] {
            assert!(!is_harness_profile_name(bad), "should reject {bad:?}");
        }
    }

    /// セッションプロファイルとMCPプロファイルは互いに相手の形を受け付けない
    /// （SIDの導出先を取り違えないことの担保）。
    #[test]
    fn session_and_mcp_profile_names_do_not_overlap() {
        let session = profile_name_for("1234-5678");
        let mcp = mcp_profile_name_for("1234-5678", "docs");
        assert!(!is_mcp_profile_name(&session));
        assert!(!crate::tier2a::session_profile::is_session_profile_name(
            &mcp
        ));
    }
}
