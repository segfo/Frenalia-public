//! WFP（Layer2出口強制）を**どう確定させるか**の判定と、**立たなかったときの説明文**。
//!
//! `run_agent.rs`の起動シーケンスから切り出してある。分割線は「Windows APIを呼ぶ副作用」と
//! 「呼ぶ前に決まる判定・文言」の境目で、こちら側は副作用を一切持たない純粋な関数だけなので
//! 単体テストで固定できる（`docs/CODE-STRUCTURE-RULES.md`の責務の2軸のうち「テスト可能性が
//! 変わる境目」で割った）。
//!
//! **この分割の目的は[BUG-111](../../../../../docs/bugs/BUG-111.md)の再発防止である。**
//! WFPが立たない経路は4つあり、帰結はどれも同じ（AppContainerのnetwork capability自体を
//! 与えない）なのに、説明の文言が経路ごとに分裂して1つは実挙動の逆を宣言していた。
//! ここでは2段のコンパイル時ゲートで、経路を足したときの取りこぼしをビルドエラーにする——
//! (1) 新しい不成立経路は[`WfpUnavailable`]のバリアントとして足すしかなく、足すと
//! [`WfpUnavailable::warning`]の`match`が非網羅になる。(2) 文言を書いても
//! [`TIER2A_NET_DENIED`]を含めなければ単体テストが落ちる。

/// Tier2a＋ドメインポリシー要求下でWFP（Layer2）が立たなかったとき、**どの不成立経路でも
/// 共通で起きる帰結**の説明。`should_grant_tier2a_network_capability`
/// （`crates/harness-tools/src/shell/net_decision.rs`）は`domain_policy_requested &&
/// !enforced_by_wfp`のとき`NetworkCapability::Deny`を返すため、結果はLayer1協調プロキシへの
/// 縮退**ではなく**AppContainer capability自体の不付与＝`run_shell`の子プロセスはソケットを
/// 1つも作れず、協調プロキシへのloopback到達すらできない（fail-closed）。
///
/// **経路ごとに文言を書かず定数へ集約している理由**: 別々に書くと片方だけが実態へ追随し、
/// もう片方が古い説明のまま残る。実際にシナリオ(B)（`NetfilterHandle::start`失敗）だけが
/// 正され、シナリオ(A)（privhelper連鎖起動後のハンドシェイク失敗）は「Layer1協調プロキシが
/// 強制する」という誤った説明のまま取り残されていた。
///
/// **この文字列はE2Eの契約である。** `crates/harness-cli/tests/tier2a_e2e.rs`が2通りに使う——
/// case 07/10は**存在**をfail-closedの証拠にし、`tier2a_smb445_layer2`は**不在**を
/// 「capability拒否分岐を通っていない＝445の拒否はWFPの手柄だ」の証拠にする。全経路が
/// この同一文言を出すことで、後者の不在チェックが拒否経路を漏れなく覆う。
///
/// **拒否が確定していない箇所でこの句を使わないこと**——証拠としての意味が薄れる。
/// 「まだ試していない」「別経路へ倒れるだけ」は不成立ではないので[`WfpPlan::NotNeeded`]や
/// `sandbox.rs`のパイプ準備失敗のように、この句を持たない別の文言で説明する。
pub const TIER2A_NET_DENIED: &str =
    "Tier2a run_shell network capability will remain denied for this session (fail-closed, no \
     outbound sockets at all, not merely unenforced)";

/// E2E（`tier2a_e2e.rs`）が検査に使う部分文字列。[`TIER2A_NET_DENIED`]の接頭辞であることを
/// 単体テストで固定してある——E2E側は文字列リテラルを直書きしており型で守られていないため、
/// ここを縮めるとE2Eが無言で「不在」と判定するようになる（`B-05`の追従漏れ）。
#[cfg(test)]
const E2E_CONTRACT_NEEDLE: &str = "Tier2a run_shell network capability will remain denied";

/// WFPが**不成立に終わった**経路。バリアント＝「ユーザーへ拒否の理由を説明する義務がある
/// 経路」であり、`NetfilterHandle`を得られなかったすべての経路がここを通る。
///
/// 新しい不成立経路を足すときは、無言で`None`を返さずここへバリアントを足すこと
/// （[`WfpUnavailable::warning`]の`match`が非網羅になってビルドが落ちるので、足し忘れは
/// 起きない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpUnavailable {
    /// セッション共有のLocal Proxyが起動しなかった。WFPを試すまでもなく拒否が確定する
    /// （プロキシが無ければ許可ドメインへ流す先が無いため）。
    SessionProxyNotStarted,
    /// シナリオ(A): privhelperが連鎖起動したdaemonとのハンドシェイクに失敗した。
    ChainLaunchHandshakeFailed(String),
    /// シナリオ(A)の不変条件が崩れた: 連鎖起動を依頼した記録があるのに、依頼に使った
    /// 投機的パイプが手元に無い。現状到達しないが、崩れたときに無言で拒否へ落ちないよう
    /// 経路として明示している。
    ChainLaunchPipeMissing,
    /// シナリオ(B): privhelperを経由せず`NetfilterHandle::start`で直接起動しようとして
    /// 失敗した。
    DirectStartFailed(String),
}

impl WfpUnavailable {
    /// stderrへそのまま出す1行。**`warning:`接頭辞まで含めて返す**——呼び出し側に文言の
    /// 組み立てを残すと、そこで経路ごとの差が再び生まれるため。
    ///
    /// どのバリアントも[`TIER2A_NET_DENIED`]を含む（単体テストで固定）。前半は経路ごとに
    /// 変えてあり、これは**どの経路を通ったかをstderrだけで識別できるようにする**ため——
    /// フォールト注入したつもりが別の経路へ落ちても緑になる[BUG-056](../../../../../docs/bugs/BUG-056.md)型の
    /// 穴を塞ぐ（`net_case_10`が`daemon rejected the request:`を検査文字列に選んでいるのと
    /// 同じ考え方）。
    pub fn warning(&self) -> String {
        match self {
            Self::SessionProxyNotStarted => format!(
                "warning: session-scoped local proxy did not start; WFP domain enforcement will \
                 not be enabled and {TIER2A_NET_DENIED}"
            ),
            Self::ChainLaunchHandshakeFailed(e) => format!(
                "warning: WFP netfilterd chain-launch handshake failed; {TIER2A_NET_DENIED}: {e}"
            ),
            Self::ChainLaunchPipeMissing => format!(
                "warning: netfilterd chain-launch was requested but the prepared pipe is missing \
                 (internal inconsistency); {TIER2A_NET_DENIED}"
            ),
            Self::DirectStartFailed(e) => {
                format!("warning: failed to start WFP netfilterd; {TIER2A_NET_DENIED}: {e}")
            }
        }
    }
}

/// WFPをどう確定させるかの計画。副作用を伴う実行（パイプの消費・daemon起動）へ入る**前**に
/// 決まる部分だけを表す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpPlan {
    /// そもそもWFPを必要としない（Tier2aでない、またはドメインポリシーの要求が無い）。
    /// **拒否ではないので何も警告しない**——ここで[`TIER2A_NET_DENIED`]を出すと、E2Eが
    /// 「不在＝拒否経路を通っていない」の証拠に使えなくなる。
    NotNeeded,
    /// 試すまでもなく不成立が確定している。
    Denied(WfpUnavailable),
    /// シナリオ(A): privhelperが連鎖起動済みなので、同じパイプでハンドシェイクする。
    ChainHandshake,
    /// シナリオ(B): 自前で`NetfilterHandle::start`を呼ぶ（投機的パイプは使わない）。
    DirectStart,
}

/// 起動時に確定している4つの事実から[`WfpPlan`]を決める。
///
/// `prepared_pipe_present`は`netfilterd_chain_attempted`が真のときだけ意味を持つ
/// （シナリオ(B)は`NetfilterHandle::start`が自前でパイプを作るため、投機的パイプの有無に
/// 関わらず`DirectStart`になる）。
pub fn plan_wfp(
    tier2a_domain_policy: bool,
    session_proxy_ready: bool,
    netfilterd_chain_attempted: bool,
    prepared_pipe_present: bool,
) -> WfpPlan {
    if !tier2a_domain_policy {
        return WfpPlan::NotNeeded;
    }
    if !session_proxy_ready {
        return WfpPlan::Denied(WfpUnavailable::SessionProxyNotStarted);
    }
    if !netfilterd_chain_attempted {
        return WfpPlan::DirectStart;
    }
    if prepared_pipe_present {
        WfpPlan::ChainHandshake
    } else {
        WfpPlan::Denied(WfpUnavailable::ChainLaunchPipeMissing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全バリアントの一覧。**`match`を1つ置いてあるのは網羅性のコンパイル時ゲート**で、
    /// バリアントを足すとこの関数がビルドエラーになり、一覧への追加を強制できる
    /// （テストの一覧は型で守られないので、ゲートが無いと足し忘れが無言で通る）。
    fn all_unavailable_paths() -> Vec<WfpUnavailable> {
        let all = vec![
            WfpUnavailable::SessionProxyNotStarted,
            WfpUnavailable::ChainLaunchHandshakeFailed("boom".to_string()),
            WfpUnavailable::ChainLaunchPipeMissing,
            WfpUnavailable::DirectStartFailed("boom".to_string()),
        ];
        for path in &all {
            match path {
                WfpUnavailable::SessionProxyNotStarted
                | WfpUnavailable::ChainLaunchHandshakeFailed(_)
                | WfpUnavailable::ChainLaunchPipeMissing
                | WfpUnavailable::DirectStartFailed(_) => {}
            }
        }
        all
    }

    /// 許可側の検証（`B-35`）: 拒否が確定した経路は**必ず**帰結を宣言する。
    /// 機構が完全に死んで（＝どの経路も何も出さなくなって）いれば落ちる。
    #[test]
    fn every_unavailable_path_declares_the_capability_denial() {
        for path in all_unavailable_paths() {
            let warning = path.warning();
            assert!(
                warning.contains(TIER2A_NET_DENIED),
                "{path:?} の警告が帰結を宣言していない: {warning}"
            );
            assert!(
                warning.starts_with("warning: "),
                "{path:?} の警告に接頭辞が無い: {warning}"
            );
        }
    }

    /// 経路の取り違え検出（BUG-056型）: 4経路が同じ文言なら、フォールト注入が意図と違う
    /// 経路へ落ちてもstderrからは区別できない。前半が経路ごとに異なることを固定する。
    #[test]
    fn each_unavailable_path_is_identifiable_from_stderr_alone() {
        let warnings: Vec<String> = all_unavailable_paths()
            .iter()
            .map(WfpUnavailable::warning)
            .collect();
        for (i, a) in warnings.iter().enumerate() {
            for (j, b) in warnings.iter().enumerate() {
                assert!(i == j || a != b, "経路{i}と経路{j}の警告が同一: {a}");
            }
        }
        // E2E・調査で実際に使っている識別句を名指しで固定する。
        assert!(WfpUnavailable::SessionProxyNotStarted
            .warning()
            .contains("session-scoped local proxy did not start"));
        assert!(WfpUnavailable::ChainLaunchHandshakeFailed("e".into())
            .warning()
            .contains("chain-launch handshake failed"));
        assert!(WfpUnavailable::ChainLaunchPipeMissing
            .warning()
            .contains("prepared pipe is missing"));
        assert!(WfpUnavailable::DirectStartFailed("e".into())
            .warning()
            .contains("failed to start WFP netfilterd"));
    }

    /// 原因（daemonからのエラー）が握り潰されず末尾に載ることを固定する。case 10 は
    /// `daemon rejected the request:` という**daemon側の文言**を検査しているので、ここが
    /// 落ちるとE2Eが「起動失敗」と「daemonが拒否」を区別できなくなる。
    #[test]
    fn the_underlying_error_is_carried_into_the_warning() {
        assert!(WfpUnavailable::ChainLaunchHandshakeFailed(
            "daemon rejected the request: nope".to_string()
        )
        .warning()
        .ends_with("daemon rejected the request: nope"));
        assert!(
            WfpUnavailable::DirectStartFailed("daemon rejected the request: nope".to_string())
                .warning()
                .ends_with("daemon rejected the request: nope")
        );
    }

    /// E2Eが直書きしている検査文字列との契約（`B-05`）。ここを縮めると
    /// `tier2a_smb445_layer2`の**不在**チェックが常に成立してしまい、拒否経路を通っていても
    /// 気付けなくなる。
    #[test]
    fn the_e2e_needle_is_a_prefix_of_the_declaration() {
        assert!(
            TIER2A_NET_DENIED.starts_with(E2E_CONTRACT_NEEDLE),
            "E2E（tier2a_e2e.rs）が検査する句が宣言文の接頭辞でなくなった"
        );
    }

    /// 誤検知してはならない入力（問4）: WFPを要求していない組み合わせでは**何も宣言しない**。
    /// 他の3フラグがどうであってもこれは変わらない。
    #[test]
    fn not_requesting_wfp_never_declares_a_denial() {
        for chain in [false, true] {
            for pipe in [false, true] {
                for proxy in [false, true] {
                    assert_eq!(
                        plan_wfp(false, proxy, chain, pipe),
                        WfpPlan::NotNeeded,
                        "tier2a_domain_policy=false なのに拒否を宣言した \
                         (proxy={proxy}, chain={chain}, pipe={pipe})"
                    );
                }
            }
        }
    }

    /// 経路選択の真理値表。`run_agent.rs`の`if`の入れ子をそのまま写したものではなく、
    /// **期待する結果**を独立に書き下してある。
    #[test]
    fn plan_covers_every_combination_of_the_startup_facts() {
        let cases = [
            // (tier2a_domain_policy, proxy_ready, chain_attempted, pipe_present) => plan
            (
                (true, false, false, false),
                WfpPlan::Denied(WfpUnavailable::SessionProxyNotStarted),
            ),
            (
                (true, false, true, true),
                WfpPlan::Denied(WfpUnavailable::SessionProxyNotStarted),
            ),
            ((true, true, false, false), WfpPlan::DirectStart),
            // シナリオ(B)は投機的パイプの有無に依存しない（start が自前で作る）。
            ((true, true, false, true), WfpPlan::DirectStart),
            ((true, true, true, true), WfpPlan::ChainHandshake),
            (
                (true, true, true, false),
                WfpPlan::Denied(WfpUnavailable::ChainLaunchPipeMissing),
            ),
        ];
        for ((tier2a, proxy, chain, pipe), expected) in cases {
            assert_eq!(
                plan_wfp(tier2a, proxy, chain, pipe),
                expected,
                "tier2a={tier2a}, proxy={proxy}, chain={chain}, pipe={pipe}"
            );
        }
    }

    /// `NotNeeded`だけが「警告を持たない計画」であることを固定する。ここが崩れると、
    /// 拒否が確定しているのに黙る経路（BUG-111で塞いだ`None => None`と同型）が復活する。
    #[test]
    fn every_plan_other_than_not_needed_either_acts_or_explains() {
        for tier2a in [false, true] {
            for proxy in [false, true] {
                for chain in [false, true] {
                    for pipe in [false, true] {
                        match plan_wfp(tier2a, proxy, chain, pipe) {
                            WfpPlan::NotNeeded => assert!(!tier2a),
                            WfpPlan::Denied(path) => assert!(
                                path.warning().contains(TIER2A_NET_DENIED),
                                "拒否が確定しているのに帰結を宣言しない計画がある"
                            ),
                            // 実行してみる計画。結末は実行後に`Denied`と同じ型で説明される。
                            WfpPlan::ChainHandshake | WfpPlan::DirectStart => assert!(tier2a),
                        }
                    }
                }
            }
        }
    }
}
