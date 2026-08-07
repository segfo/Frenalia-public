//! 構造化作業記憶（Evidence Ledger）のデータ構造。`plans/DESIGN-COGNITION.md` §3.1。
//!
//! ここは**純粋なデータ**で、ファイルにもネットワークにも触れない。生出力の退避は
//! [`crate::scratch`]、レンダリングは[`super::render`]が持つ。
//!
//! 妥当性評価（`Validity`・`Grade`・`evidence_strength`）は[`super::validity`]が持つ。
//! 型をこちらへ混ぜないのは、あちらが**判定規則**（§4.3を機械規則へ写したもの）を
//! 伴うためで、ここは規則を持たない素のデータに保つ。

use serde::{Deserialize, Serialize};

use super::validity::Validity;

/// 台帳内のIDは**追記順の連番**で、`WorkingMemory`だけが採番する。
/// 外から作れないようにフィールドを非公開にし、「台帳に存在しないIDを参照する」状態を
/// 構造的に作りにくくしている。
macro_rules! ledger_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub(crate) u32);

        impl $name {
            /// 表示・レンダリング用の短い識別子（`H1`・`E3`等）。
            pub fn label(self) -> String {
                format!("{}{}", $prefix, self.0)
            }

            /// [`Self::label`]の逆変換。`LedgerView::render_slice`が受け取る
            /// `target: Option<&str>`／`goal: Option<&str>`を型付きIDへ戻すためのもの。
            pub fn parse(s: &str) -> Option<Self> {
                s.strip_prefix($prefix)?.parse::<u32>().ok().map(Self)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.label())
            }
        }
    };
}

ledger_id!(
    /// ゴール識別子。
    GoalId,
    "G"
);
ledger_id!(
    /// 仮説識別子。
    HypId,
    "H"
);
ledger_id!(
    /// 証拠識別子。
    EvidenceId,
    "E"
);

/// ゴールの状態（§3.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalStatus {
    Open,
    Achieved,
    Blocked,
    Abandoned,
}

/// 何を達成したいか（ユーザ発話、またはPlannerが分解したサブゴール）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Goal {
    pub id: GoalId,
    pub statement: String,
    pub status: GoalStatus,
    /// 完了条件。検証可能な形で書く。
    pub done_criteria: Vec<String>,
}

/// 仮説の状態（§3.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypStatus {
    Proposed,
    Investigating,
    Confirmed,
    Refuted,
    Inconclusive,
}

impl HypStatus {
    /// 台帳スライスから真っ先に落としてよい（決着済みで、かつ支持されなかった）状態か。
    /// 予算超過時の縮約順序（[`crate::context`]）に使う。
    pub fn is_discardable(self) -> bool {
        matches!(self, HypStatus::Refuted)
    }
}

/// 「原因はX」「この方法で解決する」等の検証対象。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypId,
    pub goal: GoalId,
    pub statement: String,
    pub status: HypStatus,
    /// **調査の優先順位付け専用**（§3.4）。自己申告値は無較正でモデル層を跨ぐと別物なので、
    /// `Confirmed`への遷移ゲートにも表示にも使わない。
    pub confidence: f32,
    /// 反証条件。「何が見えれば偽か」。ここが空の仮説はM15のスキーマ検証で弾かれる。
    pub predicts: Vec<String>,
    pub supporting: Vec<EvidenceId>,
    pub refuting: Vec<EvidenceId>,
}

/// [`SourceRef`]の種別だけを取り出したもの。§4.2のCrossSource判定（「別種のソースで
/// 裏取りできているか」）は中身ではなく種別の異同で決まるので、比較用にこれを使う。
///
/// `Ord`を導出するのは集合（`BTreeSet`）に入れるため。順序自体に意味は無く、
/// 「どの種別で裏取りできたか」を決定的に列挙するための道具でしかない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    File,
    Shell,
    Web,
    Mcp,
    Memory,
    ModelPrior,
}

impl SourceKind {
    /// §3.4【E1】の接地種別か。`Confirmed`へ上げるにはこのいずれかが1件以上要る
    /// ——`ModelPrior`単独はもちろん、`Web`単独でも確証にしない。
    pub fn is_grounding(self) -> bool {
        matches!(self, SourceKind::File | SourceKind::Shell | SourceKind::Mcp)
    }
}

/// 証拠がどこから来たか（§4.2）。`ModelPrior`が最弱で、単独では`Confirmed`の根拠にできない
/// （§4.3の接地必須ルール。機械チェックは`crate::hiv::HivEngine::can_confirm`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRef {
    File {
        path: String,
        lines: (u32, u32),
    },
    Shell {
        cmd: String,
        exit: i32,
    },
    Web {
        url: String,
        fetched_at: String,
    },
    Mcp {
        server: String,
        tool: String,
        args_digest: String,
    },
    Memory {
        note_id: String,
        /// 注入時点で`reviewed.json`のウォーターマークより新しかったか（`plans/PLAN-RECALL-MEMORY.md`
        /// 「未レビュー表記」）。**正本は常に`reviewed.json`**——ここは注入時点の判定結果の
        /// 写しでしかない（`bug-pattern-rules` B-13、同じ事実の正本を2つ持たない）。
        reviewed: bool,
    },
    /// モデルの内部知識。必ず裏取りの対象になる。
    ModelPrior,
}

impl SourceRef {
    /// レンダリング用の1行表現。
    pub fn describe(&self) -> String {
        match self {
            // `(0, 0)`は「ファイル全体」（行範囲が分からない観測）。`path:0-0`と出すと
            // 存在しない行を指しているように読めるので、範囲ごと省く。
            SourceRef::File { path, lines } if *lines == (0, 0) => path.clone(),
            SourceRef::File { path, lines } => format!("{path}:{}-{}", lines.0, lines.1),
            SourceRef::Shell { cmd, exit } => format!("shell `{cmd}` (exit {exit})"),
            SourceRef::Web { url, fetched_at } => format!("{url} ({fetched_at})"),
            SourceRef::Mcp { server, tool, .. } => format!("mcp/{server}/{tool}"),
            SourceRef::Memory { note_id, reviewed } => {
                if *reviewed {
                    format!("memory/{note_id}")
                } else {
                    format!("memory/{note_id}（未レビュー）")
                }
            }
            SourceRef::ModelPrior => "model prior (要裏取り)".to_string(),
        }
    }

    /// 一次証拠（ワークスペースの実ファイル・shell観測）か。§4.2の接地優先順位で
    /// 最上位に来る種別。`Mcp`は「一次で得た主張の裏取り」の位置なのでここには入らない
    /// （`Confirmed`遷移が要求する接地の下限は[`SourceKind::is_grounding`]の方）。
    pub fn is_primary(&self) -> bool {
        matches!(self, SourceRef::File { .. } | SourceRef::Shell { .. })
    }

    /// 種別だけを取り出す（§4.2のCrossSource判定用）。
    pub fn kind(&self) -> SourceKind {
        match self {
            SourceRef::File { .. } => SourceKind::File,
            SourceRef::Shell { .. } => SourceKind::Shell,
            SourceRef::Web { .. } => SourceKind::Web,
            SourceRef::Mcp { .. } => SourceKind::Mcp,
            SourceRef::Memory { .. } => SourceKind::Memory,
            SourceRef::ModelPrior => SourceKind::ModelPrior,
        }
    }
}

/// 生出力へのポインタ（§6.3）。台帳は**生出力を持たず**、これだけを持つ。
/// 実体は[`crate::scratch::ScratchStore`]配下のファイル。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRef {
    /// 退避元のツール呼び出しID（scratch内のファイル名にもなる）。
    pub tool_call_id: String,
    /// 退避した生出力の文字数。台帳を見るだけで「展開したらどれだけ膨らむか」が分かる。
    pub chars: usize,
}

/// 蒸留された1事実（生出力ではない、§6.2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    /// 数百トークンに蒸留された主張。ここに生出力を入れてはならない。
    pub claim: String,
    pub source: SourceRef,
    /// 妥当性評価（§4.3）。`trust`/`freshness`は積む時点で情報源カタログが決め、
    /// `grade`/`conflicts`は台帳が変異のたびに再計算する（[`super::validity`]のdoc参照）。
    pub validity: Validity,
    /// 生出力へのポインタ。`None`は生出力を持たない証拠（長期記憶ノート等）。
    pub raw_ref: Option<RawRef>,
}

/// 検証手段（§3.1）。`Investigate`の`plan[].source`から決まる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMethod {
    ReRead,
    RunTest,
    TypeCheck,
    CrossSource,
    CriticReview,
}

/// 検証の結論（§3.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Confirms,
    Refutes,
    Inconclusive,
}

/// 1回の検証の結果（§3.1）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verification {
    pub hyp: HypId,
    pub method: VerifyMethod,
    pub verdict: Verdict,
    /// 【E15】まだ不足している観測。
    pub missing: Vec<String>,
    pub note: String,
}

/// 確証済み仮説に基づいて決めた行動（§3.1）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub goal: GoalId,
    pub action: String,
    pub based_on: Vec<HypId>,
    /// その行動が効いたかをどう確かめるか（§3.3 Decideの`then_verify`）。
    ///
    /// §3.1の`Decision`には無いフィールドだが、ここで捨てるとDecideに出させた
    /// 「確認方法」が台帳にも最終回答にも残らない（M15での追加）。実際に確認まで
    /// 走らせるのはM19/M20の再検証ループで、M15は提示するだけ。
    pub verify_hint: Option<String>,
}

/// 決着できず、ユーザへ返す（または調査が要る）問い（§3.1・§3.5）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenQuestion {
    pub text: String,
    /// `true`ならこれが解けるまで先へ進めない（headlessは`NeedsInput`で停止、M20）。
    pub blocking: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_render_as_short_labels() {
        assert_eq!(HypId(3).label(), "H3");
        assert_eq!(EvidenceId(12).to_string(), "E12");
        assert_eq!(GoalId(1).to_string(), "G1");
    }

    #[test]
    fn primary_sources_are_workspace_files_and_shell_observations() {
        assert!(SourceRef::File {
            path: "src/lib.rs".into(),
            lines: (1, 10)
        }
        .is_primary());
        assert!(SourceRef::Shell {
            cmd: "cargo test".into(),
            exit: 1
        }
        .is_primary());
        // web/MCP/memory/model priorは一次証拠ではない（§4.2の接地優先順位）。
        assert!(!SourceRef::Web {
            url: "https://example.com".into(),
            fetched_at: "2026-08-03".into()
        }
        .is_primary());
        assert!(!SourceRef::ModelPrior.is_primary());
    }

    #[test]
    fn source_ref_describes_itself_in_one_line() {
        let s = SourceRef::File {
            path: "src/turn.rs".into(),
            lines: (40, 52),
        };
        assert_eq!(s.describe(), "src/turn.rs:40-52");
        assert!(!s.describe().contains('\n'));
    }

    /// §3.4【E1】の接地種別の下限。`Web`/`Memory`/`ModelPrior`は接地にならない。
    #[test]
    fn only_file_shell_and_mcp_kinds_count_as_grounding() {
        for kind in [SourceKind::File, SourceKind::Shell, SourceKind::Mcp] {
            assert!(kind.is_grounding(), "{kind:?}");
        }
        for kind in [SourceKind::Web, SourceKind::Memory, SourceKind::ModelPrior] {
            assert!(!kind.is_grounding(), "{kind:?}");
        }
    }

    /// `kind()`が全バリアントを写していること（`SourceRef`にバリアントを足すと落ちる）。
    #[test]
    fn every_source_ref_maps_to_its_kind() {
        let cases = [
            (
                SourceRef::File {
                    path: "a".into(),
                    lines: (0, 0),
                },
                SourceKind::File,
            ),
            (
                SourceRef::Shell {
                    cmd: "ls".into(),
                    exit: 0,
                },
                SourceKind::Shell,
            ),
            (
                SourceRef::Web {
                    url: "https://example.com".into(),
                    fetched_at: "0".into(),
                },
                SourceKind::Web,
            ),
            (
                SourceRef::Mcp {
                    server: "docs".into(),
                    tool: "search".into(),
                    args_digest: "d".into(),
                },
                SourceKind::Mcp,
            ),
            (
                SourceRef::Memory {
                    note_id: "n".into(),
                    reviewed: true,
                },
                SourceKind::Memory,
            ),
            (SourceRef::ModelPrior, SourceKind::ModelPrior),
        ];
        for (source, kind) in cases {
            assert_eq!(source.kind(), kind, "{source:?}");
        }
    }

    /// 行範囲が分からない観測（ファイル全体）は範囲を出さない。
    #[test]
    fn a_whole_file_source_renders_without_a_line_range() {
        let s = SourceRef::File {
            path: "src/turn.rs".into(),
            lines: (0, 0),
        };
        assert_eq!(s.describe(), "src/turn.rs");
    }
}
