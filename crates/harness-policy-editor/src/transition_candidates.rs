//! [段階⑦] 観測と拒否を**遷移の辺の候補**にする（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定62・63）。
//!
//! # 何のためにあるのか
//!
//! 「このプログラムが何を起こしてよいか」は、**まだ何も禁じていない状態で1回走らせて観測する**か、
//! **禁じた状態で断られたものを見る**かのどちらかでしか分からない。前者は`observed.jsonl`、
//! 後者は`pending.jsonl`が持つ。ここはその2つを、**同じ形の1行**へ寄せる。
//!
//! 寄せるのは、**ユーザーがやることが同じ**だからである——選んで、許す。出どころが違うだけで
//! 操作系を2つ作ると、同じ処理が2箇所に生える（`docs/CODE-STRUCTURE-RULES.md`規則5.1）。
//!
//! # 「もう宣言済みか」は自分で判定しない
//!
//! 判定は[`harness_policy::transition::TransitionGraph::resolve`]——**Spawn Daemonが実際に
//! 使うのと同じ判定器**——に聞く。ここで「exeの綴りが同じなら宣言済み」のような独自判定を
//! 書くと、**画面が「宣言済み」と言っているのに撃つと断られる**という食い違いが起きる
//! （`B-13`: 正本を2つ持たない）。
//!
//! # 「解決済み」を待ち行列へ書き戻さない
//!
//! 承認しても`pending.jsonl`は書き換えない。突き合わせは**読む側が毎回計算する**
//! （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2）。書き戻すと正本が2つになり、しかも
//! 昇格側が書いたファイルを非特権側が書き換える経路ができる。
//!
//! # ここが持たないもの
//!
//! - **宣言済みの辺の一覧そのもの**（表示・並べ替え）。[`harness_policy::transition_listing`]が持つ
//!   ——モデルの`can_run_program`と同じものを画面も通す（§19.3.8）
//! - **辺をどう組み立てて書くか**。[`crate::transition_approve`]が持つ
//! - **画面の文言とキー割り当て**。`tui::transition`が持つ

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_policy::policy_file::PolicyFile;
use harness_policy::transition::{
    ArgvMatcher, ExeMatcher, GraphError, Resolution, SpawnAttempt, TransitionDenial,
    TransitionEdge, TransitionGraph,
};
use harness_policy::transition_listing::{self, Row};
use harness_sandbox::tier2a::policy_learnd::observed::ObservedRecord;
use harness_sandbox::tier2a::spawnd::transitions::{remedy, PendingRecord, Remedy};

use crate::transition_approve::{ArgvChoice, EdgeRef};

/// 候補1行＝**辺1本の提案**。
///
/// **観測された綴りをそのまま運ぶ。** 比較用に畳んだ値を出すと、画面に出る綴りと
/// `policy.json`へ書かれる綴りが食い違う（[`Row`]が同じ理由で同じことをしている）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// 起きた（起きようとした）実行ファイルのフルパス。
    pub exe: String,
    /// そのときのコマンドライン。
    pub argv: String,
    /// この種類が観測された回数。**拒否の回数ではなく種類ごとの回数**である。
    pub count: u64,
    pub last_ts: u64,
    /// argvが切り詰められている疑い。
    ///
    /// **真ならリテラルのargvで宣言してはならない**（`plans/DESIGN-MAC.md` §5.1(6)）。
    /// 切れた値をそのまま書くと、二度と一致しない辺ができる。
    pub argv_truncation: bool,
    pub source: Source,
    /// いまの`policy.json`から見て、この生成はどう扱われるか。
    pub declared: Declared,
    /// **この綴りは、宣言したとして実際に起こせるのか。**
    ///
    /// 宣言の可否とは別軸である——宣言は書けるが、OSの都合で起こせない綴りがある。
    /// **画面はこれを出すこと**。出さないと「宣言済み」と表示したものが撃つと断られる。
    pub startable: Startable,
}

/// その綴りを、生成禁止を積んだ構成で**実際に起こせるか**。
///
/// # なぜ宣言を止めないのか
///
/// 止めると、ユーザーが「なぜこの行だけ選べないのか」を画面から知れない。**書けるが通らない**
/// ことを見えるところへ出して、判断はユーザーに残す（D-42と同じ姿勢）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Startable {
    /// 分かっている範囲で起こせる。**「必ず起こせる」の保証ではない**——ここが見ているのは
    /// 綴りの形だけで、実際の失敗（ファイルが消えた等）は撃つまで分からない（`P-11`）。
    AsFarAsWeKnow,
    /// **アプリの仕組みを通る綴りなので起こせない**（ストアの実行エイリアス／MSIXの実体）。
    ///
    /// 判定は`harness_sandbox`の`starts_through_the_app_model`——
    /// **シェルの候補を選ぶのと同じ関数**である（2026-09-18に実測、`plans/mac-spike/RESULTS.md` §S62）。
    NotThroughTheAppModel,
}

impl Startable {
    /// 綴りから判定する。**候補の行が無い場面（確定の直前）でも引けるように公開している**
    /// ——書く直前にもう一度言うのは、そこが取り消しの効かない操作だからである。
    pub fn of(exe: &str) -> Self {
        if harness_sandbox::tier2a::win_appcontainer::starts_through_the_app_model(exe) {
            Startable::NotThroughTheAppModel
        } else {
            Startable::AsFarAsWeKnow
        }
    }

    /// 画面と確認ダイアログに出す一言。**`None`は「言うことが無い」。**
    pub fn note(self) -> Option<&'static str> {
        match self {
            Startable::AsFarAsWeKnow => None,
            Startable::NotThroughTheAppModel => Some(
                "この綴りはストアアプリの仕組みを通って起きるので、\
                 遷移の強制を積んだ構成では起こせません（実測）",
            ),
        }
    }
}

/// この候補がどこから来たか。**画面の見出しを分けるためと、拒否側だけに出す注記のため。**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// パス1の観測（`observed.jsonl`）。**隔離していないので遷移元ドメインが無い**ので、
    /// 代わりに起こした側の実行ファイルが分かることがある（§10.3）。
    Observed { parent_exe: Option<String> },
    /// 拒否の待ち行列（`pending.jsonl`）。
    Denied {
        /// 呼び出し元のドメイン。**`None`は観測していない**（カーネル拒否では取れない）。
        from_domain: Option<String>,
        /// OSカーネルが止めたものか（`false`はSpawn Daemonが断ったもの）。
        by_kernel: bool,
    },
}

/// いまの宣言から見た、この候補の扱い。
///
/// # なぜ真偽値1つにしないのか
///
/// 「宣言されていない」と「宣言はあるが別の理由で通らない」は、**ユーザーが次にやることが
/// 違う**。1つに潰すと、cwdが違うだけの辺に対して「宣言を足せ」と言うことになり、
/// 足しても直らない（`P-11`: 区別できるものを既定値へ潰さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Declared {
    /// 宣言が無い。**承認の対象はこれだけである。**
    No,
    /// この綴りそのものを宣言した辺がある。**`[x]`を重ね、外せば消える対象。**
    ByThisEdge {
        /// 宣言に書かれているargvの照合方法。**そのまま取り消しの指定
        /// （[`crate::transition_approve::EdgeRef`]）に使える形で持つ**
        /// ——表示用の文字列に潰すと、`(any arguments)`という綴りのリテラルと
        /// 「任意の引数」が区別できなくなる。
        argv: ArgvChoice,
        to_domain: String,
        /// **いま実際に起こせるか。** 判定は[`transition_listing`]が唯一の実装
        /// （モデルへ見せている値と同じもの）。
        runnable_now: bool,
    },
    /// パターンの辺が覆っている。**`[x]`にしない。**
    ///
    /// 外すとパターンごと消え、**この行に見えていない他のプログラムの許可も一緒に消える**
    /// ——外したときに消えるものが行の見た目と一致しない
    /// （FS側の`covering_fs_declaration`が同じ理由で同じ扱いにしている）。
    ByAPattern {
        exe: String,
        argv: String,
        to_domain: String,
    },
    /// 辺はあるが、宣言された作業ディレクトリと実際が違う。**宣言を足しても直らない。**
    CwdMismatch { declared: String },
    /// パターンの辺が2本以上一致した。**どちらの権限を与えるか決められないので拒否される。**
    Ambiguous { matched: usize },
    /// 遷移元ドメインがそもそも宣言されていない（まだ1件も承認していない状態）。
    UnknownSourceDomain,
}

impl Candidate {
    /// 承認の対象になり得るか（**まだ宣言が無いものだけ**）。
    pub fn is_approvable(&self) -> bool {
        matches!(self.declared, Declared::No | Declared::UnknownSourceDomain)
    }

    /// 取り消しの対象になり得るか（**この綴りそのものの辺があるときだけ**）。
    pub fn is_removable(&self) -> bool {
        matches!(self.declared, Declared::ByThisEdge { .. })
    }

    /// **観測された引数だけを許す宣言にできるか。**
    ///
    /// 切り詰めの疑いがある観測は`false`——切れた値をそのまま書くと、
    /// **二度と一致しない辺**ができる（`plans/DESIGN-MAC.md` §5.1(6)）。
    /// 画面はこれが`false`の行で切り替えキーを効かせないこと。
    pub fn can_narrow_to_this_argv(&self) -> bool {
        !self.argv_truncation
    }

    /// 承認するときの辺の指定。
    ///
    /// `narrow_to_this_argv`が真なら**この引数のときだけ**許す辺になる。既定は任意の引数で、
    /// これは**観測より広い**——だから承認は常にユーザーの明示操作である（D-42）。
    pub fn approval_ref(&self, narrow_to_this_argv: bool) -> EdgeRef {
        let argv = if narrow_to_this_argv && self.can_narrow_to_this_argv() {
            ArgvChoice::Literal(self.argv.clone())
        } else {
            ArgvChoice::Any
        };
        EdgeRef {
            exe: self.exe.clone(),
            argv,
        }
    }

    /// 取り消すときの辺の指定。**宣言に書かれている照合方法で指す**
    /// ——画面に出ている引数ではなく、実際に消える辺の形である。
    pub fn removal_ref(&self) -> Option<EdgeRef> {
        match &self.declared {
            Declared::ByThisEdge { argv, .. } => Some(EdgeRef {
                exe: self.exe.clone(),
                argv: argv.clone(),
            }),
            _ => None,
        }
    }

    /// 実行ファイル名（末尾の要素）。**画面の見出しと並べ替えに使う。**
    pub fn exe_file_name(&self) -> &str {
        self.exe
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.exe)
    }
}

/// いま`policy.json`が宣言していること。**候補へ重ねるための入力。**
///
/// 判定器（[`TransitionGraph`]）と一覧（[`Row`]）の両方を持つ。前者は「通るか」を答え、
/// 後者は「どの辺か・いま起こせるか」を答える。**どちらも`harness-policy`の実装で、
/// ここで作り直さない。**
#[derive(Debug)]
pub struct DeclaredEdges {
    from_domain: String,
    graph: TransitionGraph,
    /// 宣言順の辺そのもの。`rows`と**同じ並び・同じ長さ**である（[`Self::build`]が確かめる）。
    edges: Vec<TransitionEdge>,
    rows: Vec<Row>,
}

impl DeclaredEdges {
    /// `policy.json`から組み立てる。
    ///
    /// `workspace_root`は、宣言の検査が「呼び出し元が書ける場所」を知るために要る（§19.1）。
    pub fn build(
        file: &PolicyFile,
        workspace_root: &str,
        from_domain: &str,
    ) -> Result<Self, GraphError> {
        let input = file.transition_graph_input(Some(workspace_root));
        let graph = TransitionGraph::build(&input)?;
        let rows = transition_listing::rows(&input, from_domain)?;
        let edges = file
            .domain(from_domain)
            .map(|d| d.process.transitions.clone())
            .unwrap_or_default();
        // **添字で対応付ける**ので、ずれていないことをここで確かめる。
        // `transition_listing::rows`は宣言順に1辺1行を積むので本来ずれないが、
        // ずれたまま進むと**別の辺の「いま起こせるか」を表示する**ことになる。
        debug_assert_eq!(edges.len(), rows.len(), "宣言と一覧の並びがずれている");
        Ok(Self {
            from_domain: from_domain.to_string(),
            graph,
            edges,
            rows,
        })
    }

    /// 宣言されている辺の一覧（画面の「宣言済み」表示用）。**整形はしない。**
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn from_domain(&self) -> &str {
        &self.from_domain
    }

    /// この`(exe, argv)`を、いまの宣言はどう扱うか。
    ///
    /// **`cwd`を渡していない。** この画面が作る辺はcwdを宣言しないので、実cwdが判定に効くのは
    /// 「手で書いたcwd付きの辺に当たったとき」だけである。その場合は
    /// [`Declared::CwdMismatch`]として**見えるところへ出す**——黙って「未宣言」にすると、
    /// 承認しても直らない行を承認させることになる。
    fn classify(&self, exe: &str, argv: &str) -> Declared {
        let resolution = self.graph.resolve(SpawnAttempt {
            from_domain: &self.from_domain,
            exe,
            command_line: argv,
            cwd: "",
        });
        match resolution {
            Resolution::Allowed(_) => self.identify(exe, argv),
            Resolution::Denied(TransitionDenial::NoMatchingEdge) => Declared::No,
            Resolution::Denied(TransitionDenial::UnknownSourceDomain) => {
                Declared::UnknownSourceDomain
            }
            Resolution::Denied(TransitionDenial::AmbiguousPattern { matched }) => {
                Declared::Ambiguous { matched }
            }
            Resolution::Denied(TransitionDenial::CwdMismatch { declared, .. }) => {
                Declared::CwdMismatch { declared }
            }
        }
    }

    /// 通ると分かった候補について、**どの辺のおかげで通るのか**を特定する。
    ///
    /// リテラルの辺（＝この綴りそのもの）なら取り消しの対象にできる。パターンなら**できない**
    /// ——外すと、この行に見えていない他のプログラムの許可も消えるためである。
    fn identify(&self, exe: &str, argv: &str) -> Declared {
        let exe_folded = fold_for_pattern_comparison(exe);
        let argv_folded = fold_for_pattern_comparison(argv);
        for (index, edge) in self.edges.iter().enumerate() {
            let ExeMatcher::Literal(declared_exe) = &edge.exe else {
                continue;
            };
            if fold_for_pattern_comparison(declared_exe) != exe_folded {
                continue;
            }
            let argv_choice = match &edge.argv {
                ArgvMatcher::Any(_) => ArgvChoice::Any,
                ArgvMatcher::Literal(value) => {
                    if fold_for_pattern_comparison(value) != argv_folded {
                        continue;
                    }
                    ArgvChoice::Literal(value.clone())
                }
                // パターンのargvは「この綴りそのもの」ではない（下の注記側へ落とす）。
                ArgvMatcher::Pattern(_) => continue,
            };
            return Declared::ByThisEdge {
                argv: argv_choice,
                to_domain: edge.to.clone(),
                // **`runnable_now`をここで計算しない。** 暫定の規則（別ドメインへは遷移できない）
                // の正本は`transition_listing`で、写すと§22.9が着地した日に片方だけ古くなる。
                runnable_now: self.rows.get(index).is_some_and(|row| row.runnable_now),
            };
        }
        // リテラルでは見つからない＝パターンの辺が覆っている。
        let covering = self
            .rows
            .iter()
            .find(|row| row.exe_is_pattern || row.argv_is_pattern);
        match covering {
            Some(row) => Declared::ByAPattern {
                exe: row.exe.clone(),
                argv: row.argv.clone(),
                to_domain: row.to_domain.clone(),
            },
            // 判定器は「通る」と言ったのに辺が見つからない。**黙って「未宣言」にしない**
            // ——承認させても同じ辺が二重にできるだけである。
            None => Declared::Ambiguous { matched: 0 },
        }
    }
}

/// 観測（`observed.jsonl`）を候補にする。
///
/// **あふれの行と、出どころの分からない行は候補にしない**（種類ではないため）。
/// あふれた件数は呼び出し側が[`harness_sandbox::tier2a::transitions_log::FoldedRead::dropped`]で
/// 受け取り、画面に出すこと（`B-10`）。
pub fn from_observations(records: &[ObservedRecord], declared: &DeclaredEdges) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = records
        .iter()
        .filter_map(|record| match record {
            ObservedRecord::ObservedSpawn(spawn) => Some(Candidate {
                declared: declared.classify(&spawn.exe, &spawn.argv),
                startable: Startable::of(&spawn.exe),
                exe: spawn.exe.clone(),
                argv: spawn.argv.clone(),
                count: spawn.count,
                last_ts: spawn.last_ts,
                argv_truncation: spawn.argv_truncation,
                source: Source::Observed {
                    parent_exe: spawn.parent_exe.clone(),
                },
            }),
            ObservedRecord::Overflowed { .. } => None,
        })
        .collect();
    sort_for_display(&mut out);
    out
}

/// 拒否（`pending.jsonl`）を候補にする。
///
/// **`NotAboutPolicy`の拒否は候補にしない。** 要求元が壊れていた・Daemonが呼び出し元を
/// 知らなかった類であり、宣言をどう書いても変わらない——出すと、直しようのない記録に
/// 「宣言を直せ」の顔をさせることになる（分類の正本は`spawnd::transitions::remedy`）。
///
/// **`BlockedUntilHarnessImplementsIt`は候補として残す。** 宣言は足りているが
/// harness側が未実装なもので、**ユーザーが直せない**という事実そのものを画面に出す必要がある。
pub fn from_denials(records: &[PendingRecord], declared: &DeclaredEdges) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = records
        .iter()
        .filter_map(|record| {
            let (by_kernel, denial) = match record {
                PendingRecord::DeniedByDaemon(denial) => (false, denial),
                PendingRecord::DeniedByKernel(denial) => (true, denial),
                PendingRecord::Overflowed { .. } => return None,
            };
            if remedy(&denial.reason) == Remedy::NotAboutPolicy {
                return None;
            }
            Some(Candidate {
                declared: declared.classify(&denial.exe, &denial.argv),
                startable: Startable::of(&denial.exe),
                exe: denial.exe.clone(),
                argv: denial.argv.clone(),
                count: denial.count,
                last_ts: denial.last_ts,
                argv_truncation: denial.argv_truncation,
                source: Source::Denied {
                    from_domain: denial.from_domain.clone(),
                    by_kernel,
                },
            })
        })
        .collect();
    sort_for_display(&mut out);
    out
}

/// 画面へ出す順に並べる。
///
/// **決定的であること自体が要件である**——読み直すたびに並びが変わると、
/// ユーザーが「さっき見ていた行」を見失う。ファイルに現れた順（＝観測の時刻順）は
/// **同じ内容でも実行ごとに変わる**ので使わない。
fn sort_for_display(candidates: &mut [Candidate]) {
    candidates.sort_by(|a, b| {
        let by_name = a
            .exe_file_name()
            .to_ascii_lowercase()
            .cmp(&b.exe_file_name().to_ascii_lowercase());
        by_name
            .then_with(|| {
                fold_for_pattern_comparison(&a.exe).cmp(&fold_for_pattern_comparison(&b.exe))
            })
            .then_with(|| a.argv.cmp(&b.argv))
    });
}

#[cfg(test)]
#[path = "transition_candidates_tests.rs"]
mod transition_candidates_tests;
