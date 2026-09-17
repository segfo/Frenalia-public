//! [段階6e] 「このドメインから、いま何を起こせるか」の一覧
//! （`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.8）。
//!
//! # 何のためにあるのか
//!
//! 遷移の宣言は「どのプログラムがどのプログラムを起こしてよいか」を定めるが、**その内容は
//! 起こす側からは見えない**。モデルは`git`を起こせるのかどうかを、撃って拒否されるまで知れない。
//! そこで**引かれたら答える**（pull）ための一覧をここで作る。
//!
//! # ここが「判定・整形・並べ替え」の唯一の実装である
//!
//! 同じ一覧を**2つの読み手**が使う——モデル（`can_run_program`ツール）と、
//! ポリシーエディタの遷移画面（段階⑦。まだ無い）。**2つ作ると、モデルに見えるものと
//! ユーザーに見えるものがずれる**（§19.3.8）。だから純粋なこのクレートに置き、
//! 表示の都合（ページング・文面）だけを呼び出し側に持たせる。
//!
//! # LLMを1本も呼ばない
//!
//! 並べ替えは**決定的な関数**（打とうとした名前との近さ→宣言順）である。理由は§19.3.8が
//! 2つ挙げている——(a) 意図を知らないLLMが、意図を知っているLLMのために並べ替えることになる、
//! (b) この処理が乗るのは**コマンドが失敗した直後＝ユーザーが待っている最悪の場所**である。
//!
//! **同義語の辞書も持たない。** `svn`≈`git`という知識は消費者であるモデルが既に持っており、
//! 欠けているのは「いま何が使えるか」という事実だけだからである。

use crate::transition::{ArgvMatcher, ExeMatcher, GraphError, GraphInput};

/// 一覧の1行＝辺1本。
///
/// **宣言の綴りをそのまま運ぶ。** 畳んだ値（比較用に正規化したもの）を出すと、
/// モデルが見る綴りと`policy.json`に書いてある綴りが食い違う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// 実行ファイルの照合（`literal`はその値、`pattern`はパターン）。
    pub exe: String,
    /// 実行ファイルの照合がパターンか（読む側が「そのまま打てる名前」と誤解しないため）。
    pub exe_is_pattern: bool,
    /// argvの照合。`any`（任意のargvを許す）は[`ANY_ARGV`]。
    pub argv: String,
    pub argv_is_pattern: bool,
    /// 遷移先ドメイン名。
    pub to_domain: String,
    /// 遷移先から**到達できる範囲**の権限の要約（§19.3.4の到達閉包）。
    ///
    /// **直接の宣言だけでは足りない**——「このプログラムを起こすと何ができるようになるか」が
    /// この欄の問いなので、そこから先へ渡っていける範囲まで数える。
    pub rights: Rights,
    /// **いま実際に起こせるか。**
    ///
    /// `false`は「宣言は正しいが、harness側がまだ実装していない」を意味する
    /// （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2の暫定。遷移先が別ドメインの辺は
    /// そのドメインの実体を作る機構が無いので起こせない）。
    ///
    /// **この欄を落とすとモデルへ嘘を言うことになる**——一覧に出ているのに撃つと拒否される。
    pub runnable_now: bool,
}

/// argvを問わない辺の綴り。**`policy.json`の`{"any": true}`に対応する**。
pub const ANY_ARGV: &str = "(any arguments)";

/// 1つのドメインから到達できる範囲の権限（§19.3.4）。
///
/// **件数ではなく中身を持つ。** 「3件」と言われてもモデルは判断できない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rights {
    /// `(パス, アクセス種別)`。種別は`read`/`read_write`/`read_exec`の設定キー名。
    pub fs: Vec<(String, &'static str)>,
    /// 通信を許された宛先。
    pub net: Vec<String>,
}

impl Rights {
    pub fn is_empty(&self) -> bool {
        self.fs.is_empty() && self.net.is_empty()
    }
}

/// `from_domain`から宣言されている辺を、**宣言順のまま**並べる。
///
/// 並べ替えと絞り込みは呼び出し側が[`match_rank`]で行う——**一覧を作る責任と、
/// 問い合わせに応じて並べ替える責任を分ける**（エディタは問い合わせを持たない）。
///
/// 宣言されていないドメイン名を渡したときは**空を返す**。これは「辺が0本」と同じ扱いで、
/// 区別が要る呼び出し側は[`GraphInput::domains`]を自分で見ること。
pub fn rows(input: &GraphInput<'_>, from_domain: &str) -> Result<Vec<Row>, GraphError> {
    let Some(view) = input.domains.iter().find(|d| d.name == from_domain) else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::with_capacity(view.process.transitions.len());
    for edge in &view.process.transitions {
        let (exe, exe_is_pattern) = match &edge.exe {
            ExeMatcher::Literal(value) => (value.clone(), false),
            ExeMatcher::Pattern(pattern) => (pattern.clone(), true),
        };
        let (argv, argv_is_pattern) = match &edge.argv {
            ArgvMatcher::Literal(value) => (value.clone(), false),
            ArgvMatcher::Pattern(pattern) => (pattern.clone(), true),
            ArgvMatcher::Any(_) => (ANY_ARGV.to_string(), false),
        };
        rows.push(Row {
            exe,
            exe_is_pattern,
            argv,
            argv_is_pattern,
            to_domain: edge.to.clone(),
            rights: crate::transition::rights_summary(input, &edge.to)?,
            // **暫定**（§10.1.2の撤去一覧5点目）。§22.9が着地したら常に`true`になる。
            runnable_now: edge.to == from_domain,
        });
    }
    Ok(rows)
}

/// 問い合わせとの近さ。**小さいほど近い**（並べ替えの鍵にそのまま使える）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// 実行ファイル名（末尾の要素）が問い合わせと一致した。
    ExactName,
    /// 実行ファイルのパスが問い合わせで始まる／末尾の要素が問い合わせで始まる。
    PrefixName,
    /// どこかに含まれている（argvを含む）。
    Contains,
}

/// この行は問い合わせに当たるか。当たらなければ`None`（＝一覧から落とす）。
///
/// **大文字小文字を区別しない。** Windowsのパスは綴りが揺れるので、区別すると
/// `Git.exe`と打ったモデルに「無い」と答えることになる。
///
/// **同義語は見ない**（モジュールdoc）。見るのは打たれた文字そのものだけである。
pub fn match_rank(query: &str, row: &Row) -> Option<Rank> {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        // 問い合わせが空なら全部当たる（一覧として使う形）。**宣言順を崩さない**ために
        // 最も近い順位を返す——順位で並べ替えても、全行が同じ順位なら安定ソートが順序を保つ。
        return Some(Rank::ExactName);
    }
    let exe = row.exe.to_ascii_lowercase();
    let leaf = exe
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe.as_str())
        .to_string();

    if leaf == query || leaf.strip_suffix(".exe") == Some(query.as_str()) {
        return Some(Rank::ExactName);
    }
    if leaf.starts_with(&query) || exe.starts_with(&query) {
        return Some(Rank::PrefixName);
    }
    if exe.contains(&query) || row.argv.to_ascii_lowercase().contains(&query) {
        return Some(Rank::Contains);
    }
    None
}

/// 問い合わせで絞り、近い順に並べる。**同じ近さの行は宣言順のまま**（安定ソート）。
///
/// 問い合わせが空なら**全行を宣言順で**返す。
pub fn filter_and_rank(rows: Vec<Row>, query: &str) -> Vec<Row> {
    let mut ranked: Vec<(Rank, Row)> = rows
        .into_iter()
        .filter_map(|row| match_rank(query, &row).map(|rank| (rank, row)))
        .collect();
    // `sort_by_key`は安定ソートなので、同順位は元の順（＝宣言順）が保たれる。
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked.into_iter().map(|(_, row)| row).collect()
}

#[cfg(test)]
#[path = "transition_listing_tests.rs"]
mod transition_listing_tests;
