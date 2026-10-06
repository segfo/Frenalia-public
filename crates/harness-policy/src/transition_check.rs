//! 遷移の宣言に掛ける**編集時検査**（段階⑥a）。
//!
//! # なぜ判定器と別のファイルなのか
//!
//! 同じ宣言を見ているが、**問われる時点が違う**。[`super::TransitionGraph::resolve`]は
//! 子プロセスを起こそうとするたびに走る（Spawn Daemonの中、要求1件ごと）が、こちらは
//! **宣言を書くとき・読み込むときに1度だけ**走る。前者は速さと「答えを必ず返すこと」が要り、
//! 後者は**落ちた理由を人が読める文にすること**が要る。
//!
//! 規則の正本は`plans/DESIGN-MAC.md` §5.1・§19.1と
//! `plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3、パターン言語は
//! `plans/DESIGN-MAC-BROKER.md` §22.5。
//!
//! # ここで落としたものは、実行時には現れない
//!
//! [`super::TransitionGraph::build`]が検査を通らない宣言でグラフを作らないので、
//! **危険な辺が判定器へ届く経路が存在しない**。だから判定器の側に同じ検査を置いていない
//! （`bug-pattern-rules` B-05: 同じ規則を2箇所に書かない）。

use std::collections::BTreeMap;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_config::FsAccess;

use super::{
    build_anchored, is_fully_fixed, path_covered_by, ArgvMatcher, Direction, DomainView,
    ExeMatcher, GraphFacts, Rejection, TransitionEdge, MAX_DOMAIN_NAME_LEN,
};

impl GraphFacts<'_> {
    /// 全ドメインの全辺を検査する。
    pub(super) fn check_all(&self) -> Vec<Rejection> {
        let mut out = Vec::new();
        for view in &self.input.domains {
            let mut seen_literal: BTreeMap<(String, String), usize> = BTreeMap::new();
            for (index, edge) in view.process.transitions.iter().enumerate() {
                let mut reject = |reason: String| {
                    out.push(Rejection {
                        domain: view.name.to_string(),
                        edge_index: index,
                        reason,
                    })
                };
                for reason in self.check_edge(view, edge) {
                    reject(reason);
                }
                // 同じリテラルの組が2本あると、解決規則の段1が1本に定まらない。
                if let (ExeMatcher::Literal(exe), ArgvMatcher::Literal(argv)) =
                    (&edge.exe, &edge.argv)
                {
                    let key = (
                        fold_for_pattern_comparison(exe),
                        fold_for_pattern_comparison(argv),
                    );
                    if let Some(first) = seen_literal.insert(key, index) {
                        reject(format!(
                            "duplicates the literal edge at #{first}: the first resolution rule \
                             must pick exactly one edge, so two identical literal edges make the \
                             outcome depend on ordering"
                        ));
                    }
                }
            }
        }
        out
    }

    /// 辺1本に対する検査。落ちた理由をすべて返す（最初の1件で打ち切らない——
    /// 直すたびに次の理由が出てくる形にすると、編集の周回が理由の数だけ増える）。
    fn check_edge(&self, view: &DomainView<'_>, edge: &TransitionEdge) -> Vec<String> {
        let mut reasons = Vec::new();

        // (h) 遷移先ドメイン名（§19.3.14）。
        if let Err(reason) = check_domain_name(&edge.to) {
            reasons.push(reason);
        } else if !self.by_name.contains_key(edge.to.as_str()) {
            reasons.push(format!(
                "target domain {:?} is not declared; a transition to an undeclared domain would \
                 silently get the empty (and therefore always \"narrower\") rights of a typo",
                edge.to
            ));
        }

        // (a)(b)(c) 綴りの検査。
        match &edge.exe {
            ExeMatcher::Literal(value) => {
                if let Err(reason) = check_exe_literal(value) {
                    reasons.push(reason);
                }
            }
            ExeMatcher::Pattern(pattern) => {
                if let Err(reason) = check_pattern(pattern, "exe") {
                    reasons.push(reason);
                }
            }
        }
        if let ArgvMatcher::Pattern(pattern) = &edge.argv {
            if let Err(reason) = check_pattern(pattern, "argv") {
                reasons.push(reason);
            }
        }

        // (g) **実行ファイルの**パターンは「狭める／同値」の辺に限る（§19.3.5。決定66(7)で維持）。パターンが覆う場所に
        // 呼び出し元が exe を置けると、広い遷移先で任意のコードが走る。**引数のパターンは広げる辺でも許す**
        // （決定66(2)が§19.3.9の「狭める／同値に限る」を覆した。守る線は子のドメインの権限）。
        // 寿命: 実行ファイルの同一性照合（§20項目7）が入った日に外す（決定66の「各項目の寿命」）。
        if matches!(edge.exe, ExeMatcher::Pattern(_))
            && self.direction(view.name, &edge.to) == Direction::WiderOrUnknown
        {
            reasons.push(
                "an executable pattern may only narrow or keep the same rights: the caller can \
                 usually write somewhere the pattern covers, and then arbitrary code runs in the \
                 wider domain. Declare the exact path, or make the target domain no wider than \
                 this one."
                    .to_string(),
            );
        }

        // (e) **Strict のドメインへ入る辺は、呼び出し元支配の入力を固定する**（決定66の追記）。旧(e)（§19.1。広げる／
        // 証明できない辺は固定必須）の意味を、「広げるか」ではなく遷移先の Strict の印で掛ける——印の無いドメインへ
        // 入る辺は広げても固定しなくてよい（決定66。守る線は子のドメインの権限）。印の判定は[`GraphFacts::enters_strict`]
        // の1か所、束の形は[`is_fully_fixed`]の1か所が持つ。
        if self.enters_strict(view.name, &edge.to) && !is_fully_fixed(edge) {
            reasons.push(format!(
                "target domain {:?} is strict, so every caller-controlled input of an edge entering \
                 it must be fixed by the policy: declare argv as a literal and declare cwd. Without \
                 that, the caller can make the strict domain do whatever it likes with its rights.",
                edge.to
            ));
        }

        // (d) 相対パスの引数を含む辺は`cwd`必須（§5.1(5)）。
        if edge.cwd.is_none() {
            if let ArgvMatcher::Literal(argv) = &edge.argv {
                if let Some(token) = first_relative_path_token(argv) {
                    reasons.push(format!(
                        "argv contains the relative path {token:?} but the edge declares no cwd; \
                         a relative argument cannot be checked without knowing what it resolves to"
                    ));
                }
            }
        }

        // (i) 固定値が指すファイルは、呼び出し元から書けない場所にあること（§19.1）。**Strict の辺だけに掛ける**
        // （決定66の追記。P5.4a で鍵を書き方の形から印へ付け替えた——普通のモードは入力を固定しないので問いが無い）。
        //
        // **どの書ける場所に当たったかを文面に出す。** 書ける場所は宣言の外からも来る
        // （`settings.json`・`--fs-allow`。残課題 サンドボックス周辺 #65）ので、
        // 根を出さないと、宣言のどこにも書込が無いのに拒否された理由が辿れない（`B-10`）。
        // 作業ディレクトリ（P5.4d。決定66の追記の束「呼び出し元が書ける場所なら断る」）は文面を分ける——
        // 固定したのは「指す先」ではなく「子がファイルを拾う場所」なので、直し方が違う。
        let declared_cwd = edge.cwd.as_deref().map(fold_for_pattern_comparison);
        for (path, root) in self.caller_writable_fixed_paths(view, edge) {
            reasons.push(if declared_cwd.as_deref() == Some(path.as_str()) {
                format!(
                    "the declared cwd {path:?} lies under {root:?}, which this domain can write: \
                     the caller could plant files there that the child picks up from its working \
                     directory (modules, DLLs, relative arguments). Declare a cwd the caller cannot write."
                )
            } else {
                format!(
                    "the fixed value points at {path:?}, which this domain can write (it lies under \
                     {root:?}): fixing the arguments is pointless if the caller can rewrite what \
                     they point at"
                )
            });
        }

        reasons
    }

    /// 固定値（exeのリテラルと、literal argvの中のパスらしいトークンと、宣言した作業ディレクトリ）のうち、
    /// **呼び出し元が書ける場所にあるもの**と、それを覆っている書ける場所の組。
    ///
    /// **Strict の辺（[`GraphFacts::is_strict_edge`]）だけを見る**——印の無いドメインへ入る辺と自己ループ辺は、
    /// 固定してあっても空を返す（決定66の追記。印の判定を2つ作らない、`B-13`）。
    ///
    /// # この検査が見ていない範囲（P-11）
    ///
    /// - 見ているのは**宣言された書込権限**と、呼び出し側が渡した
    ///   [`GraphInput::caller_writable_roots`]だけである。後者に何が入るかはホストが決める——
    ///   `harness.exe`はワークスペースと`policy.json`の外で書込を許した場所
    ///   （`settings.json`の`fs.read_write`・`--fs-allow <path>:rw`）を渡し、ポリシーエディタは
    ///   ワークスペースだけを渡す（エディタは宣言の外で書込を許す経路を持たない）
    /// - パスの比較は綴りの畳み込み（区切りと大小）だけで、`..`・8.3形式の短い名前・
    ///   シンボリックリンクとジャンクション・ハードリンクは解決しない。**別名はSpawn Daemonが
    ///   起こす直前に、呼び出し元のトークンで実体のアクセス制御リストを見て補う**
    ///   （`harness_sandbox`の`spawnd::fixed_inputs`、[`Allowed::strict`]）
    /// - 相対パスの引数そのものは候補にしていない（[`fixed_file_paths`]のdoc。作業ディレクトリはP5.4dから候補）
    /// - 保証するのは「呼び出し元から書けない場所にある」ことだけで、
    ///   **そのファイルを別の経路で書ける主体が居ないこと**は検査していない
    fn caller_writable_fixed_paths(
        &self,
        view: &DomainView<'_>,
        edge: &TransitionEdge,
    ) -> Vec<(String, String)> {
        if !self.is_strict_edge(view.name, edge) {
            // Strict の辺でなければ、守るべき固定値が無い（固定していない辺）か、固定を求めていない（普通のモード）。
            return Vec::new();
        }
        // Strict の辺ならargvはリテラルである（`is_strict_edge`が`is_fully_fixed`を含む）。
        let argv = match &edge.argv {
            ArgvMatcher::Literal(argv) => argv.as_str(),
            ArgvMatcher::Pattern(_) | ArgvMatcher::Any(_) => "",
        };
        // 候補の集め方は起こす直前の検査と共有する（[`fixed_file_paths`]）。ここは綴りで比べるので畳む。
        let image = match &edge.exe {
            ExeMatcher::Literal(exe) => Some(exe.as_str()),
            // パターンのexeは、実際にどの綴りで起きるかが宣言からは分からないので引数と作業ディレクトリだけを見る
            // （起こす直前の検査は、要求された実際の実行ファイルを見る）。
            ExeMatcher::Pattern(_) => None,
        };
        let candidates: Vec<String> = fixed_input_places(image, argv, edge.cwd.as_deref())
            .iter()
            .map(|path| fold_for_pattern_comparison(path))
            .collect();

        let writable = self.caller_writable_roots(view.name);
        candidates
            .into_iter()
            .filter_map(|path| {
                let root = writable.iter().find(|root| path_covered_by(root, &path))?;
                Some((path, root.clone()))
            })
            .collect()
    }

    /// このドメインから書ける場所（到達閉包の`read_write`宣言＋外から渡された根）。
    fn caller_writable_roots(&self, domain: &str) -> Vec<String> {
        let mut roots: Vec<String> = self
            .input
            .caller_writable_roots
            .iter()
            .map(|root| fold_for_pattern_comparison(root))
            .collect();
        // 問いは「この呼び出し元は、その固定値を書き換えられるか」なので、実際に届く範囲（到達閉包）を見る。
        let rights = self.rights_of(self.reachable_from(domain));
        for (value, access) in &rights.fs {
            if *access == FsAccess::ReadWrite {
                roots.push(fold_for_pattern_comparison(
                    crate::normalize::literal_prefix(value),
                ));
            }
        }
        roots
    }
}

// ---------------------------------------------------------------------------
// 綴りの検査
// ---------------------------------------------------------------------------

fn check_domain_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("target domain name is empty".to_string());
    }
    if name.len() > MAX_DOMAIN_NAME_LEN {
        return Err(format!(
            "target domain name is {} characters; the AppContainer profile name it goes into \
             leaves at most {MAX_DOMAIN_NAME_LEN}, so the approval would pass and the profile \
             would fail to be created at run time",
            name.len()
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(format!(
            "target domain name {name:?} may only contain ASCII letters, digits, '-' and '.' \
             (the AppContainer profile name it goes into accepts nothing else)"
        ));
    }
    Ok(())
}

/// `exe.literal`はフルパスに限る（§5.1(4)）。
fn check_exe_literal(value: &str) -> Result<(), String> {
    if is_absolute_path(&fold_for_pattern_comparison(value)) {
        Ok(())
    } else {
        Err(format!(
            "exe literal {value:?} is not a full path; the observed events only carry the leaf \
             name, so a leaf-only declaration would match whatever program happens to have that \
             name"
        ))
    }
}

/// パターン言語の規則（§22.5）を編集時に見る。
fn check_pattern(pattern: &str, field: &str) -> Result<(), String> {
    if pattern == ".*" {
        return Err(format!(
            "{field} pattern \".*\" means \"anything\"; write it as the one spelling for that, \
             `\"any\": true` (two spellings for the same meaning grow a path that only handles one)"
        ));
    }
    if pattern.contains("(?i") {
        return Err(format!(
            "{field} pattern turns on the regex engine's case folding, which folds Unicode; \
             this axis folds the input itself with ASCII rules, so write the pattern in lowercase \
             instead"
        ));
    }
    if pattern.contains(r"\\") {
        return Err(format!(
            "{field} pattern contains an escaped backslash; separators in patterns are always \
             '/' (the input is folded that way), and a literal backslash can never match"
        ));
    }
    if let Some(upper) = first_unescaped_uppercase(pattern) {
        return Err(format!(
            "{field} pattern contains the uppercase {upper:?}; the input is folded to lowercase \
             before matching, so an uppercase letter outside an escape can never match"
        ));
    }
    if let Err(e) = build_anchored(pattern) {
        return Err(format!(
            "{field} pattern is not a valid regular expression: {e}"
        ));
    }
    Ok(())
}

/// escape列の外にある最初の大文字（§22.5「パターンは小文字で書く」）。
///
/// **escape列の中は見ない**——`\D`（非数字）を機械的に小文字化すると`\d`（数字）になり、
/// **意味が反転する**。だから畳むのは入力側だけにし、パターン側は書き手に小文字で書かせる。
fn first_unescaped_uppercase(pattern: &str) -> Option<char> {
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // 次の1文字はescape列の一部なので飛ばす。
            chars.next();
            continue;
        }
        if c.is_ascii_uppercase() {
            return Some(c);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// コマンドラインの中のパス
// ---------------------------------------------------------------------------

/// 畳み込み済みのパスが絶対か（`c:/…` か `//server/…`）。
fn is_absolute_path(folded: &str) -> bool {
    let bytes = folded.as_bytes();
    if folded.starts_with("//") {
        return true;
    }
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

/// コマンドライン文字列を、引用符を尊重して粗くトークンへ割る。
///
/// **`CreateProcess`の引数解析を再現するものではない**（§15が完全互換を目指さないと定めている
/// のと同じ理由で、ここでも目指さない）。**検査のためだけに使う**ので、割り方が粗いぶんは
/// 「cwdを余分に要求する」側へ外れる。
fn split_command_line(command_line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in command_line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// そのトークンは「パスらしい」か。
///
/// # 限界（P-11）
///
/// **見分けは当て推量である。** 区切りを含むか、末尾に拡張子らしい綴りがあるか、`.`で始まるか
/// だけを見ている。したがって**拡張子も区切りも持たない相対パス**（`python script`の`script`）は
/// 見落とす。見落とすと`cwd`を要求しないので、**この検査は安全側へ倒れていない**。
/// 完全な判定は原理的にできない（何がパスかは起こすプログラムが決める）ので、
/// **見落とす側が残ることを書いておく**。
fn looks_like_path(token: &str) -> bool {
    if token.contains('/') || token.contains('\\') {
        return true;
    }
    if token.starts_with('.') {
        return true;
    }
    match token.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && !ext.is_empty()
                && ext.len() <= 8
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// argvの中の、最初の「相対パスらしい」トークン（§5.1(5)）。
fn first_relative_path_token(command_line: &str) -> Option<String> {
    split_command_line(command_line)
        .into_iter()
        .skip(1) // argv[0]は呼び出し元が書いた綴りそのままで、同一性の根拠に使わない（§5.1(3)）
        .find(|token| {
            looks_like_path(token) && !is_absolute_path(&fold_for_pattern_comparison(token))
        })
}

/// argvの中の、絶対パスらしいトークン（**書かれた綴りのまま**）。
///
/// 畳み込まずに返すのは、Daemonがこの値でファイルを実際に開くからである
/// （[`fixed_file_paths`]）。綴りで比べる側は、受け取ってから畳む。
fn absolute_path_tokens(command_line: &str) -> Vec<String> {
    split_command_line(command_line)
        .into_iter()
        .skip(1)
        .filter(|token| {
            looks_like_path(token) && is_absolute_path(&fold_for_pattern_comparison(token))
        })
        .collect()
}

/// 固定辺で**固定したファイル**——起こす実行ファイルと、argv[0]以降の絶対パスらしいトークン
/// ——と、**宣言した作業ディレクトリ**（P5.4d）を、書かれた綴りのまま返す。
///
/// 読み込み時の検査（[`GraphFacts::caller_writable_fixed_paths`]）と、Daemonが起こす直前に
/// 呼び出し元のトークンでOSに聞く検査（`harness_sandbox`の`spawnd::fixed_inputs`）が
/// **同じ候補**を見るための、唯一の集め方である（片方だけ候補が増えると、2層の検査が
/// 別のファイルを見ることになる）。
///
/// 作業ディレクトリを候補に入れるのは、決定66の追記の束が「作業ディレクトリ: 呼び出し元が書ける場所なら断る」
/// と定めているためである——子は作業ディレクトリからモジュール・DLL・相対パスの引数を拾うので、プログラムと
/// 引数を固定しても、呼び出し元がそこへ置いたものが子の権限で読まれる。
///
/// # 見ていないもの（P-11）
///
/// **相対パスの引数そのもの**は候補にしない。相対トークンの見分けは当て推量で（`/c`のようなスイッチもパスに
/// 見える）、候補にすると正当な辺まで断る。相対パスは作業ディレクトリの下で解決されるので、作業ディレクトリが
/// 書けないことを確かめれば、相対パスが指す先を呼び出し元が**新しく置く**ことは防げる——ただし作業ディレクトリの
/// 配下の個々のファイル・サブディレクトリに別のACEで書込が許されている形は見ない。
pub(super) fn fixed_file_paths(image: &str, command_line: &str, cwd: Option<&str>) -> Vec<String> {
    fixed_input_places(Some(image), command_line, cwd)
}

/// [`fixed_file_paths`]の本体。実行ファイルがパターンの辺（読み込み時の検査で、実際の綴りが宣言からは分からない）
/// は`image`を`None`で呼ぶ。**候補の並べ方はここだけが持つ**（実行ファイル→絶対パスの引数→作業ディレクトリ）。
fn fixed_input_places(image: Option<&str>, command_line: &str, cwd: Option<&str>) -> Vec<String> {
    image
        .map(str::to_string)
        .into_iter()
        .chain(absolute_path_tokens(command_line))
        .chain(cwd.map(str::to_string))
        .collect()
}
