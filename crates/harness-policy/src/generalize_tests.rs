//! [`crate::generalize`]の単体テスト。M15.7の完了条件「ルール一般化の純粋関数の単体テスト」
//! （`docs/INDEX.md`）にあたる。

use super::*;

use crate::normalize::Source;

fn fs(path: &str, access: FsAccess) -> DeniedCandidate {
    DeniedCandidate::fs(Source::Etw, path, access, "STATUS_ACCESS_DENIED", 1, 0)
}

fn net(domain: &str) -> DeniedCandidate {
    DeniedCandidate::net(Source::Network, domain, "domain_denied", 1, 0)
}

/// `None`は畳まない。拒否された対象がそのまま1件1提案になる。
#[test]
fn generalization_none_keeps_every_path_separate() {
    let candidates = vec![
        fs("C:/Users/me/.cargo/registry/a.crate", FsAccess::Read),
        fs("C:/Users/me/.cargo/registry/b.crate", FsAccess::Read),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2);
    assert_eq!(proposals[0].value, "C:/Users/me/.cargo/registry/a.crate");
    assert_eq!(proposals[1].value, "C:/Users/me/.cargo/registry/b.crate");
    // 畳み込みが起きていないことを直接主張する。「警告が空」を代用にしない
    // ——収集源由来の注記（OS監査の`read`は推定である旨）は畳み込みと無関係に付くため。
    assert!(proposals
        .iter()
        .all(|p| !p.warnings.iter().any(|w| w.contains("generalized from"))));
}

/// [D-62] **同一親配下に何件あっても親へ畳まない。** 観測された値がそのまま1件1提案になる。
///
/// 畳んでいた頃（`--generalize dir`が既定）は、この入力が`C:/Users/me/.cargo/registry`1本に
/// なっていた。付与は継承ACE（`(OI)(CI)`）なので、**観測していない兄弟ファイルと将来そこに
/// 作られるファイルまで**読めるようになる。ユーザーに見えるのは「2件をまとめた1行」なのに、
/// 実際に開くのはディレクトリ全体だった。
#[test]
fn siblings_in_the_same_directory_are_not_folded_into_their_parent() {
    let candidates = vec![
        fs("C:/Users/me/.cargo/registry/a.crate", FsAccess::Read),
        fs("C:/Users/me/.cargo/registry/b.crate", FsAccess::Read),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2, "2件の観測は2件の提案のままであること");
    let values: Vec<&str> = proposals.iter().map(|p| p.value.as_str()).collect();
    assert_eq!(
        values,
        vec![
            "C:/Users/me/.cargo/registry/a.crate",
            "C:/Users/me/.cargo/registry/b.crate"
        ]
    );
    // 親ディレクトリが提案として現れないこと。**これが本体の主張**——ここが破れると、
    // 承認1回でサブツリー全体が開く。
    assert!(
        !values.contains(&"C:/Users/me/.cargo/registry"),
        "親ディレクトリを提案してはならない（継承ACEでサブツリー全体が開く）"
    );
}

/// 兄弟が1件しか無いディレクトリは畳まない。畳むと「1ファイルの拒否でディレクトリ全体を開く」
/// 提案になり、一般化が常に権限を広げる方向にしか働かなくなる。
#[test]
fn generalization_directory_does_not_widen_a_lone_path() {
    let candidates = vec![fs("C:/Users/me/.gitconfig", FsAccess::Read)];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].value, "C:/Users/me/.gitconfig");
    assert!(!proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("generalized from")));
}

/// ドライブルート直下までは畳まない（`C:/`への一般化はサンドボックスの意味を消す、T-16）。
#[test]
fn generalization_never_folds_up_to_a_drive_root() {
    let candidates = vec![
        fs("C:/toolsA", FsAccess::ReadExec),
        fs("C:/toolsB", FsAccess::ReadExec),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2, "must not collapse into C:/");
    assert!(proposals
        .iter()
        .all(|p| p.value != "C:" && p.value != "C:/"));
}

/// [D-62] **バージョン番号らしい要素をワイルドカードにしない。**
///
/// ワイルドカードは畳み込みより footprint が広い。`approve::grant_root`は**最初の`*`の手前で
/// 切る**ので、`.../toolchains/*/bin`という値のACEは`.../toolchains`**全体**に付く
/// ——観測していない全toolchainバージョンが対象になる。実際この開発機の台帳には、
/// その結果として`C:/Users/segfo/.rustup/toolchains`が付与ルートとして残っていた。
#[test]
fn version_segments_are_not_wildcarded() {
    let candidates = vec![
        fs(
            "C:/Users/me/.rustup/toolchains/1.89.0/bin",
            FsAccess::ReadExec,
        ),
        fs(
            "C:/Users/me/.rustup/toolchains/1.90.0/bin",
            FsAccess::ReadExec,
        ),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2);
    assert!(
        proposals.iter().all(|p| !p.value.contains('*')),
        "ワイルドカードを含む値を提案してはならない: {:?}",
        proposals.iter().map(|p| &p.value).collect::<Vec<_>>()
    );
}

/// [D-62] 16進ハッシュらしい要素もワイルドカードにしない（理由は上と同じ）。
#[test]
fn hash_segments_are_not_wildcarded() {
    let candidates = vec![
        fs("C:/cache/a1b2c3d4e5f6/pkg", FsAccess::Read),
        fs("C:/cache/9f8e7d6c5b4a/pkg", FsAccess::Read),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2);
    assert!(proposals.iter().all(|p| !p.value.contains('*')));
}

/// 意味のある名前（英字混じり）はワイルドカードで潰さない。潰すと提案が広がりすぎる。
#[test]
fn generalization_auto_leaves_meaningful_segments_alone() {
    let candidates = vec![fs(
        "C:/Users/me/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe",
        FsAccess::ReadExec,
    )];

    let proposals = generalize(&candidates);

    assert_eq!(
        proposals[0].value,
        "C:/Users/me/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe"
    );
}

/// **P-03**: 同じパスが`read`と`read_write`で拒否されていても、強い方へ寄せて1本にしない。
/// 別々の提案として出し、どちらを受け入れるかをユーザーに選ばせる。
#[test]
fn different_access_levels_never_merge_into_the_stronger_one() {
    let candidates = vec![
        fs("C:/Users/me/.cargo", FsAccess::Read),
        fs("C:/Users/me/.cargo", FsAccess::ReadWrite),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2);
    let keys: Vec<_> = proposals.iter().map(|p| p.key).collect();
    assert!(keys.contains(&SettingsKey::FsRead));
    assert!(keys.contains(&SettingsKey::FsReadWrite));
}

/// `read_write`の提案には必ずwrite-containmentを弱める旨の警告が付く（D-42）。
#[test]
fn read_write_proposals_always_carry_a_write_containment_warning() {
    let proposals = generalize(
        &[fs("C:/Users/me/out", FsAccess::ReadWrite)],
    );

    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("write containment")));
}

/// ドメインはFSの畳み込み（親ディレクトリ・ワイルドカード）の対象外で、そのまま1件1提案。
#[test]
fn domains_are_not_subject_to_path_folding() {
    let candidates = vec![net("api.example.com"), net("cdn.example.com")];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 2);
    assert!(proposals
        .iter()
        .all(|p| p.key == SettingsKey::NetAllowDomains));
    assert_eq!(proposals[0].id, "net-1");
    assert_eq!(proposals[1].id, "net-2");
}

/// idは並びが決定的なので、入力順を変えても同じ提案が同じidになる
/// （`--accept fs-2`が実行のたびに別のものを指すと危険）。
#[test]
fn proposal_ids_are_stable_regardless_of_input_order() {
    let a = fs("C:/z/one", FsAccess::Read);
    let b = fs("C:/a/two", FsAccess::Read);

    let forward = generalize(&[a.clone(), b.clone()]);
    let backward = generalize(&[b, a]);

    let ids_and_values: Vec<_> = forward
        .iter()
        .map(|p| (p.id.clone(), p.value.clone()))
        .collect();
    let reversed: Vec<_> = backward
        .iter()
        .map(|p| (p.id.clone(), p.value.clone()))
        .collect();
    assert_eq!(ids_and_values, reversed);
    assert_eq!(
        ids_and_values[0],
        ("fs-1".to_string(), "C:/a/two".to_string())
    );
}

/// 複数の収集源から同じ対象が来たら1提案に畳み、`sources()`で両方が見える
/// （提案側で重み付けはしないが、由来は判断材料として残す）。
#[test]
fn evidence_keeps_every_contributing_source() {
    let candidates = vec![
        DeniedCandidate::fs(Source::Preflight, "C:/x", FsAccess::Read, "no path", 1, 0),
        DeniedCandidate::fs(Source::Etw, "C:/x", FsAccess::Read, "denied", 4, 9),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].sources(), vec![Source::Preflight, Source::Etw]);
    assert_eq!(proposals[0].observed_count(), 5);
}

/// **推定を推定として見せる**（RESULTS.md §12.4/§14.3）。OS監査由来の`read`は
/// 「読み取りだった」ではなく「書込だと判る材料が無かった」を意味するので、
/// 削除・書込が目的なら`read_write`を選ぶよう注記する。
#[test]
fn os_audit_read_proposals_disclose_that_read_is_only_a_guess() {
    let proposals = generalize(
        &[DeniedCandidate::fs(
            Source::Etw,
            "C:/Users/me/notes.txt",
            FsAccess::Read,
            "STATUS_ACCESS_DENIED",
            1,
            0,
        )],
    );

    let warning = proposals[0]
        .warnings
        .iter()
        .find(|w| w.contains("conservative guess"))
        .expect("the inference must be disclosed");
    assert!(
        warning.contains("fs.read_write"),
        "it must say what to do instead"
    );
}

/// 他の収集源（preflight・CoW）由来の`read`にはこの注記を付けない——あちらは
/// 要求されたアクセスを実際に知っている（CoWはRedirector DLLが生のマスクを記録する）。
#[test]
fn non_audit_read_proposals_do_not_carry_the_guess_disclosure() {
    for source in [Source::Preflight, Source::Cow] {
        let proposals = generalize(
            &[DeniedCandidate::fs(
                source,
                "C:/Users/me/notes.txt",
                FsAccess::Read,
                "denied",
                1,
                0,
            )],
        );
        assert!(
            !proposals[0]
                .warnings
                .iter()
                .any(|w| w.contains("conservative guess")),
            "{source:?} knows the requested access; it must not be described as a guess"
        );
    }
}

// ---------------------------------------------------------------------------
// 昇格の梯子（D-46、`plans/PLAN-M15.7-FOLLOWUP.md` W4）
// ---------------------------------------------------------------------------

fn granted(entries: &[(&str, FsAccess)]) -> crate::insufficient::GrantedPaths {
    crate::insufficient::GrantedPaths::new(
        entries
            .iter()
            .map(|(path, access)| ((*path).to_string(), *access))
            .collect(),
    )
}

/// **W4の本体。** 既に`fs.read`で許可済みのパスの拒否は、`fs.read`を提案し直しても
/// `apply`が`(no changes)`になるだけなので、**昇格候補で置き換える**。
///
/// `read`許可下の拒否からは「書込・削除・実行のいずれか」までしか絞れないので、
/// 片方へ自動で寄せず両方を並べる（P-03・D-42）。
#[test]
fn a_denial_under_an_existing_read_grant_is_replaced_by_both_escalation_targets() {
    let proposals = generalize_with_granted(
        &[fs("C:/tools/bin/rustc.exe", FsAccess::Read)],
        &granted(&[("C:/tools", FsAccess::Read)]),
    );

    assert_eq!(proposals.len(), 2, "{proposals:#?}");
    assert!(
        proposals
            .iter()
            .all(|p| p.value == "C:/tools/bin/rustc.exe"),
        "the value is unchanged; only the key escalates: {proposals:#?}"
    );
    let keys: Vec<SettingsKey> = proposals.iter().map(|p| p.key).collect();
    assert_eq!(
        keys,
        vec![SettingsKey::FsReadWrite, SettingsKey::FsReadExec]
    );
    assert!(
        !proposals.iter().any(|p| p.key == SettingsKey::FsRead),
        "the redundant fs.read proposal must be gone -- applying it would print (no changes)"
    );
    // なぜkeyが変わったのかが提案自身から読めること。
    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("ALREADY allowed as fs.read")));
    assert!(proposals
        .iter()
        .any(|p| p.warnings.iter().any(|w| w.contains("runs a program"))));
}

/// `read_exec`許可下の拒否は`read_write`の1件だけになる（実行は既に許可済みなので候補から外れる）。
#[test]
fn a_denial_under_a_read_exec_grant_escalates_only_to_read_write() {
    let proposals = generalize_with_granted(
        &[fs("C:/tools/x.dll", FsAccess::Read)],
        &granted(&[("C:/tools", FsAccess::ReadExec)]),
    );

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].key, SettingsKey::FsReadWrite);
}

/// `read_write`許可下の拒否は`read_exec`の1件。ただし「この機構が付与しない権利かもしれない」
/// ことを必ず添える——設定変更では直らない場合があると分かっていなければ、ユーザーは
/// 提案を受理し続けることになる。
#[test]
fn a_denial_under_a_read_write_grant_escalates_to_read_exec_and_admits_the_limit() {
    let proposals = generalize_with_granted(
        &[fs("C:/data/tool.exe", FsAccess::Read)],
        &granted(&[("C:/data", FsAccess::ReadWrite)]),
    );

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].key, SettingsKey::FsReadExec);
    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("does not grant at all")));
}

/// **既に許可済みの1件を根拠に、他の候補まで広げない。** [D-62]で畳み込みを廃止したので、
/// 兄弟は別々の提案として残る——許可済みの側には注記が付き、もう片方は素の候補のままになる。
#[test]
fn an_already_granted_sibling_is_annotated_without_widening_the_other() {
    let proposals = generalize_with_granted(
        &[
            fs("C:/tools/bin/a.exe", FsAccess::Read),
            fs("C:/tools/bin/b.exe", FsAccess::Read),
        ],
        &granted(&[("C:/tools/bin/a.exe", FsAccess::Read)]),
    );

    let values: Vec<&str> = proposals.iter().map(|p| p.value.as_str()).collect();
    assert!(
        !values.contains(&"C:/tools/bin"),
        "親ディレクトリを提案してはならない: {values:?}"
    );
    // 許可済みの`a.exe`は昇格候補が並ぶ（D-46: 許可済みなのに拒否された＝その許可では足りない）。
    // **昇格するのは観測されたパス自身のaccessだけ**で、対象パスは広がらない。
    let a: Vec<&RuleProposal> = proposals
        .iter()
        .filter(|p| p.value == "C:/tools/bin/a.exe")
        .collect();
    assert!(!a.is_empty(), "granted path is still proposed: {proposals:#?}");
    assert!(
        a.iter()
            .any(|p| p.warnings.iter().any(|w| w.contains("ALREADY allowed"))),
        "許可済みなのに拒否された＝その許可では足りない、は出す: {a:#?}"
    );
    // 未許可の`b.exe`は素の候補のまま（片方の事情がもう片方へ伝染しない）。
    let b = proposals
        .iter()
        .find(|p| p.value == "C:/tools/bin/b.exe")
        .expect("ungranted sibling is proposed");
    assert_eq!(b.key, SettingsKey::FsRead);
    assert!(
        !b.warnings.iter().any(|w| w.contains("ALREADY allowed")),
        "許可済みなのは兄弟の方であって、この候補ではない: {:#?}",
        b.warnings
    );
}

/// 許可済みでないパスは従来どおり1件のまま（昇格経路が既定の挙動を変えていないこと）。
#[test]
fn an_ungranted_path_still_yields_exactly_one_proposal() {
    let proposals = generalize_with_granted(
        &[fs("C:/elsewhere/x.txt", FsAccess::Read)],
        &granted(&[("C:/tools", FsAccess::Read)]),
    );

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].key, SettingsKey::FsRead);
}

/// **idは入力の並び順に依存しない。** 1グループが複数提案へ割れても、`(key, value)`で
/// 並べ替えてから採番するので`--accept fs-2`が実行ごとに別のものを指さない。
#[test]
fn ids_stay_deterministic_when_a_group_expands_into_several_proposals() {
    let granted = granted(&[("C:/tools", FsAccess::Read)]);
    let forward = vec![
        fs("C:/tools/a.txt", FsAccess::Read),
        fs("C:/zzz/b.txt", FsAccess::Read),
    ];
    let reversed: Vec<DeniedCandidate> = forward.iter().rev().cloned().collect();

    let a = generalize_with_granted(&forward, &granted);
    let b = generalize_with_granted(&reversed, &granted);

    let ids_and_keys = |proposals: &[RuleProposal]| -> Vec<(String, SettingsKey, String)> {
        proposals
            .iter()
            .map(|p| (p.id.clone(), p.key, p.value.clone()))
            .collect()
    };
    assert_eq!(ids_and_keys(&a), ids_and_keys(&b));
    assert_eq!(a.len(), 3, "2 escalated + 1 untouched: {a:#?}");
}

/// **ディレクトリ自身が観測されたときは、それも候補として残る。**
///
/// 祖先チェーンのオープン（`cmd`系は祖先を「通過」ではなく**オープン**する）で、ディレクトリ
/// 自身が拒否として実際に観測される。[D-62]で畳み込みを廃止しても**この経路は残る**——
/// 観測された事実を捨てるわけにはいかないからである。
///
/// つまり「値がディレクトリの候補」は今後も出る。**それを承認すればサブツリー全体が開く**ので、
/// ポリシーエディタの一括選択（親行のチェック）はこの種の候補を巻き込んではならない。
/// その保証は`proposal_tree`側のテストが持つ。
#[test]
fn a_directly_observed_directory_stays_a_candidate_of_its_own() {
    let candidates = vec![
        fs("C:/Users/me/.cargo/registry", FsAccess::Read),
        fs("C:/Users/me/.cargo/registry/a.crate", FsAccess::Read),
        fs("C:/Users/me/.cargo/registry/b.crate", FsAccess::Read),
    ];

    let proposals = generalize(&candidates);

    assert_eq!(proposals.len(), 3, "3件の観測は3件の提案: {proposals:#?}");
    let dir: Vec<&RuleProposal> = proposals
        .iter()
        .filter(|p| p.value == "C:/Users/me/.cargo/registry" && p.key == SettingsKey::FsRead)
        .collect();
    assert_eq!(
        dir.len(),
        1,
        "同じ設定値の提案が2件並ぶと、どちらを承認すればよいのか決められない: {proposals:#?}"
    );
    assert_eq!(
        dir[0].observed_count(),
        1,
        "ディレクトリ自身の観測回数だけを数える（子の回数を足し込まない）"
    );
}

/// **`breadth`が拒否する値へは畳まない。**
///
/// `C:/Program Files/Git`と`C:/Program Files/GitHub CLI`を親へ畳むと`C:/Program Files`
/// （ドライブ直下＝広すぎる）になる。畳んだ結果は`policy apply`も`approve`も受け付けないうえ、
/// **それぞれ単体なら承認できたはずの子が一覧から消える**ので、使える候補が1件も残らなくなる。
#[test]
fn folding_does_not_produce_a_value_the_breadth_guard_would_reject() {
    // 祖先チェーンのオープンでは、ディレクトリ自身がこの形で観測される（実測の一覧そのまま）。
    let candidates = vec![
        fs("C:/Program Files/Git", FsAccess::Read),
        fs("C:/Program Files/GitHub CLI", FsAccess::Read),
    ];

    let proposals = generalize(&candidates);

    let values: Vec<&str> = proposals.iter().map(|p| p.value.as_str()).collect();
    assert!(
        !values.contains(&"C:/Program Files"),
        "承認できない親へ畳んではいけない: {values:?}"
    );
    assert!(
        values.contains(&"C:/Program Files/Git") && values.contains(&"C:/Program Files/GitHub CLI"),
        "畳めない場合は子をそのまま残す（消してしまうと選べる候補が無くなる）: {values:?}"
    );
    assert!(
        proposals
            .iter()
            .all(|p| !crate::breadth::check(p).is_too_broad()),
        "残った候補はどれも承認できる幅であること: {values:?}"
    );
}

/// ネットワークの提案は昇格の対象外（FSパスの許可状態とは無関係）。
#[test]
fn domain_proposals_are_untouched_by_the_escalation_ladder() {
    let proposals = generalize_with_granted(
        &[net("api.example.com")],
        &granted(&[("C:/", FsAccess::Read)]),
    );

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].key, SettingsKey::NetAllowDomains);
    assert_eq!(proposals[0].id, "net-1");
}

// ---------------------------------------------------------------------------
// 昇格の条件と、展開後の畳み込み（ポリシーエディタが実行前診断の結果を合流させるようになって
// 初めて露出した2つの穴。`plans/PLAN-POLICY-EDITOR-EXEC-DENIAL.md`）
// ---------------------------------------------------------------------------

/// **`fs.read`許可下の`fs.read_exec`提案は、昇格で置き換えない。**
///
/// 置き換えると、実行権を得る唯一の正解が`fs.read_write`と2件に割れる（頼まれていない
/// 書込穴が並ぶ＝P-03の逆）。D-46が宣言している「置き換えるべき条件＝`apply`が
/// `(no changes)`になる条件」は、**提案自身のkeyまで覆われているとき**にだけ成立する。
#[test]
fn a_read_exec_proposal_is_not_escalated_just_because_read_is_already_granted() {
    let proposals = generalize_with_granted(
        &[fs("C:/Users/me/.cargo/bin/cargo.exe", FsAccess::ReadExec)],
        &granted(&[("C:/Users/me/.cargo/bin", FsAccess::Read)]),
    );

    assert_eq!(proposals.len(), 1, "{proposals:#?}");
    assert_eq!(proposals[0].key, SettingsKey::FsReadExec);
    assert_eq!(proposals[0].value, "C:/Users/me/.cargo/bin/cargo.exe");
    assert!(
        !proposals.iter().any(|p| p.key == SettingsKey::FsReadWrite),
        "a write hole nobody asked for must not appear: {proposals:#?}"
    );
}

/// 対（B-35）: **覆われている側は従来どおり昇格する。** 上のゲートが梯子そのものを
/// 殺していないことを、同じ許可状態で確かめる。
#[test]
fn a_read_proposal_under_the_same_read_grant_still_escalates() {
    let proposals = generalize_with_granted(
        &[fs("C:/Users/me/.cargo/bin/cargo.exe", FsAccess::Read)],
        &granted(&[("C:/Users/me/.cargo/bin", FsAccess::Read)]),
    );

    let keys: Vec<SettingsKey> = proposals.iter().map(|p| p.key).collect();
    assert_eq!(
        keys,
        vec![SettingsKey::FsReadWrite, SettingsKey::FsReadExec]
    );
}

/// `fs.read_write`許可下の`fs.read_exec`提案も残す（両者は互いに包含しない）。
#[test]
fn a_read_exec_proposal_survives_a_read_write_grant() {
    let proposals = generalize_with_granted(
        &[fs("C:/data/tool.exe", FsAccess::ReadExec)],
        &granted(&[("C:/data", FsAccess::ReadWrite)]),
    );

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].key, SettingsKey::FsReadExec);
}

/// **別々の出所が同じ`(key, value)`を作ったら1件へ畳む。**
///
/// 畳まないと、同じ設定値の提案がidだけ違う形で2行並び、観測回数も割れる（片方を承認しても
/// もう片方が未承認のまま残って見える）。ここでは「昇格で生まれた`fs.read_exec`」と
/// 「最初から`fs.read_exec`として導出された候補」が衝突する——展開**後**にしか出会わない組み合わせ。
#[test]
fn proposals_from_different_sources_that_land_on_the_same_key_and_value_are_merged() {
    let candidates = vec![
        // 観測された拒否（ETWは読取と実行を区別できないので`read`で入る）→ 昇格で read_exec が出る
        fs("C:/tools/bin/thing.exe", FsAccess::Read),
        // 別経路（実行像・実行前診断）が直接 read_exec として出した同じ値
        DeniedCandidate::fs(
            Source::Preflight,
            "C:/tools/bin/thing.exe",
            FsAccess::ReadExec,
            "named by the pre-run diagnosis",
            1,
            0,
        ),
    ];

    let proposals = generalize_with_granted(
        &candidates,
        &granted(&[("C:/tools", FsAccess::Read)]),
    );

    let read_exec: Vec<&RuleProposal> = proposals
        .iter()
        .filter(|p| p.key == SettingsKey::FsReadExec)
        .collect();
    assert_eq!(read_exec.len(), 1, "{proposals:#?}");
    assert_eq!(
        read_exec[0].observed_count(),
        2,
        "the evidence of both sources must be summed, not split: {:#?}",
        read_exec[0]
    );
    // 同じ文の警告が2回並ばないこと（行ごとの警告と共通警告の切り分けが濁る）。
    let mut warnings = read_exec[0].warnings.clone();
    let total = warnings.len();
    warnings.sort();
    warnings.dedup();
    assert_eq!(warnings.len(), total, "duplicated warnings: {warnings:#?}");
    // idは連番のまま（畳んだ結果に穴が空かない）。
    let fs_ids: Vec<&str> = proposals
        .iter()
        .filter(|p| p.key != SettingsKey::NetAllowDomains)
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(fs_ids, vec!["fs-1", "fs-2"], "{proposals:#?}");
}

/// [`restate_access`]は**keyに依存する警告だけ**を差し替え、値と証拠には触れない。
#[test]
fn restating_the_access_swaps_only_the_key_dependent_warnings() {
    // key非依存の警告の実例には**ワイルドカード注意**を使う。[D-62]で一般化を廃止したので
    // harnessが`*`を作ることはないが、ユーザーが手で書いた宣言はpreflight由来の候補として
    // 戻ってくる——その経路でこの警告は今も出る。
    let original = generalize(&[fs("C:/tools/**", FsAccess::Read)]).remove(0);
    assert!(
        original
            .warnings
            .iter()
            .any(|w| w.contains("came from OS auditing")),
        "precondition: the fs.read guess warning is present: {original:#?}"
    );
    assert!(
        original.warnings.iter().any(|w| w.contains("wildcard")),
        "precondition: the key-independent wildcard warning is present: {original:#?}"
    );

    let restated = restate_access(&original, SettingsKey::FsReadExec);

    assert_eq!(
        restated.id, original.id,
        "the id must not move under the user"
    );
    assert_eq!(restated.key, SettingsKey::FsReadExec);
    assert_eq!(restated.value, original.value);
    assert_eq!(restated.evidence, original.evidence);
    assert!(
        !restated
            .warnings
            .iter()
            .any(|w| w.contains("came from OS auditing")),
        "the fs.read-only guess warning must go: {restated:#?}"
    );
    assert!(
        restated.warnings.iter().any(|w| w.contains("wildcard")),
        "warnings that do not depend on the key must stay: {restated:#?}"
    );
    assert!(
        restated
            .warnings
            .iter()
            .any(|w| w.contains("chosen by hand") && w.contains("fs.read")),
        "the fact that a human picked this access must be visible: {restated:#?}"
    );
}

/// 逆向き（B-35の対）: `fs.read_write`へ言い換えたら、その注意書きが**付く**。
#[test]
fn restating_to_read_write_adds_the_write_containment_warning() {
    let original = generalize(
        &[fs("C:/tools/x.txt", FsAccess::Read)],
    )
    .remove(0);

    let restated = restate_access(&original, SettingsKey::FsReadWrite);

    assert!(restated
        .warnings
        .iter()
        .any(|w| w.contains("weakens write containment")));
}

/// accessの巡回はこのenumが持つ（表示側で並びを書かない）。ドメインには次が無い。
#[test]
fn the_fs_access_cycle_is_owned_by_the_settings_key() {
    assert_eq!(
        SettingsKey::FsRead.next_fs_access(),
        Some(SettingsKey::FsReadWrite)
    );
    assert_eq!(
        SettingsKey::FsReadWrite.next_fs_access(),
        Some(SettingsKey::FsReadExec)
    );
    assert_eq!(
        SettingsKey::FsReadExec.next_fs_access(),
        Some(SettingsKey::FsRead)
    );
    assert_eq!(SettingsKey::NetAllowDomains.next_fs_access(), None);
    assert_eq!(SettingsKey::NetAllowDomains.fs_access(), None);
    assert_eq!(
        SettingsKey::FsReadExec.fs_access(),
        Some(FsAccess::ReadExec)
    );
}
