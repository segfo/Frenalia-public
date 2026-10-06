//! [`env_for_nested`]・[`force_request_pipe`]・[`caller_handles_for`]の単体テスト（`mod nested_env_tests`）。
//!
//! 2026-10-06 に`server.rs`のインラインの試験からそのまま移した（`plans/position-domains/P5.md` P5.1）。
//! モジュールの名前は`nested_env_tests`のまま残した——試験の絞り込みの文字列と、
//! 後続の段（P5.4c）がこの名前で試験を足す。

use super::*;
use harness_policy::transition::{ChildOutput, EnvOverride, EnvPolicy};
use crate::tier2a::spawnd::CallerHandles;
use windows::Win32::Foundation::HANDLE;

use crate::tier2a::spawnd::child_plan::ChildPlan;
use crate::tier2a::spawnd::server::write_redirector_env;
use crate::tier2a::spawnd::{DomainIdentitySpec, DomainSpec, RedirectorSpec};

const PIPE: &str = r"\\.\pipe\x";

/// 系統の基準env。**harnessが所有する名前が1つ入っている**（窓口のパイプ名）。
fn base() -> Vec<(String, String)> {
    vec![
        ("PATH".to_string(), "C:/w/bin".to_string()),
        (
            crate::tier2a::spawnd::REQUEST_PIPE_ENV.to_string(),
            PIPE.to_string(),
        ),
    ]
}

/// 呼び出し元が申告してくる環境。**基準envとは別物**——シェルの中で設定された変数が
/// ここに載る。
fn caller() -> Vec<(String, String)> {
    vec![
        ("PATH".to_string(), "C:/caller/bin".to_string()),
        ("FOO".to_string(), "set-in-the-shell".to_string()),
    ]
}

fn value_of<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// [段階6f-1] **`PassThrough`は呼び出し元の申告を通す。**
///
/// 段階6bは系統の基準envに固定しており、シェルで設定した変数は子へ1つも届かなかった。
/// **届くこと**と、**窓口の名前が系統の値で強制されること**を1本で見る——
/// 後者が落ちると、起こした子は「自分は誰にも頼めない」状態になり、症状は
/// 「孫が作れない」という判定とは無関係な形で出る。
#[test]
fn pass_through_hands_the_callers_own_environment_to_the_child() {
    let env = env_for_nested(&base(), Some(&caller()), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));

    assert_eq!(
        value_of(&env, "FOO"),
        Some("set-in-the-shell"),
        "シェルの中で設定された変数が子へ届いていない。\
         `$env:FOO=1; git ...` が効かない形である: {env:?}"
    );
    assert_eq!(
        value_of(&env, "PATH"),
        Some("C:/caller/bin"),
        "呼び出し元の`PATH`ではなく系統の値が使われている: {env:?}"
    );
    assert_eq!(
        value_of(&env, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(PIPE),
        "窓口の名前が系統の値になっていない: {env:?}"
    );
}

/// [段階6f-1] **「申告していない」と「空だと申告した」は別である**（`P-11`）。
///
/// # なぜこの1本が要るのか——**実機で踏んだ**
///
/// 2026-09-17、この2つを同じに扱っていたため、**許可された遷移が1つ残らず
/// 「起こそうとして失敗した」になった**。`SystemRoot`の無い環境ブロックを渡された
/// `CreateProcessW`は`ERROR_ENVVAR_NOT_FOUND`(203)で失敗する——症状は
/// 「宣言は合っているのに起きない」で、**宣言の側をいくら直しても直らない**。
#[test]
fn an_unstated_environment_falls_back_to_the_lineage_but_an_empty_one_does_not() {
    let unstated = env_for_nested(&base(), None, &EnvPolicy::CallerPlusDiff(EnvOverride::default()));
    assert_eq!(
        value_of(&unstated, "PATH"),
        Some("C:/w/bin"),
        "申告が無いのに系統の基準envが使われていない。\
         **`SystemRoot`の無い環境ブロックで子を起こすことになる**: {unstated:?}"
    );

    let declared_empty = env_for_nested(&base(), Some(&[]), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));
    assert_eq!(
        value_of(&declared_empty, "PATH"),
        None,
        "**空だと申告したのに系統の値が混ざっている。** 2つを同じに扱うと、\
         申告の有無が結果に出ない: {declared_empty:?}"
    );
    // 空だと申告しても、harnessが所有する名前だけは系統の値で戻る。
    assert_eq!(
        value_of(&declared_empty, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(PIPE)
    );
}

/// [段階6f-1] **呼び出し元がharness所有の名前を名乗っても、系統の値が勝つ。**
///
/// これが§10.1.2の「envの欄を置いてもいけない」が守りたかった一点である。
/// 効かなくなると、サンドボックスの中のプロセスが**窓口の名前を自分で決められる**
/// ——偽の窓口へ繋がせて、拒否されたはずの生成を「許可」と答えさせられる。
#[test]
fn a_caller_cannot_redeclare_a_harness_owned_variable() {
    let mut claimed = caller();
    claimed.push((
        crate::tier2a::spawnd::REQUEST_PIPE_ENV.to_string(),
        r"\\.\pipe\attacker".to_string(),
    ));
    claimed.push((
        // 綴りの大小でも素通りしないこと。
        redirector_env::DIFF_LAYER.to_ascii_lowercase(),
        r"C:\attacker\diff".to_string(),
    ));

    let env = env_for_nested(&base(), Some(&claimed), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));

    assert_eq!(
        value_of(&env, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(PIPE),
        "呼び出し元が名乗った窓口の名前が子へ渡っている: {env:?}"
    );
    assert_eq!(
        value_of(&env, redirector_env::DIFF_LAYER),
        None,
        "**系統に無いharness所有の変数が、呼び出し元の申告から子へ渡っている。** \
         差分層の置き場を呼び出し元が決められる形である: {env:?}"
    );
}

/// [段階6f-1] **1回の生成にしか意味が無い値は、系統からも戻さない。**
///
/// 初期化完了を知らせるハンドルの値は、トップレベルを起こしたときのものである。
/// 子のプロセスでは別のオブジェクトを指す（か、何も指さない）ので、そのまま渡すと
/// **DLLが知らない相手へ完了を書き込む**。正しい値は`prepare_redirector`が毎回書き直す。
#[test]
fn the_one_shot_ready_handle_is_not_carried_over_from_the_lineage() {
    let mut base = base();
    base.push((redirector_env::READY_HANDLE.to_string(), "284".to_string()));

    let env = env_for_nested(&base, Some(&caller()), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));

    assert_eq!(
        value_of(&env, redirector_env::READY_HANDLE),
        None,
        "トップレベルのハンドル値が子へ持ち越されている: {env:?}"
    );
}

/// [BUG-160] **OSが書き換える名前は、呼び出し元の値ではなく系統の基準envの値になる。**
///
/// 呼び出し元（＝AppContainerの中のプロセス）が持っている`TEMP`は、
/// **既にOSの置き換えを1回受けた値**である。そのまま渡すと同じ置き換えが重なり、
/// 存在しない場所を指す（`os_rewritten_env_names`のdoc）。
///
/// # ここで測っているのは規則であって、OSの挙動ではない
///
/// 「重なると壊れる」を実機で見るのは
/// `win_appcontainer::spawnd_e2e_tests::env_substitution_tests`である（昇格が要る）。
/// **この1本はWin32を1行も通らない**ので、規則が壊れたことだけを素で見張る。
///
/// # 対で見る（`B-35`）
///
/// 基準envに在るときは戻ること**と**、同じ経路を通る普通の変数（`FOO`）が
/// 呼び出し元の値のまま届くことを一緒に表明する。後者が無いと、
/// **基準envで丸ごと上書きする実装**でも緑になる——それは段階6f-1が直したものへの巻き戻しである。
#[test]
fn the_os_rewritten_names_come_from_the_lineage_not_from_the_caller() {
    let mut base = base();
    base.push((
        "TEMP".to_string(),
        r"C:\Users\u\AppData\Local\Temp".to_string(),
    ));
    base.push((
        "LOCALAPPDATA".to_string(),
        r"C:\Users\u\AppData\Local".to_string(),
    ));

    let mut caller = caller();
    // **AppContainerの中のプロセスが実際に持っている値**（置き換え済み）。
    caller.push((
        "TEMP".to_string(),
        r"C:\Users\u\AppData\Local\Packages\pkg\AC\Temp".to_string(),
    ));
    // 綴りの大小でも素通りしないこと（harness所有の名前と同じ扱い）。
    caller.push((
        "localappdata".to_string(),
        r"C:\Users\u\AppData\Local\Packages\pkg\AC".to_string(),
    ));

    let env = env_for_nested(&base, Some(&caller), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));

    assert_eq!(
        value_of(&env, "TEMP"),
        Some(r"C:\Users\u\AppData\Local\Temp"),
        "置き換え済みの`TEMP`がそのまま子へ渡っている。\
         OSがもう1回置き換えるので、子は存在しない場所を指す（BUG-160）: {env:?}"
    );
    assert_eq!(
        value_of(&env, "LOCALAPPDATA"),
        Some(r"C:\Users\u\AppData\Local"),
        "`LOCALAPPDATA`が系統の値に戻っていない。**`TEMP`はこの値から導かれる**ので、\
         ここが置き換え済みだと`TEMP`を直しても子の`TEMP`は二重のままになる: {env:?}"
    );
    assert_eq!(
        env.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("LOCALAPPDATA"))
            .count(),
        1,
        "同じ名前が2つ載っている（どちらが効くかは実装依存になる）: {env:?}"
    );
    assert_eq!(
        value_of(&env, "FOO"),
        Some("set-in-the-shell"),
        "OSが書き換える名前**以外**まで系統の値で潰している。\
         シェルで設定した変数が子へ届かない形で、段階6f-1の決定への巻き戻しである: {env:?}"
    );
}

/// [BUG-160] **系統の基準envに無ければ、子からも消える。**
///
/// harness所有の名前と同じ規則である（そちらの「消す側を落とすと呼び出し元が生やせる」と
/// 対になる）。ここで呼び出し元の値を残すと、**トップレベルが持っていなかった`TEMP`を
/// nestedだけが持つ**——シェルと子で環境が食い違い、突き合わせの受け入れが
/// 「差が出ないこと」を主張できなくなる。
#[test]
fn an_os_rewritten_name_absent_from_the_lineage_does_not_survive_from_the_caller() {
    let mut caller = caller();
    caller.push((
        "TEMP".to_string(),
        r"C:\Users\u\AppData\Local\Packages\pkg\AC\Temp".to_string(),
    ));

    // 基準envには`TEMP`が無い。
    let env = env_for_nested(&base(), Some(&caller), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));

    assert_eq!(
        value_of(&env, "TEMP"),
        None,
        "系統が持っていない`TEMP`を、呼び出し元の申告から子が受け取っている: {env:?}"
    );
}

/// [P5.4c] **普通の辺は呼び出し元の申告へ差分を当てる**（決定66(5)）。**`set`は上書き、`unset`は取り除く。**
///
/// 対で見る（`B-35`）——`set`だけを測ると、`unset`を無視する実装でも緑になる。
#[test]
fn an_ordinary_edge_applies_the_edge_overrides_on_top_of_the_callers_environment() {
    let over = EnvOverride {
        set: [("PATH".to_string(), "C:/fixed".to_string())]
            .into_iter()
            .collect(),
        unset: vec!["FOO".to_string()],
    };
    let env = env_for_nested(&base(), Some(&caller()), &EnvPolicy::CallerPlusDiff(over));

    assert_eq!(
        value_of(&env, "PATH"),
        Some("C:/fixed"),
        "宣言した固定値が効いていない: {env:?}"
    );
    assert_eq!(
        value_of(&env, "FOO"),
        None,
        "宣言した取り除きが効いていない: {env:?}"
    );
    assert_eq!(
        env.iter().filter(|(n, _)| n == "PATH").count(),
        1,
        "同じ名前が2つ載っている（どちらが効くかは実装依存になる）: {env:?}"
    );
}

/// [P5.4c] **Strict の辺は harness の基準の値＋辺の差分で、呼び出し元の値は1つも通さない**（決定66の追記）。
///
/// # 何が守られるのか
///
/// Strict のドメインは呼び出し元に自由に使わせたくない権利を持つ。引数を固定しても、環境変数で振る舞いを
/// 変えられる実行ファイルは多い（`PYTHONSTARTUP`・`GIT_EXTERNAL_DIFF`等）ので、**固定した操作の中身を
/// 呼び出し元が選べてしまう**。基準の値から組み直すとその経路が閉じる。
///
/// **対で見る**（`B-35`）: 同じ入力を普通の辺へ渡すと呼び出し元の値が届く（上の試験と同じ入力）。
/// 片方だけだと、「常に基準から組む」実装でも「常に呼び出し元から組む」実装でも緑になる。
#[test]
fn a_strict_edge_starts_from_the_harness_baseline_not_from_the_caller() {
    let over = || EnvOverride {
        set: [("GIT_PAGER".to_string(), "cat".to_string())]
            .into_iter()
            .collect(),
        unset: Vec::new(),
    };
    let strict = env_for_nested(
        &base(),
        Some(&caller()),
        &EnvPolicy::BaselinePlusDiff(over()),
    );

    assert_eq!(
        value_of(&strict, "FOO"),
        None,
        "**呼び出し元がシェルで設定した変数が、Strict の辺の子へ届いている。** 固定した操作の中身を\
         呼び出し元が環境変数で選べる形である: {strict:?}"
    );
    assert_eq!(
        value_of(&strict, "PATH"),
        Some("C:/w/bin"),
        "Strict の辺の`PATH`が系統の基準の値になっていない（呼び出し元の値が通っている）: {strict:?}"
    );
    assert_eq!(
        value_of(&strict, "GIT_PAGER"),
        Some("cat"),
        "Strict の辺でも辺の差分は効く（決定66の追記の束の表）: {strict:?}"
    );

    // 対: 同じ入力の普通の辺では、呼び出し元の値が届く。
    let ordinary = env_for_nested(&base(), Some(&caller()), &EnvPolicy::CallerPlusDiff(over()));
    assert_eq!(value_of(&ordinary, "FOO"), Some("set-in-the-shell"));
    assert_eq!(value_of(&ordinary, "PATH"), Some("C:/caller/bin"));
    assert_eq!(value_of(&ordinary, "GIT_PAGER"), Some("cat"));
}

/// [P5.4c] **Strict の辺でも、辺の宣言は`unset`で基準の名前を落とせる**（差分の両側が効く。`B-35`）。
/// あわせて、harness が所有する名前は**どちらのモードでも**系統の値で強制される
/// （[`an_edge_declaration_cannot_redirect_the_request_pipe`]の Strict 版）。
#[test]
fn a_strict_edge_honours_both_sides_of_the_diff_but_not_the_harness_owned_names() {
    let over = EnvOverride {
        set: [(
            crate::tier2a::spawnd::REQUEST_PIPE_ENV.to_string(),
            r"\\.\pipe\declared".to_string(),
        )]
        .into_iter()
        .collect(),
        unset: vec!["PATH".to_string()],
    };
    let env = env_for_nested(&base(), Some(&caller()), &EnvPolicy::BaselinePlusDiff(over));

    assert_eq!(
        value_of(&env, "PATH"),
        None,
        "Strict の辺で宣言した取り除きが効いていない（基準の値が残っている）: {env:?}"
    );
    assert_eq!(
        value_of(&env, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(PIPE),
        "Strict の宣言から窓口の名前を差し替えられている: {env:?}"
    );
}

/// **辺の宣言でも、harnessが所有する名前は差し替えられない。**
///
/// `policy.json`は人が書くものだが、**そこから窓口の名前を差し替えられる形にはしない**
/// ——宣言を1行足すだけで強制を外せることになる。
#[test]
fn an_edge_declaration_cannot_redirect_the_request_pipe() {
    let over = EnvOverride {
        set: [(
            crate::tier2a::spawnd::REQUEST_PIPE_ENV.to_string(),
            r"\\.\pipe\declared".to_string(),
        )]
        .into_iter()
        .collect(),
        unset: Vec::new(),
    };
    let env = env_for_nested(&base(), Some(&caller()), &EnvPolicy::CallerPlusDiff(over));

    assert_eq!(
        value_of(&env, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(PIPE),
        "宣言で窓口の名前を差し替えられている: {env:?}"
    );
}

/// [段階6f-2] **トップレベルの子にも窓口の名前が必ず入る。対で見る**（`B-35`）。
///
/// - **無ければ足す**——足さないと、生成禁止を積んだ子は**何も起動できない**
///   （フックは窓口の名前をここからしか取らない）。しかも症状は「なぜか子プロセスが
///   作れない」という遠い形で出る
/// - **有っても上書きする**——呼び出し元が別の名前を載せていたら、そちらへ繋ぎに行く
///   （`env_for_nested`がnestedに対して塞いでいるのと同じ穴が、トップレベルに開く）
#[test]
fn the_daemon_puts_its_own_request_pipe_into_every_top_level_child() {
    const MINE: &str = r"\\.\pipe\the-real-one";

    let mut missing = vec![("PATH".to_string(), r"C:\bin".to_string())];
    force_request_pipe(&mut missing, MINE);
    assert_eq!(
        value_of(&missing, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(MINE),
        "窓口の名前が入っていない。この子は生成禁止を積んだ瞬間に何も起動できなくなる: {missing:?}"
    );

    let mut claimed = vec![(
        crate::tier2a::spawnd::REQUEST_PIPE_ENV.to_string(),
        r"\\.\pipe\somebody-elses".to_string(),
    )];
    force_request_pipe(&mut claimed, MINE);
    assert_eq!(
        value_of(&claimed, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(MINE),
        "呼び出し元が載せた名前が残っている。窓口を差し替えられる: {claimed:?}"
    );
    assert_eq!(claimed.len(), 1, "同じ名前が2つ並んでいる: {claimed:?}");
}

/// **環境変数の名前は大文字小文字を区別しない**（Windows）。
///
/// 区別してしまうと、`Path`を上書きしたつもりが`PATH`と2つ並び、
/// **どちらが効くかは`CreateProcessW`の実装依存**になる。宣言した側が効かない向きに
/// 倒れると、固定したはずの`PATH`が呼び出し元の値のまま残る。
#[test]
fn overrides_match_environment_variable_names_case_insensitively() {
    let over = EnvOverride {
        set: [("path".to_string(), "C:/fixed".to_string())]
            .into_iter()
            .collect(),
        unset: vec!["foo".to_string()],
    };
    let env = env_for_nested(&base(), Some(&caller()), &EnvPolicy::CallerPlusDiff(over));

    assert_eq!(
        env.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("path"))
            .count(),
        1,
        "綴りの大小で別の変数として扱われている（同じ名前が2つ載る）: {env:?}"
    );
    assert_eq!(value_of(&env, "PATH"), Some("C:/fixed"));
    assert_eq!(value_of(&env, "FOO"), None);
}

/// [BUG-180] **Redirectorの設定の名前は、系統の基準envから戻さない。**
///
/// 戻すと、この子へ注入する設定（別ドメインへ移る子では`HARNESS_COW_EXT_ROOTS`を外したもの）
/// より先に基準envの値が並ぶ。環境ブロックは同じ名前が2つあれば先の方が効くので、
/// **外したはずのワークスペース外への誘導が生き返る**。
///
/// **対で見る**（`B-35`）: 窓口の名前は今までどおり基準envから戻る。片方だけだと、
/// 「harness所有の名前を全部戻さない」実装でも通る。
#[test]
fn the_redirector_settings_are_not_restored_from_the_lineage() {
    let mut base = base();
    base.push((
        redirector_env::EXT_ROOTS.to_string(),
        r"C:\outside".to_string(),
    ));
    base.push((
        redirector_env::DIFF_LAYER.to_string(),
        r"C:\cow\s1".to_string(),
    ));

    let env = env_for_nested(&base, Some(&caller()), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));

    assert_eq!(
        value_of(&env, redirector_env::EXT_ROOTS),
        None,
        "系統のトップレベルのワークスペース外への誘導が、注入設定を待たずに子へ渡っている: {env:?}"
    );
    assert_eq!(value_of(&env, redirector_env::DIFF_LAYER), None, "{env:?}");
    assert_eq!(
        value_of(&env, crate::tier2a::spawnd::REQUEST_PIPE_ENV),
        Some(PIPE),
        "窓口の名前まで戻らなくなっている: {env:?}"
    );
}

/// [BUG-180] 実際に子へ渡る環境を、Daemonと同じ順で組んで見る——
/// `env_for_nested`のあとに、計画した注入設定を[`write_redirector_env`]で書く。
///
/// 別ドメインへ移る子にはワークスペース外への誘導が**無く**、自己ループの子には**1つ**ある。
/// 差分層の置き場はどちらも**1つ**（2つ並ぶと、どちらが効くかが並び順で決まる）。
#[test]
fn a_cross_domain_child_gets_no_ext_roots_but_a_self_loop_child_gets_exactly_one() {
    use crate::tier2a::spawnd::table::ProcessTable;

    let spec = RedirectorSpec::Cow {
        workspace_root: r"C:\ws".to_string(),
        diff_layer_dir: r"C:\cow\s1".to_string(),
        ext_capture_roots: vec![r"C:\outside".to_string()],
        diff_layer_capability_sid: "S-1-15-3-1024-104".to_string(),
    };
    // 系統の基準envは、トップレベルへ同じ設定を注入した後のものである（`spawn_top_level`）。
    let mut lineage_env = base();
    write_redirector_env(&spec, &mut lineage_env, HANDLE(0x1234 as *mut _));

    let entry = DomainSpec {
        name: "entry-profile".to_string(),
        policy_domain: "entry".to_string(),
        container_sid: "S-1-15-2-1-2-3".to_string(),
        capability_sids: vec!["S-1-15-3-1024-102".to_string()],
        identity: DomainIdentitySpec::OwnPackage,
    };
    let target = DomainSpec {
        name: "d0-profile".to_string(),
        policy_domain: "d0".to_string(),
        container_sid: "S-1-15-2-4-5-6".to_string(),
        ..entry.clone()
    };
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, 0x11, 0x1000, entry, lineage_env, Some(spec))
        .expect("register");
    let top = table.resolve(4200, |_| true).expect("resolve");

    let env_for = |plan: &ChildPlan<'_>| {
        let mut env = env_for_nested(&top.base_env, Some(&caller()), &EnvPolicy::CallerPlusDiff(EnvOverride::default()));
        if let Some(spec) = plan.redirector() {
            write_redirector_env(spec, &mut env, HANDLE(0x5678 as *mut _));
        }
        env
    };
    let occurrences = |env: &[(String, String)], name: &str| {
        env.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .count()
    };

    let cross = env_for(&ChildPlan::nested(&top, &target));
    assert_eq!(
        occurrences(&cross, redirector_env::EXT_ROOTS),
        0,
        "別ドメインへ移る子にワークスペース外への誘導が渡っている: {cross:?}"
    );
    assert_eq!(
        occurrences(&cross, redirector_env::DIFF_LAYER),
        1,
        "{cross:?}"
    );

    let self_loop = env_for(&ChildPlan::nested(&top, &top.domain));
    assert_eq!(
        occurrences(&self_loop, redirector_env::EXT_ROOTS),
        1,
        "自己ループの子のワークスペース外への誘導が消えている、または2つ並んでいる: {self_loop:?}"
    );
    assert_eq!(
        occurrences(&self_loop, redirector_env::DIFF_LAYER),
        1,
        "{self_loop:?}"
    );
}

/// 呼び出し元が載せてきた3本（値は区別できるように別々にする）。
fn requested() -> CallerHandles {
    CallerHandles {
        stdin: Some(0x10),
        stdout: Some(0x20),
        stderr: Some(0x30),
    }
}

/// [P5.4b] **普通の辺は、呼び出し元の標準入力・標準出力・標準エラーを3本とも子へ渡す**（決定66(3)(4)。
/// 出力の既定は返す）。P5.3 までは「固定していない、かつ広げない」辺でしか渡しておらず、広げる辺の子は
/// 何も受け取れなかった——その巻き戻りをここで止める。
#[test]
fn an_ordinary_edge_hands_all_three_stdio_handles_to_the_child() {
    assert_eq!(
        caller_handles_for(ChildOutput::Return, false, requested()),
        requested()
    );
}

/// [P5.4b] **Strict の辺は標準入力だけを断つ**（決定66の追記の束。固定argvのシェルは、stdinが端末でなければ
/// そこからコマンドを読む）。出力は辺の設定に従うので、返す辺なら標準出力・標準エラーは渡す（対）
/// ——3本まとめて断つ旧来の形（BUG-161 の`CallerHandles::default()`）へ戻すと、Strict のログ分析が結果を返せない。
#[test]
fn a_strict_edge_cuts_only_the_callers_stdin() {
    assert_eq!(
        caller_handles_for(ChildOutput::Return, true, requested()),
        CallerHandles {
            stdin: None,
            stdout: Some(0x20),
            stderr: Some(0x30),
        }
    );
}

/// [P5.4b] **捨てる辺は標準出力・標準エラーを渡さない**（`None`＝子は`NUL`へ書く）。標準入力は普通の辺なら渡す（対）。
/// Strict かつ捨てる辺は3本とも渡さない（2つの指示は独立している）。
#[test]
fn a_discarding_edge_cuts_stdout_and_stderr_but_not_stdin() {
    assert_eq!(
        caller_handles_for(ChildOutput::Discard, false, requested()),
        CallerHandles {
            stdin: Some(0x10),
            stdout: None,
            stderr: None,
        }
    );
    assert_eq!(
        caller_handles_for(ChildOutput::Discard, true, requested()),
        CallerHandles::default()
    );
}
