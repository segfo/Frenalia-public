//! 入れ子の子へ渡す入力（環境変数・要求受付パイプの名前・呼び出し元の標準入出力）を組む関数。
//!
//! 2026-10-06 に`server.rs`からそのまま移した——`server.rs`は本体1,000行を超えており、
//! P5 の後続の段（子の出力の扱い・環境変数の作り方の統一。決定66）がこの1か所を直せるように、
//! 先に置き場を分けた（`plans/position-domains/P5.md` P5.1）。

use harness_policy::transition::ChildOutput;

use super::CallerHandles;
use crate::tier2a::win_appcontainer::{
    harness_owned_env_names, os_rewritten_env_names, redirector_env,
};

/// [P5.4b] 呼び出し元が載せてきた標準入出力（`requested`）のうち、**子へ渡してよいものだけ**を残す
/// （判定器の[`harness_policy::transition::Allowed::output`]と[`harness_policy::transition::Allowed::strict`]に従う）。
///
/// | 何 | 渡す条件 | 根拠 |
/// |---|---|---|
/// | 標準入力 | **Strict の辺でない**とき | 決定66(3)は普通の辺で渡す。Strict の辺は断つ——固定argvのシェルは、stdinが端末でなければそこからコマンドを読む（BUG-161） |
/// | 標準出力・標準エラー | 出力の設定が**返す**とき | 決定66(4)。捨てる辺では`None`にし、子は`NUL`へ書く |
///
/// **渡さないものは`None`へ差し替える**——`None`のハンドルは Daemon が引き抜かないので、呼び出し元の持ち物は
/// 1つも子へ行かない（`pull_caller_stdio`が`NUL`を開く）。
///
/// # 限界
///
/// 決めるのは呼び出し元の標準入出力だけである。**出力を捨てても、子が呼び出し元の読める場所へ書いたファイル**は
/// 呼び出し元へ届く（組み合わせの対＝決定66の Limit 1 の側の問題）。
pub(super) fn caller_handles_for(
    output: ChildOutput,
    strict: bool,
    requested: CallerHandles,
) -> CallerHandles {
    let CallerHandles {
        stdin,
        stdout,
        stderr,
    } = requested;
    let returns = output.is_return();
    CallerHandles {
        stdin: stdin.filter(|_| !strict),
        stdout: stdout.filter(|_| returns),
        stderr: stderr.filter(|_| returns),
    }
}

/// [段階6f-2] **窓口の名前を、起こす子のenvへDaemonの値で書き込む**（[`Shared::request_pipe`]のdoc）。
///
/// 呼び出し元が同じ名前を載せていても**こちらの値で上書きする**——差し替えられる余地を
/// 残さないのは、[`env_for_nested`]がnestedに対してやっているのと同じ理由である。
///
/// # なぜ関数に出してあるのか
///
/// **系統の全員がこの1点に依存する。** 生成禁止を積んだ子はこの変数が無いと何も起動できず、
/// 失敗の形は「なぜか子プロセスが作れない」という遠い症状になる。だから
/// **昇格もDaemonも要らない場所で対のテストが見張れる**形にしてある。
pub(super) fn force_request_pipe(env: &mut Vec<(String, String)>, request_pipe: &str) {
    env.retain(|(name, _)| name != super::REQUEST_PIPE_ENV);
    env.push((super::REQUEST_PIPE_ENV.to_string(), request_pipe.to_string()));
}

/// 辺のenv方針を呼び出し元の申告へ当て、**harnessが所有する名前だけを系統の値で強制する**
/// （§19.1の表と、2026-09-17の決定3）。
///
/// # 呼び出し元の申告を使うようになった理由（段階6f-1）
///
/// 段階6bは系統のbase env（harnessが組んだトップレベルの環境）に固定していた。
/// §10.1.2が「envの欄を置いてもいけない」と書いていたためだが、**それが守りたかったのは
/// `PATH`と窓口のパイプ名を差し替えられないことだった**。固定のままだと、⑤を既定へ入れた日に
/// **シェルで設定した`$env:FOO`が子へ1つも届かなくなる**——PowerShellのセッション変数や
/// activate系スクリプトが黙って効かなくなる形である。
///
/// そこで**名前を限って塞ぐ**ことにした。規則は1つだけである。
///
/// > harnessが所有する名前（[`harness_owned_env_names`]）は、子の値が**常に系統の値**になる。
/// > 系統に無ければ子からも消える。それ以外は呼び出し元の申告をそのまま通す。
///
/// **「消す」側を落とすと、呼び出し元が`HARNESS_COW_DIFF_LAYER`を勝手に生やせる**
/// （`B-01`: 付与と撤収の対を片方だけにしない）。
///
/// # Redirectorの設定の名前は、ここでは戻さない
///
/// `HARNESS_COW_*`等（[`redirector_env::FROM_INJECTED_SPEC`]）は系統のbase envにも入っているが、
/// それは**トップレベルへ注入した設定から書いた値**である。ここでは消すだけにして、
/// この子へ注入する設定から[`prepare_redirector`]が生成のたびに書き直す。理由は2つある。
///
/// - `HARNESS_COW_READY_HANDLE`は**トップレベルを起こしたときのハンドル値**で、この子には意味が無い
/// - [BUG-180] 別ドメインへ移る子へは`HARNESS_COW_EXT_ROOTS`を外した設定で注入する。
///   基準envの値を戻すと、環境ブロックは同じ名前が2つあれば先の方が効くので、
///   **外したはずの誘導が基準envの値で生き返る**
///
/// # [BUG-160] OSが書き換える名前も、同じ規則で系統の値に戻す
///
/// **理由はharness所有の名前とまったく違うのに、打ち手は同じである。**
/// あちらは「呼び出し元に名乗らせない」ためだが、こちらは
/// **呼び出し元が持っている値が既にOSの出力だから**である
/// （[`os_rewritten_env_names`]に何が起きるかの全文がある）。
///
/// 系統の基準envは、トップレベルの子を起こしたときにharnessがOSへ渡した値そのものなので、
/// これを戻せばOSは**トップレベルと同じ入力から同じ結果**を出す——つまり
/// 「Daemonが起こした子」と「シェルが自分で起こした子」の環境が一致する。
///
/// **剥がすのではなく戻す**のが要点である。綴りから接頭辞を剥がす形だと、
/// 孫・ひ孫と深くなるたびに何回剥がすかを数えることになるが、基準envは系統で1つなので
/// **深さに依らず1回で正しい値になる**。
pub(super) fn env_for_nested(
    base_env: &[(String, String)],
    caller_env: Option<&[(String, String)]>,
    policy: &harness_policy::transition::EnvPolicy,
) -> Vec<(String, String)> {
    use harness_policy::transition::EnvPolicy;
    // **申告が無いときは系統の基準env**（段階6bと同じ）。`Some(空)`とは別物である
    // ——混ぜると`SystemRoot`の無い環境ブロックになり、`CreateProcessW`が
    // `ERROR_ENVVAR_NOT_FOUND`で落ちる（[`SpawnRequest::Spawn::env`]のdoc）。
    let caller_env = caller_env.unwrap_or(base_env);
    let mut env: Vec<(String, String)> = match policy {
        EnvPolicy::PassThrough => caller_env.to_vec(),
        EnvPolicy::Fixed(over) => {
            let mut env: Vec<(String, String)> = caller_env
                .iter()
                .filter(|(name, _)| {
                    !over.unset.iter().any(|u| u.eq_ignore_ascii_case(name))
                        && !over.set.keys().any(|s| s.eq_ignore_ascii_case(name))
                })
                .cloned()
                .collect();
            for (name, value) in &over.set {
                env.push((name.clone(), value.clone()));
            }
            env
        }
    };

    // harnessが所有する名前を、申告から**全部落とす**。辺の`set`で書かれていても落とす
    // ——`policy.json`は人が書くものだが、窓口の名前を宣言で差し替えられる形にはしない。
    //
    // [BUG-160] **OSが書き換える名前も同じ扱いにする**（理由は関数のdoc）。2つの一覧を
    // 1つの繰り返しで処理するのは、**落とす側と戻す側が対だから**である——別々に書くと、
    // 片方の一覧にだけ名前を足した日に「落としたのに戻さない」が生まれる（`B-01`）。
    let forced: Vec<&'static str> = harness_owned_env_names()
        .into_iter()
        .chain(os_rewritten_env_names())
        .collect();
    env.retain(|(name, _)| !forced.iter().any(|o| o.eq_ignore_ascii_case(name)));
    // 系統の値を戻す。**Redirectorの設定の名前は戻さない**（上記。注入する設定から書く）。
    for name in forced {
        if redirector_env::FROM_INJECTED_SPEC
            .iter()
            .any(|spec_name| spec_name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        if let Some((_, value)) = base_env.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            env.push((name.to_string(), value.clone()));
        }
    }
    env
}

/// [段階6b] 辺のenv方針を当てる規則。**Win32を1行も通らないので昇格が要らない。**
#[cfg(test)]
#[path = "nested_inputs_tests.rs"]
mod nested_env_tests;
