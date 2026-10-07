//! 入れ子の子へ渡す入力（環境変数・要求受付パイプの名前・呼び出し元の標準入出力）を組む関数。
//!
//! 2026-10-06 に`server.rs`からそのまま移した——`server.rs`は本体1,000行を超えており、
//! P5 の後続の段（子の出力の扱い・環境変数の作り方の統一。決定66）がこの1か所を直せるように、
//! 先に置き場を分けた（`plans/position-domains/P5.md` P5.1）。
//! 呼び出し元の標準入出力を引き抜く部品（`OpenedStdio`・`pull_caller_stdio`・`close_all`・`NUL`を開く関数）は、2026-10-07 に
//! 同じく`server.rs`からそのまま移した（`plans/position-domains/P6.md` P6.4 の準備）。

use harness_policy::transition::ChildOutput;

use super::CallerHandles;
use super::server::{err, SpawnDaemonError};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_GENERIC_WRITE, OPEN_EXISTING};
use windows::Win32::System::Threading::GetCurrentProcess;
use crate::win_common::wide;
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

/// 辺のenv方針（[`EnvPolicy`]）どおりに子へ渡す環境変数を組む
/// （決定66(5)と追記の表、2026-09-17の決定3）。**どちらのモードでも harness 所有の名前は系統の値で強制する。**
///
/// # 呼び出し元の申告を使うようになった理由（段階6f-1。普通の辺がこれである）
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
    // [P5.4c] **出発点だけが2つに分かれる**（決定66(5)と追記）。差分の当て方は1つで、どちらも同じ行を通る。
    //
    // - 普通の辺（[`EnvPolicy::CallerPlusDiff`]）: 呼び出し元の申告。**申告が無いときは系統の基準env**
    //   （段階6bと同じ）。`Some(空)`とは別物である——混ぜると`SystemRoot`の無い環境ブロックになり、
    //   `CreateProcessW`が`ERROR_ENVVAR_NOT_FOUND`で落ちる（[`SpawnRequest::Spawn::env`]のdoc）
    // - Strict の辺（[`EnvPolicy::BaselinePlusDiff`]）: **系統の基準envだけ**。申告は読まない
    //   ——引数を固定しても環境変数で振る舞いを変えられるので、呼び出し元に操作の中身を選ばせない
    let (start, over) = match policy {
        EnvPolicy::CallerPlusDiff(over) => (caller_env.unwrap_or(base_env), over),
        EnvPolicy::BaselinePlusDiff(over) => (base_env, over),
    };
    let mut env: Vec<(String, String)> = start
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

/// 入れ子の子へ渡す環境変数を**1か所で**組む（`server::serve_spawn_request`はこれだけを呼ぶ）。
///
/// 3段を順に当てる——(1) 辺のenv方針（[`env_for_nested`]。呼び出し元の申告か harness の基準＋差分）、
/// (2) harness が所有する名前とOSが書き換える名前の強制（同関数の中）、(3) **遷移先のドメインの
/// 中継プロキシの宛先への差し替え**（[`force_domain_proxy`]。決定69 の前例の(6)。自己ループでは当てない）。
///
/// **3段を呼び出し側で並べない。** 並べると、順番を入れ替えた経路（プロキシの宛先を先に入れてから
/// harness 所有の名前を戻す）が書けてしまい、どちらが勝つかが経路ごとに変わる（`B-05`）。
pub(super) fn env_for_nested_child(
    caller: &super::table::Caller,
    caller_env: Option<&[(String, String)]>,
    policy: &harness_policy::transition::EnvPolicy,
    target_domain: &super::DomainSpec,
) -> Vec<(String, String)> {
    let mut env = env_for_nested(&caller.base_env, caller_env, policy);
    if target_domain != &caller.domain {
        force_domain_proxy(&mut env, &target_domain.proxy_env);
    }
    env
}

/// [決定69 の前例の(6)] **遷移先のドメインの中継プロキシの宛先へ強制で差し替える。**
///
/// | 遷移先のドメイン | 子の環境 |
/// |---|---|
/// | 出口を持つ（`proxy_env`が空でない） | **そのドメインの宛先**（呼び出し元の値は捨てる） |
/// | 出口を持たない（`proxy_env`が空） | 中継プロキシの名前を**全部消す** |
///
/// # なぜ消す側が要るのか
///
/// 消さないと、**出口を持たないドメインの子が呼び出し元（入口）のプロキシの宛先を知っている**ことになる。
/// その子はWFPの既定拒否でそのポートへ繋げないので通信はできないが、「宛先を知らない」と「繋げない」が
/// 混ざると、E2Eで子の失敗の理由が読めなくなる（P5.7 の⑥がまさにこの形で、入口と同じ宛先を知っていた）。
/// それ以上に、**付与と撤収を対にしない形**（`B-01`）そのものである——差し替える側だけ書くと、空のドメインで
/// 呼び出し元の値が生き残る。
///
/// 名前の一覧は[`harness_core::is_proxy_env_name`]が持つ（組む側の`proxy_env_vars`と同じ正本。`B-05`）。
/// **自己ループ（呼び出し元と同じドメイン）では呼ばない**——呼び出し元の環境がそのまま正しい。
pub(super) fn force_domain_proxy(env: &mut Vec<(String, String)>, proxy_env: &[(String, String)]) {
    env.retain(|(name, _)| !harness_core::is_proxy_env_name(name));
    for (name, value) in proxy_env {
        env.push((name.clone(), value.clone()));
    }
}

/// [段階6b] 辺のenv方針を当てる規則。**Win32を1行も通らないので昇格が要らない。**
/// [段階6f-1] 申告が無かった欄の代わりに何を開くか。
///
/// **`Read`の側を作っていないのは意図である**——標準入力の申告が無い子は
/// 「標準入力を持たない」（`None`）であって、「空を読む」ではない。`NUL`を読ませると
/// **即EOF**になり、`None`とほぼ同じに見えるが、`isatty`相当の問い合わせの答えが変わる。
enum Nul {
    Write,
}

/// [段階6f-1] nestedの子へ渡すstdio一式を**集める**入れ物。
///
/// # なぜ入れ物が要るのか
///
/// 3本のうち2本目で失敗したとき、**1本目を閉じなければ漏れる**。返り道ごとに閉じる形にすると、
/// 4本目が生えた日に必ずどれかが漏れる（`B-01`・`B-06`）。集めておいて、
/// 失敗したら[`close_all`]へ渡す。
///
/// 成功した場合は`create_suspended_in_job`が**成否によらず全部閉じる**契約を持っているので、
/// こちら側で閉じるのは「あそこへ渡す前に落ちたとき」だけである。
#[derive(Default)]
pub(super) struct OpenedStdio {
    pub(super) opened: Vec<HANDLE>,
}

impl OpenedStdio {
    /// 呼び出し元のハンドルを引き抜く。申告が無ければ`fallback`（`None`ならハンドル無し）。
    ///
    /// **`DUPLICATE_SAME_ACCESS`で引き抜く。** アクセスを広げない——広げても得る物は無いが、
    /// 「Daemonを通すと権限が増える」形を1つも作らないためである（`P-01`）。
    fn pull(
        &mut self,
        caller_process: HANDLE,
        claimed: Option<u64>,
        fallback: Option<Nul>,
    ) -> Result<Option<HANDLE>, SpawnDaemonError> {
        let handle = match claimed {
            Some(value) => {
                let mut mine = HANDLE::default();
                unsafe {
                    DuplicateHandle(
                        caller_process,
                        HANDLE(value as *mut _),
                        GetCurrentProcess(),
                        &mut mine,
                        0,
                        // 子へ継承させる値なので、複製の時点で継承可にしておく。
                        true,
                        DUPLICATE_SAME_ACCESS,
                    )
                }
                .map_err(|e| {
                    // **嘘の値を送られただけのことがある。** 理由を具体的に残しておかないと、
                    // 「起こせなかった」としか分からない（`B-10`）。
                    err(format!("DuplicateHandle(caller stdio {value:#x}): {e}"))
                })?;
                Some(mine)
            }
            None => match fallback {
                Some(Nul::Write) => Some(open_nul_for_write()?),
                None => None,
            },
        };
        if let Some(handle) = handle {
            self.opened.push(handle);
        }
        Ok(handle)
    }

    /// 集めたハンドルを`inherit_handles`として取り出す。
    pub(super) fn take_for_inherit(self) -> Vec<HANDLE> {
        self.opened
    }
}

/// 3本まとめて引き抜く。**途中で落ちたら、開いたぶんは呼び出し側が[`close_all`]で閉じる。**
///
/// 標準出力・標準エラーは`NUL`の逃げ道があるので必ず値が返る。標準入力だけは
/// 「持たない」があり得る（[`Nul`]のdoc）。
pub(super) fn pull_caller_stdio(
    opened: &mut OpenedStdio,
    caller_process: HANDLE,
    handles: &super::CallerHandles,
) -> Result<(Option<HANDLE>, HANDLE, HANDLE), SpawnDaemonError> {
    let stdin_read = opened.pull(caller_process, handles.stdin, None)?;
    let stdout_write = opened
        .pull(caller_process, handles.stdout, Some(Nul::Write))?
        .expect("the NUL fallback always yields a handle");
    let stderr_write = opened
        .pull(caller_process, handles.stderr, Some(Nul::Write))?
        .expect("the NUL fallback always yields a handle");
    Ok((stdin_read, stdout_write, stderr_write))
}

/// 集めたハンドルを全部閉じる。**`create_suspended_in_job`へ渡す前に落ちたときだけ呼ぶ。**
pub(super) fn close_all(handles: &[HANDLE]) {
    unsafe {
        for handle in handles {
            let _ = CloseHandle(*handle);
        }
    }
}

/// 継承させられる`NUL`（書き込み用）を1本開く。
///
/// # なぜ`NUL`なのか
///
/// [`create_suspended_in_job`]は`stdout_write`・`stderr_write`を**必ず**要求する
/// （`Option`ではない）。nestedの子の出力を運ぶ先が6bには無いので、捨てる先を渡す。
/// **パイプを作って読み捨てるスレッドを立てるより、OSに捨てさせるほうが部品が少ない。**
///
/// **継承させるハンドルなので`bInheritHandle`を立てる。** サンドボックスの子は`NUL`を
/// 自分で開くこともできるが、それは別の話である——ここで渡すのは
/// `STARTUPINFO`の`hStdOutput`に入れる値で、無効ハンドルを入れると子の起動自体が不安定になる。
fn open_nul_for_write() -> Result<HANDLE, SpawnDaemonError> {
    let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    unsafe {
        let name = wide("NUL");
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                | windows::Win32::Storage::FileSystem::FILE_SHARE_READ,
            Some(&sa as *const _),
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(|e| err(format!("CreateFileW(NUL): {e}")))
    }
}

#[cfg(test)]
#[path = "nested_inputs_tests.rs"]
mod nested_env_tests;
