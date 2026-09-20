//! `dev-elevated-runner`の共有部分（プロトコル型・入力検証・パイプIPCヘルパー）。
//! IPCヘルパーは`crates/harness-sandbox/src/netfilterd.rs`と同型のパターン（overlapped I/O・
//! タイムアウト付きread/write・現在ユーザSID限定DACL）を複製したもの。ライフサイクルが
//! 異なる（本クレートは多数のクライアント接続を順番に受け続ける、netfilterdは1セッション
//! 2往復で終了）ため、netfilterd.rs自身のdocコメントに倣い汎用化せず複製する。

use serde::{Deserialize, Serialize};

/// E2E専用のブローカー（[`RunRequest::LaunchPrivhelper`]の実装）。**`KNOWN_TARGETS`とは別の口**で、
/// 唯一クライアント由来の文字列が起動に影響する経路なので、縛りは全部そちらのモジュールが持つ。
///
/// 電文の型（[`PrivhelperLaunchRequest`]）だけは他のワイヤ型と一緒にこのファイルへ置く
/// ——ブローカーの実装は`harness-sandbox`のWindows専用モジュールに依存するが、
/// 型はプラットフォームに依らず直列化できる必要がある。
#[cfg(windows)]
pub mod privhelper_broker;

pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\dev-elevated-runner-";

/// 最終要求からこの時間操作が無ければサーバは自動終了する（タイマーではなく、
/// 「次のクライアント接続を待つ`ConnectNamedPipe`のタイムアウト」として実装する。
/// 退役した%TEMP%キューデーモンの教訓＝生存期間をOSの待機プリミティブに紐付ける、
/// を踏まえたもの。無期限の常駐にはしない）。
pub const IDLE_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// クライアントは自由なコマンドラインを一切送らない。送るのは下表のキー名（記号を含まない
/// 識別子）だけで、実際に実行される`cargo`の引数列はサーバ側にハードコードされた固定値
/// （このテーブル）から引く。クライアント由来の文字列が引数配列へ混入する経路が無いため、
/// 「`&&`/`;`等のシェルメタ文字を拒否する」を個別チェックする必要すらない——キーが完全一致
/// しない時点で拒否される（ユーザー指示: 「どのテストケースを実行するか」だけを送る設計）。
///
/// **例外は`RunRequest::LaunchPrivhelper`ひとつだけ**（E2E専用、[`privhelper_broker`]）。
/// あちらは実行時にしか決まらないパイプ名を運ぶので固定テーブルでは表せず、代わりに
/// 「置き場・ファイル名・中身・パイプ名の形」を受信側で検査する。**このテーブルの性質を
/// 語るときは、その例外も一緒に語ること**（同じ事実を説明する文が2箇所にあると、片方が
/// 実装に追随せず「もう塞がっている」と誤読される、BUG-111）。
/// 新しいテストターゲットが必要になったら、このテーブルへ1行追加する（コード変更が要る、
/// 実行時の任意入力では増やせない）。
pub const KNOWN_TARGETS: &[(&str, &[&str])] = &[
    (
        "e2e-all",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
        ],
    ),
    (
        "e2e-cow-matrix",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_cow_commit_matrix",
        ],
    ),
    (
        "e2e-net-matrix",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_net_policy_matrix",
        ],
    ),
    // BUG-128 の回帰テスト（`docs/bugs/BUG-128.md`）: CoW（`--sandbox tier2a-cow`）下で git が
    // オブジェクトを書き `git commit` が完走することを実機で確かめる。修正前は透過層(Redirector)で
    // 完走しなかった（`.git/objects/pack: Function not implemented`）。`e2e-cow-matrix`とは別に
    // 置くのは、20件の行列全体を回さずこの1測定だけを撃てるようにするため（1要素＝1測定）。
    // フィルタ文字列はテスト関数名と一致していなければならない（`check_tests_actually_ran`が
    // 0件マッチを非0で落とす、BUG-056同型）。
    (
        "e2e-cow-git-injection",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_cow_git_commit_writes_objects_under_the_redirector",
        ],
    ),
    // [⑤'] 遷移MACの強制（`--enforce-transitions`）を**製品の経路で**撃つ。
    // 生成禁止を積んだセッションで、宣言していないプログラムが断られ、その事実が
    // `run_shell`の出力末尾の注記としてモデルへ届くこと——そして宣言すれば通ること（対）。
    // `e2e-all`と別に置くのは、行列全体を回さずこの1測定だけを撃てるようにするため
    // （1要素＝1測定。`e2e-cow-git-injection`と同じ置き方）。
    (
        "e2e-transition-enforced",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "enforcing_transitions_denies_undeclared_programs_and_tells_the_model_how_to_fix_it",
        ],
    ),
    // [残課題#39] 敵対的な`.git/config`に仕掛けられた発火（`diff.external`、BUG-150）を、
    // 遷移MACが止められるかを実機で測る。宣言を0本から1つずつ足していき、**どこまで許すと
    // 発火まで届くか**を数える（鎖の段数は決め打ちしない）。1回の起動で複数のTier2aセッションを
    // 作るので、`e2e-transition-enforced`とは別の的にしてある（1要素＝1測定）。
    (
        "e2e-git-config-transition",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "a_git_config_trap_cannot_reach_its_program_when_transitions_are_enforced",
        ],
    ),
    // [残課題#39の残り] 同じ仕掛けを、**1段ごとに別のドメインへ渡る形**で測る。
    // 上の的が測れているのは「同じドメインの中での許否」までで（§S64）、**鎖は測れていなかった**
    // ——別ドメインで子を起こす機構が無かったためである（#45／#55）。2026-09-20に着地した。
    //
    // **上の的と分けてある**（1要素＝1測定）。混ぜると、同じドメインで止まったのか
    // 跨げなかったのかが1つの合否に畳まれて読めなくなる。
    (
        "e2e-git-config-chain",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "the_git_config_trap_chain_is_judged_across_domains",
        ],
    ),
    // [§S73の宿題] 遷移先ドメインが呼び出し元より**狭い**ことを測る。§S73が測れたのは
    // 「別のドメインとして判定された」までで、**権限が狭いことは1度も測っていなかった**
    // ——遷移先は宣言を持たないので、積まれるのはセッション共通の土台だけだからである。
    //
    // **実ACL（`--fs-allow`）を1本書くので、他の的と混ぜない**（台帳を触る腕は直列化が要る）。
    (
        "e2e-domain-narrowing",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "a_transition_target_domain_is_narrower_than_the_caller",
        ],
    ),
    // [⑤を既定へ入れる準備①] **既定の遷移宣言一式の一次データ**を測る。実務に近い台本を
    // 旗つきで回し、宣言を0本から足しながら**断られたものの一覧**を数える
    // （`plans/DESIGN-MAC-ENFORCEMENT.md`が「旗を立てた回に何が断られるかを数えることが
    // 一次データになる」と定めている）。1回の起動で何度もTier2aセッションを作るので、
    // `e2e-git-config-transition`とは別の的にしてある（1要素＝1測定）。
    (
        "e2e-declaration-survey",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "what_a_realistic_session_needs_declared",
        ],
    ),
    // N8-③-C-WFP: 生TCPの445が本番Tier2aのWFP適用下でも塞がるかを測る
    // （`plans/net-spike/RESULTS.md` N8-③-C）。`e2e-net-matrix`とは別に置くのは、
    // 行列全体を回さずこの1件だけを撃てるようにするため（1要素＝1測定）。
    // 検証用ホストのIPは `C:\harness-e2e\n8-smb-host.txt` から読む——昇格側プロセスへ
    // 呼び出し元の環境変数が引き継がれる保証が無いため（`CLAUDE.md`）。
    (
        "n8-smb445-layer2",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_smb445_layer2",
        ],
    ),
    // W7: ワークスペース**内**の実行が、そのファイルのACEで制御されるかの実測
    // （D-79の前提測定。`plans/DESIGN-SANDBOX-APPPOLICY.md` D-79の「限界」節が
    // 「スクリプトは止まらない」と書いているのを、実機で確かめる側）。
    // 行列全体（`e2e-all`）とは別に置くのは、2ラウンド×8経路のこの測定だけを
    // 撃てるようにするため（1要素＝1測定）。
    (
        "e2e-exec-ace",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            // 前方一致で2本を拾う——`..._ace_matrix`（実行はACEで制御できるか）と
            // `..._runs_but_cannot_reach_the_network`（走っても外へは出られない）。
            // **この2本は必ず一緒に走らせる**: 前者だけを見ると「止まらない＝何でもできる」と
            // 読める（実際にそう読まれた）。フィルタで対にしてある。
            "tier2a_workspace_exec",
        ],
    ),
    // フィルタはモジュール名と一致していなければならない。`cow_diagnostics`→
    // `cow_containment_tests`の改名にここが追随しておらず、CoW封じ込めE2E一式が
    // 「0件マッチ＝exit 0」で黙って緑になっていた（`docs/bugs/BUG-056.md`）。
    // 同クラスの再発は`check_tests_actually_ran`が捕まえる。
    (
        "cow-diagnostics",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::cow_containment_tests",
        ],
    ),
    // 段階5c: Tier2aの一問一答と長寿命セッションが、キャンセル時にJob配下の孫まで
    // 終了することを実機で測る。実ACLを変更するため昇格側から直列実行する。
    (
        "cancel-descendants",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::cancel_descendants_tests",
        ],
    ),
    // 段階5: Spawn Daemon本体の受け入れ（1枚もの`docs/guide/11a-mac-enforcement-map.md`§3の
    // 「対で2本を2組」）。実ACLとAppContainerプロファイルを触るので昇格側から直列実行する。
    //
    // **フィルタはモジュール名と完全に一致していること**——一致しないと0件マッチで
    // 黙って緑になる（BUG-056。`check_tests_actually_ran`がその検問）。
    (
        "spawn-daemon",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::spawnd_e2e_tests",
            // 待ち時間の観測は受け入れではないので、この的からは外す
            // （`spawn-daemon-latency`が別に回す）。混ぜると受け入れが1分近く延びる。
            "--skip",
            "top_level_spawn_latency",
            // [残課題#52] Page Heapの診断も受け入れではないので外す
            // （`spawn-daemon-pageheap`が別に回す）。**理由は所要時間ではない**——
            // Page Heapはレジストリで実行ファイル名に対して機械全体に効くので、
            // 混ぜると受け入れの26本が「デバッグ用アロケータの下の挙動」を測ることになる。
            // **時期が来て一本化するときは、この2行と`spawn-daemon-pageheap`の項を消すだけ**
            // （テスト本体は`spawnd_e2e_tests`の中に在るので移動は起きない）。
            "--skip",
            "the_spawn_matrix_under_page_heap_records_where_it_faults",
        ],
    ),
    // [BUG-160] Daemon経由で起こした子の環境が二重に置き換わる件の測定と受け入れ（対2本）。
    //
    // **受け入れ`spawn-daemon`にも含まれている**（同じモジュールの下に在るので、あちらの
    // フィルタが拾う）。ここに別の的を置いてあるのは、**この2本だけを撃てるようにする**ため
    // ——1本が4つのAppContainerセッションを作るので、直している最中に29本ぶん待たずに済む。
    // `e2e-cow-git-injection`と同じ置き方（1要素＝1測定）。
    (
        "spawn-daemon-env-substitution",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::spawnd_e2e_tests::env_substitution_tests",
        ],
    ),
    // T1の観測（`docs/STATUS.md`残課題#43）: 要求受付パイプの混雑。同時接続数を振って、
    // 何割が混雑に当たり何ミリ秒待つかを測る。**合否の判定を持たない**——赤くなるのは
    // 「測定が成立していない」ときだけである（アクセス拒否が混じった・到着がそろわなかった等）。
    // `spawn-daemon`（受け入れ）と混ぜないのは`spawn-daemon-latency`と同じ理由。
    (
        "spawn-daemon-congestion",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "request_pipe_congestion_by_concurrency",
        ],
    ),
    // [残課題#52] プローブが`0xC0000374`（ヒープ破壊）で落ちる件の**根本原因出し**。
    // Page Heap(Full)を実行ファイルへ載せ、壊した瞬間のアドレスとモジュールをVEHで記録する。
    //
    // **受け入れ`spawn-daemon`と混ぜない理由は所要時間ではない**——Page Heapはレジストリで
    // 機械全体に効くので、受け入れが測る対象そのものを変えてしまう（計器で対象を変えない）。
    //
    // 赤くなるのは測定が成立していないとき——Page Heapが効いていない／記録の受け皿が
    // 繋がっていない／生成禁止を積まない腕で子が1つも生まれない／撤収に失敗した。
    //
    // **もう1つ、「OS側が直った合図」でも赤くなる。** この経路はPage Heapの下では必ず落ちるので
    // プローブの足跡は`starting taskscheduler`で止まる。直ると`finished taskscheduler`が出る
    // ——それを見張って赤にし、暫定対応の撤去へ誘導する（撤去箇所はその`assert`の文面が持つ）。
    // **素の回は今も落ちたり落ちなかったりする**ので、この合図は`spawn-daemon`側には置けない。
    // だから直ったかを確かめたいときは、この的を撃つ。
    //
    // **これは「時期が来たら`spawn-daemon`へ一本化する」前提の特設ターゲットである。**
    //
    // 撤去箇所は**2つだけ**——`spawn-daemon`の`--skip`の2行と、この項。
    // テスト本体は`spawnd_e2e_tests`の中に在るので移動は起きない
    // （`docs/DEV-ENVIRONMENT.md`はキー名を列挙しないので、そちらに消す行は無い）。
    //
    // 撤去の条件: **OS側が直ったとき**（上の見張りが赤で教える）。そのとき経路の使い分けごと
    // 要らなくなるので、この的も畳める。畳んで`spawn-daemon`へ残すなら、**Page Heapを載せた回と
    // 載せない回で受け入れの判定と所要時間が変わらないこと**を1回測ってからにする
    // ——変わるなら、受け入れは製品ではなく計器を測っていることになる。
    (
        "spawn-daemon-pageheap",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "the_spawn_matrix_under_page_heap_records_where_it_faults",
        ],
    ),
    // ④の観測: 直接生成とDaemon経由のトップレベル起動時間。**合否の判定を持たない**
    // （性能の閾値が未定義。数字は後続の判断のための観測値である）。
    (
        "spawn-daemon-latency",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "top_level_spawn_latency",
        ],
    ),
    // ACE付与/撤収（fs passthrough・traverse chain・継承ACE）の実機回帰。BUG-046の修正3で
    // 追加した`traverse_chain_grants_every_ancestor_on_a_test_owned_drive_root`を含む
    // （そちらは`subst`のテスト所有ドライブを使うので単体では昇格不要だが、同モジュールの
    // 他テストが`C:\`直下への書込を伴うためここから回す）。
    (
        "ace-grant-revoke",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::ace_grant_revoke_tests",
        ],
    ),
    // [BUG-112] Redirector DLLの掃除が孤立ACEを本当に回収するかの測定。**昇格は要らない**が、
    // 実物のセッション台帳（`appcontainer-session-ledger.json`）へエントリを開いて自分で
    // 落とす測定を含むため、`cargo test`の並列実行から切り離してここから直列で回す
    // （並列だと、隣のテストが付けたACEの回収名を奪い得る）。フィルタはモジュール名と
    // 一致していなければならない——一致しないと0件マッチで黙って緑になる（BUG-056）。
    // `check_tests_actually_ran`がその検問である。
    (
        "redirector-dll-sweep",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::redirector_dll_sweep_tests",
        ],
    ),
    // M15.7 A-3: ETW実現性スパイク（判定ゲート）。`Microsoft-Windows-Kernel-File`の
    // リアルタイムセッションでACL拒否が観測できるかを実機で確かめる。
    // M15.7: Global Object Access Auditing を AppContainer の package SID へ絞れるかの実測。
    // **マシンの監査ポリシーを一時的に変更する**（テスト側のDropガードで撤去）。
    (
        "etw-audit-scope",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "can_global_object_access_auditing_be_scoped",
        ],
    ),
    // M15.7: 許可レベル×操作種別の真理値表（拒否から操作種別を推定できるかの実測）。
    // M15.7: 削除の拒否がCreate段階で起きるのか、SetInformation段階なのかの実測。
    (
        "etw-delete-denial",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "where_does_a_delete_denial_surface",
        ],
    ),
    // M15.7 / 残課題a-2: 「開けるが操作で落ちる」拒否がどのイベント列として現れるか。
    (
        "etw-operation-denial",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "where_does_an_operation_stage_denial_surface",
        ],
    ),
    (
        "etw-access-matrix",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "access_denials_by_granted_level_and_operation",
        ],
    ),
    // M15.7: 既知の未検証項目（EventsLost・変換不能パス・相関取りこぼし・短命プロセス帰属率・
    // DELETE_PATHの失敗時発火）の実測。
    (
        "etw-diagnostics",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::etw::diagnostics_tests",
        ],
    ),
    // M15.7 A-4d: AppContainer子プロセスでのETW実測（拒否の観測・PID帰属・PackageFullNameの有無）。
    (
        "e2e-policy-learn",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "appcontainer_child_denials",
        ],
    ),
    // BUG-111の残り（シナリオ(A)のE2Eが成立するかの前提）: 昇格したこのデーモン配下から
    // **非昇格（`is_elevated()`が偽）の子プロセス**を起こせるかを測る。
    // **このデーモン経由でしか意味を持たない測定である**——非昇格のシェルから走らせると
    // どの手法も成功して見える（テスト自身が冒頭で昇格を確認して落とす）。
    (
        "spike-deelevation",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "tier2a::deelevation_spike_tests",
        ],
    ),
    // MAC §7.1.1の最初のgo/no-go。Daemon役が保持プロセスへAttachConsoleした状態で、
    // CHILD_PROCESS_RESTRICTED付きAppContainerシェルが実行印と終了コードを返すかを測る。
    // ユーザー指定により昇格区間は必ずこの固定ターゲットから直列で実行する。
    (
        "spike-mac-console-attach",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "go_no_go_attach_console_restricted_shell_runs",
        ],
    ),
    // [2026-09-12・段階6c] **テストの`#[ignore]`が名指ししていたのに、この表に無かった。**
    // `mac_spike_mitigation_etw_tests.rs`は「`dev-elevated-run.exe spike-mac-mitigation-etw`で
    // 走らせろ」と書いているが、的が無いので**その案内どおりに撃つと存在しない的として弾かれる**。
    // 実装ではなく案内の側が嘘をついていた形なので、的を足して合わせる。
    //
    // 測るのは「生成禁止（`CHILD_PROCESS_RESTRICTED`）でカーネルが止めた生成を、ETWで
    // 観測できるか」である（`Microsoft-Windows-Security-Mitigations` Id=4）。段階6cで
    // 待ち行列にカーネル拒否の欄を作ったので、**その欄を実際に埋められることの確かめ先**になる。
    (
        "spike-mac-mitigation-etw",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "mac_spike_mitigation_etw_tests",
        ],
    ),
    // **MAC §7.1.1の測定4はここに載せない。** 実測（2026-09-05）で昇格を1度も要求せずに
    // 完走したので、素の`cargo test`で回す。昇格して測ると保持プロセスの整合性レベルが
    // 本番（非昇格のDaemonが作る）と変わる＝測る世界が変わる（B-08）。
    // 回し方は`plans/mac-spike/RESULTS.md`が持つ。
    (
        "spike-etw-fs",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::etw::spike_tests",
        ],
    ),
    // ポリシー設定モード(Tier1)構想向け: Kernel-Network/DNS-ClientのETW実現性スパイク
    // (plans/POLICY-EDITOR-TOMOYO-DIG.md)。
    (
        "spike-etw-net",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::etw::network_spike_tests",
        ],
    ),
    // ポリシー定義モード(Tier1)構想向け: record-allモードで、package SID無しのTier1
    // プロセスツリーがharness_pid起点の親子継承だけで正しく相関・帰属できるかの実機スパイク
    // (plans/POLICY-EDITOR-TOMOYO-DIG.md、`tier1-proxy-luminous-marshmallow.md`)。
    (
        "spike-etw-tier1-record-all",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::etw::tier1_record_all_spike_tests",
        ],
    ),
    // ポリシーエディタのパス1（Tier1でrecord-all記録）の実機E2E。ビルド済みの
    // `harness-policy-editor.exe`を起動する形なので、収集器の解決経路（current_exeの隣）も
    // 本番と同じものを通る（`crates/harness-policy-editor/tests/record_e2e.rs`）。
    (
        "e2e-policy-editor-record",
        &[
            "test",
            "-p",
            "harness-policy-editor",
            "--test",
            "record_e2e",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ],
    ),
    // ポリシーエディタのパス2（Tier2aでのドメイン記録）の実機E2E。WFPの出口強制daemonを
    // 起こすため管理者権限と外部への到達性が要る（`crates/harness-policy-editor/tests/
    // record_net_e2e.rs`）。**2本目は対のテスト**で、生ソケットがWFPに落とされることを
    // 確かめる——落とされないなら1本目の「到達できた」は強制の証明にならない。
    (
        "e2e-policy-editor-pass2",
        &[
            "test",
            "-p",
            "harness-policy-editor",
            "--test",
            "record_net_e2e",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ],
    ),
    // 上の`e2e-policy-editor-pass2`のうち**FS側の1本だけ**を撃つ。承認したFS宣言が実DACLへ
    // 届くか・宛先SIDがcapability SIDか（残課題#20の不変条件）・取り消し後に何が残るかを測る。
    // 別の口にするのは`e2e-cow-git-injection`と同じ理由で、**1要素＝1測定**にしたいため
    // ——4本まとめて回すとネットワーク3本の所要時間と外部到達性に測定が引きずられる。
    // フィルタ文字列はテスト関数名と一致していなければならない（0件マッチを`check_tests_actually_ran`が
    // 非0で落とす、BUG-056同型）。
    (
        "e2e-policy-editor-exec-ace",
        &[
            "test",
            "-p",
            "harness-policy-editor",
            "--test",
            "record_net_e2e",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "an_executable_that_cannot_be_started_becomes_a_read_exec_candidate_and_then_runs",
        ],
    ),
    // D-56: 昇格daemonの寿命をプロセスへ合わせたときの**機構E2E**。実daemonを
    // `apply → clear → apply → teardown`と駆動し、各段でWFPフィルタの実件数を数える
    // （`crates/harness-sandbox/src/tier2a/netfilterd.rs`の`reuse_e2e`）。
    // 固定するのは「待機中は0件」「畳んだ直後の再適用が通る」「Teardownでdaemonが終わる」。
    (
        "netfilterd-reuse",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "netfilterd::reuse_e2e",
        ],
    ),
    // D-56 段階2: 収集器daemonを`StartCollect → StopCollect → StartCollect → Teardown`と
    // 駆動する。**非昇格でも走る2件**（プロトコルの検出器・拒否後の接続維持）はここに含めず
    // 通常の`cargo test`で回るので、このターゲットが拾うのは実際にETWセッションを張る分
    // ——固定するのは「待機中はセッションを持たない」「畳んだ直後の再開が通る」。
    (
        "policy-learnd-reuse",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::reuse_tests",
        ],
    ),
    // 段階6d（argv観測の製品化、`plans/DESIGN-MAC-ENFORCEMENT.md` §10.3）の受け入れ。
    // **直列で撃つ**——片方はマシン全体のsystem loggerの枠を意図的に埋めるので、
    // 並行して走る測定があると道連れにする（`--test-threads=1`）。
    (
        "policy-learn-argv",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::argv_e2e_tests",
        ],
    ),
    (
        "e2e-loopback-exemption",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "loopback",
        ],
    ),
    // 中断された`etw-fs-allow-reach`が残したプローブツリー（`C:\harness-fsallow-<pid>`）を掃く。
    // 後片付けは`Ctrl+C`・クラッシュでは走らず、残骸は**昇格して作られたので非昇格では消せない**
    // ——だから昇格して掃く口が別に要る（`docs/bugs/BUG-140.md`層4）。**台帳には触れない**ので、
    // 実体を消した後に`harness fs prune`（非昇格でよい）を撃つこと。
    // フィルタ文字列はテスト関数名と一致していなければならない（`check_tests_actually_ran`が
    // 0件マッチを非0で落とす、BUG-056同型）。
    (
        "etw-fs-allow-sweep",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "sweep_probe_trees_left_by_interrupted_runs",
        ],
    ),
    // M15.5: MCPサーバ隔離（D-38）の実機E2E。workspace/`.harness`への到達不可（残課題#4）と、
    // サーバ別の出口allowlist（残課題#3）。`--test-threads=1`はAppContainerプロファイル・
    // WFPというマシン全体の共有状態を触るため（Tier2a残課題#4と同じ理由）。
    (
        "e2e-mcp",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "win_appcontainer::mcp_e2e_tests",
        ],
    ),
    // T2: **MCP stdioの子が要求受付パイプへ到達できないこと**を、製品のトランスポート
    // （`harness-mcp`の`AppContainerTransportFactory`）を実際に通して測る
    // （`plans/DESIGN-MAC-DOMAIN.md` §22.2.2）。`e2e-mcp`（D-38の隔離）とは**別の口**にしてある
    // ——あちらは`harness-sandbox`のテストで、製品のトランスポートを1行も通らない。
    //
    // **昇格は要らない**（プロファイル作成もACE付与先もこのユーザーが所有する）が、
    // AppContainerプロファイルという**マシン全体の共有状態**を触るのでここから直列で回す
    // （`redirector-dll-sweep`と同じ理由）。事前に`tier2a_proc_probe.exe`の配置が要る。
    (
        "e2e-mcp-spawn-reach",
        &[
            "test",
            "-p",
            "harness-mcp",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "transport_stdio_e2e_tests",
        ],
    ),
    // T2の対の片側: **ポリシーエディタのパス2の子は要求受付パイプへ届き、
    // `unknown_source_domain`で断られる**。`e2e-policy-editor-pass2`へ混ぜないのは
    // `e2e-policy-editor-exec-ace`と同じ理由で、**1要素＝1測定**にするため
    // ——あちらの3本は外部到達性を要するので、所要時間がそちらに引きずられる。
    // フィルタ文字列はテスト関数名と一致していなければならない（0件マッチを
    // `check_tests_actually_ran`が非0で落とす、BUG-056同型）。
    (
        "e2e-policy-editor-pass2-spawn-reach",
        &[
            "test",
            "-p",
            "harness-policy-editor",
            "--test",
            "record_net_e2e",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "pass2_reaches_the_request_pipe",
        ],
    ),
    (
        "e2e-wfp-multisession",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "wfp::tests::e2e_",
        ],
    ),
    (
        "e2e-sandbox-vm-ignored",
        &[
            "test",
            "-p",
            "harness-sandbox-vm",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ],
    ),
    // --- `plans/PLAN-M15.7-FOLLOWUP.md` W1/W6/W7 用（テスト本体は各工程で書く） ---
    //
    // **キーの追加はデーモン停止＋再ビルド＋UACを伴うので、テストより先にまとめて登録する。**
    // ここに書いたフィルタ文字列はテスト名に対する契約であり、後から名前を変えると
    // 再びこの往復が要る。テストが存在しない間これら3件は`check_tests_actually_ran`により
    // **非0で失敗する**（「まだ書いていない」を緑と誤認しないため、意図した挙動）。
    //
    // W1: `--fs-allow`の到達性を、祖先が未付与の状態で実測する。
    (
        "etw-fs-allow-reach",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "policy_learnd::etw::fs_allow_reach_tests",
        ],
    ),
    // W6: `--fs-allow`を実CLIフラグ経由で通すout-of-process E2E。
    (
        "e2e-fs-allow",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_fs_allow",
        ],
    ),
    // W7: netfilterdからのpolicy-learnd連鎖起動（追加UACなし経路）をassertにする。
    (
        "e2e-chain-launch",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_chain_launch",
        ],
    ),
    // M16（認知レイヤー残課題#4）: 妥当性の経路を**本物のMCPサーバ**で通す。
    // 事前に`cargo build -p harness-mcp --bin mcp-mock-server`が要る（テスト側が不在を検出して
    // 手順付きで落とす）。`e2e-policy-learn`と**同時に走らせない**（docs/INDEX.mdの並列レーン注記）。
    (
        "e2e-mcp-corroboration",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_mcp_corroboration",
        ],
    ),
    // D-27（`plans/VERIFY-TODO.md`項目1）: fs passthrough台帳の参照カウントと、並行起動時の
    // read-modify-write直列化。**保護対象の`fs-passthrough-ledger.json`を触る**ため、
    // 他のE2Eと同時に走らせない。
    (
        "e2e-fs-ledger",
        &[
            "test",
            "-p",
            "harness-cli",
            "--features",
            "e2e-mock",
            "--",
            "--ignored",
            "--nocapture",
            "tier2a_fs_ledger_lifecycle",
        ],
    ),
    // `dev-elevated-runner`自身は除外する。デーモン(`dev-elevated-runnerd.exe`)がこの
    // コマンドを実行している間、自分自身の実行ファイルは起動中でロックされておりリンクし
    // 直せない（実機で`error: failed to remove file ...dev-elevated-runnerd.exe: アクセスが
    // 拒否されました`を確認済み）。本セッションで再ビルドが必要な対象はharness本体側だけ。
    // D-81の検証用NTFSボリューム（VHD）。**作成と撤収を別ターゲットにしてある**——
    // 昇格側プロセスへ呼び出し元の環境変数が引き継がれる保証が無いので、1つのターゲットに
    // 引数で向きを渡すと「撤収したつもりで作成していた」という無言の取り違えになる
    // （`n2-loopback-exemption-add`／`-remove`と同じ理由）。
    (
        "vhd-ntfs-create",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "vhd_ntfs_create",
        ],
    ),
    (
        "vhd-ntfs-remove",
        &[
            "test",
            "-p",
            "harness-sandbox",
            "--lib",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "vhd_ntfs_remove",
        ],
    ),
    // 残課題#53の計測（`crates/harness-mcp/tests/loopback_drop_probe.rs`）: ループバックの
    // 接続要求を**どの部品がどの理由で捨てているか**を`pktmon`に名指しさせる。
    // **開始・報告・停止を3つのキーに分けてある**——昇格側プロセスへ呼び出し元の環境変数が
    // 引き継がれる保証が無いので、1つのキーに向きを渡すと「停止したつもりで開始していた」
    // という無言の取り違えになる（`n2-loopback-exemption-add`／`-remove`と同じ理由）。
    // **監視セッションとフィルタは実マシンに残る共有状態なので、`-start`を撃ったら
    // 必ず`-stop`を撃つこと。**
    (
        "pktmon-drop-start",
        &[
            "test",
            "-p",
            "harness-mcp",
            "--test",
            "loopback_drop_probe",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "start_the_loopback_drop_monitor",
        ],
    ),
    // パケットの計数ではなくTCPIPの**イベント**を集める側（`127.0.0.1`はNDISを通らないので
    // パケット計数からは原理的に見えない。同ファイルのdoc参照）。**停止は`pktmon-drop-stop`と
    // 共通**——停止のキーを2つに割ると「どちらを撃つか」の判断が要り、外した回にセッションが残る。
    (
        "pktmon-trace-start",
        &[
            "test",
            "-p",
            "harness-mcp",
            "--test",
            "loopback_drop_probe",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "start_the_tcpip_event_trace",
        ],
    ),
    (
        "pktmon-drop-report",
        &[
            "test",
            "-p",
            "harness-mcp",
            "--test",
            "loopback_drop_probe",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "report_the_loopback_drops",
        ],
    ),
    (
        "pktmon-drop-stop",
        &[
            "test",
            "-p",
            "harness-mcp",
            "--test",
            "loopback_drop_probe",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "stop_the_loopback_drop_monitor",
        ],
    ),
    (
        "workspace-build",
        &["build", "--workspace", "--exclude", "dev-elevated-runner"],
    ),
    (
        "workspace-clippy",
        &[
            "clippy",
            "--workspace",
            "--exclude",
            "dev-elevated-runner",
            "--all-targets",
        ],
    ),
    (
        "workspace-test",
        &["test", "--workspace", "--exclude", "dev-elevated-runner"],
    ),
];

/// クライアント→デーモンの要求。
///
/// **`kind`タグ付きで直列化する。** タグの無い構造体のままフィールドを足すと、古いデーモンが
/// 新しい要求を「知らないフィールドは無視」して**別の要求として実行**し得る。タグを必須に
/// すれば、古い個体は解釈できずに落ちる（無言の取り違えより、はっきり落ちる方を選ぶ）。
/// 電文の型を変えたので、**動いているデーモンは先に止めてから再ビルドする**
/// （`docs/DEV-ENVIRONMENT.md`の`KNOWN_TARGETS`変更手順と同じ）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RunRequest {
    /// 固定テーブルから`cargo`引数列を引いて実行する（`dev-elevated-run.exe <target>`）。
    Target {
        /// `KNOWN_TARGETS`のキーのいずれかと完全一致する必要がある。
        target: String,
    },
    /// **E2E専用**: `harness-privhelper.exe`を昇格したまま起こす（`privhelper_broker`）。
    LaunchPrivhelper(PrivhelperLaunchRequest),
}

/// クライアント（非昇格のharness本体）→デーモンの、privhelper起動要求の中身。
///
/// **パイプ名は実行時に決まる**ので`KNOWN_TARGETS`の固定テーブルでは表せない。これが
/// このデーモンで唯一「クライアント由来の文字列が起動に影響する」経路であり、だからこそ
/// 受信側（`privhelper_broker`）が置き場・ファイル名・中身・パイプ名の形を検査する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivhelperLaunchRequest {
    /// 非昇格側が作って待っている名前付きパイプ（`\\.\pipe\harness-privhelper-...`）。
    pub pipe_name: String,
    /// `harness-privhelper.exe`が置いてあるディレクトリ（`C:\harness-e2e\`配下）。
    pub launcher_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// サーバ側が権威的に検証する（クライアント側でも同じ関数を使うが、クライアントを
/// 信用しない——実際にコマンドを起動するのはサーバ側の`resolve_target`であり、
/// そちらも独立に`KNOWN_TARGETS`の完全一致を要求する）。
pub fn validate_target(target: &str) -> Result<(), String> {
    if KNOWN_TARGETS.iter().any(|(name, _)| *name == target) {
        Ok(())
    } else {
        let known: Vec<&str> = KNOWN_TARGETS.iter().map(|(name, _)| *name).collect();
        Err(format!(
            "unknown target {target:?} (known targets: {known:?})"
        ))
    }
}

/// `target`に対応する固定引数列を返す。`validate_target`と同じ完全一致判定を独立に
/// 行うため、こちらを呼ぶだけでも安全（`validate_target`を呼び忘れても任意引数は
/// 実行されない）。
pub fn resolve_target_args(target: &str) -> Option<&'static [&'static str]> {
    KNOWN_TARGETS
        .iter()
        .find(|(name, _)| *name == target)
        .map(|(_, args)| *args)
}

/// `cargo test`のstdoutから、**実際に実行された**テスト件数（passed + failed）を数える。
///
/// テストハーネスはバイナリごとに
/// `test result: ok. 12 passed; 0 failed; 3 ignored; 0 measured; 45 filtered out; ...`
/// を1行印字する。複数のテストバイナリが走る対象（`e2e-all`等）では**合計**を返す
/// ——個々のバイナリが0件になるのは正常（`--ignored`が1つも当たらないターゲットがある）で、
/// 「どれも走らなかった」だけが異常だからである。
///
/// `test result:`行が1つも無ければ`None`。これは「0件走った」とは違う状態
/// （テストハーネスがそもそも起動していない＝ビルド失敗等）なので、呼び出し側が
/// 区別できるようにする。
pub fn executed_test_count(stdout: &str) -> Option<u64> {
    let mut total: Option<u64> = None;
    for line in stdout.lines() {
        let Some(summary) = line.trim_start().strip_prefix("test result:") else {
            continue;
        };
        let passed = count_before(summary, "passed").unwrap_or(0);
        let failed = count_before(summary, "failed").unwrap_or(0);
        total = Some(total.unwrap_or(0) + passed + failed);
    }
    total
}

/// `ok. 12 passed; 0 failed; ...`から`label`直前の数値を取り出す。
///
/// 失敗した実行の要約は`FAILED. 10 passed; 2 failed; ...`という形なので、
/// 小文字の`failed`を探せば見出し語の`FAILED.`とは衝突しない。
fn count_before(summary: &str, label: &str) -> Option<u64> {
    let index = summary.find(label)?;
    summary[..index]
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()
}

/// テストターゲットなのに1件も走らなかったら、それは「緑」ではなく**壊れたフィルタ**である。
///
/// `cargo test`はフィルタが1件もマッチしなくてもexit 0を返すため、`KNOWN_TARGETS`の
/// フィルタ文字列がモジュール改名に追随しそこねると、E2E一式が黙って走らなくなる
/// （`docs/bugs/BUG-056.md`。CoW封じ込めE2E 17件が実際にこれを踏んだ）。
/// **「テストが走っていない」は「テストが通った」と外形上区別が付かない**ので、
/// ここで明示的に潰す。
///
/// テストを実行しないターゲット（`workspace-build`・`workspace-clippy`）は対象外。
/// 未知のキーも`Ok`にする——入力検証は[`validate_target`]の責務であり、ここを
/// 意味の違う2つ目のゲートにしない。
pub fn check_tests_actually_ran(target: &str, stdout: &str) -> Result<(), String> {
    let Some(args) = resolve_target_args(target) else {
        return Ok(());
    };
    if args.first() != Some(&"test") {
        return Ok(());
    }
    match executed_test_count(stdout) {
        Some(0) => Err(format!(
            "target {target:?} reported success but ran 0 tests. `cargo test` exits 0 when its \
             filter matches nothing, so this is a broken filter, not a pass. Check the filter for \
             {target:?} in KNOWN_TARGETS (crates/dev-elevated-runner/src/lib.rs) against the \
             actual module/test names -- see docs/bugs/BUG-056.md"
        )),
        None => Err(format!(
            "target {target:?} reported success but its output contains no test-harness summary \
             ('test result:' line). The test binaries probably never started"
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-056の実物。`cargo test -p harness-sandbox --lib -- --ignored --test-threads=1
    /// --nocapture win_appcontainer::cow_diagnostics`（改名前のフィルタ）が実際に印字した出力。
    /// **捏造せず実機から採る**——このクラスを閉じる関数が、想像した書式ではなく
    /// 本物の書式を相手にしていることを固定するため。
    const ZERO_TESTS: &str =
        "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; \
                              0 measured; 252 filtered out; finished in 0.00s\n";

    #[test]
    fn a_normal_run_counts_the_tests_it_executed() {
        let stdout = "running 12 tests\n\ntest result: ok. 12 passed; 0 failed; 3 ignored; \
                      0 measured; 45 filtered out; finished in 1.23s\n";
        assert_eq!(executed_test_count(stdout), Some(12));
        assert!(check_tests_actually_ran("cow-diagnostics", stdout).is_ok());
    }

    /// 実行件数であって成功件数ではない。失敗を含む実行は「走った」に数える
    /// （失敗そのものは終了コードが既に伝えている）。見出し語の`FAILED.`を
    /// `failed`と取り違えないことも、ここで一緒に固定される。
    #[test]
    fn a_failing_run_still_counts_as_having_run() {
        let stdout = "test result: FAILED. 10 passed; 2 failed; 0 ignored; 0 measured; \
                      0 filtered out; finished in 4.00s\n";
        assert_eq!(executed_test_count(stdout), Some(12));
    }

    /// 複数のテストバイナリが走る対象（`e2e-all`）では、0件のバイナリが混ざるのは正常。
    /// 判定は合計で行う。
    #[test]
    fn one_empty_binary_among_several_is_not_a_failure() {
        let stdout = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; \
                      0 measured; 7 filtered out; finished in 0.00s\n\nrunning 3 tests\n\n\
                      test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; \
                      0 filtered out; finished in 9.00s\n";
        assert_eq!(executed_test_count(stdout), Some(3));
        assert!(check_tests_actually_ran("e2e-all", stdout).is_ok());
    }

    /// BUG-056そのもの。全バイナリ0件なら、exit 0でも失敗にする。
    #[test]
    fn a_target_that_ran_no_tests_at_all_is_reported_as_broken() {
        assert_eq!(executed_test_count(ZERO_TESTS), Some(0));
        let error = check_tests_actually_ran("cow-diagnostics", ZERO_TESTS)
            .expect_err("0 tests must not be treated as a pass");
        assert!(error.contains("ran 0 tests"), "{error}");
        // 次に踏む人が原因へ最短で行けること（メッセージの中身も契約の一部）。
        assert!(error.contains("KNOWN_TARGETS"), "{error}");
        assert!(error.contains("BUG-056"), "{error}");
    }

    /// テストハーネスが1度も起動しなかった場合は「0件」とは別の失敗として報告する。
    #[test]
    fn output_without_any_harness_summary_is_reported_separately() {
        assert_eq!(
            executed_test_count("error: could not compile `harness-cli`"),
            None
        );
        let error = check_tests_actually_ran("cow-diagnostics", "error: could not compile")
            .expect_err("a missing harness summary must not be treated as a pass");
        assert!(error.contains("no test-harness summary"), "{error}");
    }

    /// テストを実行しないターゲットは対象外（`cargo build`の出力に`test result:`は無い）。
    #[test]
    fn non_test_targets_are_out_of_scope() {
        assert!(check_tests_actually_ran("workspace-build", "    Finished `dev` profile").is_ok());
        assert!(check_tests_actually_ran("workspace-clippy", "").is_ok());
        // 入力検証は`validate_target`の責務なので、未知のキーはここでは判定しない。
        assert!(check_tests_actually_ran("no-such-target", ZERO_TESTS).is_ok());
        assert!(validate_target("no-such-target").is_err());
    }

    /// 2種類の要求が、どちらも自分の`kind`として往復すること（**送る側と受け取る側で
    /// 閉じているかを両方向で見る**、B-03）。
    #[test]
    fn both_request_kinds_round_trip() {
        let target = RunRequest::Target {
            target: "e2e-net-matrix".to_string(),
        };
        let launch = RunRequest::LaunchPrivhelper(PrivhelperLaunchRequest {
            pipe_name: r"\\.\pipe\harness-privhelper-1-0-2".to_string(),
            launcher_dir: std::path::PathBuf::from(r"C:\harness-e2e\scenarioA"),
        });

        for request in [target, launch] {
            let bytes = serde_json::to_vec(&request).unwrap();
            let parsed: RunRequest = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(format!("{parsed:?}"), format!("{request:?}"));
        }
    }

    /// タグの無い**旧形式**は受け付けない。ここが通ってしまうと、要求の種類を取り違えた
    /// まま昇格側が動く（古いクライアントが生きていたときに、無言で別の意味になる）。
    #[test]
    fn a_request_without_a_kind_tag_is_rejected() {
        let legacy = br#"{"target":"e2e-net-matrix"}"#;

        let parsed: Result<RunRequest, _> = serde_json::from_slice(legacy);

        assert!(parsed.is_err(), "an untagged legacy request must not parse");
    }

    /// `KNOWN_TARGETS`の中で`cargo test`を走らせる全ターゲットが、この検知の対象に入ること。
    /// 新しいテストターゲットを足したときに、この検知だけ素通りする形にならないよう固定する。
    #[test]
    fn every_test_target_is_covered_by_the_zero_test_check() {
        for (name, args) in KNOWN_TARGETS {
            if args.first() != Some(&"test") {
                continue;
            }
            assert!(
                check_tests_actually_ran(name, ZERO_TESTS).is_err(),
                "test target {name:?} would silently pass with 0 tests"
            );
        }
    }
}

#[cfg(windows)]
pub mod win {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WAIT_OBJECT_0,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::IO::OVERLAPPED;

    #[derive(Debug)]
    pub enum IpcError {
        Ipc(String),
        Win32(String),
    }

    impl std::fmt::Display for IpcError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                IpcError::Ipc(s) => write!(f, "ipc error: {s}"),
                IpcError::Win32(s) => write!(f, "win32 error: {s}"),
            }
        }
    }

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn current_user_sid_string() -> windows::core::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
            let mut ret_len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
            let mut buf = vec![0u8; ret_len as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                ret_len,
                &mut ret_len,
            )?;
            let _ = CloseHandle(token);
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut sid_str = windows::core::PWSTR::null();
            ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str)?;
            let s = sid_str.to_string()?;
            let _ = windows::Win32::Foundation::LocalFree(HLOCAL(sid_str.0 as *mut _));
            Ok(s)
        }
    }

    pub fn pipe_name_for_current_user() -> windows::core::Result<String> {
        Ok(format!("{PIPE_NAME_PREFIX}{}", current_user_sid_string()?))
    }

    pub fn user_only_security_attributes(sid: &str) -> windows::core::Result<SECURITY_ATTRIBUTES> {
        let sddl = format!("D:(A;;GA;;;{sid})");
        unsafe {
            let sddl_w = wide(&sddl);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
            Ok(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            })
        }
    }

    pub fn run_overlapped<F>(
        handle: HANDLE,
        timeout: std::time::Duration,
        op_name: &str,
        start: F,
    ) -> Result<u32, IpcError>
    where
        F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
    {
        use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
        use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult};
        unsafe {
            let event = CreateEventW(None, true, false, PCWSTR::null())
                .map_err(|e| IpcError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
            let mut overlapped = OVERLAPPED {
                hEvent: event,
                ..Default::default()
            };
            let pending = match start(&mut overlapped as *mut _) {
                Ok(()) => false,
                Err(e) => {
                    let code = e.code();
                    if code == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) {
                        true
                    } else if code == windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                        let _ = CloseHandle(event);
                        return Ok(0);
                    } else {
                        let _ = CloseHandle(event);
                        return Err(IpcError::Ipc(format!("{op_name} failed to start: {e}")));
                    }
                }
            };
            if pending {
                let wait =
                    WaitForSingleObject(event, timeout.as_millis().min(u32::MAX as u128) as u32);
                if wait != WAIT_OBJECT_0 {
                    let _ = CancelIoEx(handle, Some(&overlapped as *const _));
                    let mut transferred = 0u32;
                    let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
                    let _ = CloseHandle(event);
                    return Err(IpcError::Ipc(format!(
                        "{op_name} timed out after {timeout:?}"
                    )));
                }
            }
            let mut transferred = 0u32;
            let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
            let _ = CloseHandle(event);
            result.map_err(|e| {
                IpcError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}"))
            })?;
            Ok(transferred)
        }
    }

    pub fn write_all_timeout(
        handle: HANDLE,
        buf: &[u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &buf[offset..];
            let written = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
                WriteFile(handle, Some(slice), None, Some(ov))
            })?;
            if written == 0 {
                return Err(IpcError::Ipc("WriteFile wrote 0 bytes".to_string()));
            }
            offset += written as usize;
        }
        Ok(())
    }

    pub fn read_exact_timeout(
        handle: HANDLE,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &mut buf[offset..];
            let read = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
                ReadFile(handle, Some(slice), None, Some(ov))
            })?;
            if read == 0 {
                return Err(IpcError::Ipc(
                    "ReadFile read 0 bytes (pipe closed?)".to_string(),
                ));
            }
            offset += read as usize;
        }
        Ok(())
    }

    pub fn write_framed_timeout(
        handle: HANDLE,
        payload: &[u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        let len = (payload.len() as u32).to_le_bytes();
        write_all_timeout(handle, &len, timeout)?;
        write_all_timeout(handle, payload, timeout)
    }

    pub fn read_framed_timeout(
        handle: HANDLE,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, IpcError> {
        let mut len_buf = [0u8; 4];
        read_exact_timeout(handle, &mut len_buf, timeout)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            read_exact_timeout(handle, &mut payload, timeout)?;
        }
        Ok(payload)
    }

    pub fn connect_with_timeout(
        pipe: HANDLE,
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::System::Pipes::ConnectNamedPipe;
        run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
            ConnectNamedPipe(pipe, Some(ov))
        })?;
        Ok(())
    }
}
