//! **分流 U-1 の使い捨て計装**（`plans/handoff/fs-boundary-cost/U-1.md`）。合流時に消す。
//!
//! ## 何のためにあるか
//!
//! FS境界を張る費用には2通りの払い方があり、**課金の単位が違う**。
//! いまの方式は「許可したい1個のファイルに1行書く」ので**ノード1個につき1回**払う。
//! 対抗案（ブローカーがハンドルを手渡す）は書かない代わりに**開くたびに1回**払う。
//! したがって採否は「1ノードあたり平均何回開くか」で決まるが、その数字が1点も無かった。
//!
//! ここが数えるのはその1つだけである——**宣言ツリーの中のパスに対して、
//! 開く操作と属性の問い合わせがそれぞれ何回飛び、異なるパスが何本あったか**。
//!
//! ## 製品の既定挙動は1ビットも変えない
//!
//! 環境変数 `HARNESS_FSCOST_COUNT_DIR` が設定されているときだけ有効になる
//! （[`count_dir`]）。設定されていなければ [`count_only`] が `false` を返し、
//! 各フックは従来の分岐へそのまま落ちる。
//!
//! 有効なときは**逆に、CoWの誘導を全部止める**（リダイレクト・copy-up・台帳追記・
//! ディレクトリ列挙のマージ・リネーム書換のすべて）。計測したいのは
//! 「素のツールが何回開くか」であって、CoWが挟まったときの数ではないため。
//! 言い換えると、このモードのDLLは**観測者であって誘導者ではない**。
//!
//! ## 計器が測定対象を汚さないための設計（`plans/mac-spike/RESULTS.md` §S13-0 の教訓）
//!
//! §S13-0 では、付与記録の計装が**プロセス内の一覧を毎回線形走査**したせいで
//! 1件あたりが9.6倍に膨らみ、「計装を測っていた」ことが後から分かった。同じ形を避けるため:
//!
//! * 1操作あたりの仕事は**ハッシュ表1回の更新だけ**（走査しない・整形しない）。
//! * ファイルへは**1操作ごとに書かない**。書くのは [`DUMP_EVERY_OPS`] 回ごとの全体書き出しと、
//!   プロセス終了時（`DllMain`の`DLL_PROCESS_DETACH`）の1回だけ。
//! * 終了時の書き出しは `try_lock`（待たない）で行う。**プロセス終了時、OSは他のスレッドを
//!   先に止めてから`DllMain`を呼ぶ**ので、止められたスレッドが表のロックを握っていた場合に
//!   `lock()`で待つと**その場で永久に止まる**。待たずに諦め、代わりに `.lost` ファイルを置いて
//!   「このプロセスぶんは落とした」と数えられるようにする（**外挿で埋めないため**）。

use super::*;

use std::sync::atomic::{AtomicU64, Ordering};

/// 全体書き出しの間隔（操作回数）。プロセス終了時の書き出しを取りこぼしたときの
/// 損失をこの回数ぶんに抑えるための保険であって、通常はここに達しない
/// （1回のrustc起動が数千〜数万件）。
const DUMP_EVERY_OPS: u64 = 50_000;

/// 計数結果の出力先。`HARNESS_FSCOST_COUNT_DIR` が空でなければ有効。
pub(crate) fn count_dir() -> Option<&'static PathBuf> {
    static D: OnceLock<Option<PathBuf>> = OnceLock::new();
    D.get_or_init(|| get_env("HARNESS_FSCOST_COUNT_DIR").map(PathBuf::from))
        .as_ref()
}

/// 「観測だけして誘導しない」モードか。フックの分岐はすべてこれ1つで切り替える。
pub(crate) fn count_only() -> bool {
    count_dir().is_some()
}

/// 1パスあたりの計数。`open`は`NtCreateFile`/`NtOpenFile`（＝ハンドルが返る操作＝
/// ブローカー案が肩代わりできる操作）、`attr`は`NtQueryAttributesFile`/
/// `NtQueryFullAttributesFile`（＝パスを渡して答えが返る操作＝**ハンドル手渡しでは
/// 埋まらない**操作、T-5 §3-5）。
#[derive(Default, Clone, Copy)]
pub(crate) struct PathCounts {
    pub(crate) open: u64,
    pub(crate) attr: u64,
}

fn table() -> &'static Mutex<HashMap<String, PathCounts>> {
    static T: OnceLock<Mutex<HashMap<String, PathCounts>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

static TOTAL_OPEN: AtomicU64 = AtomicU64::new(0);
static TOTAL_ATTR: AtomicU64 = AtomicU64::new(0);
/// ワークスペースのルート自身（相対パスが空文字列）への操作。T-2 のノード数え方は
/// ルート自身を数えないので、分子からも外して別立てで持つ。
static ROOT_OPS: AtomicU64 = AtomicU64::new(0);
/// ワークスペース配下ではない分類（`_ext`・差分層の別名）に当たった回数。
/// 測定の構成上ゼロであるべきで、ゼロでなければ数字の読み方が変わる。
static NON_WORKSPACE_OPS: AtomicU64 = AtomicU64::new(0);
/// `<dir>\*` のようなワイルドカード付きの指定（`FindFirstFile` の入口）。ノードではない。
static WILDCARD_OPS: AtomicU64 = AtomicU64::new(0);
static OPS_SINCE_DUMP: AtomicU64 = AtomicU64::new(0);

/// 操作の種別。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// ハンドルが返る（`NtCreateFile`/`NtOpenFile`）。
    Open,
    /// パスを渡して属性が返る（`NtQuery*AttributesFile`）。
    Attr,
}

/// 1件記録する。`kind`が`Workspace`以外なら別カウンタへ寄せるだけで表には載せない。
pub(crate) fn record(kind: TargetKind, ledger_key: &str, op: Op) {
    if kind != TargetKind::Workspace {
        NON_WORKSPACE_OPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // 末尾の区切りは同じノードの別の綴りなので落とす（`sub/` と `sub` を2ノードに割らない）。
    let trimmed = ledger_key.trim_end_matches('/');
    if trimmed.is_empty() {
        ROOT_OPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // ワイルドカードを含むものは**ノードではない**（`FindFirstFile` が `<dir>\*` の形で
    // 投げてくる）。ノード数で割る比の分子に混ぜると水増しになるので、別勘定にする。
    if trimmed.contains('*') || trimmed.contains('?') {
        WILDCARD_OPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // NTFSは大小を区別しないので、綴り違いを同じノードとして畳む。
    let key = trimmed.to_ascii_lowercase();
    {
        let Ok(mut g) = table().lock() else { return };
        let slot = g.entry(key).or_default();
        match op {
            Op::Open => slot.open += 1,
            Op::Attr => slot.attr += 1,
        }
    }
    match op {
        Op::Open => TOTAL_OPEN.fetch_add(1, Ordering::Relaxed),
        Op::Attr => TOTAL_ATTR.fetch_add(1, Ordering::Relaxed),
    };
    if OPS_SINCE_DUMP.fetch_add(1, Ordering::Relaxed) + 1 >= DUMP_EVERY_OPS {
        OPS_SINCE_DUMP.store(0, Ordering::Relaxed);
        dump("periodic");
    }
}

/// このプロセスぶんの出力ファイル名（1プロセス1本、上書き）。PIDは再利用されるので
/// 初期化時刻とイメージ名を混ぜて衝突を避ける。
fn out_stem() -> &'static str {
    static S: OnceLock<String> = OnceLock::new();
    S.get_or_init(|| {
        let pid = unsafe { GetCurrentProcessId() };
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        let exe: String = exe
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        format!("p-{pid}-{}-{exe}", now_millis())
    })
}

/// 表の中身をファイルへ書き出す（全体を上書き）。ロックを握ったままI/Oしない。
pub(crate) fn dump(reason: &str) {
    let Some(dir) = count_dir() else { return };
    let snapshot: Vec<(String, PathCounts)> = match table().try_lock() {
        Ok(g) => g.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        Err(_) => {
            // 待たない（モジュールdocの理由）。落としたことを機械可読に残す。
            let _ = std::fs::write(
                dir.join(format!("{}.lost", out_stem())),
                format!("reason={reason}\n"),
            );
            return;
        }
    };
    let mut text = String::with_capacity(snapshot.len() * 48 + 256);
    text.push_str(&format!("#reason\t{reason}\n"));
    text.push_str(&format!("#pid\t{}\n", unsafe { GetCurrentProcessId() }));
    text.push_str(&format!(
        "#exe\t{}\n",
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    text.push_str(&format!(
        "#total_open\t{}\n",
        TOTAL_OPEN.load(Ordering::Relaxed)
    ));
    text.push_str(&format!(
        "#total_attr\t{}\n",
        TOTAL_ATTR.load(Ordering::Relaxed)
    ));
    text.push_str(&format!("#root_ops\t{}\n", ROOT_OPS.load(Ordering::Relaxed)));
    text.push_str(&format!(
        "#wildcard_ops\t{}\n",
        WILDCARD_OPS.load(Ordering::Relaxed)
    ));
    text.push_str(&format!(
        "#non_workspace_ops\t{}\n",
        NON_WORKSPACE_OPS.load(Ordering::Relaxed)
    ));
    text.push_str(&format!("#distinct_paths\t{}\n", snapshot.len()));
    for (path, c) in &snapshot {
        text.push_str(&format!("{}\t{}\t{}\n", c.open, c.attr, path));
    }
    let _ = std::fs::write(dir.join(format!("{}.tsv", out_stem())), text);
}

/// プロセス生成のたびに1行残す（被覆率の分母を後から数えるため）。
/// 1プロセスにつき1行なので、実行時間への影響は無視できる。
pub(crate) fn record_child(pid: u32, injected: bool, label: &str) {
    let Some(dir) = count_dir() else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("_procs.log"))
    {
        let _ = writeln!(
            f,
            "{}\t{}\t{}\t{}",
            unsafe { GetCurrentProcessId() },
            pid,
            injected,
            label
        );
    }
}
