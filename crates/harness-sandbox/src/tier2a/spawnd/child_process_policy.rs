//! 子プロセスを作れるかの姿勢（`CHILD_PROCESS_RESTRICTED`を積むか）と、このプロセスが選んだ姿勢の宣言・読み口
//! （`spawnd/mod.rs`からそのまま移した。`plans/position-domains/P6.md` P6.4 の準備）。

/// 子プロセス自身が、さらに子プロセスを作れるか（設計書`plans/DESIGN-MAC-ENFORCEMENT.md`§7）。
///
/// # これは何を指定するものか
///
/// `CreateProcessW`へ渡す属性リストの1項目
/// （`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`）である。`Restricted`で起こした
/// プロセスは、**どんな方法でも子プロセスを作れなくなる**——`CreateProcessW`のフックを
/// 迂回して`NtCreateUserProcess`を直接呼んでも、カーネルが`STATUS_CHILD_PROCESS_BLOCKED`で
/// 拒否する（2026-08-13に6経路すべてで実測、`plans/mac-spike/RESULTS.md`§S1）。
/// **起動の瞬間に1回決まり、後から付けることも外すこともできない。**
///
/// # 「どの子なら許すか」はここに入らない
///
/// この属性が持つのは「作れない」の1ビットだけで、許可の情報を1つも運ばない。
/// 代わりに起こすのはSpawn Daemonで、Redirector DLLはサンドボックスの中の
/// `CreateProcessW`呼び出しを**Daemonへの頼み方へ変換する**だけである（許可証ではない）。
/// 何を許すかを判定するのは遷移ポリシーの評価で、**段階6b（2026-09-12）でDaemonがそれを
/// 呼ぶようになった**——宣言した辺に一致する要求は実際に起こり、一致しないものは
/// [`DenyReason::Transition`]で断られる。
///
/// # なぜ製品の既定が`Unrestricted`のままなのか（**理由が2回入れ替わった**）
///
/// **もう「判定が無いから」でも「フックが頼まないから」でもない。** 6bで判定が入り、
/// **6f-2（2026-09-17）でフックがDaemonへの依頼へ変換するようになった**
/// ——生成禁止を積んだ子の`CreateProcessW`は、いま実際に窓口を通って起きる。
///
/// **6f-3（2026-09-18）で、拒否がモデルへ届くようになった**——`run_shell`が、そのコマンドの
/// 間に断られた遷移を出力末尾へ注記し、`can_run_program`の存在を教える（§19.3.8）。
///
/// **決め事はもう残っていない**（2026-09-18に残課題#50が決着した）。生成禁止を積む構成では、
/// Tier2aシェルの候補から**アプリの仕組みを通る綴り**（ストアの実行エイリアス・MSIXの実体）を
/// 外してWindows PowerShell 5.1へ落とす——どちらも遷移先にできないと測ってある
/// （`plans/mac-spike/RESULTS.md` §S62）。切り替えは[`Self::PRODUCT_DEFAULT`]を読むので、
/// **姿勢を変えた日に一緒に動く。**
///
/// 残っているのは**書くこと**である——既定の遷移宣言一式と、カーネル拒否の購読者
/// （§10.2が「⑤を既定へ入れる回」と定めている）。
///
/// いま`Restricted`を選べるのは受入テストだけである。
/// **この2択は「機構を作るか」ではなく「既定へ入れるか」の軸である**
/// （`docs/guide/11a-mac-enforcement-map.md`§2）。
///
/// # 電文には載らない
///
/// Daemon1本につき1つで、要求ごとには切り替えられない（`server::serve`の引数として
/// 起動時に決まる）。理由は[`SpawnTopLevelRequest`]の末尾のコメントにある
/// ——**落とせる形の欄を置くと、いつか落とされる**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildProcessPolicy {
    /// 子プロセスを作れる（**今日の製品の既定**）。
    Unrestricted,
    /// OSが子プロセス生成そのものを拒否する（段階⑤）。
    Restricted,
}

/// このホストプロセスが選んだ姿勢（[`declare_child_process_policy`]が1回だけ書く）。
static DECLARED_CHILD_PROCESS_POLICY: std::sync::OnceLock<ChildProcessPolicy> =
    std::sync::OnceLock::new();

/// **このプロセスの姿勢を宣言する**（最初の宣言が勝ち、勝ったときだけ`true`）。
///
/// # なぜプロセス単位なのか（2026-09-18、⑤'の前半）
///
/// 姿勢を読む場所が**2種類の時点**に分かれているためである。
///
/// | いつ読むか | 誰が | 何に使うか |
/// |---|---|---|
/// | **preflightの中**（セッションの準備） | [`crate::tier2a::win_appcontainer::shell_candidates`] | シェルの候補から「遷移先にできない綴り」を外すか（残課題#50・§S62） |
/// | preflightの後 | Daemonを起こす2つのホスト | Daemonへ渡す姿勢 |
///
/// 前者へ引数で届けるには`preflight`の引数を増やすことになり、**呼び出しは68箇所**ある。
/// したがって「このプロセスは何を選んだか」を1回だけ書いて、両方が同じものを読む形にする。
///
/// # 書いてよいのは製品の起動経路1箇所だけである
///
/// `OnceLock`はプロセス単位なので、**テストが書くと同じテストバイナリ内の他のテストへ漏れる**
/// （`B-27`。同じ理由で`SELECTED_SHELL`のdocも書くのを禁じている）。
/// テストは今までどおり**Daemonを起こすAPIへ姿勢を明示して渡す**こと——
/// あちらは既定値を持たない形になっている。
/// 宣言が1箇所であることは`launch.rs`の数え上げテストが固定している。
pub fn declare_child_process_policy(policy: ChildProcessPolicy) -> bool {
    DECLARED_CHILD_PROCESS_POLICY.set(policy).is_ok()
}

/// このプロセスが選んだ姿勢。**宣言が無ければ[`ChildProcessPolicy::PRODUCT_DEFAULT`]**。
///
/// **落ち先が既定値なのは、意味のある既定だからである**——宣言しないホスト
/// （ポリシーエディタ・テスト・サブコマンド）は本当に生成禁止を積まない。
/// 「選ばせずに黙って決める」形ではない。
pub fn child_process_policy_for_this_process() -> ChildProcessPolicy {
    DECLARED_CHILD_PROCESS_POLICY
        .get()
        .copied()
        .unwrap_or(ChildProcessPolicy::PRODUCT_DEFAULT)
}

impl ChildProcessPolicy {
    /// **製品が選んでいる姿勢。⑤を既定へ入れる回に、この1行だけを変える。**
    ///
    /// # なぜ定数にしたのか（2026-09-18、残課題#50の測定の後）
    ///
    /// **この値を読む場所が、Daemonを起こす2つのホスト以外にも増えたためである。**
    /// 3つ目は**Tier2aのシェルの選び方**で、生成禁止を積むなら
    /// 「呼び出し元の中から起こせる綴り」しか選べない
    /// （[`win_appcontainer::shell_candidates`]。ストアの実行エイリアスとMSIXの実体は
    /// どちらも起こせないことを実測した——`plans/mac-spike/RESULTS.md` §S62）。
    ///
    /// 綴りを3箇所に散らすと、**片方だけ直したときに「生成禁止は積んだのに、
    /// シェルは遷移先にできない綴りのまま」**という状態が作れてしまう。
    /// そのときサンドボックスの中のプログラムはシェルを1本も起こせない。
    ///
    /// # 変えた日に何が赤くなるか
    ///
    /// **綴りを`ChildProcessPolicy::Restricted`にすると、`launch.rs`の数え上げテストが
    /// 火を噴く**（この定数が素のままであることを固定している）。
    /// それが「既定へ入れる決定をした」印であり、畳み方はそのテストのdocが持つ。
    pub const PRODUCT_DEFAULT: Self = ChildProcessPolicy::Unrestricted;

    /// 生成禁止を積むか。
    ///
    /// **`== ChildProcessPolicy::Restricted`と書かないためにある。** 製品コードが
    /// その綴りを使うのは「**姿勢を選んだ**とき」だけに保ちたい——
    /// `launch.rs`の数え上げテストがその綴りの出現を0件で固定しており、
    /// 比較のために書いた行まで「選んだ」と数えられてしまうからである。
    /// **`Self::`で書くことで、選択と比較の綴りが分かれる。**
    pub fn is_restricted(self) -> bool {
        match self {
            Self::Restricted => true,
            Self::Unrestricted => false,
        }
    }

    /// `harness-spawnd.exe`のコマンドライン引数へ書くときの綴り。
    ///
    /// **読む側（[`ChildProcessPolicy::from_arg`]）と対でここに置く。** 綴りを別々の
    /// ファイルに書くと、片方だけ直したときに**Daemonが起動を断るのではなく、
    /// 黙って違う姿勢で立ち上がる**形になり得る（`B-05`）。
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Restricted => "restricted",
        }
    }

    /// [`ChildProcessPolicy::as_arg`]の逆。**知らない綴りは`None`**で、呼び出し側は起動を断る。
    ///
    /// **既定へ倒さない。** 「読めなかったら`Unrestricted`」にすると、綴りを間違えた日に
    /// 生成禁止が黙って外れる——強制が外れたことは症状として現れないので、誰も気付けない。
    pub fn from_arg(arg: &str) -> Option<Self> {
        match arg {
            "unrestricted" => Some(Self::Unrestricted),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}
