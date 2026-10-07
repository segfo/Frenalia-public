//! パス2の進行と結果を人へ見せる文言（CLIと画面が共有する。表示側で書き写さない、`docs/CODE-STRUCTURE-RULES.md`規則5）。
//! `record_net.rs`からそのまま移した（P6.5 の準備。親の本体が1,000行を超えないように、足す前に置き場を分けた）。

use super::*;

/// 記録を始める前・始めた直後にユーザーへ見せる前置き（CLIとTUIで共有）。
///
/// `max_prompts`は実際に出そうなUACの回数。実行前のUI（回数がまだ確定しない）は上限の2を
/// 渡す。**ACEが付くのはこのパスだけ**という事実をここに書いておくのは、それが
/// 「実行してよいか」の判断材料そのものだからである。
pub fn elevation_notice(max_prompts: u8) -> String {
    format!(
        "隔離: Tier2a（AppContainer＋WFP＋Local Proxy）。UACが最大{max_prompts}回出ます\n\
         （ACEの付与と、WFPの出口強制daemonの起動が管理者権限を要するためです）。\n\
         **ACEが実際に付くのはこのパスだけです**——付けた穴は台帳に記録され、終了時に撤収します。"
    )
}

/// WFPが立ったことをユーザーへ伝える1行（CLIとTUIで共有する）。
///
/// **`reused`をここで文言に出すのが要点。** 2回目以降はdaemonを再利用するのでUACが出ないが、
/// それを「強制が掛かっていない」と読み違えられると、この記録の意味が正反対になる（B-32）。
/// 表示側ごとに書くと片方だけが再利用に触れる文面になるので、実行側が1つだけ持つ
/// （`ELEVATION_NOTICE`・[`elevation_notice`]と同じ方針、`docs/CODE-STRUCTURE-RULES.md`規則5）。
pub fn wfp_enforced_line(reused: bool) -> String {
    let base = "WFPのdefault-denyを張りました（loopbackの穴は上の2つのポートだけ）";
    if reused {
        format!("{base}。既存の昇格daemonを再利用したのでUACは出ていません")
    } else {
        base.to_string()
    }
}

/// パス2で**実際に拒否されたFSアクセス**の欄（CLIとTUIで共有する）。
///
/// # 通信をどう扱ったかを必ず書く（決定64）
///
/// FSはどちらのモードでも宣言どおりに強制されるが、通信の扱いはモードで違う
/// （[`NetMode`]）。記録で走らせた実行は**FSは強制・通信は全許可**という中間状態にあり、
/// これを書かないと「宣言どおりに動くことを確かめた」と誤読される。強制で走らせた実行は
/// 通信も宣言どおりだが、その宣言が効くのは**この試験実行の中だけ**である——`harness.exe`
/// 本体はまだ`policy.json`の`net.allow_domains`で通信を許さない（決定6の移設が残っている）。
///
/// `collector_started`が偽なら**観測していない**。「拒否が0件だった」と区別できないと、
/// fail-openは単なる隠蔽になる（D-43）。
pub fn render_fs_denials(
    aggregate: &crate::aggregate::Aggregate,
    collector_started: bool,
    etw_available: bool,
    net_mode: NetMode,
) -> String {
    let mut out = String::from("\n観測されたFS拒否（このドメインの宣言で強制した結果）:\n");
    if !collector_started {
        out.push_str(
            "  （観測していません——収集器を起動できませんでした。\n\
             「拒否が0件だった」ではありません）\n",
        );
    } else if !etw_available {
        out.push_str(
            "  （観測していません——ETWセッションを張れませんでした。\n\
             理由はfs-audit.jsonlの制御レコードに残っています）\n",
        );
    } else if aggregate.denied == 0 {
        out.push_str("  （拒否は1件も観測されませんでした）\n");
    } else {
        out.push_str(&format!(
            "  {}件の拒否を観測しました。候補は下の一覧と同じ形で確認できます:\n\
             harness-policy-editor show <session>\n",
            aggregate.denied
        ));
    }
    // **FSを観測できなかった回にも出す。** 通信の扱いは収集器の成否と無関係に効いている事実で、
    // 決定64より前はFSの観測が無い回にこの一文ごと抜けていた。
    out.push_str(net_mode_note(net_mode));
    out
}

/// [`render_fs_denials`]の末尾に付ける、通信の扱いの注記（[`NetMode`]ごとに1つ）。
///
/// **`match`にワイルドカードを書かない**——モードを足した人のビルドがここで落ちる。
pub fn net_mode_note(mode: NetMode) -> &'static str {
    match mode {
        NetMode::RecordAll => {
            "\n注意: **この実行で通信は全許可です**（接続先を記録するため）。\n\
             ここに出ているのはFSの拒否だけで、通信の強制は試していません。\n\
             宣言した通信先だけで動くかは、強制モードで走らせると確かめられます。\n"
        }
        NetMode::Declared => {
            "\n注意: **この実行で通信は宣言どおりに強制しました**（policy.jsonのnet.allow_domains\n\
             に一致する宛先だけを中継プロキシと名前解決が通し、ほかは断りました）。\n\
             断られた宛先は通信の候補一覧に出ます。ただしこの宣言が効くのはこの試験実行の中だけで、\n\
             harness.exe本体はまだpolicy.jsonのnet.allow_domainsで通信を許しません\n\
             （本体で効くのは.harness/settings.jsonのnet.allow_domainsです）。\n"
        }
    }
}

/// 中継プロキシを起こしたときの1行（CLIとTUIで共有する。表示側で書き写さない、B-05）。
pub fn proxy_started_line(addr: std::net::SocketAddr, mode: NetMode, allowed: usize) -> String {
    match mode {
        NetMode::RecordAll => format!("Local Proxy: {addr}（記録: 通信先を全部許して記録する）"),
        NetMode::Declared => format!(
            "Local Proxy: {addr}（強制: 宣言した通信先 {allowed}件だけを許し、ほかは断る）"
        ),
    }
}

/// [決定68(2)] パス2が子を起こす場所の1行（CLIの「始める場所:」と記録画面の編集できない行が共有する）。
/// パス2は常に入口のドメインから始める——`harness.exe`の子が必ず入口で始まるので、それ以外の始め方は確認にならない。
pub fn pass2_start_line() -> String {
    format!(
        "始める場所: {}（入口のドメイン）",
        crate::policy_file::ENTRY_DOMAIN
    )
}

/// [決定68(1)] 遷移先のドメインを用意した結果の1行（[`NetRecordEvent::DomainsProvisioned`]。CLIと画面が共有する）。
/// 用意できなかったものは**数を必ず出す**（`B-10`）——理由はドメインごとの警告が持ち、そこへの遷移は Daemon が断る。
pub fn domains_provisioned_line(provisioned: &[String], skipped: usize) -> String {
    let made = if provisioned.is_empty() {
        "用意した遷移先のドメインはありません".to_string()
    } else {
        format!(
            "遷移先のドメインを{}つ用意しました: {}",
            provisioned.len(),
            provisioned.join(", ")
        )
    };
    if skipped == 0 {
        made
    } else {
        format!("{made}（ほかに{skipped}つは用意できなかった——理由は警告を見てください。そこへの遷移は断られます）")
    }
}
