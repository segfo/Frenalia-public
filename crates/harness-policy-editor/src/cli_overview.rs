//! サブコマンド無しで起動し、標準入出力が端末でないとき（パイプ・リダイレクト）に出す概要（[`super`]のCLIの続き）。
//!
//! 2026-10-05に`main.rs`から**そのまま**移した（`main.rs`は本体1,000行を超えているので、位置ごとのドメインの記録の
//! 説明を足す前に置き場を分けた。`plans/position-domains/P4.md`の P4.7）。

pub(super) fn print_overview() {
    println!("harness-policy-editor — LLMを介さずに「このコマンドに何を許すか」を決める道具");
    println!();
    println!("記録は2パスで行います（FSのpermissiveさとネットワーク強制は同一トークンでは");
    println!("両立しないため、同時にではなく順番に使います）:");
    println!("  パス1  隔離なし（Tier0）で触ったファイルを全部記録");
    println!("  中間   FS候補をユーザーが承認して policy.json へ書く");
    println!("  パス2  Tier2a（AppContainer＋WFP＋Proxy）で接続したドメインを記録");
    println!();
    println!("端末から引数なしで起動すると、記録・編集の2画面のTUIが開きます");
    println!("（いま概要が出ているのは、標準入出力が端末ではないためです）。");
    println!();
    println!("使えるコマンド:");
    println!("  record -- <コマンド>        隔離せずに実行し、触ったファイルを記録する（UAC 1回）");
    println!("  approve --domain <name> --accept <id>...");
    println!("                              候補を承認して .harness/policy.json へ書く");
    println!(
        "  record-net --domain <name>  Tier2aで実行し、接続したドメインを記録する（UAC 最大2回）"
    );
    println!("             [--enforce-net]  通信をpolicy.jsonのnet.allow_domainsだけに絞り、ほかは断る");
    println!("  sessions                    記録セッションの一覧");
    println!("  show [<id>] [--net]         記録を読み直して候補を表示する（記録し直さない）");
    println!("  unapprove --domain <name> --fs <値> --access <種別> | --net <ドメイン> | --all");
    println!("                              承認済み宣言を取り消す（ACLは次のパス2開始時に撤収）");
    println!("  approve-declared --domain <name> --fs <値> --access <種別>");
    println!("                              policy.jsonにある宣言をこのマシンで承認する");
    println!();
    println!("記録と閲覧は独立したコマンドです。記録し終えてから編集へ進む一方通行ではなく、");
    println!("いつでも記録し直す・別の一般化度合いで見直すことができます。");
    println!();
    println!("approve は policy.json へ宣言を書き、このマシンの承認台帳へ承認を記録するだけで、");
    println!("ACLは触りません。ACEが付くのは、承認済みのファイル宣言を record-net（パス2）か");
    println!("harness.exe の起動が読んだときです。");
    println!();
    println!("宣言どおりに走らせて確かめるのは record-net --enforce-net です。強制で効くのは");
    println!("この試験実行の中だけで、harness.exe本体はまだpolicy.jsonのnet.allow_domainsで");
    println!("通信を許しません（本体ではsettings.jsonのnet.allow_domainsが効きます）。");
    println!();
    println!("宣言を直すには: 取り消しは unapprove か TUI の宣言画面の Space、ファイル宣言の");
    println!("種類と ** の付け替えは TUI の宣言画面の c・R です。");
    println!("まだ無いもの: policy.json のパスそのものの書き換えと、付け替えのコマンド。");
}
