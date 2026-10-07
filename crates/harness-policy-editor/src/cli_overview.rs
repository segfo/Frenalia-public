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
    println!("端末から引数なしで起動すると、記録・承認待ち・宣言の3画面のTUIが開きます");
    println!("（いま概要が出ているのは、標準入出力が端末ではないためです）。");
    println!();
    println!("使えるコマンド:");
    println!("  record -- <コマンド>        隔離せずに実行し、触ったファイルを記録する（UAC 1回）");
    println!("  approve [--domain <name>] --accept <id>...");
    println!("                              候補を承認して .harness/policy.json へ書く");
    println!(
        "  record-net [-- <コマンド>]   入口のドメインから遷移を強制してTier2aで実行し、接続したドメインを記録する（UAC 最大2回）"
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
    println!("パス1の記録がプロセスの木（process-audit.jsonl）を持つと、候補は記録した木の位置ごとの");
    println!("ドメインに分かれます（show は各候補に書く先のドメインを添えます）。approve はそれぞれの");
    println!("ドメインへファイルの宣言だけを書き、--domain は使えません。policy.json にまだ無い");
    println!("ドメインの候補はそこへ届く遷移の辺も要るので、TUI の承認待ち（F2）で遷移と一緒に");
    println!("承認してください（遷移の辺を書くのは TUI だけです）。パス2の記録も、Spawn Daemon が書く");
    println!("許可した生成の記録（spawn-audit.jsonl）を持つと、拒否を起こしたドメインに分かれます（同じく");
    println!("--domain は使えません。どのドメインにも引けない拒否は件数だけ出ます）。");
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
    println!();
    // [P5.6] 2つのモードと書込の同意（決定66(8)と追記）。正本は決定66の追記で、ここは使い分けの要約だけ。
    println!("遷移には2つのモードがあります。使い分けの問いは「子のドメインの権限を、呼び出し元に丸ごと");
    println!("渡しても困らないか」です——困らなければ普通（入力を固定しない。守る線は子のドメインの権限）、");
    println!("困るなら Strict（ドメインに印を付け、入る辺は入力を固定した辺だけにする）。印は TUI の宣言画面の");
    println!("遷移タブの s で付け外しします（正本: plans/POLICY-EDITOR-TOMOYO-DIG.md の「決定66の追記」）。");
    println!();
    println!("書く前の確認: --auto-approve（--yes は同じ意味）は確認済みとして書きますが、広がる遷移（書くと");
    println!("呼び出し元が子を通して新しく使えるようになる権限）か新しい組み合わせが1件でもあれば書きません。");
    println!("それも含めて書くときは、明細を読んだうえで --force-approve を付けます。");
}
