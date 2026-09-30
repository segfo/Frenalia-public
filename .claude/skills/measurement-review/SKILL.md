---
name: measurement-review
description: >
  このリポジトリ（harness）で測定結果をレビューするときの固有値。記録の置き場と採番、
  先に読むべき過去の失敗の節番号、再利用できる検算部品とツリー生成器、突き合わせ先の節、
  昇格が要る測定の流し方、実機測定の直列化と台帳の扱い、結果の返し先を定める。
  検問そのもの（計器・対照・検算・ゲートの位置・振っていない軸・結論の射程）は
  グローバルスキル measurement-review が正本なので、そちらと併せて参照すること。
  測定結果を報告する前、その数字で決める前、過去の測定記録を根拠にする前は必ず両方を参照する。
---

# 測定結果レビューの固有値（このリポジトリ）

> **検問の正本はグローバルスキル [[measurement-review]]。**
> 段A〜段D（計器を疑う／両側の対照／検算／ゲートの位置／構成の記録／汚れた回／振っていない軸／
> 外挿／結論と量の一致／突き合わせ／後始末）と出力の作法は、すべてそちらが持つ。
> **ここへ複製しない。** 本スキルはこのリポジトリの**値と配置**だけを持つ。

## 測定記録の置き場と採番

**種別はすべて記録（Journal）**——過去形・append-only で、過去の記述を書き換えない。
訂正も追記で行い、「今どうなっているか」は別の正本を指す（規約の正本は
`docs/DOCUMENT-RULES.md`。本スキルはそれを測定に当てはめた配置表だけを持つ）。

| 記録 | 何の測定を持つか | 採番 |
|---|---|---|
| `plans/mac-spike/RESULTS.md` | ACL配布・伝播・保護の費用と挙動、Lazy fault-in、Spawn Daemon周り | `S1`〜（`## S31.` の形） |
| `plans/etw-spike/RESULTS.md` | ETW観測（拒否収集・argv・切り詰め）、**測定規律そのものの出典** | `1`〜（`## 18.` `### 18.5` の形） |
| `plans/net-spike/RESULTS.md` | ネットワーク出口制御の粒度、SSHブローカー | `1`〜 と `N1`〜（分流の記号） |
| `plans/e2e/RESULTS.md` | Tier2a E2Eの実施記録（回帰の実行結果・実機確認） | 日付見出し |
| `plans/vm-spike/RESULTS.md`・`projfs-spike`・`go-hook-spike` | Tier3・ProjFS・Goフックの実現性 | 各書の形 |
| `plans/handoff/<topic>/*.md` | 分流セッションが測った分（合流前の一次記録） | `T-N`・`U-N` |

**新しい測定をどこへ書くかは、機構ではなく「その記録が既に持っている軸」で決める。**
同じ量を別の節へ書くと、検問10（突き合わせ）の相手が見つからなくなる。

## 測定を読む前・設計する前に読む2節

グローバル側の検問2（両側の対照）と検問4（ゲートの位置）は、**このリポジトリでの失敗から作られている**。
原文は次の2節にあり、**新しいセッションが測定へ着手する前に読む**。

- `plans/etw-spike/RESULTS.md` **§18.5**「この誤りから何を引くか」——同じ交絡を3回踏んだ記録。
  対象だけでなく関わる全オブジェクトの拒否を出す／権利はビットを手で選ばない／
  成功するはずのケースを必ず1つ混ぜる
- 同 **§21.4**「この測定自体からの教訓」——§18.5へ「ゲートがどこにあるかを先に確かめる」を足した節

`plans/net-spike/RESULTS.md`・`plans/e2e/RESULTS.md`・`plans/mac-spike/RESULTS.md` は
この2節を名指しで引いている。**引いた側にも「規律が効いて何を捕まえたか」が書いてある**ので、
実例が要るときはそちらを見る。

## 再利用できる検算部品（新しく書く前に見る）

- **`measure_arm`** — `crates/harness-sandbox/src/tier2a/win_appcontainer/acl_baseline_cost_tests.rs:600`。
  1回の測定に3つの検算が入っている（最深部の葉の実効マスクが宛先SID自身のマスクと一致する／
  救済walkが全ノードを歩いて1件も書かない／撤収後に対象SIDのACEが1本も残らない）。
  **assertメッセージが「これが崩れると上の数字が無意味になる」理由まで書いてある**——
  新しい検算を足すときはこの書き方を真似る。
  検算は既存部品で行い、同じ事実を2箇所で判定しない（`B-05`）。
- **ツリー生成器** — 同ディレクトリの `test_support.rs`。
  `build_forest_tree`（K と深さを同時に振れる）、
  `build_wide_tree`（`build_forest_tree` の `depth=1` へ委譲）。
  深さ専用だった `build_chain_tree` は、唯一の使い手（残課題#20の測定M3-c）と一緒に
  2026-09-30に消した。深さとパス長の関係を前提にした測定をまたやるなら、消したコミットの親から戻す。
  **過去の数字はこの形で取られている。** 形を変えると過去と並べられなくなるので、
  変えるときは等価を突き合わせるテストを `#[ignore]` 無しで置き、
  **委譲をわざと壊して赤くなることまで確かめる**（`B-27`）。
- **規模の上書き** — `HARNESS_TEST_ACL_COST_NODES`（腕が多いときに1腕あたりのファイル数を下げる）。
  **下げたら「読むのは絶対値ではなく比」と節に書く。**

## 残してある測定（新しく測定を書く前に、流用できないか見る）

判定を1回出して終わる使い捨てではなく、**同じ問いを撃ち直すために残すと宣言した測定**の一覧である
（`docs/CODE-STRUCTURE-RULES.md`規則2の例外）。**寿命の宣言は各ファイルの冒頭が持ち、ここは索引だけ**
——足すときはファイルの冒頭に「寿命: 消さない」の節を書いてから、ここへ1行足す。
「判定が出たら消す」と宣言した使い捨ての側の件数と残りは`docs/STATUS.md`「コード構造リファクタ」の規則2の段が持つ。

| 測定（`crates/harness-sandbox/src/tier2a/`配下） | 何を測るか／撃ち直す場面 | 動かし方 | 結果の記録 |
|---|---|---|---|
| `policy_learnd/etw/diagnostics_tests.rs` | ETW収集器の取りこぼしの桁（`EventsLost`・変換できないパス・相関の取りこぼし・短命プロセスの帰属）。収集器を変えたとき | `dev-elevated-run.exe etw-diagnostics` | `plans/etw-spike/RESULTS.md` §12 |
| `policy_learnd/etw/access_matrix_tests.rs` | 許可レベル×操作種別の真理値表（拒否の形から何が言えるか）。拒否から提案を組む判定を変えたとき | `dev-elevated-run.exe etw-access-matrix` | 同 §15〜§18 |
| `policy_learnd/etw/audit_scope_tests.rs` | `auditpol /resourceSACL`をpackage SIDへ絞れるか（答えは「否」）。OSの版が変わったとき・4656の経路を検討し直すとき。**マシンの監査ポリシーを一時的に変える**（Dropで戻す） | `dev-elevated-run.exe etw-audit-scope` | 同 §14 |
| `win_appcontainer/control_dir_propagation_probe_tests.rs` | 保護したノード自身が、親の伝播で保護ビットを失うか・許可ACEを載せるか（手順15×置き場6×深さ2）と、その直し方の費用。BUG-145の案Aの採否・保護の書き方を変えたとき | 非昇格。`cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture control_dir_` | `docs/bugs/BUG-145.md`・`plans/mac-spike/RESULTS.md` |
| `win_appcontainer/dacl_protection_probe_tests.rs` | どの書込口で`SE_DACL_PROTECTED`が実際に立つか（制御ビットと、伝播が下へ届くかの実効の両方）。保護を書く経路を変えたとき | 非昇格。`cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture dacl_protection_write_path_matrix_probe` | `docs/bugs/BUG-083.md` |
| `win_appcontainer/d79_exec_split_tests.rs` | 継承ACEを2本に割ると、ディレクトリは辿れたまま無宣言のexeだけが止まるか、とその費用。**D-79（ワークスペース内の実行を宣言制にする。不採用）を覆すとき**の材料 | 非昇格。`cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture d79_exec_split_tests` | `plans/mac-spike/RESULTS.md` §S9 |

## 軸の値は、このリポジトリを実測して決める

思いつきの値を振らない。過去の測定が使った決め方は次の形である（**値は実体側が持つので写さない**）。

| 軸 | 何を測って決めたか |
|---|---|
| K（root直下の子の数） | このリポジトリの直下の子の実数 |
| 深さ | ディレクトリの最大深さの実数 |
| 宛先SIDの本数 | `WorkspaceMode::ALL` のモード数（D-84） |
| 規模（ノード数） | このリポジトリの実ノード数に合わせた値 |

## 突き合わせ先（検問10）

- **費用の単価**（1ノードあたりの配布・walk）は `plans/mac-spike/RESULTS.md` の §S10系が基準を持つ。
  新しい測定の単価がそこと同じ帯に入るかを見る。**数値をここへ書き写さない**——実体側だけが持つ
- **食い違ったら、まず古い方の条件を読む。** このリポジトリでは「過去の測定は既知の欠陥が
  残っていた頃のもので、直った後の世界を測っていることの裏付けになった」という決着が実際にある
- **過去の結論が覆った実例が複数ある。** サンドボックス関連の測定を設計する前に
  `plans/e2e/RESULTS.md` と `docs/STATUS.md` の該当行を見る（「解決済み」と書かれた事実が
  再測定で覆っている箇所がある）

## 昇格・直列化・台帳（測定の実行条件）

- **昇格が起きる測定は `dev-elevated-runner` 経由**。条件は「テストか」でも「自分が `sudo` を打つか」でもなく
  **「昇格が起きるか」**だけ（正本は `CLAUDE.md` と
  `docs/DEV-ENVIRONMENT.md`「管理者権限が必要なテストは `dev-elevated-runner` を使う」）。
  `KNOWN_TARGETS` と完全一致しない単発コマンドは、**操作の側をテストにして足す**
- **UACをキャンセルした回・中断された回は「観測」として残し、数字には混ぜない**（検問6）。
  節にどちらなのかを明記する
- **実機を使う区間は直列化する**——`C:\harness-e2e\_measure-lock\<名前>` にファイルを置き、
  終了後に消す（`plans/handoff/fs-boundary-cost/INDEX.md` の運用）。
  並行セッションが同じ実機を触ると、両方の数字が汚れる
- **台帳を触る測定は、実行前にリポジトリ外へバックアップする**
  （`docs/DEV-ENVIRONMENT.md`「クリーンアップ時に絶対に消してはいけないファイル」）。
  台帳が消えると**撤収可能性そのものが失われる**ので、検問11（後始末）はここまで含む

## 結果の返し先

測定して分かったことは、記録へ追記するだけで終わらせない。

| 分かったこと | 返す先 |
|---|---|
| 実測そのもの（過去形） | 上の表の該当 `RESULTS.md` へ**追記** |
| 実装の現在状態が変わった | `docs/STATUS.md`（唯一の正本） |
| その案の採否・原因の確定 | `docs/bugs/BUG-NNN.md` |
| 設計上の決定が変わった／確定した | 該当 `plans/DESIGN*.md`。**確定前に [[plan-review-gates]] を掛ける** |
| 次のセッションへ渡す未確定 | `plans/handoff/` 配下（[[session-handoff]] のローカル側が置き場を持つ） |

## このスキルの育て方

このリポジトリで測定の抜けを見つけたら、**それが値・配置の問題か、検問の問題か**を分ける。

- **置き場・採番・部品・実行条件**の問題 → ここへ1行足す
- **見落としの形**（どういう抜けだったか）の問題 → グローバル [[measurement-review]] の該当検問へ、
  **節番号を出さず形だけで**足す（番号は他リポジトリと衝突する）
