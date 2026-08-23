# AGENTS.md

このファイルは、このリポジトリで作業する Codex / coding agent 向けの入口です。
詳細な規則の正本は既存の `CLAUDE.md` とスキル群に置き、このファイルには「何を先に読むか」と
「どの作業でどの正本を見るか」だけをまとめます。

## 最初に読むもの

作業を始める前に、次をこの順で確認してください。

1. グローバル指示: `C:\Users\segfo\.claude\CLAUDE.md`
2. グローバルスキル一覧: `C:\Users\segfo\.claude\skills`
3. このリポジトリの指示: `CLAUDE.md`
4. 現在状態と文書規約: `docs/INDEX.md`, `docs/STATUS.md`, `docs/DOCUMENT-RULES.md`

グローバル指示とリポジトリ固有指示が同じ主題を扱う場合は、リポジトリ固有指示を優先します。
ただし、グローバル指示が明示している「スキル内容や件数を別文書へ複製しない」という原則は守ってください。

## 返答と言語

ユーザーへの説明・報告・質問・提案は常に日本語で行います。コード、コマンド、パス、識別子、引用した英語原文は原文のままで構いません。

ユーザーへ説明するときは、グローバルスキル `premise-first-explanation` を正本として参照してください。
番号やファイル名だけで結論へ飛ばず、前提、根拠の中身、意図、帰結が伝わる順にします。

## 実装前に見るスキル

作業の種類に応じて、`C:\Users\segfo\.claude\skills\<skill-name>\SKILL.md` を読んでから着手してください。
この一覧は索引であり、各スキルの細かいルールや数字はここへ写しません。

- 実装・設計変更の前: `bug-pattern-rules`
- バグ修正・失敗調査・テスト失敗の原因追跡: `bug-fix-workflow`
- 新しいテスト、検証、E2E、assert、整合性確認: `test-logic-rules`
- リファクタ、責務分割、移動、重複統合、最適化: `safe-refactoring`
- ファイル配置、モジュール分割、公開範囲、DRY、テスト配置: `code-structure-rules`
- 排他、単一インスタンス、生存判定、ロック、共有状態の read-modify-write: `shared-state-exclusion`
- 設計書・実装計画の作成または大幅改稿、プランレビュー: `plan-review-gates`
- 解説文書・入門ガイド・図解付き説明: `explanatory-guide-writing` と `doc-explanation-granularity`
- 参考資料一覧の作成・更新: `doc-references-rules`
- SVG 図の作成・修正: `svg-diagram-rules`
- 階層構造やツリー構造の SVG 図: `svg-diagram-rules` に加えて `hierarchy-diagram-rules`
- Mermaid 図の SVG 書き出し: `mermaid-svg-export`
- Marp スライド生成: `generic-slide-maker` または `format-slide-maker`
- 既存 Marp スライドの校正: `slide-proofreader` と `slide-rules`
- バグ記録・バグカタログ更新: グローバル `bug-catalog-rules` とローカル `.claude\skills\bug-catalog-rules\SKILL.md`
- セッション引き継ぎ: グローバル `session-handoff` とローカル `.claude\skills\session-handoff\SKILL.md`
- スキル作成・追記・移動: `skill-authoring`

## このリポジトリで特に守ること

- 新しい事実、決定、残課題、状態は、書く前に `docs/DOCUMENT-RULES.md` で正本の置き場を確認します。
- 作業開始前に `docs/INDEX.md` で現在のフェーズを確認し、対応する `plans/DESIGN*.md` の該当節を読んでください。
- セキュリティ機構や新しい書込経路に触れるときは `docs/SECURITY-PRINCIPLES.md` を確認します。
- コード構造の判断は `docs/CODE-STRUCTURE-RULES.md` を優先し、必要に応じてグローバル `code-structure-rules` を補助として使います。
- 実装の現在状態と残課題は `docs/STATUS.md` が正本です。
- 昇格が起きる操作は、単発コマンドでもテスト内部でも `dev-elevated-runner` 経由にします。詳細は `docs/DEV-ENVIRONMENT.md` を参照してください。
- `%APPDATA%\harness\config\*-ledger.json` はこの実マシンに残した変更を追跡する台帳なので、クリーンアップに巻き込んで削除しないでください。
- Python スクリプトを実行する必要がある場合は、素の `python` / `python3` ではなく `uv run <script>.py` を使います。

## 検証

通常の開発確認には次を使えます。

```powershell
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace
```

昇格を伴う検証や実機状態を変える検証は、`docs/DEV-ENVIRONMENT.md` の手順と `dev-elevated-runner` の
対象一覧を確認してから実行してください。

## 文書とスキルを更新するとき

このファイルは入口です。詳細な規則、検問、件数、採番範囲、手順本文をここへ複製しないでください。
規則を変える必要がある場合は、正本である `CLAUDE.md`、`docs/*.md`、`plans/*.md`、または該当スキルを更新し、
このファイルには参照先だけを必要最小限で残します。
