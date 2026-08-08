//! `fs-audit.jsonl`の1行分レコード（`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.1で追加した4番目の収集源）。
//!
//! **書く側は昇格したOS監査収集器**（`harness-policy-learnd.exe`、`harness-sandbox`の
//! `tier2a::policy_learnd`）、**読む側は非特権の`harness-cli`**（`harness policy suggest`）である。
//! 型を2箇所に別々実装すると、片側だけスキーマが変わっても誰も気付かないまま静かに
//! 候補が消える——`harness-change-ledger`が`CowOpEntry`を1本化しているのと同じ理由で
//! （`docs/CODE-STRUCTURE-RULES.md`規則5）、定義はここだけに置く。

use serde::{Deserialize, Serialize};

use harness_config::FsAccess;

/// イベントの発生源。preflightで分かる「設定済み穴の付与失敗」と、実行中の「未設定パスへの試行」は
/// 発生源が違うが、提案エンジンから見ればどちらも同じ denied candidate である（§11.1）。
/// この区別を残すのは、ユーザーが「いつ・どの層で」拒否されたのかを追えるようにするため。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAuditKind {
    /// Tier2a preflightがACE付与・到達性プローブで拒否した（`fs-passthrough-ledger.json`側と同源）。
    Preflight,
    /// 実行中にETW（`Microsoft-Windows-Kernel-File`）が観測したアクセス拒否。
    Etw,
    /// Windows Security Auditing（4656/4663）由来。現時点では書かれない（採用していない）が、
    /// 語彙は§11.1が定めた3値なので型としては持っておく。
    SecurityAudit,
    /// 収集器自身の状態（セッション開始失敗・プロバイダ不在・権限不足）。**拒否イベントではない。**
    /// `allowed`は意味を持たず、`reason`が理由を運ぶ。D-43のfail-openを「黙って空」にしないための
    /// 制御レコードで、`wfp.rs`の`start_wfp_drop_audit`が`net_event_collection_enable_failed`を
    /// 書くのと同じ役割を持つ。
    Control,
}

/// `fs-audit.jsonl`の1行。§11.1が必須とする項目
/// （`kind`・`path`・`access`・`allowed`・`reason`・`process_id`・`image_path`・`timestamp_unix_ms`）をそのまま持つ。
///
/// `access`が`Option`なのは[`FsAuditKind::Control`]のためで、拒否イベントでは常に`Some`である。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsAuditEvent {
    pub kind: FsAuditKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<FsAccess>,
    pub allowed: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    /// 親プロセスID。ポリシーエディタの記録モードが「プロセス単位で折り畳む」ツリー表示を
    /// 組み立てるために使う。`#[serde(default)]`なので、この項目を持たない旧`fs-audit.jsonl`
    /// （deny-only収集器が書いたもの）を読んでも失敗しない。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    pub timestamp_unix_ms: u64,
}

impl FsAuditEvent {
    /// 拒否イベント（収集器が実際に観測した1件）。
    pub fn denied(
        kind: FsAuditKind,
        path: impl Into<String>,
        access: FsAccess,
        reason: impl Into<String>,
        timestamp_unix_ms: u64,
    ) -> Self {
        Self::observed(kind, path, access, false, reason, timestamp_unix_ms)
    }

    /// record-allモード用: 拒否・許可を問わず観測した1件を組み立てる。`denied`はこれの
    /// `allowed=false`固定版に相当する（重複を避けるため`denied`側から委譲している）。
    pub fn observed(
        kind: FsAuditKind,
        path: impl Into<String>,
        access: FsAccess,
        allowed: bool,
        reason: impl Into<String>,
        timestamp_unix_ms: u64,
    ) -> Self {
        Self {
            kind,
            path: Some(path.into()),
            access: Some(access),
            allowed,
            reason: reason.into(),
            process_id: None,
            parent_process_id: None,
            image_path: None,
            timestamp_unix_ms,
        }
    }

    /// 収集器の状態を伝える制御レコード（D-43）。**候補には昇格しない。**
    pub fn control(reason: impl Into<String>, timestamp_unix_ms: u64) -> Self {
        Self {
            kind: FsAuditKind::Control,
            path: None,
            access: None,
            allowed: false,
            reason: reason.into(),
            process_id: None,
            parent_process_id: None,
            image_path: None,
            timestamp_unix_ms,
        }
    }

    pub fn with_process(mut self, pid: u32, image_path: Option<String>) -> Self {
        self.process_id = Some(pid);
        self.image_path = image_path;
        self
    }

    pub fn with_parent_process(mut self, parent_pid: u32) -> Self {
        self.parent_process_id = Some(parent_pid);
        self
    }

    /// JSONL 1行へ直列化する（末尾改行は含めない）。
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// 現在時刻をUnixミリ秒で返す。収集器が制御レコードを書くときに使う
/// （ETW由来のイベントは`EventHeader.TimeStamp`から換算した値を持つので、こちらは使わない）。
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `access`は設定キー名（`read`/`read_write`/`read_exec`）と同じ綴りで直列化される。
    /// 収集器が書いた行をそのまま`fs.read_exec`の提案語彙へ写せることが、この一致の目的。
    #[test]
    fn access_serializes_with_the_settings_vocabulary() {
        let event = FsAuditEvent::denied(
            FsAuditKind::Etw,
            r"C:\Users\me\.rustup\toolchains\stable\bin\rustc.exe",
            FsAccess::ReadExec,
            "STATUS_ACCESS_DENIED",
            1_700_000_000_000,
        );

        let line = event.to_jsonl_line().unwrap();
        assert!(line.contains(r#""access":"read_exec""#), "{line}");
        assert!(line.contains(r#""kind":"etw""#), "{line}");

        let round_tripped: FsAuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(round_tripped, event);
    }

    /// 制御レコードは`path`/`access`を持たず、キー自体が出力から省かれる（読む側で
    /// 「パスの無い拒否イベント」と誤読されないように）。
    #[test]
    fn control_records_omit_path_and_access() {
        let event = FsAuditEvent::control("etw_session_start_failed: access denied", 42);

        let line = event.to_jsonl_line().unwrap();
        assert!(!line.contains("\"path\""), "{line}");
        assert!(!line.contains("\"access\""), "{line}");
        assert!(line.contains(r#""kind":"control""#), "{line}");
    }

    /// 収集器が後から項目を足しても古い行が読めるよう、省略可能な項目は`default`で復元する。
    #[test]
    fn optional_process_fields_default_when_absent() {
        let line = r#"{"kind":"etw","path":"C:/x","access":"read","allowed":false,"reason":"denied","timestamp_unix_ms":7}"#;

        let event: FsAuditEvent = serde_json::from_str(line).unwrap();

        assert_eq!(event.process_id, None);
        assert_eq!(event.parent_process_id, None);
        assert_eq!(event.image_path, None);
        assert_eq!(event.access, Some(FsAccess::Read));
    }

    /// `parent_process_id`は`with_parent_process`で付与でき、往復する。
    /// ポリシーエディタの記録モードがプロセスツリー表示を組み立てる材料。
    #[test]
    fn parent_process_id_round_trips() {
        let event = FsAuditEvent::denied(
            FsAuditKind::Etw,
            r"C:\x.txt",
            FsAccess::Read,
            "denied",
            1,
        )
        .with_process(200, Some(r"C:\cargo.exe".to_string()))
        .with_parent_process(100);

        let line = event.to_jsonl_line().unwrap();
        assert!(line.contains(r#""parent_process_id":100"#), "{line}");

        let round_tripped: FsAuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(round_tripped, event);
    }

    /// `observed`はrecord-allモード用の一般化されたコンストラクタで、`allowed`を明示できる。
    /// `denied`はこれの`allowed=false`固定版に相当する（内部で委譲している）。
    #[test]
    fn observed_can_represent_both_allowed_and_denied_records() {
        let allowed_event = FsAuditEvent::observed(
            FsAuditKind::Etw,
            r"C:\ok.txt",
            FsAccess::Read,
            true,
            "observed",
            5,
        );
        assert!(allowed_event.allowed);

        let denied_via_observed = FsAuditEvent::observed(
            FsAuditKind::Etw,
            r"C:\secret.txt",
            FsAccess::Read,
            false,
            "denied",
            5,
        );
        let denied_via_denied = FsAuditEvent::denied(
            FsAuditKind::Etw,
            r"C:\secret.txt",
            FsAccess::Read,
            "denied",
            5,
        );
        assert_eq!(denied_via_observed, denied_via_denied);
    }
}
