//! Tier3（Hyper-V外層AlmaLinux VM + Incus内層コンテナ）の実行機構本体
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md`、`plans/vm-spike/RESULTS.md`）。
//!
//! `harness-vmsandboxd`（常駐デーモン、`crate::tier3::vmsandboxd`）の中でのみ呼ばれる。本体プロセス
//! （非管理者）はここのHyper-V操作を直接呼ばない（D-21）。Incus REST APIはmTLS越しの
//! ネットワーク呼び出しであり管理者権限を要しないが、デーモンプロセス内に閉じて構わないため
//! ここへ同居させる。
//!
//! **Phase 1（`run_shell`統合）+ Phase 2（出口許可リスト統合）は完了・実機E2E確認済み**
//! （`RESULTS.md`§3.9/§3.10）。出口許可リスト（Incus ACL + nftables DNAT + SNI preread
//! プロキシ + 監査ログ）は`allow_domains`が非空の場合のみ構成し、空なら無制限出口のまま
//! （`--net-allow-domain`未指定時の後方互換）。ゴールデン像へのIncusクライアント証明書焼き込み
//! も完了しており、ランタイムはSSH・ペアリング不要でmTLS直結できる。
//!
//! **Phase 3実装済み（台帳+GC・ウォームスタート）**、**Phase B実装済み（VM共有化・
//! マルチセッション並行化、`DESIGN-SANDBOX-VMISOLATION.md`項目8）**:
//! - **VM共有化（`crate::tier3::vm_host::VmHost`）**: 外層VMはもうセッションごとに新規作成される
//!   専有物ではなく、参照カウントされる共有resident資源になった。`VmSession::start`は
//!   `VmHost::attach`（未起動なら起動、起動済みなら`refcount`を増やして即座にアタッチ）を
//!   呼ぶだけで、VM作成コード自体は`vm_host`モジュールへ移動した。ウォームスタート
//!   （`--tier3-warm`）もこの`attach`の内部実装（checkpointからの`Restore-VMSnapshot`）に
//!   統合され、`WarmLock`によるファイルロック直列化は不要になった（daemonプロセス内の
//!   `Mutex`一本で足りる、daemon自体がS-2の固定パイプ名で単一プロセスに保証されているため）。
//! - **台帳+GC（D-24）**: `crate::tier3::vm_ledger`のスキーマをVM共有化に合わせて分離した
//!   （単一の`VmHostEntry`＋`workspace_id`単位の`WorkspaceResourceEntry`群）。
//!   `gc_orphan_sessions`は`VmHost::attach`のStopped→Running遷移直前にのみ呼ばれる
//!   （セッション途中で誤って現在生存中のVMを孤児扱いしないため）。
//! - **マルチセッション並行化**: `vmsandboxd::serve_resident`はthread-per-session化され、
//!   `SessionRegistry`が同時実行数上限（既定4・`--tier3-max-sessions`）を管理する。各セッションに
//!   割り当てられる`slot`番号がコンテナの静的IP・SNIプロキシポートの衝突回避に使われる。
//! - **ワークスペース単位資源の参照カウント共有**（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）:
//!   SMB共有・使い捨てアカウント・NTFS ACE・CIFSマウントは`workspace_id`
//!   （`smb_share::compute_workspace_id`）単位で参照カウント共有する。Incusコンテナと
//!   出口許可リストはセッション単位のまま（同一ワークスペースでもコンテナは分ける）。
//!
//! **Tier3残課題の解消済み範囲**:
//! - VM refcountが0になった際、warm運用なら`WarmIdle`へparkして次回warm復帰できる。
//! - SNI監査ログはslot別のVM内ファイルへ分離し、teardown時にセッション別ログとして
//!   `.harness/sandbox/tier3-net-audit-<session_id>.log`へ回収する。
//! - nginx設定の反映は既存プロセスへの`nginx -s reload`を優先し、未起動時だけ新規起動する。
//!
//! ワークスペース共有は`WorkspaceShareMode::Cifs`（SMBライブ共有、Incus disk deviceでのbind-mount）
//! が既定であり、D-22のライブマウントはこの経路で実現済み。`HARNESS_TIER3_CIFS_WORKSPACE=0`で
//! 選べる`WorkspaceShareMode::CopyInOut`（セッション境界でのcopy-in/copy-out）は非既定の
//! フォールバック経路として残っている。
//!
//! 固定の運用規約（`plans/vm-spike/RESULTS.md`§3.6/§3.7で確立、実機E2E確認済み）:
//! - ゴールデン親VHDX: `C:\ProgramData\harness\golden-images\almalinux-golden.vhdx`
//! - 内部vSwitch: `harness-tier3-outer-internal`（`172.20.100.0/24`、ホスト側ゲートウェイ
//!   `172.20.100.1`、`New-NetNat`による出口）
//! - ゲスト静的IP: `172.20.100.10`（ゴールデン像へ焼き込み済み、DHCP不要）
//! - Incus API: `172.20.100.10:8443`（mTLS、クライアント証明書はゴールデン像へ焼き込み済み。
//!   `harness-firstboot.sh`のステップ3.5が起動直後に`incus config trust add-certificate`で
//!   自動信頼登録する）
//! - SSHホスト制御チャネル（Phase 2で追加）: `root`鍵認証限定、harness専用ed25519鍵ペアを
//!   `%APPDATA%\harness\config\tier3-ssh\`に保持しゴールデン像へ焼き込み済み。AlmaLinux VM
//!   自体（ホストOS）へnginx/nftables設定を配置・起動するために使う（Incus REST APIはコンテナ
//!   管理のみでVM自体のOS操作はできないため）。

use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use harness_core::validate_domain_pattern;
use serde::Deserialize;
// --- 責務別サブモジュール（docs/CODE-STRUCTURE-RULES.md 規則3） ---
//
// 分割線は「どの外部システムと話すか」で引いている。
//
// | モジュール | 話す相手 |
// |---|---|
// | `config`          | —（型とプロセス起動ヘルパー） |
// | `credentials`     | ファイルシステム / NTFS ACL |
// | `ssh`             | ssh.exe（外層VM） |
// | `incus`           | Incus REST API（mTLS越しのHTTP） |
// | `egress`          | —（純粋な文字列生成。実VM無しで単体テストできる） |
// | `workspace_share` | SMB / PowerShell / SSH |
// | `session`         | 上記全部を束ねる |
//
// 公開パス（`harness_sandbox::tier3::vmsandbox::VmSession` 等）を変えないため、
// 各モジュールの公開項目はここでglob再エクスポートする。

mod config;
mod credentials;
mod egress;
mod incus;
mod session;
mod ssh;
mod workspace_share;

pub use config::*;
pub use credentials::*;
pub use incus::*;
pub use session::*;

// `egress`・`ssh`・`workspace_share`はクレート外へ出す項目を持たない（Tier3の内部実装）。
// 兄弟モジュールから参照できるようにするためだけの再エクスポートなので`pub(crate)`。
pub(crate) use egress::*;
pub(crate) use ssh::*;
pub(crate) use workspace_share::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_path_leaves_ascii_alone() {
        assert_eq!(urlencoding_path("/workspace/foo.txt"), "/workspace/foo.txt");
    }

    #[test]
    fn urlencoding_path_escapes_space() {
        assert_eq!(
            urlencoding_path("/workspace/a b.txt"),
            "/workspace/a%20b.txt"
        );
    }

    #[test]
    fn build_sni_proxy_conf_multi_maps_allowed_domains_to_allow() {
        let sessions = vec![EgressSession {
            slot: 0,
            container_ip: "10.76.180.61".to_string(),
            allow_domains: vec!["example.com".to_string(), "api.example.org".to_string()],
        }];
        let conf = build_sni_proxy_conf_multi(&sessions);
        assert!(conf.contains("example.com     \"example.com:443\";"));
        assert!(conf.contains("api.example.org     \"api.example.org:443\";"));
        assert!(conf.contains("example.com     \"ALLOW\";"));
        assert!(conf.contains("default              \"\";"));
        assert!(conf.contains("default              \"DENY\";"));
        assert!(conf.contains(&format!(
            "listen {INCUS_BRIDGE_IP}:{};",
            sni_proxy_port_for_slot(0)
        )));
        assert!(conf.contains(&format!(
            "access_log {} sniaudit;",
            sni_audit_log_path_for_slot(0)
        )));
    }

    #[test]
    fn build_sni_proxy_conf_multi_with_no_sessions_has_no_server_blocks() {
        let conf = build_sni_proxy_conf_multi(&[]);
        assert!(!conf.contains("ALLOW"));
        assert!(!conf.contains("listen"));
    }

    #[test]
    fn build_sni_proxy_conf_multi_isolates_ports_and_domains_per_slot() {
        let sessions = vec![
            EgressSession {
                slot: 0,
                container_ip: "10.76.180.61".to_string(),
                allow_domains: vec!["a.example.com".to_string()],
            },
            EgressSession {
                slot: 1,
                container_ip: "10.76.180.62".to_string(),
                allow_domains: vec!["b.example.com".to_string()],
            },
        ];
        let conf = build_sni_proxy_conf_multi(&sessions);
        assert!(conf.contains(&format!(
            "listen {INCUS_BRIDGE_IP}:{};",
            sni_proxy_port_for_slot(0)
        )));
        assert!(conf.contains(&format!(
            "listen {INCUS_BRIDGE_IP}:{};",
            sni_proxy_port_for_slot(1)
        )));
        // 各セッションのmapに、他セッションのドメインが混ざっていないこと（A-8是正の回帰）。
        let slot0_map_start = conf.find("$sni_upstream_0").unwrap();
        let slot0_map_end = conf.find("$sni_upstream_1").unwrap();
        assert!(conf[slot0_map_start..slot0_map_end].contains("a.example.com"));
        assert!(!conf[slot0_map_start..slot0_map_end].contains("b.example.com"));
        assert!(conf.contains(&format!(
            "access_log {} sniaudit;",
            sni_audit_log_path_for_slot(0)
        )));
        assert!(conf.contains(&format!(
            "access_log {} sniaudit;",
            sni_audit_log_path_for_slot(1)
        )));
    }

    #[test]
    fn build_sni_proxy_conf_multi_maps_wildcard_domains_to_original_sni() {
        let sessions = vec![EgressSession {
            slot: 0,
            container_ip: "10.76.180.61".to_string(),
            allow_domains: vec!["*.example.com".to_string()],
        }];
        let conf = build_sni_proxy_conf_multi(&sessions);

        assert!(conf.contains(r#"~^(.+\.)?example\.com$     "$ssl_preread_server_name:443";"#));
        assert!(conf.contains(r#"~^(.+\.)?example\.com$     "ALLOW";"#));
    }

    #[test]
    fn validate_allow_domain_accepts_normal_domains() {
        assert!(validate_allow_domain("example.com").is_ok());
        assert!(validate_allow_domain("api.example-1.co.jp").is_ok());
        assert!(validate_allow_domain("*.example.com").is_ok());
    }

    #[test]
    fn validate_allow_domain_rejects_injection_characters() {
        assert!(validate_allow_domain("example.com\";}\nserver{{").is_err());
        assert!(validate_allow_domain("").is_err());
        assert!(validate_allow_domain(&"a".repeat(300)).is_err());
        assert!(validate_allow_domain("127.0.0.1").is_err());
    }

    #[test]
    fn build_nftables_script_adds_dnat_and_s5_filter_drop_per_session() {
        let sessions = vec![EgressSession {
            slot: 2,
            container_ip: "10.76.180.63".to_string(),
            allow_domains: vec!["example.com".to_string()],
        }];
        let script = build_nftables_script(&sessions);
        let port = sni_proxy_port_for_slot(2);
        assert!(script.contains(&format!(
            "ip saddr 10.76.180.63 tcp dport 443 redirect to :{port}"
        )));
        assert!(script.contains(&format!(
            "ip daddr {INCUS_BRIDGE_IP} tcp dport {port} ip saddr != 10.76.180.63 drop"
        )));
    }

    /// BUG-026: 状態表S0〜S7（`docs/bugs/BUG-026.md`参照）の8状態すべてで
    /// `decide_workspace_action`が期待どおりのアクションを返すことを表駆動で検証する。
    /// 台帳の有無×ゲスト側マウントの健全性の2×2の組み合わせ自体は4通りしかない
    /// （S0〜S3はいずれも「台帳無し」に潰れる、S4〜S6はいずれも「台帳有り・不健全」に潰れる）
    /// ため、実際の分岐点は`(existing_present, mount_healthy)`の4通りで尽くされる。
    #[test]
    fn decide_workspace_action_covers_all_four_ledger_mount_combinations() {
        // S7: 台帳有り・マウント健全 → Reuse。
        assert_eq!(decide_workspace_action(true, true), WorkspaceAction::Reuse);
        // S4/S5/S6: 台帳有り・マウント不健全 → Repair。
        assert_eq!(
            decide_workspace_action(true, false),
            WorkspaceAction::Repair
        );
        // S0〜S3: 台帳無し（マウントの有無に関わらず）→ CreateFresh。
        assert_eq!(
            decide_workspace_action(false, true),
            WorkspaceAction::CreateFresh
        );
        assert_eq!(
            decide_workspace_action(false, false),
            WorkspaceAction::CreateFresh
        );
    }

    /// [BUG-026回帰テスト・実機E2E] `%APPDATA%`の台帳へ「workspace_id一致・ゲスト側マウント
    /// 無し」のstale `WorkspaceResourceEntry`（状態S6、`docs/bugs/BUG-026.md`の状態表参照）を
    /// 自己完結で注入し、実際にVM/コンテナを起動して`VmSession::start`の挙動を確認する。
    /// 2026-07-27の実機検証で、修正前はここが初回試行（`add_disk_device`の10回リトライを
    /// 待つまでもなく、VM冷起動・コンテナ作成を経た約44秒後）で"Missing source path"に
    /// 確実に失敗することを確定させた（根本原因: 再利用分岐が台帳の存在だけでゲスト側マウント
    /// 済みとみなし、実際のマウントを検証しない）。修正後はF2のRepair分岐が発火し、
    /// パスワードローテーション+再mountを経て`Ready`相当（`Ok`）まで到達することを確認する。
    #[test]
    #[ignore]
    fn bug026_stale_ledger_entry_without_guest_mount_is_repaired_not_missing_source_path() {
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root must resolve");
        let config = VmSandboxConfig::default();
        let workspace_id = crate::tier3::smb_share::compute_workspace_id(&workspace_root);

        // 状態S6を自己完結で構成する: 台帳にだけ（ゲスト側マウント無しで）エントリを作る。
        // `smb_share_name`/`smb_user`/`smb_user_sid`はダミー（実際のWindows資源は作らない）。
        crate::tier3::vm_ledger::record_workspace_resource(
            &workspace_id,
            &workspace_root,
            "harness-ws-bug026-repro",
            "hns3-bug026-repro",
            "S-1-5-21-0-0-0-9999",
        );

        let result = VmSession::start(&workspace_root, &config, &[], false, 0);
        match result {
            Err(e) => {
                let msg = e.to_string();
                println!("=== BUG-026 repro: VmSession::start failed: {msg} ===");
                panic!(
                    "expected the Repair branch (F2) to recover from a stale ledger entry \
                     without a guest mount, but VmSession::start still failed: {msg}"
                );
            }
            Ok(session) => {
                println!(
                    "=== BUG-026 repro: VmSession::start recovered via Repair as expected \
                     (session_id={}) ===",
                    session.session_id()
                );
                let _ = session.teardown(&workspace_root, &config);
            }
        }

        // 後始末: 万一パニックした場合も含め、注入した台帳エントリと実資源をGCへ寄せる。
        let _ = crate::tier3::vmsandbox::gc_orphan_sessions(&config, "");
    }
}
