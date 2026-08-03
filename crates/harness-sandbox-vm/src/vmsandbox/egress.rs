//! ゲスト側egress制御の設定生成。中核は**副作用を持たない純粋な文字列生成**。
//!
//! nginxのSNIプロキシ設定（許可ドメインのmapとupstream）とnftablesスクリプトを組み立てる。
//! セッションごとにポートを分ける（`SNI_PROXY_PORT_BASE + slot`）——単一ポートだと全セッションの
//! 許可ドメインが1つの`map`に混ざり、会話単位で出口を絞るというTier3の目的が崩れる（S-5、
//! DNATは認可ではない）。
//!
//! `build_sni_proxy_conf_multi`/`build_nftables_script`は実VMを起動せず単体テストできる
//! 数少ないTier3構成要素であり、そのために切り出している（`docs/CODE-STRUCTURE-RULES.md`規則3）。

use super::*;

/// Incusブリッジ`incusbr0`自身のIP（SNI prereadプロキシのlisten先、`plans/vm-spike/
/// RESULTS.md`§3.2/§3.8で確立した値。AlmaLinux golden像のIncusネットワーク既定設定に依存する
/// ため固定値として扱う）。
pub(crate) const INCUS_BRIDGE_IP: &str = "10.76.180.1";
/// SNI prereadプロキシのlistenポートの基準値。**Phase B**: 常駐VM上に複数セッションが同居する
/// ため、セッションごとに`SNI_PROXY_PORT_BASE + slot`でポートを分ける（`slot`は
/// `vmsandboxd::SessionRegistry`が同時実行数上限の枠として払い出す番号、
/// `crate::vmsandbox::container_static_ip_cidr`と同じ`slot`を共有する）。単一ポートのままだと、
/// 全セッションの許可ドメインが1つの`map`に混ざり、会話単位で出口を絞るというTier3の目的が
/// 崩れる（S-5、DNATは認可ではない）。
pub(crate) const SNI_PROXY_PORT_BASE: u16 = 8444;
const SNI_PROXY_CONF_PATH: &str = "/root/harness-sni-proxy.conf";
const SNI_PROXY_PID_PATH: &str = "/run/harness-sni-proxy.pid";
const SNI_AUDIT_LOG_DIR: &str = "/var/log/nginx/harness-sni-audit";
const NFTABLES_TABLE: &str = "harness_tier3";

pub(crate) fn sni_proxy_port_for_slot(slot: u8) -> u16 {
    SNI_PROXY_PORT_BASE + slot as u16
}

pub(crate) fn sni_audit_log_path_for_slot(slot: u8) -> String {
    format!("{SNI_AUDIT_LOG_DIR}/slot-{slot}.log")
}

/// 常駐VM上で現在出口許可リストを構成中の1セッション分の情報
/// （`crate::vm_host::VmHost`が全アクティブセッション分をまとめて保持する）。
#[derive(Debug, Clone)]
pub(crate) struct EgressSession {
    pub slot: u8,
    pub container_ip: String,
    pub allow_domains: Vec<String>,
}

/// `allow_domains`の入力検証（B-1）。S-2で固定パイプ名IPCが同一ユーザーの任意プロセスへ
/// 開かれた以上、`allow_domains`はもう信頼できる内部値ではなく外部入力として扱う必要がある。
/// パターンの意味は`harness_core::DomainPolicy`と共通化し、ここではTier3固有の`VmError`
/// へ包み直す。
pub(crate) fn validate_allow_domain(domain: &str) -> Result<(), VmError> {
    validate_domain_pattern(domain)
        .map_err(|e| VmError::Incus(format!("invalid allow_domain: {e}")))
}

/// SNI prereadプロキシのnginx設定を、**現在アクティブな全セッション分**まとめて動的生成する
/// （`plans/vm-spike/RESULTS.md`§3.8の単一セッション版から、Phase Bでセッションごとに
/// 独立した`map`+`server`ブロックへ拡張。2セッション目の設定生成が1セッション目のものを
/// 消してしまう問題（A-8）への是正）。ブロック間で`map`のターゲット変数名が衝突しないよう
/// `slot`をsuffixにする。
pub(crate) fn build_sni_proxy_conf_multi(sessions: &[EgressSession]) -> String {
    let mut server_blocks = String::new();
    for s in sessions {
        let map_lines: String = s
            .allow_domains
            .iter()
            .map(|d| sni_upstream_map_entry(d))
            .collect();
        let decision_lines: String = s
            .allow_domains
            .iter()
            .map(|d| sni_decision_map_entry(d))
            .collect();
        let port = sni_proxy_port_for_slot(s.slot);
        let audit_log = sni_audit_log_path_for_slot(s.slot);
        server_blocks.push_str(&format!(
            r#"
    map $ssl_preread_server_name $sni_upstream_{slot} {{
{map_lines}        default              "";
    }}
    map $ssl_preread_server_name $sni_decision_{slot} {{
{decision_lines}        default              "DENY";
    }}

    server {{
        listen {INCUS_BRIDGE_IP}:{port};
        ssl_preread on;
        proxy_pass $sni_upstream_{slot};
        proxy_connect_timeout 5s;
        proxy_timeout 30s;
        access_log {audit_log} sniaudit;
    }}
"#,
            slot = s.slot,
            audit_log = audit_log,
        ));
    }
    format!(
        r#"load_module /usr/lib64/nginx/modules/ngx_stream_module.so;
worker_processes auto;
error_log /var/log/nginx/harness-sni-proxy-error.log warn;
events {{ worker_connections 1024; }}
stream {{
    resolver 1.1.1.1 valid=60s;

    log_format sniaudit '$time_iso8601 client=$remote_addr sni="$ssl_preread_server_name" '
                         'upstream=$upstream_addr '
                         'bytes_sent=$bytes_sent bytes_received=$bytes_received '
                         'duration=$session_time status=$status';
{server_blocks}}}
"#
    )
}

pub(crate) fn sni_upstream_map_entry(pattern: &str) -> String {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix = nginx_regex_escape_domain(suffix);
        format!("        ~^(.+\\.)?{suffix}$     \"$ssl_preread_server_name:443\";\n")
    } else {
        format!("        {pattern}     \"{pattern}:443\";\n")
    }
}

pub(crate) fn sni_decision_map_entry(pattern: &str) -> String {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix = nginx_regex_escape_domain(suffix);
        format!("        ~^(.+\\.)?{suffix}$     \"ALLOW\";\n")
    } else {
        format!("        {pattern}     \"ALLOW\";\n")
    }
}

pub(crate) fn nginx_regex_escape_domain(domain: &str) -> String {
    domain.replace('.', "\\.")
}

/// nftables: 全アクティブセッション分のDNAT（コンテナ発の443宛先を各自のSNIプロキシポートへ
/// 透過リダイレクト）+ S-5 filterチェーン（「送信元IPが当該セッションのコンテナIPでない限り、
/// そのセッションのproxyポートへの到達をdrop」）をまとめて再構成する。DNATは認可ではない
/// （コンテナBが直接`10.76.180.1:<Aのポート>`へ繋げばAの許可リストを使えてしまう、または
/// 同一L2での送信元IP詐称でAのDNATに乗れてしまう）ため、filterチェーンが実質的な認可点になる。
pub(crate) fn build_nftables_script(sessions: &[EgressSession]) -> String {
    let mut lines = String::new();
    lines.push_str(&format!("nft add table ip {NFTABLES_TABLE}\n"));
    lines.push_str(&format!(
        "nft 'add chain ip {NFTABLES_TABLE} prerouting {{ type nat hook prerouting priority dstnat ; }}'\n"
    ));
    lines.push_str(&format!(
        "nft 'add chain ip {NFTABLES_TABLE} input {{ type filter hook input priority filter ; policy accept ; }}'\n"
    ));
    for s in sessions {
        let port = sni_proxy_port_for_slot(s.slot);
        lines.push_str(&format!(
            "nft add rule ip {NFTABLES_TABLE} prerouting iifname \"incusbr0\" ip saddr {ip} tcp dport 443 redirect to :{port}\n",
            ip = s.container_ip,
        ));
        // S-5: このセッション専用のproxyポートへは、そのセッションのコンテナIP以外からの
        // 到達をdropする（DNAT経路以外での直接アクセス・送信元IP詐称の両方を塞ぐ）。
        lines.push_str(&format!(
            "nft add rule ip {NFTABLES_TABLE} input ip daddr {INCUS_BRIDGE_IP} tcp dport {port} ip saddr != {ip} drop\n",
            ip = s.container_ip,
        ));
    }
    lines
}

/// SNI prereadプロキシ + nftables DNAT/filter + コンテナ側Incus ACLを、AlmaLinux VM自体へ
/// SSH経由で構成する。**Phase B**: `active_sessions`は呼び出し時点で出口を構成している
/// 全セッション（このセッション自身を含む）——1本の呼び出しが常にVM全体の設定を丸ごと
/// 再生成するため、呼び出し側（`crate::vm_host::VmHost`）が単一ロックの下で
/// 「集合を更新→この関数を呼ぶ」を一体で行う必要がある（さもないと2セッション目の呼び出しが
/// 1セッション目の設定を消す、A-8）。
pub(crate) fn apply_egress_ruleset(
    guest_ip: IpAddr,
    ssh_key: &Path,
    active_sessions: &[EgressSession],
) -> Result<(), VmError> {
    for s in active_sessions {
        for d in &s.allow_domains {
            validate_allow_domain(d)?;
        }
    }

    // 1. nginx SNI prereadプロキシを配置・反映。既に起動中ならreloadし、未起動またはreload
    //    失敗時のみ新規起動する。セッション追加/削除のたびに既存TLS接続を切らないため。
    let conf = build_sni_proxy_conf_multi(active_sessions);
    ssh_push_file(guest_ip, ssh_key, conf.as_bytes(), SNI_PROXY_CONF_PATH)?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!("mkdir -p {SNI_AUDIT_LOG_DIR}"),
        Duration::from_secs(10),
    )?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!(
            "if test -f {SNI_PROXY_PID_PATH} && kill -0 $(cat {SNI_PROXY_PID_PATH}) 2>/dev/null; then \
             nginx -c {SNI_PROXY_CONF_PATH} -g 'pid {SNI_PROXY_PID_PATH};' -s reload; \
             else nginx -c {SNI_PROXY_CONF_PATH} -g 'pid {SNI_PROXY_PID_PATH};'; fi"
        ),
        Duration::from_secs(10),
    )?;

    // 2. nftables: 既存テーブルを削除してから全セッション分を作り直す（べき等性、A-8是正）。
    let _ = ssh_exec(
        guest_ip,
        ssh_key,
        &format!("nft delete table ip {NFTABLES_TABLE}"),
        Duration::from_secs(10),
    );
    if !active_sessions.is_empty() {
        let script = build_nftables_script(active_sessions);
        ssh_exec_checked(guest_ip, ssh_key, &script, Duration::from_secs(15))?;
    }

    Ok(())
}

/// コンテナ側Incus ACL: tcp/443への直接出口を宛先指定なしで許可するだけでよい
/// （プロキシの存在をコンテナに一切意識させない、`RESULTS.md`§3.8）。セッション単位で
/// 一度だけ呼べばよく、VM全体の再生成とは独立（コンテナ削除で自動的に消える）。
pub(crate) fn attach_egress_acl(incus: &IncusClient, container_name: &str) -> Result<(), VmError> {
    let acl_name = format!("{container_name}-egress");
    incus.create_network_acl(&acl_name)?;
    incus.attach_acl_to_container(container_name, &acl_name)?;
    Ok(())
}

/// セッション終了時、SNIプロキシの監査ログをホスト側ワークスペースへ書き出す
/// （VMはteardownで消えるため、これが唯一のフォレンジック記録になる。ユーザー要望
/// 「通信の監査」への対応、`plans/vm-spike/RESULTS.md`§3.8参照）。
pub(crate) fn fetch_and_persist_audit_log(
    guest_ip: IpAddr,
    ssh_key: &Path,
    workspace_root: &Path,
    session_id: &str,
    slot: u8,
) -> Result<(), VmError> {
    let remote_log = sni_audit_log_path_for_slot(slot);
    let (stdout, _stderr, code) = ssh_exec(
        guest_ip,
        ssh_key,
        &format!("cat {remote_log} 2>/dev/null"),
        Duration::from_secs(15),
    )?;
    if code != 0 || stdout.is_empty() {
        return Ok(()); // ログが無い（一度も通信が発生しなかった等）場合は何もしない。
    }
    let audit_dir = workspace_root.join(".harness").join("sandbox");
    std::fs::create_dir_all(&audit_dir)?;
    let audit_path = audit_dir.join(format!("tier3-net-audit-{session_id}.log"));
    std::fs::write(audit_path, stdout)?;
    Ok(())
}

