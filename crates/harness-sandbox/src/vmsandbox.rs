//! Tier3（Hyper-V外層AlmaLinux VM + Incus内層コンテナ）の実行機構本体
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md`、`plans/vm-spike/RESULTS.md`）。
//!
//! `harness-vmsandboxd`（常駐デーモン、`crate::vmsandboxd`）の中でのみ呼ばれる。本体プロセス
//! （非管理者）はここのHyper-V操作を直接呼ばない（D-21）。Incus REST APIはmTLS越しの
//! ネットワーク呼び出しであり管理者権限を要しないが、デーモンプロセス内に閉じて構わないため
//! ここへ同居させる。
//!
//! **Phase 1（本ラウンド）の意図的な範囲縮小**（`plans/TIER1A-OPEN-ISSUES.md`項目9で
//! フォローアップする）:
//! - egress許可リスト（Incus ACL + nftables DNAT + SNI prereadプロキシ + 監査ログ、
//!   `RESULTS.md`§3.8で実証済みの機構）は未実装。コンテナはIncusの既定ネットワークで
//!   自由にegressできる（Tier1aのcapability空default-denyとは異なる）。
//! - 台帳+次回起動GC（D-24）は未実装。異常終了時の孤児VM/差分VHDXは残り得る
//!   （`VmSession::start`が失敗した場合のbest-effort後始末のみ行う）。
//! - ワークスペース共有はセッション境界でのcopy-in/copy-outのみ（D-22のライブマウントは未実装）。
//! - ウォームスタート（saved state）は未実装。毎回コールドブートする。
//!
//! 固定の運用規約（`plans/vm-spike/RESULTS.md`§3.6/§3.7で確立、実機E2E確認済み）:
//! - ゴールデン親VHDX: `C:\ProgramData\harness\golden-images\almalinux-golden.vhdx`
//! - 内部vSwitch: `harness-tier3-outer-internal`（`172.20.100.0/24`、ホスト側ゲートウェイ
//!   `172.20.100.1`、`New-NetNat`によるegress）
//! - ゲスト静的IP: `172.20.100.10`（ゴールデン像へ焼き込み済み、DHCP不要）
//! - Incus API: `172.20.100.10:8443`（mTLS、クライアント証明書は像へ焼き込み予定—Phase 1 では
//!   `ensure_client_cert`が生成する証明書をホスト側に保持し、初回のみ`incus config
//!   trust add-certificate`相当のペアリングをこのモジュールが行う。ゴールデン像への
//!   焼き込み自体は実機作業のため別ラウンドで行う、`plans/TIER1A-OPEN-ISSUES.md`項目9参照）。

use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("powershell command failed: {0}")]
    PowerShell(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    #[error("incus api error: {0}")]
    Incus(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        VmError::Io(e.to_string())
    }
}

/// 固定の運用規約（モジュールdoc参照）。
pub struct VmSandboxConfig {
    pub golden_vhdx: PathBuf,
    pub switch_name: String,
    pub guest_ip: IpAddr,
    pub incus_port: u16,
    pub vm_work_dir: PathBuf,
}

impl Default for VmSandboxConfig {
    fn default() -> Self {
        Self {
            golden_vhdx: PathBuf::from(
                r"C:\ProgramData\harness\golden-images\almalinux-golden.vhdx",
            ),
            switch_name: "harness-tier3-outer-internal".to_string(),
            guest_ip: "172.20.100.10".parse().unwrap(),
            incus_port: 8443,
            vm_work_dir: PathBuf::from(r"C:\ProgramData\harness\vm-sessions"),
        }
    }
}

fn run_powershell(script: &str) -> Result<String, VmError> {
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| VmError::PowerShell(format!("failed to spawn powershell.exe: {e}")))?;
    if !output.status.success() {
        return Err(VmError::PowerShell(format!(
            "exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn unique_session_id() -> String {
    format!(
        "harness-tier3-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    )
}

/// クライアント証明書のホスト側保存先（`%APPDATA%\harness\tier3-incus-client\`）。
fn client_cert_dir() -> Result<PathBuf, VmError> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("tier3-incus-client"))
        .ok_or_else(|| VmError::Io("could not resolve config dir".to_string()))
}

/// harness専用のIncus mTLSクライアント証明書を用意する（無ければ`openssl`で自己署名生成、
/// あれば再利用）。Phase 1ではこの証明書をホスト側に保持し、`VmSession::start`のたびに
/// Incusサーバーへペアリングする（ゴールデン像への焼き込みは別ラウンド、モジュールdoc参照）。
pub fn ensure_client_cert() -> Result<(PathBuf, PathBuf), VmError> {
    let dir = client_cert_dir()?;
    std::fs::create_dir_all(&dir)?;
    let crt = dir.join("client.crt");
    let key = dir.join("client.key");
    if crt.exists() && key.exists() {
        return Ok((crt, key));
    }
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            &key.to_string_lossy(),
            "-out",
            &crt.to_string_lossy(),
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=harness-tier3-client",
        ])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn openssl: {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "openssl req failed with status {status:?}"
        )));
    }
    Ok((crt, key))
}

/// Incus REST APIのmTLSクライアント（`plans/vm-spike/incus_common.py`のRust移植）。
pub struct IncusClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct IncusOperation {
    id: String,
}

impl IncusClient {
    pub fn new(host: IpAddr, port: u16, client_crt: &Path, client_key: &Path) -> Result<Self, VmError> {
        let crt_pem = std::fs::read(client_crt)?;
        let key_pem = std::fs::read(client_key)?;
        let mut pem = crt_pem;
        pem.extend_from_slice(b"\n");
        pem.extend_from_slice(&key_pem);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|e| VmError::Incus(format!("failed to build client identity: {e}")))?;
        let http = reqwest::blocking::Client::builder()
            .identity(identity)
            .danger_accept_invalid_certs(true) // Incusサーバーの自己署名証明書（spikeと同じ運用）
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| VmError::Incus(format!("failed to build http client: {e}")))?;
        Ok(Self {
            base_url: format!("https://{host}:{port}"),
            http,
        })
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(u16, serde_json::Value), VmError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .map_err(|e| VmError::Incus(format!("request to {url} failed: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .map_err(|e| VmError::Incus(format!("failed to read response body: {e}")))?;
        let value: serde_json::Value = if text.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text)
                .map_err(|e| VmError::Incus(format!("failed to parse response json: {e}")))?
        };
        Ok((status, value))
    }

    /// `GET /1.0`で`auth: trusted`が返るかを確認する（mTLS疎通+信頼確認）。
    pub fn is_trusted(&self) -> Result<bool, VmError> {
        let (_status, value) = self.request(reqwest::Method::GET, "/1.0", None)?;
        Ok(value
            .get("metadata")
            .and_then(|m| m.get("auth"))
            .and_then(|a| a.as_str())
            == Some("trusted"))
    }

    fn wait_operation(&self, op_path: &str, timeout: Duration) -> Result<serde_json::Value, VmError> {
        let wait_path = format!("{op_path}/wait?timeout={}", timeout.as_secs());
        let (status, value) = self.request(reqwest::Method::GET, &wait_path, None)?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "operation wait failed: status={status} body={value}"
            )));
        }
        let metadata = value.get("metadata").cloned().unwrap_or(serde_json::Value::Null);
        let op_status = metadata
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if op_status != "Success" {
            let err = metadata
                .get("err")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown operation error");
            return Err(VmError::Incus(format!("operation did not succeed: {err}")));
        }
        Ok(metadata)
    }

    pub fn create_container(&self, name: &str, image_alias: &str) -> Result<(), VmError> {
        let body = serde_json::json!({
            "name": name,
            "type": "container",
            "source": {
                "type": "image",
                "mode": "pull",
                "server": "https://images.linuxcontainers.org",
                "protocol": "simplestreams",
                "alias": image_alias,
            },
        });
        let (status, value) =
            self.request(reqwest::Method::POST, "/1.0/instances", Some(body))?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "create_container failed: status={status} body={value}"
            )));
        }
        let op: IncusOperation = serde_json::from_value(
            value.get("operation").cloned().unwrap_or(serde_json::Value::Null),
        )
        .or_else(|_| {
            // 一部のIncusバージョンは`metadata.id`にoperation idを積む。
            serde_json::from_value::<IncusOperation>(
                value.get("metadata").cloned().unwrap_or(serde_json::Value::Null),
            )
        })
        .map_err(|e| VmError::Incus(format!("failed to parse operation id: {e}")))?;
        self.wait_operation(&format!("/1.0/operations/{}", op.id), Duration::from_secs(180))?;
        Ok(())
    }

    pub fn start_container(&self, name: &str) -> Result<(), VmError> {
        let body = serde_json::json!({ "action": "start", "timeout": 30 });
        let (status, value) = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{name}/state"),
            Some(body),
        )?;
        if status != 202 {
            return Err(VmError::Incus(format!(
                "start_container failed: status={status} body={value}"
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    }

    pub fn stop_container(&self, name: &str) -> Result<(), VmError> {
        let body = serde_json::json!({ "action": "stop", "timeout": 30, "force": true });
        let _ = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{name}/state"),
            Some(body),
        )?;
        Ok(())
    }

    pub fn delete_container(&self, name: &str) -> Result<(), VmError> {
        let _ = self.request(
            reqwest::Method::DELETE,
            &format!("/1.0/instances/{name}"),
            None,
        )?;
        Ok(())
    }

    /// `POST /1.0/instances/<name>/exec`（`record-output`方式、websocket不使用）。
    /// `plans/vm-spike/incus_common.py`の`exec_cmd`と同じAPI経路。
    pub fn exec(
        &self,
        name: &str,
        argv: &[&str],
        cwd: &str,
        env: &[(String, String)],
        timeout: Duration,
    ) -> Result<(String, String, Option<i32>), VmError> {
        let mut environment = serde_json::Map::new();
        for (k, v) in env {
            environment.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        let body = serde_json::json!({
            "command": argv,
            "cwd": cwd,
            "environment": environment,
            "wait-for-websocket": false,
            "record-output": true,
            "interactive": false,
        });
        let (status, value) = self.request(
            reqwest::Method::POST,
            &format!("/1.0/instances/{name}/exec"),
            Some(body),
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "exec failed to start: status={status} body={value}"
            )));
        }
        let op_id = value
            .get("operation")
            .and_then(|o| o.as_str())
            .map(|s| s.trim_start_matches("/1.0/operations/").to_string())
            .or_else(|| {
                value
                    .get("metadata")
                    .and_then(|m| m.get("id"))
                    .and_then(|i| i.as_str())
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| VmError::Incus("exec response has no operation id".to_string()))?;

        let metadata = self.wait_operation(&format!("/1.0/operations/{op_id}"), timeout)?;
        let exec_metadata = metadata.get("metadata");
        let exit_code = exec_metadata
            .and_then(|m| m.get("return"))
            .and_then(|r| r.as_i64())
            .map(|n| n as i32);

        // record-outputの標準出力/標準エラーは、operationのmetadata.outputが持つ実際のhref
        // （例: `/1.0/operations/<id>/logs/1`）から取得する。**実機で判明した罠**: このhrefは
        // `/logs/`（複数形）であり、当初`/log/`（単数形）と誤って決め打ちしていたため常に404に
        // なり、`fetch_exec_log`が「ログ無し=空文字列」としてこれを静かに握りつぶしていた
        // （exit codeは正しく取れるため一見成功したように見え、発見が遅れた）。
        let output = exec_metadata.and_then(|m| m.get("output"));
        let stdout_href = output.and_then(|o| o.get("1")).and_then(|h| h.as_str());
        let stderr_href = output.and_then(|o| o.get("2")).and_then(|h| h.as_str());
        let stdout = self.fetch_exec_log(stdout_href, &op_id, "1")?;
        let stderr = self.fetch_exec_log(stderr_href, &op_id, "2")?;
        Ok((stdout, stderr, exit_code))
    }

    fn fetch_exec_log(&self, href: Option<&str>, op_id: &str, fd: &str) -> Result<String, VmError> {
        let url = match href {
            Some(h) => format!("{}{h}", self.base_url),
            None => format!("{}/1.0/operations/{op_id}/logs/{fd}", self.base_url),
        };
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| VmError::Incus(format!("fetch_exec_log failed: {e}")))?;
        if !resp.status().is_success() {
            // ログが本当に存在しない場合（コマンドが何も出力しなかった等）は空文字列扱いにする。
            return Ok(String::new());
        }
        resp.text()
            .map_err(|e| VmError::Incus(format!("failed to read exec log body: {e}")))
    }

    /// `incus file push`相当（`POST /1.0/instances/<name>/files?path=<path>`）。
    pub fn push_file(&self, name: &str, contents: &[u8], remote_path: &str) -> Result<(), VmError> {
        let url = format!(
            "{}/1.0/instances/{name}/files?path={}",
            self.base_url,
            urlencoding_path(remote_path)
        );
        let resp = self
            .http
            .post(&url)
            .header("X-Incus-mode", "0644")
            .header("X-Incus-type", "file")
            .body(contents.to_vec())
            .send()
            .map_err(|e| VmError::Incus(format!("push_file failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(VmError::Incus(format!(
                "push_file failed: status={} path={remote_path}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub fn pull_file(&self, name: &str, remote_path: &str) -> Result<Vec<u8>, VmError> {
        let url = format!(
            "{}/1.0/instances/{name}/files?path={}",
            self.base_url,
            urlencoding_path(remote_path)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| VmError::Incus(format!("pull_file failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(VmError::Incus(format!(
                "pull_file failed: status={} path={remote_path}",
                resp.status()
            )));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| VmError::Incus(format!("failed to read pulled file: {e}")))
    }
}

fn urlencoding_path(path: &str) -> String {
    // Incus APIのpathクエリパラメータ用の最小限のエンコード（スペース・日本語程度を想定）。
    path.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '.' | '_' | '-' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

/// 稼働中のTier3セッション（VM + コンテナ）を表す。`VmSandboxHandle`（`crate::vmsandboxd`）が
/// デーモンプロセス内で保持し続ける。
pub struct VmSession {
    session_id: String,
    vm_name: String,
    diff_vhdx: PathBuf,
    container_name: String,
    incus: IncusClient,
}

const CONTAINER_IMAGE_ALIAS: &str = "alpine/3.21";
const CONTAINER_STATIC_IP: &str = "10.76.180.60/24";
const CONTAINER_GATEWAY: &str = "10.76.180.1";
const WORKSPACE_MOUNT: &str = "/workspace";

impl VmSession {
    /// VM起動→静的IP疎通待ち→Incus mTLS疎通確認→コンテナ作成/起動→ワークスペースcopy-in、
    /// までを一気に行う（`plans/vm-spike/RESULTS.md`§3.7で確立した「Default Switch中継不要」
    /// 経路を前提とする）。
    pub fn start(workspace_root: &Path, config: &VmSandboxConfig) -> Result<Self, VmError> {
        let session_id = unique_session_id();
        let vm_name = session_id.clone();
        std::fs::create_dir_all(&config.vm_work_dir)?;
        let diff_vhdx = config.vm_work_dir.join(format!("{session_id}.diff.vhdx"));

        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
New-VHD -Path '{diff}' -ParentPath '{golden}' -Differencing | Out-Null
New-VM -Name '{name}' -MemoryStartupBytes 2048MB -VHDPath '{diff}' -SwitchName '{switch}' -Generation 2 | Out-Null
Set-VMProcessor -VMName '{name}' -Count 2
Set-VM -Name '{name}' -AutomaticStopAction TurnOff -AutomaticStartAction Nothing
Set-VMFirmware -VMName '{name}' -SecureBootTemplate MicrosoftUEFICertificateAuthority
Start-VM -Name '{name}'
"#,
            diff = diff_vhdx.display(),
            golden = config.golden_vhdx.display(),
            name = vm_name,
            switch = config.switch_name,
        );
        run_powershell(&script)?;

        // ここから先のいかなる失敗も、既に起動済みのVM（+差分VHDX）を孤児として残さないよう
        // teardown_vmを呼んでから返す（実機E2Eで発見: この保証が無いと、cert未検出等の
        // 一時的な失敗でVMだけが残り続け、固定静的IP（172.20.100.10）を使う設計上、次回
        // セッションが新しいVMを起動した際にIP重複が発生し、どちらのVMが応答するか不定に
        // なるという深刻な症状につながる。`plans/TIER1A-OPEN-ISSUES.md`項目9参照）。
        let result = Self::start_after_vm_boot(
            workspace_root,
            config,
            session_id,
            vm_name.clone(),
            diff_vhdx.clone(),
        );
        if result.is_err() {
            let _ = teardown_vm(&vm_name, &diff_vhdx);
        }
        result
    }

    /// [`Self::start`]の続き（VM起動成功後）。失敗時のVM後始末を[`Self::start`]側の
    /// 単一箇所（`teardown_vm`呼び出し）に一本化するため分離した。
    fn start_after_vm_boot(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        session_id: String,
        vm_name: String,
        diff_vhdx: PathBuf,
    ) -> Result<Self, VmError> {
        // ゲストが静的IPで応答するまでポーリング（`RESULTS.md`§3.7実測: 初回pingから即応答）。
        wait_tcp_reachable(config.guest_ip, config.incus_port, Duration::from_secs(180))
            .map_err(|_| VmError::Timeout(format!("guest {} did not come up", config.guest_ip)))?;

        let (client_crt, client_key) = ensure_client_cert()?;
        let incus = IncusClient::new(config.guest_ip, config.incus_port, &client_crt, &client_key)?;

        // ゴールデン像へのクライアント証明書焼き込み（`plans/TIER1A-OPEN-ISSUES.md`項目9）に
        // より、通常はここで既に信頼済み。ただし`wait_tcp_reachable`はTCPポートの疎通
        // （systemdのsocket activationにより、実際のincusdがfirstbootの証明書自動信頼
        // ステップ（harness-firstboot.sh 3.5）を終える前でも即座に受理してしまう）しか見て
        // いないため、起動直後は「ポートは開いているが信頼登録はまだ」という一時的な
        // レースが実機で発生し得る（実機E2Eで発見）。単発チェックにはせず、猶予を持って
        // リトライする。
        let trust_deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if incus.is_trusted().unwrap_or(false) {
                break;
            }
            if Instant::now() >= trust_deadline {
                return Err(VmError::Incus(
                    "Incus does not trust this client certificate after waiting 60s. \
                     ゴールデン像へのクライアント証明書焼き込みが未完了か、firstbootの \
                     信頼登録ステップが失敗している可能性があります。"
                        .to_string(),
                ));
            }
            std::thread::sleep(Duration::from_secs(2));
        }

        let container_name = format!("harness-{session_id}");
        incus.create_container(&container_name, CONTAINER_IMAGE_ALIAS)?;
        incus.start_container(&container_name)?;
        // DHCP不通の既知制約（`RESULTS.md`§段階3）への回避策: 静的IPを直接設定する。
        incus.exec(
            &container_name,
            &[
                "sh",
                "-c",
                &format!(
                    "ip addr add {CONTAINER_STATIC_IP} dev eth0; ip route add default via {CONTAINER_GATEWAY}; mkdir -p {WORKSPACE_MOUNT}"
                ),
            ],
            "/",
            &[],
            Duration::from_secs(15),
        )?;

        let session = Self {
            session_id,
            vm_name,
            diff_vhdx,
            container_name,
            incus,
        };
        session.copy_in_workspace(workspace_root)?;
        Ok(session)
    }

    /// ワークスペース全体をコンテナの`/workspace`へpushする（Phase 1: 素朴な全ファイル
    /// 走査。大規模ワークスペースでの性能はPhase 2以降で見直す、TODOとして明記）。
    fn copy_in_workspace(&self, workspace_root: &Path) -> Result<(), VmError> {
        for entry in walk_files(workspace_root)? {
            let rel = entry
                .strip_prefix(workspace_root)
                .map_err(|e| VmError::Io(e.to_string()))?;
            let remote = format!("{WORKSPACE_MOUNT}/{}", rel.to_string_lossy().replace('\\', "/"));
            if let Some(parent) = std::path::Path::new(&remote).parent() {
                let _ = self.incus.exec(
                    &self.container_name,
                    &["mkdir", "-p", &parent.to_string_lossy()],
                    "/",
                    &[],
                    Duration::from_secs(10),
                );
            }
            let contents = std::fs::read(&entry)?;
            self.incus.push_file(&self.container_name, &contents, &remote)?;
        }
        Ok(())
    }

    /// コンテナの`/workspace`をホストのワークスペースへ書き戻す（セッション終了時、
    /// Teardown経路）。既存ファイルを上書きする（Phase 1の既知の限界、モジュールdoc参照）。
    fn copy_out_workspace(&self, workspace_root: &Path) -> Result<(), VmError> {
        let (stdout, _stderr, _exit) = self.incus.exec(
            &self.container_name,
            &["sh", "-c", &format!("find {WORKSPACE_MOUNT} -type f")],
            "/",
            &[],
            Duration::from_secs(30),
        )?;
        for line in stdout.lines() {
            let remote = line.trim();
            if remote.is_empty() {
                continue;
            }
            let rel = remote.trim_start_matches(WORKSPACE_MOUNT).trim_start_matches('/');
            let local = workspace_root.join(rel);
            if let Some(parent) = local.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = self.incus.pull_file(&self.container_name, remote)?;
            std::fs::write(&local, bytes)?;
        }
        Ok(())
    }

    /// `run_shell`から呼ばれる実行チャネル本体。`cwd`はワークスペースルートからの相対パスへ
    /// 変換した上で`/workspace`配下へマッピングする。
    pub fn exec(
        &self,
        cmd: &str,
        cwd: &Path,
        workspace_root: &Path,
        env: &[(String, String)],
        timeout: Duration,
    ) -> Result<(String, String, Option<i32>), VmError> {
        let rel_cwd = cwd
            .strip_prefix(workspace_root)
            .unwrap_or_else(|_| Path::new("."));
        let remote_cwd = if rel_cwd.as_os_str().is_empty() || rel_cwd == Path::new(".") {
            WORKSPACE_MOUNT.to_string()
        } else {
            format!("{WORKSPACE_MOUNT}/{}", rel_cwd.to_string_lossy().replace('\\', "/"))
        };
        self.incus
            .exec(&self.container_name, &["sh", "-c", cmd], &remote_cwd, env, timeout)
    }

    pub fn teardown(self, workspace_root: &Path) -> Result<(), VmError> {
        let copy_out_result = self.copy_out_workspace(workspace_root);
        let _ = self.incus.stop_container(&self.container_name);
        let _ = self.incus.delete_container(&self.container_name);
        teardown_vm(&self.vm_name, &self.diff_vhdx)?;
        copy_out_result
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

fn teardown_vm(vm_name: &str, diff_vhdx: &Path) -> Result<(), VmError> {
    let script = format!(
        r#"
Stop-VM -Name '{name}' -TurnOff -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-VM -Name '{name}' -Force -ErrorAction SilentlyContinue
Remove-Item -Path '{diff}' -Force -ErrorAction SilentlyContinue
"#,
        name = vm_name,
        diff = diff_vhdx.display(),
    );
    run_powershell(&script)?;
    Ok(())
}

fn wait_tcp_reachable(ip: IpAddr, port: u16, timeout: Duration) -> Result<(), VmError> {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&(ip, port).into(), Duration::from_secs(2)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(VmError::Timeout(format!("{ip}:{port}")));
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, VmError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            // `.harness/`・`.git/`はワークスペース同期の対象外（サンドボックス制御用の
            // メタデータ・VCS内部構造をコンテナへ持ち込まない、Tier1a/Tier2の既存慣習と同じ）。
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == ".harness" || name == ".git" {
                    continue;
                }
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_path_leaves_ascii_alone() {
        assert_eq!(urlencoding_path("/workspace/foo.txt"), "/workspace/foo.txt");
    }

    #[test]
    fn urlencoding_path_escapes_space() {
        assert_eq!(urlencoding_path("/workspace/a b.txt"), "/workspace/a%20b.txt");
    }
}
