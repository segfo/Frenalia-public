//! Incus REST APIクライアント。話す相手は外層VM内のIncusデーモン（mTLS越しのHTTP）。
//!
//! コンテナの作成/起動/停止/削除・ファイル転送・`exec`・ネットワーク設定を担う。
//! 非同期化はしない（`vmsandboxd`自体が非async、`netfilterd`と同じ設計）ため
//! `reqwest::blocking`を使う。

use super::*;

/// Incus REST APIのmTLSクライアント（`plans/vm-spike/incus_common.py`のRust移植）。
/// **`Clone`（Phase B、`crate::vm_host::VmHost`）**: 内部は`String`（base_url）・`IpAddr`
/// （Copy）・`reqwest::blocking::Client`（内部Arc、実接続を保持しない設定オブジェクト）のみ
/// なので複製は安全。常駐VMへ複数セッションが同時にアタッチする際、各セッションが同じ
/// resident VMへの接続設定を独立に保持できるようにするために必要。
#[derive(Clone)]
pub struct IncusClient {
    base_url: String,
    host_ip: IpAddr,
    http: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct IncusOperation {
    id: String,
}

impl IncusClient {
    pub fn new(
        host: IpAddr,
        port: u16,
        client_crt: &Path,
        client_key: &Path,
    ) -> Result<Self, VmError> {
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
            host_ip: host,
            http,
        })
    }

    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
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

    fn wait_operation(
        &self,
        op_path: &str,
        timeout: Duration,
    ) -> Result<serde_json::Value, VmError> {
        let wait_path = format!("{op_path}/wait?timeout={}", timeout.as_secs());
        let (status, value) = self.request(reqwest::Method::GET, &wait_path, None)?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "operation wait failed: status={status} body={value}"
            )));
        }
        let metadata = value
            .get("metadata")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
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

    /// **Phase B実機E2Eで発見**: Incus自体が`POST /1.0/instances`（作成）操作を1件ずつしか
    /// 受け付けず、常駐VM上で複数セッションがほぼ同時に`create_container`を呼ぶと
    /// `Failed creating instance record: Instance is busy running a "create" operation`で
    /// 一方が失敗する（旧「1VM=1セッション」前提では同時に1コンテナしか作られないため
    /// 顕在化しなかった）。コンテナ名自体は`session_id`でユニークなので衝突ではなく、
    /// Incus側の直列化待ちにすぎないため、この特定のエラーメッセージに対してのみ短い
    /// バックオフ付きリトライを行う（作成自体は実測0.3秒程度と高速、`RESULTS.md`参照）。
    pub fn create_container(&self, name: &str, image_alias: &str) -> Result<(), VmError> {
        const MAX_ATTEMPTS: u32 = 20;
        let mut last_err = None;
        for attempt in 0..MAX_ATTEMPTS {
            match self.try_create_container(name, image_alias) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("busy running a") {
                        std::thread::sleep(Duration::from_millis(300 + 100 * attempt as u64));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| VmError::Incus("create_container: exhausted retries".to_string())))
    }

    fn try_create_container(&self, name: &str, image_alias: &str) -> Result<(), VmError> {
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
        let (status, value) = self.request(reqwest::Method::POST, "/1.0/instances", Some(body))?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "create_container failed: status={status} body={value}"
            )));
        }
        let op: IncusOperation = serde_json::from_value(
            value
                .get("operation")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .or_else(|_| {
            // 一部のIncusバージョンは`metadata.id`にoperation idを積む。
            serde_json::from_value::<IncusOperation>(
                value
                    .get("metadata")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
        })
        .map_err(|e| VmError::Incus(format!("failed to parse operation id: {e}")))?;
        self.wait_operation(
            &format!("/1.0/operations/{}", op.id),
            Duration::from_secs(180),
        )?;
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

    /// `POST /1.0/network-acls`: 「tcp/443への直接出口を宛先指定なしで許可、それ以外は
    /// コンテナのdevice側でdrop」という許可リストを1本作る（`plans/vm-spike/RESULTS.md`
    /// §3.8で実機実証済みの構成。既存の同名ACLがあれば削除してから作り直す）。
    /// **実機で判明した罠**（`RESULTS.md`§3.8で既知の限界として記録済みだったもの）: tcp/443
    /// のみ許可すると、コンテナ内のDNS解決（UDP/TCP 53）自体がACLでブロックされ、
    /// `wget https://example.com/`のような普通の呼び出しが名前解決の時点で失敗する
    /// （`bad address`）。SNIベースの許可/拒否は実際の443接続でのみ強制されるため、DNS問い合わせ
    /// 自体は宛先を問わず許可しても実害は小さい（漏れる情報は問い合わせたドメイン名のみで、
    /// 実際のデータ疎通は引き続きSNIプロキシが強制する）。
    pub fn create_network_acl(&self, name: &str) -> Result<(), VmError> {
        let _ = self.request(
            reqwest::Method::DELETE,
            &format!("/1.0/network-acls/{name}"),
            None,
        )?;
        let body = serde_json::json!({
            "name": name,
            "description": "harness Tier3 egress allowlist (SNI proxy transparent redirect)",
            "egress": [
                {"action": "allow", "protocol": "tcp", "destination_port": "443", "state": "enabled"},
                {"action": "allow", "protocol": "udp", "destination_port": "53", "state": "enabled"},
                {"action": "allow", "protocol": "tcp", "destination_port": "53", "state": "enabled"},
            ],
            "ingress": [],
        });
        let (status, value) =
            self.request(reqwest::Method::POST, "/1.0/network-acls", Some(body))?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "create_network_acl failed: status={status} body={value}"
            )));
        }
        Ok(())
    }

    /// コンテナの`eth0`デバイスへACLを適用し、既定出口をdropにする
    /// （`security.acls.default.出口.action=drop`、`RESULTS.md`§3.8）。
    pub fn attach_acl_to_container(
        &self,
        container_name: &str,
        acl_name: &str,
    ) -> Result<(), VmError> {
        let (status, value) = self.request(
            reqwest::Method::GET,
            &format!("/1.0/instances/{container_name}"),
            None,
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "attach_acl_to_container: failed to fetch instance: status={status} body={value}"
            )));
        }
        let inst = value
            .get("metadata")
            .ok_or_else(|| VmError::Incus("instance response has no metadata".to_string()))?;
        let mut devices = inst
            .get("expanded_devices")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        devices["eth0"] = serde_json::json!({
            "name": "eth0",
            "network": "incusbr0",
            "type": "nic",
            "security.acls": acl_name,
            "security.acls.default.egress.action": "drop",
            "security.acls.default.ingress.action": "allow",
        });
        let config = inst
            .get("config")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let body = serde_json::json!({ "devices": devices, "config": config });
        let (status, value) = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{container_name}"),
            Some(body),
        )?;
        if status == 202 {
            self.wait_operation(
                &format!(
                    "/1.0/operations/{}",
                    value
                        .get("metadata")
                        .and_then(|m| m.get("id"))
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                ),
                Duration::from_secs(30),
            )?;
        } else if status >= 400 {
            return Err(VmError::Incus(format!(
                "attach_acl_to_container failed: status={status} body={value}"
            )));
        }
        Ok(())
    }

    /// ワークスペースのCIFSライブ共有をコンテナへbind-mountするdisk deviceを追加する
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md`§2.4のライブ共有方式）。`attach_acl_to_container`
    /// と同じ「GETで`expanded_devices`取得→Rust側でマージ→PUTで丸ごと書き戻す」手順を踏む
    /// （単純な`PATCH`だとdevicesのネストしたマージが期待通り効かない可能性があるため、
    /// 既存のACL付与ロジックが確立した手順に合わせて安全側に倒す）。
    ///
    /// `source`はコンテナが動くAlmaLinux VM自身の中のパス（`mount -t cifs`した先、
    /// 例`/mnt/harness-workspace`）であり、Windowsホスト側のパスではない点に注意。
    /// **BUG-026で根本原因を確定**: `Missing source path ... for disk`は「Incus側の
    /// ファイルシステム状態確認の遅延」ではなく、呼び出し側（`attach_to_guest`）が
    /// **台帳の再利用分岐で実際にゲスト側マウントを検証せずここへ来た場合に決定論的に
    /// 発生する**（台帳はWindows側で永続、マウントはVM寿命限りのため両者がズレ得る）。
    /// 根本修正は呼び出し側（`guest_workspace_mount_is_healthy`によるゲスト直接問い合わせ、
    /// `docs/bugs/BUG-026.md`参照）で行うため、ここでのリトライは真にIncus側の短い
    /// ファイルシステム反映遅延（実在するマウントに対する一時的な取りこぼし）だけを
    /// 吸収する短めの回数に留める。
    pub fn add_disk_device(
        &self,
        container_name: &str,
        device_name: &str,
        source: &str,
        path: &str,
    ) -> Result<(), VmError> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = None;
        for attempt in 0..MAX_ATTEMPTS {
            match self.try_add_disk_device(container_name, device_name, source, path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Missing source path") {
                        std::thread::sleep(Duration::from_millis(300 + 200 * attempt as u64));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| VmError::Incus("add_disk_device: exhausted retries".to_string())))
    }

    fn try_add_disk_device(
        &self,
        container_name: &str,
        device_name: &str,
        source: &str,
        path: &str,
    ) -> Result<(), VmError> {
        let (status, value) = self.request(
            reqwest::Method::GET,
            &format!("/1.0/instances/{container_name}"),
            None,
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "add_disk_device: failed to fetch instance: status={status} body={value}"
            )));
        }
        let inst = value
            .get("metadata")
            .ok_or_else(|| VmError::Incus("instance response has no metadata".to_string()))?;
        let mut devices = inst
            .get("expanded_devices")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        devices[device_name] = serde_json::json!({
            "type": "disk",
            "source": source,
            "path": path,
        });
        let config = inst
            .get("config")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let body = serde_json::json!({ "devices": devices, "config": config });
        let (status, value) = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{container_name}"),
            Some(body),
        )?;
        if status == 202 {
            self.wait_operation(
                &format!(
                    "/1.0/operations/{}",
                    value
                        .get("metadata")
                        .and_then(|m| m.get("id"))
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                ),
                Duration::from_secs(30),
            )?;
        } else if status >= 400 {
            return Err(VmError::Incus(format!(
                "add_disk_device failed: status={status} body={value}"
            )));
        }
        Ok(())
    }

    /// unprivilegedコンテナのroot（namespace内uid 0）がホスト側（このAlmaLinux VM自身の
    /// ファイルシステム上）で実際に何uid/gidへマップされるかを返す。**実機で判明した罠**:
    /// `incus config get <name> volatile.idmap.base`は常に`0`を返す（無関係な旧フィールド
    /// らしく、実際のマッピングは`volatile.idmap.current`というJSON配列にある）。この値を
    /// CIFSマウントの`uid=/gid=`（`forceuid,forcegid`込み）へ渡さないと、コンテナ内から見た
    /// ホスト実uid 0所有のファイルが`nobody`扱いになり書込みが`Permission denied`になる
    /// （spike検証で発見。`shift=true`によるidmap shiftはCIFSが対応しておらず
    /// `Required idmapping abilities not available`で失敗するため、この静的uid合わせが
    /// 唯一の非特権コンテナ向け解決策）。
    pub fn container_root_host_id(&self, name: &str) -> Result<(u32, u32), VmError> {
        let (status, value) = self.request(
            reqwest::Method::GET,
            &format!("/1.0/instances/{name}"),
            None,
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "container_root_host_id: failed to fetch instance: status={status} body={value}"
            )));
        }
        let idmap_str = value
            .get("metadata")
            .and_then(|m| m.get("config"))
            .and_then(|c| c.get("volatile.idmap.current"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| {
                VmError::Incus(format!("container {name} has no volatile.idmap.current"))
            })?;
        let idmap: Vec<serde_json::Value> = serde_json::from_str(idmap_str)
            .map_err(|e| VmError::Incus(format!("failed to parse volatile.idmap.current: {e}")))?;
        let uid = idmap
            .iter()
            .find(|e| {
                e.get("Isuid").and_then(|v| v.as_bool()) == Some(true)
                    && e.get("Nsid").and_then(|v| v.as_i64()) == Some(0)
            })
            .and_then(|e| e.get("Hostid"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                VmError::Incus(format!("container {name}: no uid mapping for nsid 0"))
            })?;
        let gid = idmap
            .iter()
            .find(|e| {
                e.get("Isgid").and_then(|v| v.as_bool()) == Some(true)
                    && e.get("Nsid").and_then(|v| v.as_i64()) == Some(0)
            })
            .and_then(|e| e.get("Hostid"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                VmError::Incus(format!("container {name}: no gid mapping for nsid 0"))
            })?;
        Ok((uid as u32, gid as u32))
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

pub(crate) fn urlencoding_path(path: &str) -> String {
    // Incus APIのpathクエリパラメータ用の最小限のエンコード（スペース・日本語程度を想定）。
    path.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '.' | '_' | '-' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

