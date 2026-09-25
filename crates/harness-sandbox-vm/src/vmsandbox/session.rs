//! 1セッションのライフサイクル。上の各モジュール（Incus・SSH・ワークスペース共有）を
//! 束ねる層。
//!
//! `VmSession::attach_to_guest`が「常駐VMへアタッチ→コンテナ作成/起動→ワークスペース資源の
//! 確保」までを行い、`teardown`が撤収する。VM自体の起動/撤収は`crate::vm_host::VmHost`が
//! 参照カウントで管理する共有資源のため、本モジュールは自分のコンテナとワークスペース単位
//! 資源だけを知る。`gc_orphan_sessions`は前回の異常終了で残った資源を回収する。

use super::*;

/// 稼働中のTier3セッション（常駐VM上の1コンテナ）を表す。`VmSandboxHandle`
/// （`crate::vmsandboxd`）がデーモンプロセス内で保持し続ける。**Phase B**: VM自体は
/// `crate::vm_host::VmHost`が参照カウントで管理する共有resident資源になったため、本構造体は
/// もはやVMの識別子（旧`vm_name`/`diff_vhdx`）を保持しない——teardown時にVMを操作するのは
/// `VmHost::release`の責務であり、本構造体が知る必要があるのは自分のコンテナと
/// ワークスペース単位資源（`workspace_id`）だけである。
pub struct VmSession {
    session_id: String,
    /// このセッションが同時実行数上限の枠として払い出された番号（`vmsandboxd::SessionRegistry`
    /// 参照）。コンテナの静的IP・SNIプロキシポートの衝突回避に使う。
    slot: u8,
    /// `short_id(canonicalized workspace_root)`（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）。
    /// SMB共有・使い捨てアカウント・NTFS ACE・CIFSマウントはこのIDで参照カウント共有する。
    workspace_id: String,
    container_name: String,
    incus: IncusClient,
    /// 出口許可リスト（SNIプロキシ+nftables DNAT）を構成した場合のみ`Some`（`allow_domains`
    /// が非空だった場合）。teardown時にこれを見て監査ログ取得・出口設定解除の要否を判定する。
    ssh_key: Option<PathBuf>,
    /// `WorkspaceShareMode::Cifs`のセッションかどうかのフラグを兼ねる（`Some`なら
    /// teardownで`copy_out_workspace`をスキップし、ワークスペース単位資源の参照カウント
    /// 解放を行う）。実際の共有名・アカウント名は台帳の`WorkspaceResourceEntry`が正であり
    /// （`workspace_id`単位で複数セッションが共有し得るため）、本フィールドはteardown時の
    /// 分岐判定にのみ使う。
    smb_share_name: Option<String>,
}

/// ワークスペース単位資源（SMB共有・使い捨てアカウント・NTFS ACE・CIFSマウント）の
/// 「台帳を見て無ければ作成/参照カウント0なら破棄する」判定〜実行を全セッション横断で
/// 直列化するロック（Phase B実機E2Eで発見したTOCTOUバグの是正、`attach_to_guest`/
/// `teardown`のdoc参照）。`workspace_id`単位ではなくプロセス全体で単一にしている理由は、
/// 作成・破棄そのものが高速（数百ms、`RESULTS.md`参照）でありワークスペースをまたいだ
/// 競合が実運用上ほぼ無いため、実装を単純に保つトレードオフを取ったもの。
static WORKSPACE_RESOURCE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const CONTAINER_IMAGE_ALIAS: &str = "alpine/3.21";
/// コンテナの静的IPのベースオクテット。実際のIPは`10.76.180.{CONTAINER_IP_BASE + slot}/24`
/// （`slot`: 0..同時実行数上限）。**Phase Bで新規発見**: 旧実装は全コンテナに固定
/// `10.76.180.60/24`を割り当てていた（旧「1VM=1セッション」前提では同時に1コンテナしか
/// 存在しないため無害だったが、常駐VM上に複数コンテナが同居する今回の設計ではIP衝突になる）。
const CONTAINER_IP_BASE: u8 = 61;
const CONTAINER_GATEWAY: &str = "10.76.180.1";
const WORKSPACE_MOUNT: &str = "/workspace";

pub(crate) fn container_static_ip_cidr(slot: u8) -> String {
    format!("10.76.180.{}/24", CONTAINER_IP_BASE.saturating_add(slot))
}

pub(crate) fn container_ip(slot: u8) -> String {
    format!("10.76.180.{}", CONTAINER_IP_BASE.saturating_add(slot))
}

/// ゲストが静的IPで応答し、Incus mTLSクライアント証明書が信頼されるまで待つ（コールドブート
/// ・ウォームRestoreの両方から共有、B4/B5参照）。`guest_wait_timeout`は呼び出し側が
/// コールド/ウォームに応じて使い分ける（コールドは起動+firstbootを見込み長め、ウォームは
/// 既に起動済みのはずなので短め、B8参照）。
pub(crate) fn wait_for_guest_ready(
    config: &VmSandboxConfig,
    guest_wait_timeout: Duration,
) -> Result<IncusClient, VmError> {
    // ゲストが静的IPで応答するまでポーリング（`RESULTS.md`§3.7実測: 初回pingから即応答）。
    wait_tcp_reachable(config.guest_ip, config.incus_port, guest_wait_timeout)
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

    Ok(incus)
}

impl VmSession {
    /// 常駐VM（`crate::vm_host::VmHost`が参照カウントで管理）へアタッチ→コンテナ作成/起動→
    /// ワークスペース資源の確保、までを一気に行う。**Phase B**: VM自体の起動は
    /// `VmHost::attach`が担う。2セッション目以降は既に起動済みのVMへ即座にアタッチするだけで、
    /// 新規VM作成は発生しない。`slot`は`vmsandboxd::SessionRegistry`が同時実行数上限の枠として
    /// 払い出す番号で、コンテナの静的IP・SNIプロキシポートの衝突回避に使う。
    pub fn start(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        allow_domains: &[String],
        warm: bool,
        slot: u8,
    ) -> Result<Self, VmError> {
        let session_id = unique_session_id();
        let incus = crate::vm_host::VmHost::global().attach(config, warm)?;
        let result = Self::attach_to_guest(
            workspace_root,
            config,
            session_id,
            incus,
            allow_domains,
            slot,
        );
        if result.is_err() {
            // VM自体は他セッションが使用中の可能性があるため、ここでは「このセッションの
            // 取り分」を返上するだけでよい（refcountが0になれば`VmHost::release`が実際に
            // VMを停止する）。
            crate::vm_host::VmHost::global().release(config);
        }
        result
    }

    /// ゲストへの疎通確認済み`incus`クライアント（`Self::start`＝`VmHost::attach`が既に
    /// 用意したもの）を受け取り、コンテナ作成からワークスペース資源の確保までを行う。
    fn attach_to_guest(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        session_id: String,
        incus: IncusClient,
        allow_domains: &[String],
        slot: u8,
    ) -> Result<Self, VmError> {
        let container_name = format!("harness-{session_id}");
        incus.create_container(&container_name, CONTAINER_IMAGE_ALIAS)?;
        incus.start_container(&container_name)?;

        // **実機で判明した罠**: `start_container`はIncus APIへstart操作を投げた後
        // 固定500msスリープするだけで、コンテナ内のeth0（veth）が実際に出現するのを待たない。
        // 直後に`ip addr add ... dev eth0`を撃つと稀に"Cannot find device"で失敗するが、
        // 後続コマンドを`;`区切りにしていたため`exec`全体のexit codeは最後の`mkdir -p`の
        // 結果になってしまい、失敗が一切表面化しないまま`/etc/resolv.conf`だけは書かれる
        // （＝DNSサーバは設定されるがIPv4アドレス自体が無く、`wget`が"bad address"で
        // 静かに失敗する）という形で発覚した。eth0の出現をポーリングで待ってから設定する。
        let mut eth0_ready = false;
        for _ in 0..30 {
            let (stdout, _stderr, code) = incus.exec(
                &container_name,
                &["sh", "-c", "ip link show eth0"],
                "/",
                &[],
                Duration::from_secs(5),
            )?;
            if code == Some(0) && stdout.contains("eth0") {
                eth0_ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        if !eth0_ready {
            return Err(VmError::Incus(format!(
                "container {container_name}: eth0 did not appear within timeout"
            )));
        }

        // DHCP不通の既知制約（`RESULTS.md`§段階3）への回避策: 静的IPを直接設定する。
        // **実機で判明した罠(1)**: `ip addr add`で後乗せするだけでは不十分。Alpineの
        // `/etc/network/interfaces`は既定で`iface eth0 inet dhcp`のままであり、ifupdown-ngが
        // 起動したバックグラウンドの`udhcpc -b`がDHCPサーバ不在のまま再試行ループを続けている。
        // このリトライサイクルが手動追加したアドレスをフラッシュしてしまうため、数秒〜十数秒後
        // （LLMのターン往復程度の時間）に静的IPが消え、`wget: bad address`として現れていた
        // （`ip addr add`直後の短時間チェックでは再現しなかったため発見が遅れた）。
        // `ifdown`/`ifup`でifupdown-ng自体にstatic管理させることで、udhcpcのプロセスごと
        // 止めて再発を防ぐ。**実機で判明した罠(1b)**: `ifdown eth0`直後に間を置かず`ifup eth0`を
        // 実行すると、`ifdown`が止めたはずの旧`udhcpc`プロセスがロックファイルをまだ解放しきって
        // おらず`ifup: could not acquire exclusive lock for eth0: Resource temporarily unavailable`
        // で失敗することがある（プロセス終了が非同期のため）。`pkill`で明示的に刈り取ってから
        // 短いリトライループで`ifup`する。
        // **実機で判明した罠(2)**: 静的IP割当はNetworkManager/dhclientを経由しないため
        // `/etc/resolv.conf`が空のままになり、コンテナ内のDNS解決自体が失敗する
        // （`nslookup`が既定の`127.0.0.1`へ問い合わせて`Connection refused`になる）。
        // ACL（`create_network_acl`）でUDP/TCP 53の出口を許可しても、そもそも問い合わせ先の
        // リゾルバが設定されていなければ無意味なため、ここで明示的に設定する
        // （nginx SNIプロキシの`resolver`ディレクティブと同じ`1.1.1.1`に揃える）。
        // 最終判定は`ifup`自身の終了コードではなく`ip -4 addr show eth0`にinetが実在するかで
        // 行う（`&&`連結の最後の条件が全体のexit codeを決めるため、確実に反映される）。
        let interfaces_conf = format!(
            "auto eth0\niface eth0 inet static\n    address {}\n    gateway {CONTAINER_GATEWAY}\n",
            container_static_ip_cidr(slot)
        );
        // **実機で判明した罠(3)**: コンテナ起動直後、Alpineのopenrc `networking`サービスは
        // eth0の自動DHCPブリングアップをまだ実行中のことがあり（`rc-status`で`networking
        // [starting]`のまま長時間止まる、Incusブリッジ側のIPv4 DHCP応答が遅い/来ない場合に
        // 発生）、この間ifupdown-ngの排他ロックを握ったままになる。**この状態で
        // `rc-service networking stop`を叩くと、openrcのサービスマネージャ自身が
        // 「start処理が終わるまでstopを受け付けない」ため一緒にハングする**（実機で確認：
        // stopコマンド自体が返ってこず、後続の`ifdown`/`pkill`にすら到達しない。openrc経由の
        // 「お行儀の良い」停止要求では、まさにこの詰まった状態を解消できない）。openrcを
        // 経由せず、ロックを握っている実プロセス（自動`ifup`本体・その子の`dhcp`ヘルパー・
        // `udhcpc`）を`pkill -9`で直接強制終了することで、openrc側の「starting」状態が
        // 詰まっていても確実に解放できる（`pkill -9 -x udhcpc`だけでは、まだ`ifup`本体や
        // `dhcp`ヘルパーが生き残ってロックを取り直す可能性があるため、3つとも対象にする）。
        // **実機で判明した罠(3b)**: 当初`pkill -9 -f 'ifup -i'`（コマンドライン全体一致）を
        // 使ったところ、この`pkill`コマンド自身の引数文字列に"ifup -i"という部分文字列が
        // 含まれるため`-f`が**自分自身にもマッチして自殺**した（exit=137=SIGKILL、実機で
        // 再現・特定）。プロセス名の完全一致のつもりで`-x ifup`/`-x dhcp`/`-x udhcpc`
        // （`/proc/<pid>/comm`は確かに"ifup"/"dhcp"/"udhcpc"と一致することを実機確認済み）に
        // 切り替えたが、**それでも対象を1つも殺せず無言で失敗し続けた**（`>/dev/null 2>&1`で
        // 抑制していたため気付くのに時間を要した）。原因はAlpineのbusybox版`pkill`の`-x`が
        // GNU版と異なり`/proc/comm`（basenameのみ）ではなく**フルパス込みの起動名**
        // （`/sbin/udhcpc`等）との完全一致を要求すること（実機で`pkill -9 udhcpc`
        // （`-x`無し、部分一致）なら確実に殺せることを確認して特定）。`-x`を外した部分一致に
        // 変更する（自プロセス自身の`comm`は`sh`のため、`-f`を使わない限りこのパターンで
        // 自己マッチする心配は無い）。
        // **診断強化（原因未特定の実機障害切り分け用）**: 従来は各ステップを`>/dev/null 2>&1`で
        // 抑制していたため、失敗時にstdout/stderrが両方空のままexit codeだけが返り、どのステップで
        // 落ちたか一切判別できなかった（`docs/bugs/`記録予定の障害）。`set -x`で実行トレースを残し、
        // 各ステップ後に`STEP=`マーカーをstdoutへ出す。最終判定も単一の`&&`鎖からifブランチへ
        // 分離し、`FAIL=no-inet`かどうかで「ifupは成功扱いだがIPが付かない」ケースを識別できるように
        // する。失敗が確定した場合のみ、追加の往復を要さず同一execの中で診断ダンプ
        // （アドレス・ルート・interfaces内容・ifupdown-ng状態・`ifup -v`生出力・rc-status・
        // プロセス残存）を出す。**罠(3b)の教訓によりpkillのパターン自体は一切変更しない**
        // （`-f`を足すと自分自身にマッチして自殺する）。
        //
        // **実機診断で判明した罠(4)**: 上記の診断強化により、当初原因不明だった本エクスポート
        // の失敗が次のように特定できた（`docs/bugs/`記録予定）。冒頭の`pkill -9 udhcpc`実行時点
        // では、コンテナ起動直後のopenrc自動DHCPブリングアップがまだudhcpcを起動し切っておらず
        // （`rc-status`が`networking [started]`を返す時点でも、実プロセスの生成は追いついて
        // いないことがある）、直後の`sleep 1`より後にudhcpcが新規生成されて`ifdown`/`ifup`の
        // 排他ロックを握ってしまう。結果、リトライループの大半が
        // `could not acquire exclusive lock for eth0: Resource temporarily unavailable`で
        // 空振りし、ロックがようやく空いた回では今度はifupdown-ng側が「(旧DHCP設定のまま)既に
        // 設定済み」とみなし`ifup: skipping auto interface eth0 (already configured), use
        // --force to force configuration`で**無言のexit 0スキップ**をする。どちらも冒頭1回の
        // `pkill`＋`ifup`（force無し）では防げないため、リトライの**毎周**で
        // `pkill -9 udhcpc`を撃ち直しつつ`ifup --force`で明示的に強制再設定する形へ変える。
        let (stdout, stderr, code) = incus.exec(
            &container_name,
            &[
                "sh",
                "-c",
                &format!(
                    "set -x; \
                     pkill -9 ifup; \
                     pkill -9 dhcp; \
                     pkill -9 udhcpc; \
                     echo 'STEP=pkill-done'; \
                     sleep 1; \
                     printf '%s' '{interfaces_conf}' > /etc/network/interfaces; \
                     echo 'STEP=interfaces-written'; \
                     ifdown eth0; \
                     echo 'STEP=ifdown-done'; \
                     ok=0; i=0; while [ $i -lt 20 ]; do \
                       pkill -9 udhcpc; pkill -9 dhcp; \
                       ifup --force eth0 && {{ ok=1; break; }}; \
                       i=$((i+1)); sleep 1; \
                     done; \
                     echo \"STEP=ifup-loop-done ok=$ok tries=$i\"; \
                     if ip -4 addr show eth0 | grep -q 'inet '; then \
                       echo 'STEP=inet-ok'; \
                       echo 'nameserver 1.1.1.1' > /etc/resolv.conf; \
                       mkdir -p {WORKSPACE_MOUNT}; \
                       echo 'STEP=resolv-and-mkdir-done'; \
                     else \
                       echo 'FAIL=no-inet'; \
                       echo '---diag: ip -4 addr show eth0---'; ip -4 addr show eth0; \
                       echo '---diag: ip -4 route---'; ip -4 route; \
                       echo '---diag: /etc/network/interfaces---'; cat /etc/network/interfaces; \
                       echo '---diag: /run/ifstate/eth0---'; cat /run/ifstate/eth0 2>&1; \
                       echo '---diag: ifup -v eth0---'; ifup -v eth0 2>&1; \
                       echo '---diag: rc-status -a---'; rc-status -a 2>&1; \
                       echo '---diag: ps w---'; ps w; \
                       exit 1; \
                     fi"
                ),
            ],
            "/",
            &[],
            Duration::from_secs(60),
        )?;
        if code != Some(0) {
            return Err(VmError::Incus(format!(
                "container {container_name}: static IP/DNS setup failed (exit={code:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            )));
        }

        // 出口許可リスト（SNIプロキシ+nftables DNAT+コンテナACL）は`allow_domains`が
        // 非空の場合のみ構成する。既定（省略時）はPhase 1と同じ無制限出口のまま
        // （既存の`--net-allow-domain`未指定時の挙動を変えない、D-02と同じ「オプトイン」思想）。
        // **Phase B（B-1）**: IPCが同一ユーザーの任意プロセスへ開かれた以上`allow_domains`は
        // 外部入力として扱い、`validate_allow_domain`で妥当性を確認してから使う。
        let ssh_key = if allow_domains.is_empty() {
            None
        } else {
            for d in allow_domains {
                validate_allow_domain(d)?;
            }
            let key = ensure_ssh_keypair()?;
            attach_egress_acl(&incus, &container_name)?;
            crate::vm_host::VmHost::global().configure_egress(
                config,
                &key,
                slot,
                container_ip(slot),
                allow_domains.to_vec(),
            )?;
            Some(key)
        };

        let workspace_id = crate::smb_share::compute_workspace_id(workspace_root);

        // ワークスペース共有（`WorkspaceShareMode`、移行期間の切り替えフラグ）。
        // `Cifs`: Windows側でSMB共有→SSH経由でゲストへ認証情報配布→ゲスト内`mount -t cifs`
        // →Incus disk deviceでコンテナへbind-mount、のライブ共有シーケンス。**Phase B**:
        // `workspace_id`単位で参照カウント共有する（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）。
        // 既に他セッションが同じワークスペースの共有・アカウント・CIFSマウントを用意済みなら
        // 新規作成せず参照カウントだけ増やして再利用する。
        //
        // **TOCTOU**: 「台帳を見て既存資源が無ければ作成する」という判定と作成は、
        // `WORKSPACE_RESOURCE_LOCK`で直列化しないと2セッションが同時に「無い」と判定して
        // 同じ`workspace_id`の共有・アカウントを二重作成してしまう（BUG-024）。判定〜
        // 作成/修復〜台帳記録〜`add_disk_device`までを1つのクリティカルセクションにする。
        //
        // **BUG-026**: 台帳（L1、Windows側で永続）だけを根拠に「ゲスト側マウント（L2、
        // VM寿命限り）済み」とみなしてはならない。両者の整合は`decide_workspace_action`が
        // ゲストへ直接問い合わせて判定し（`guest_workspace_mount_is_healthy`）、ズレていれば
        // Repair（パスワードローテーション+再mount）で修復する。さらに`add_disk_device`が
        // 失敗した場合は、直前に増やした/作った台帳エントリを必ず巻き戻す（経路B＝
        // refcount単調増加による自己増殖の遮断）。
        let workspace_lock = WORKSPACE_RESOURCE_LOCK.lock().unwrap();
        let smb_share_name = if config.workspace_share_mode == WorkspaceShareMode::Cifs {
            let mount_point = format!("/mnt/harness-workspace-{workspace_id}");
            let host_ssh_key = ensure_ssh_keypair()?;

            let acquire_result = acquire_or_repair_workspace_share(
                workspace_root,
                &workspace_id,
                config,
                &host_ssh_key,
                &mount_point,
                &incus,
                &container_name,
            );
            let (share, user) = match acquire_result {
                Ok(pair) => pair,
                Err(e) => {
                    // [BUG-028] `add_disk_device`失敗時（下記）と対称: `acquire_or_repair_workspace_share`
                    // 内部（`create_fresh_workspace_share`/`repair_workspace_share`）の失敗が
                    // `record_workspace_resource`後（台帳に記録済み）で起きた場合、ここで
                    // 巻き戻さないと台帳エントリと実体（共有・アカウント・NTFS ACE）の両方が孤児化する。
                    // `record_workspace_resource`前（例: `create_ephemeral_share`自体の失敗）の場合は
                    // `release_workspace_resource`が`None`を返すため何もしない
                    // （そちらは`create_ephemeral_share`自身がbest-effortで後始末済み）。
                    if let Some(removed) =
                        crate::vm_ledger::release_workspace_resource(&workspace_id)
                    {
                        let _ = ssh_exec(
                            config.guest_ip,
                            &host_ssh_key,
                            &format!(
                                "umount -l {mount_point} 2>/dev/null; rm -f /etc/harness-smb-{workspace_id}.cred"
                            ),
                            Duration::from_secs(15),
                        );
                        crate::smb_share::destroy_ephemeral_share(
                            &removed.smb_share_name,
                            &removed.smb_user,
                            Some(Path::new(&removed.workspace_root)),
                        );
                    }
                    drop(workspace_lock);
                    return Err(e);
                }
            };

            if let Err(e) =
                incus.add_disk_device(&container_name, "workspace", &mount_point, WORKSPACE_MOUNT)
            {
                // F3: `add_disk_device`失敗時は、直前に増やした/作ったワークスペース資源の
                // refcountを必ず巻き戻す。ロックはこの巻き戻しの間保持したまま
                // （再取得するとデッドロックする）。
                if let Some(removed) = crate::vm_ledger::release_workspace_resource(&workspace_id) {
                    let _ = ssh_exec(
                        config.guest_ip,
                        &host_ssh_key,
                        &format!(
                            "umount -l {mount_point} 2>/dev/null; rm -f /etc/harness-smb-{workspace_id}.cred"
                        ),
                        Duration::from_secs(15),
                    );
                    crate::smb_share::destroy_ephemeral_share(
                        &removed.smb_share_name,
                        &removed.smb_user,
                        Some(Path::new(&removed.workspace_root)),
                    );
                }
                drop(workspace_lock);
                return Err(e);
            }

            let _ = user; // 台帳（`WorkspaceResourceEntry`）が正であり、ここでは使わない。
            Some(share)
        } else {
            None
        };
        drop(workspace_lock);

        let session = Self {
            session_id,
            slot,
            workspace_id,
            container_name,
            incus,
            ssh_key,
            smb_share_name,
        };
        if config.workspace_share_mode == WorkspaceShareMode::CopyInOut {
            session.copy_in_workspace(workspace_root)?;
        }
        Ok(session)
    }

    /// ワークスペース全体をコンテナの`/workspace`へpushする（Phase 1: 素朴な全ファイル
    /// 走査。大規模ワークスペースでの性能はPhase 2以降で見直す、TODOとして明記）。
    fn copy_in_workspace(&self, workspace_root: &Path) -> Result<(), VmError> {
        for entry in walk_files(workspace_root)? {
            let rel = entry
                .strip_prefix(workspace_root)
                .map_err(|e| VmError::Io(e.to_string()))?;
            let remote = format!(
                "{WORKSPACE_MOUNT}/{}",
                rel.to_string_lossy().replace('\\', "/")
            );
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
            self.incus
                .push_file(&self.container_name, &contents, &remote)?;
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
            let rel = remote
                .trim_start_matches(WORKSPACE_MOUNT)
                .trim_start_matches('/');
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
    ///
    /// **`sh -c`を差し込むのはここだけ**——`run_shell`はその場のコードをシェルへ渡す道具なので
    /// それが正しい。引数の配列を渡す`run_program`は[`Self::exec_argv`]を通る。
    pub fn exec(
        &self,
        cmd: &str,
        cwd: &Path,
        workspace_root: &Path,
        env: &[(String, String)],
        timeout: Duration,
    ) -> Result<(String, String, Option<i32>), VmError> {
        let remote_cwd = self.remote_cwd(cwd, workspace_root);
        self.incus.exec(
            &self.container_name,
            &["sh", "-c", cmd],
            &remote_cwd,
            env,
            timeout,
        )
    }

    /// `run_program`から呼ばれる実行チャネル（D-108）。**引数の配列をそのまま渡す。**
    ///
    /// コンテナへ渡す口（[`crate::vmsandbox::incus::Incus::exec`]）は元々配列を受け取るので、
    /// ここでシェルを挟む理由が無い——挟むと、構造化で消したはずの「解釈する層」が戻る（D-96）。
    pub fn exec_argv(
        &self,
        argv: &[String],
        cwd: &Path,
        workspace_root: &Path,
        env: &[(String, String)],
        timeout: Duration,
    ) -> Result<(String, String, Option<i32>), VmError> {
        let remote_cwd = self.remote_cwd(cwd, workspace_root);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.incus
            .exec(&self.container_name, &borrowed, &remote_cwd, env, timeout)
    }

    /// ホストの作業ディレクトリを、コンテナ内の`/workspace`配下へ写す。
    fn remote_cwd(&self, cwd: &Path, workspace_root: &Path) -> String {
        let rel_cwd = cwd
            .strip_prefix(workspace_root)
            .unwrap_or_else(|_| Path::new("."));
        if rel_cwd.as_os_str().is_empty() || rel_cwd == Path::new(".") {
            WORKSPACE_MOUNT.to_string()
        } else {
            format!(
                "{WORKSPACE_MOUNT}/{}",
                rel_cwd.to_string_lossy().replace('\\', "/")
            )
        }
    }

    /// **Phase B**: VM自体はもう`self`が所有していない（`crate::vm_host::VmHost`が参照カウント
    /// で管理する共有resident資源）ため、`config`を受け取って最後に`VmHost::release`を呼ぶ。
    pub fn teardown(self, workspace_root: &Path, config: &VmSandboxConfig) -> Result<(), VmError> {
        // `WorkspaceShareMode::Cifs`セッションはライブ共有のためワークスペースの中身は
        // 常にホストの実ファイルシステムそのもの（bind-mountを外すだけ）で、明示的な
        // copy-outは不要（`copy_in_workspace`と同じくPhase 1の全ファイルpull往復を避ける、
        // このライブ共有方式を導入した本来の目的）。
        let copy_out_result = if self.smb_share_name.is_some() {
            Ok(())
        } else {
            self.copy_out_workspace(workspace_root)
        };
        // 出口許可リストを構成していた場合のみ、VMが消える前に監査ログを回収し、
        // このセッション分の出口設定をVM全体の集合から取り除く（A-8、`VmHost::release_出口`）。
        if let Some(ssh_key) = &self.ssh_key {
            let _ = fetch_and_persist_audit_log(
                self.incus.host_ip(),
                ssh_key,
                workspace_root,
                &self.session_id,
                self.slot,
            );
            let _ = crate::vm_host::VmHost::global().release_egress(config, ssh_key, self.slot);
        }
        let _ = self.incus.stop_container(&self.container_name);
        let _ = self.incus.delete_container(&self.container_name);

        // ワークスペース単位資源（SMB共有・ローカルアカウント・CIFSマウント・NTFS ACE）の
        // 参照カウントをデクリメントする。0になった最後の1セッションだけが実際に破棄する
        // （`DESIGN-SANDBOX-VMISOLATION.md`項目6-a、A-4の構造的解消）。
        if self.smb_share_name.is_some() {
            // `attach_to_guest`の作成判定と同じロックで直列化する（TOCTOU是正、
            // `WORKSPACE_RESOURCE_LOCK`のdoc参照）。
            let _workspace_lock = WORKSPACE_RESOURCE_LOCK.lock().unwrap();
            if let Some(removed) = crate::vm_ledger::release_workspace_resource(&self.workspace_id)
            {
                if let Ok(host_ssh_key) = ensure_ssh_keypair() {
                    let mount_point = format!("/mnt/harness-workspace-{}", self.workspace_id);
                    let cred_remote = format!("/etc/harness-smb-{}.cred", self.workspace_id);
                    // umount+cred削除はbest-effort（VM自体がこの後停止する可能性もあるため、
                    // 失敗してもteardown全体は止めない、`teardown_vm`と同じ方針）。
                    let _ = ssh_exec(
                        config.guest_ip,
                        &host_ssh_key,
                        &format!("umount {mount_point} 2>/dev/null; rm -f {cred_remote}"),
                        Duration::from_secs(15),
                    );
                }
                crate::smb_share::destroy_ephemeral_share(
                    &removed.smb_share_name,
                    &removed.smb_user,
                    Some(Path::new(&removed.workspace_root)),
                );
            }
        }

        crate::vm_host::VmHost::global().release(config);
        copy_out_result
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// D-24: 台帳+実機照会の両方を突き合わせ、前回の孤児resident VM・差分VHDX・ワークスペース
/// 単位資源を撤収する（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6・§4・項目8）。
/// **Phase B**: `crate::vm_host::VmHost::attach`のStopped→Running遷移直前、または
/// `harness tier3 gc`（別プロセス）から呼ばれる。VMが1台の共有resident資源になったため、
/// 孤児判定の単位も「複数の`session_id`エントリ」から「単一のVMホストエントリ」へ変わった——
/// 孤児と判定された場合、そのVMの生存期間中に参照カウントを管理していたdaemonプロセスの
/// `SessionRegistry`ごと消失しているとみなし、台帳上の全`workspace_resources`エントリも
/// 合わせて撤収する。
///
/// **BUG-027対策**: 台帳に記録された`daemon_pid`（このVMを起動した常駐daemon自身のPID）が
/// 生存している間は、そのVM・全`workspace_resources`をGC対象から一切除外する。これが無いと、
/// セッション実行中に別プロセスから`harness tier3 gc`を叩いただけで、稼働中のVM・コンテナ・
/// SMB共有・NTFS ACEを無条件で撤収してしまう（`docs/bugs/BUG-027.md`）。
///
/// **BUG-026対策（F4）**: `workspace_resources`は孤児VMの有無に関わらず無条件で整合させる。
/// 本関数が実際に呼ばれる時点（daemonがVMをこれから起こす瞬間、またはgc専用プロセス）では
/// アクティブセッションは存在しない前提のため、台帳上の全エントリは定義上stale。また、
/// 台帳に記録されていないWindows側実体（`New-LocalUser`名前衝突後の作り直し漏れ等、状態S2/S3）
/// も`smb_share::enumerate_windows_workspace_shares`で直接走査して回収する（旧実装は
/// `orphans.is_empty()`で早期returnし、孤児VMが無い場合`workspace_resources`を一切見ないため、
/// これらを永久に回収できなかった）。
///
/// 個々の撤収に失敗しても処理は止めない（best-effort、`plans/TIER1A-OPEN-ISSUES.md`
/// 項目9）。GC自体の失敗で`StartSession`を失敗させないよう、呼び出し側は戻り値を無視して
/// 構わない設計（stderrへログするのみ）。
pub fn gc_orphan_sessions(config: &VmSandboxConfig, current_session_id: &str) -> Vec<String> {
    let ledger = crate::vm_ledger::load();

    let resident_daemon_alive = ledger
        .vm_host
        .as_ref()
        .map(|h| crate::vm_ledger::is_pid_alive(h.daemon_pid))
        .unwrap_or(false);
    if resident_daemon_alive {
        eprintln!(
            "gc_orphan_sessions: resident daemon (pid still alive) owns the VM; skipping GC \
             this round to avoid tearing down an active session (BUG-027)"
        );
        return Vec::new();
    }

    let existing_vm_names = match run_powershell(
        "Get-VM -Name 'harness-tier3-*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name",
    ) {
        Ok(stdout) => stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("gc_orphan_sessions: failed to list Hyper-V VMs, skipping GC this round: {e}");
            return Vec::new();
        }
    };

    let orphans = crate::vm_ledger::select_orphan_vm_names(&ledger, &existing_vm_names);

    // F4: 孤児VMの有無に関わらず、台帳上のworkspace_resourcesは無条件で整合させる
    // （resident_daemon_aliveでないと確定した以上、アクティブセッションは存在しないため
    // 台帳上の全エントリは定義上stale）。
    for resource in crate::vm_ledger::select_all_workspace_resources(&ledger) {
        crate::smb_share::destroy_ephemeral_share(
            &resource.smb_share_name,
            &resource.smb_user,
            Some(Path::new(&resource.workspace_root)),
        );
    }
    let cleared = crate::vm_ledger::update(|current| {
        current.workspace_resources.clear();
        current.clone()
    });

    // F4: 台帳に載っていないWindows側実体（状態S2/S3）も実体側から直接走査して回収する。
    // 直前のループで台帳追跡分は既に破棄済みのため、ここで見つかるのは真に台帳から
    // 不可視だった孤児のみ。
    for (share, user, path) in crate::smb_share::enumerate_windows_workspace_shares() {
        crate::smb_share::destroy_ephemeral_share(&share, &user, Some(&path));
    }

    if orphans.is_empty() {
        return orphans;
    }

    for vm_name in &orphans {
        // **実機で発見**: `vm_name`から`{vm_name}.diff.vhdx`という命名規則を推測すると、
        // 実際の常駐VMの差分VHDXファイル名（`crate::vm_host::resident_diff_vhdx_path`が
        // 決める固定名`resident.diff.vhdx`）と一致しない。台帳に記録が無い場合
        // （`vm_host`が`None`になった後の再実行等）は、常駐VM名である前提で正しいパスを導く。
        let diff_vhdx = cleared
            .vm_host
            .as_ref()
            .filter(|h| &h.vm_name == vm_name)
            .map(|h| PathBuf::from(&h.diff_vhdx))
            .unwrap_or_else(|| {
                if vm_name == crate::vm_host::RESIDENT_VM_NAME {
                    crate::vm_host::resident_diff_vhdx_path(config)
                } else {
                    config.vm_work_dir.join(format!("{vm_name}.diff.vhdx"))
                }
            });
        if let Err(e) = teardown_vm(vm_name, &diff_vhdx) {
            eprintln!("gc_orphan_sessions: failed to tear down orphan VM {vm_name}: {e}");
        }
    }
    crate::vm_ledger::remove_vm_host();

    // 台帳・生存VMのどちらからも参照されなくなった差分VHDXの取りこぼしを一掃する
    // （teardown_vm自体が消し忘れた場合の保険、`vm_work_dir`直下のみを対象にする）。
    let Ok(read_dir) = std::fs::read_dir(&config.vm_work_dir) else {
        return orphans;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(session_part) = file_name.strip_suffix(".diff.vhdx") else {
            continue;
        };
        if session_part == current_session_id || existing_vm_names.iter().any(|n| n == session_part)
        {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }

    orphans
}

pub(crate) fn teardown_vm(vm_name: &str, diff_vhdx: &Path) -> Result<(), VmError> {
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

pub(crate) fn wait_tcp_reachable(ip: IpAddr, port: u16, timeout: Duration) -> Result<(), VmError> {
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

pub(crate) fn walk_files(root: &Path) -> Result<Vec<PathBuf>, VmError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            // `.harness/`・`.git/`はワークスペース同期の対象外（サンドボックス制御用の
            // メタデータ・VCS内部構造をコンテナへ持ち込まない、Tier2a/Tier2bの既存慣習と同じ）。
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
