//! 観測した監査イベントを、人が判断できる形（許可ルールの候補）へ畳み込む。
//!
//! # record-allは「拒否」ではなく「触った全部」が入ってくる
//!
//! `harness policy suggest`が使う`harness_policy::normalize_fs_audit`は、`allowed: true`の
//! 行を**捨てる**（deny-onlyの収集器を前提にしているため）。記録モードの出力はほぼ全部が
//! `allowed: true`なので、そのまま通すと候補が0件になる。ここでは
//! [`harness_policy::FsFolder`]で許可・拒否の両方を畳み込む。
//!
//! # `.harness`配下は候補にしない
//!
//! 2つの理由があり、どちらも実害がある。
//!
//! 1. `.harness`はサンドボックスから開けてはいけない制御ディレクトリである（P-08）。
//!    ここへの許可を提案すると、承認台帳や設定をサンドボックス内から書き換える経路を
//!    提案していることになる。`harness_policy::gate::check_proposal`は
//!    `--require-sandbox`との矛盾しか見ないので、この種の提案を止めてくれない。
//! 2. **記録の産物が自分の入力へ戻る**——収集器が書く`fs-audit.jsonl`は
//!    `<workspace>/.harness/sandbox/policy-editor-<id>/`にあるため、workspaceを走査する
//!    コマンド（`cargo build`・`rg`等）を記録すると、前回の記録結果が今回の候補に
//!    混ざり込む。放置すると記録のたびに候補が増える自己参照ループになる。
//!
//! **除外した件数は必ず表示する。** 黙って捨てると「観測できなかった」と区別できない（B-09）。
//!
//! # マシン全体のインストール先（`C:/Windows`・`C:/Program Files`）配下も候補にしない
//!
//! D-58は**実行像**をここから除外していた（[`Aggregate::add_exec_candidate`]）が、
//! **アクセス由来の候補は素通ししていた**——これがBUG-099である。実行を除外する根拠
//! （既定で与えられているので承認しても得るものが無い）は読み取りにもそのまま当てはまるのに、
//! 判定が実行側にしか無かった。
//!
//! 承認されると**失うものがある**。`preflight`は宣言されたパスの**親**をtraverse付与の対象に
//! 入れる（D-45。`win_appcontainer/preflight.rs`の`for requested in passthrough`——
//! **access種別で絞っていない**）。祖先チェーンには`C:/Program Files (x86)`が入り、そこは
//! TrustedInstaller所有でAdministratorsですら`Modify`（`WRITE_DAC`を含まない）なので、
//! 昇格しても付与できない。traverse付与の失敗は警告ではなく`Err`で、**そのドメインの
//! パス2が丸ごと落ちる**。実機で`cargo`ドメインの宣言8件がこれを起こした。
//!
//! したがって除外は**access種別を問わない**。`fs.read`だけを除外しても、`fs.read_write`の
//! 候補（ETWはdisposition 2/4/5をそう畳む）が同じ祖先で同じ失敗を起こす——
//! `breadth::check_value`が`fs.read_write`を止めるのは`C:/Program Files`**そのもの**
//! （深さ2）だけで、その配下の深いパスは通してしまう。
//!
//! **判定は[`harness_policy::breadth::is_default_exec_root_path`]を実行像と共有する**（B-05）。
//! ここで別の規則を持つと、候補に出さないのに「無い」と言って承認を促す自己矛盾を
//! 読み取り側で作り直すことになる。
//!
//! # 実行された像は`fs.read_exec`の候補になる
//!
//! ETWは**読取と実行を区別できない**（`plans/etw-spike/RESULTS.md` §17: 両者の`CreateOptions`は
//! アクセス権と無関係なヒントビット1つを除いて同じ）。したがってアクセスイベントから作る候補は
//! 構造的に`fs.read`止まりで、`fs.read_exec`の候補は**1件も出ない**。ところが実行権が付くのは
//! `read_exec`だけなので、workspace外の実行ファイルを使うコマンドは記録→承認→パス2の順で進むと
//! 必ず`Access is denied`に当たる（実測: `cargo`ドメインは`read` 668件・`read_exec` 0件だった）。
//!
//! 一方で**「何が実行されたか」は観測できている**——`ProcessStart`の実行像である。これは
//! 拡張子からの推測ではなく観測事実で、`.exe`という名前のデータファイルを拾うこともない。
//! [`Aggregate::add_event`]は、プロセスの素性を初めて知った時点でその1件を
//! `fs.read_exec`の候補として合流させる（畳み込み・一般化・幅の判定は既存の`generalize`が行う）。
//!
//! # 起動を拒否された実行ファイルは、実行像としては観測されない
//!
//! 上の経路には**構造的な穴**がある——`ProcessStart`が出るのは起動できたときだけなので、
//! **パス2で実際に詰まった当の実行ファイルだけが候補に出てこない**。実データでも、
//! `.cargo/bin/cargo.exe`の拒否行は`access: "read"`（ETWは読取と実行を区別しない）で、
//! `image_path`は開いた側の`powershell.exe`だった。
//!
//! そこで**もう1つの情報源**を使う。パス2は子を起こす前に到達性を測っており
//! （[`crate::exec_reach`]）、届かないと分かった実行ファイルの綴りをマニフェストへ残す。
//! [`from_session`]がそれを`fs.read_exec`の候補として合流させる——**実行像と同じ除外規則**を
//! 通し（[`Aggregate::add_exec_candidate`]）、足したことは注記に出す（B-09。「観測されなかった」と
//! 「意図して足した」が区別できないと、なぜ`cargo.exe`が候補にあるのかを調べようがない）。
//!
//! # パス2の候補は「記録時点の宣言」を知った上で作る
//!
//! パス2の収集器はdeny-only（`record_all: false`）なので、その候補は**全部が拒否**である。
//! したがってD-46の前提——「既に許可済みなのに拒否された＝その許可では足りない」——が
//! そのまま成立する。マニフェストに残した宣言のスナップショットを[`Aggregate::granted`]へ入れ、
//! `generalize_with_granted`を通す。**パス1では渡さない**: あちらの候補は「拒否」ではなく
//! 「触った全部」なので、同じ推論をすると宣言済みのパスを触っただけで
//! 「readでは足りない」と言い出す。

use std::collections::BTreeMap;

use harness_config::FsAccess;
use harness_policy::{
    event::{FsAuditEvent, FsAuditKind},
    normalize::Source,
    DeniedCandidate, FsFolder, GrantedPaths, RuleProposal,
};

use crate::session_dir::{RecordManifest, RecordSessionDir};

/// 記録1回分の集計結果。
#[derive(Debug)]
pub struct Aggregate {
    /// 候補にしないパスの規則（[`crate::exclusion`]）。**`Default`を持たせない**——
    /// 生成する全経路に「このセッションのworkspaceはどこか」を必ず答えさせるため
    /// （B-06: 配線漏れをコンパイラに数えさせる）。
    rules: crate::exclusion::ExclusionRules,
    folder: FsFolder,
    /// 観測した監査イベント（制御レコードを含む）の総数。
    pub events_seen: u64,
    /// うち許可されていたもの。
    pub allowed: u64,
    /// うち拒否されていたもの。**パス1は隔離しないので、これは通常権限での拒否である**
    /// （[`Self::render`]の注記を参照）。
    pub denied: u64,
    /// `.harness`配下だったため候補にしなかった件数（モジュールdoc参照）。
    pub excluded_control_dir: u64,
    /// **探しに行ったが、そこに無かった**ため候補にしなかった件数。
    ///
    /// DLL検索順・PATH探索・任意設定ファイルの探索は、存在しないパスを大量に叩く（実測では
    /// `cargo test`1回で3,132パス中848パスがこれ）。**存在しないファイルへの許可には意味が無い**
    /// ので候補にしないが、件数は出す（B-09）。
    pub excluded_missing_target: u64,
    /// パス・access種別を持たないイベント（候補にできない）。
    pub without_path: u64,
    /// **AppContainerに既定で実行権がある場所**（`C:/Windows`・`C:/Program Files`配下）
    /// だったため、`fs.read_exec`の候補にしなかった実行像の数（モジュールdoc・B-09）。
    pub excluded_default_exec_image: u64,
    /// 同じ場所への**アクセス**（`fs.read`/`fs.read_write`）だったため候補にしなかった
    /// イベント数（モジュールdoc「マシン全体のインストール先」・BUG-099・B-09）。
    ///
    /// [`Self::excluded_default_exec_image`]とは**数えている対象が違う**ので別に持つ——
    /// あちらは「起動したプロセスの像」、こちらは「触ったパス」で、1つに混ぜると
    /// どちらの理由で候補が消えたのか説明できない文言になる（B-32）。判定は共有する。
    pub excluded_machine_wide_root: u64,
    /// [BUG-103] **このセッションのworkspace配下**だったため候補にしなかった件数
    /// （[`crate::exclusion::Excluded::SessionWorkspace`]）。
    ///
    /// 上の2つと違い、アクセス由来と実行像由来を**1本にまとめている**。理由が同じなら
    /// 説明も対処も同じ（「Tier2aが起動時にツリー全体へRWXを付与済み」）だからで、
    /// BUG-099が分けたのは説明が違ったからである（既定で読める／既定で実行できる）。
    pub excluded_session_workspace: u64,
    /// [BUG-103] `%TEMP%`配下だったため候補にしなかった件数。
    pub excluded_ephemeral_temp: u64,
    /// [BUG-103] harness自身のサンドボックスプロファイル配下だったため候補にしなかった件数。
    pub excluded_sandbox_profile: u64,
    /// [BUG-103追記] `%LOCALAPPDATA%\Packages`（全MSIXアプリの専用データ置き場）配下だったため
    /// 候補にしなかった件数。**プロファイル名の判定とは別に数える**——候補の畳み込みが
    /// 親へ丸めた値はプロファイル名を含まないので、実際に承認されていたのはこちらだった。
    pub excluded_msix_package_data: u64,
    /// 設定パスへ寄せられていない実行像（旧形式の監査ログに残るNTパス）の数。
    /// 変換に必要なボリューム対応表は昇格側にしか無いので、読む側では解けない。
    pub excluded_legacy_image_path: u64,
    /// 実行前診断が名指ししたため`fs.read_exec`の候補へ**足した**実行ファイル（モジュールdoc）。
    /// **これは観測ではない**ので、注記でそう書く（B-09）。
    pub diagnosed_exec: Option<String>,
    /// 収集器自身が書いた制御レコードの内容。**候補ではないが必ず見せる**（D-43）。
    pub collector_notes: Vec<String>,
    /// JSONLとして解釈できなかった行数。
    pub unparsable_lines: u64,
    /// PID → プロセスの素性（ツリー表示用）。
    processes: BTreeMap<u32, ProcessNode>,
    /// **この記録を走らせた時点で既に許可されていたパス**（パス2のみ。モジュールdoc）。
    /// 空なら従来どおり昇格は起きない。
    granted: GrantedPaths,
}

/// 候補の出所。除外の**理由**は共通でも、**数える先**が分かれることがあるので区別する
/// （BUG-099: マシン全体のインストール先は「触ったパス」と「起動した像」で説明が違う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    /// 観測したFSアクセス（`fs.read`/`fs.read_write`の候補になる）。
    Access,
    /// 起動したプロセスの像・実行前診断が名指しした実行ファイル（`fs.read_exec`の候補）。
    ExecImage,
}

/// 記録中に観測した1プロセス。
#[derive(Debug, Clone, Default)]
pub struct ProcessNode {
    pub parent_pid: Option<u32>,
    pub image: Option<String>,
    pub accesses: u64,
}

impl Aggregate {
    /// **除外規則を必ず受け取る**（[`crate::exclusion::ExclusionRules`]のdoc、B-06）。
    pub fn new(rules: crate::exclusion::ExclusionRules) -> Self {
        Self {
            rules,
            folder: FsFolder::default(),
            events_seen: 0,
            allowed: 0,
            denied: 0,
            excluded_control_dir: 0,
            excluded_missing_target: 0,
            without_path: 0,
            excluded_default_exec_image: 0,
            excluded_machine_wide_root: 0,
            excluded_session_workspace: 0,
            excluded_ephemeral_temp: 0,
            excluded_sandbox_profile: 0,
            excluded_msix_package_data: 0,
            excluded_legacy_image_path: 0,
            diagnosed_exec: None,
            collector_notes: Vec::new(),
            unparsable_lines: 0,
            processes: BTreeMap::new(),
            granted: GrantedPaths::default(),
        }
    }

    /// 除外に当たった1件を、理由ごとのカウンタへ数え上げる。**候補にしたかどうかを返す**。
    ///
    /// アクセス由来（[`Self::add_event`]）と実行像由来（[`Self::add_exec_candidate`]）が
    /// **同じ規則・同じ数え方**を通る唯一の場所。`kind`を受けるのは、マシン全体の
    /// インストール先だけ「触ったパス」と「起動した像」で説明が違うためである（BUG-099）。
    fn note_exclusion(
        &mut self,
        path: &str,
        kind: CandidateKind,
    ) -> Option<crate::exclusion::Excluded> {
        use crate::exclusion::Excluded;
        let reason = self.rules.excluded(path)?;
        let counter = match (reason, kind) {
            (Excluded::HarnessControlDir, _) => &mut self.excluded_control_dir,
            (Excluded::MachineWideRoot, CandidateKind::Access) => {
                &mut self.excluded_machine_wide_root
            }
            (Excluded::MachineWideRoot, CandidateKind::ExecImage) => {
                &mut self.excluded_default_exec_image
            }
            (Excluded::SessionWorkspace, _) => &mut self.excluded_session_workspace,
            (Excluded::EphemeralTemp, _) => &mut self.excluded_ephemeral_temp,
            (Excluded::SandboxProfile, _) => &mut self.excluded_sandbox_profile,
            (Excluded::MsixPackageData, _) => &mut self.excluded_msix_package_data,
        };
        *counter = counter.saturating_add(1);
        Some(reason)
    }

    /// このセッションの除外規則（TUIがworkspaceのロック行を描くのに使う）。
    pub fn rules(&self) -> &crate::exclusion::ExclusionRules {
        &self.rules
    }

    /// 監査イベント1件を取り込む。
    pub fn add_event(&mut self, event: &FsAuditEvent) {
        self.events_seen = self.events_seen.saturating_add(1);

        if event.kind == FsAuditKind::Control {
            self.collector_notes.push(event.reason.clone());
            return;
        }

        if let Some(pid) = event.process_id {
            let node = self.processes.entry(pid).or_default();
            node.accesses = node.accesses.saturating_add(1);
            // 素性は**最初に分かった値を保つ**（後から`None`で上書きしない）。
            if node.parent_pid.is_none() {
                node.parent_pid = event.parent_process_id;
            }
            if node.image.is_none() {
                node.image = event.image_path.clone();
                // **素性を初めて知ったこの1回だけ**、実行像を候補として合流させる。
                // アクセス1件ごとに数えると、観測回数がそのプロセスのI/O量になってしまう
                // ——ここで数えたいのは「そのイメージから何個プロセスが起動したか」である。
                if let Some(image) = node.image.clone() {
                    self.add_exec_image(&image, event.timestamp_unix_ms);
                }
            }
        }

        if event.allowed {
            self.allowed = self.allowed.saturating_add(1);
        } else {
            self.denied = self.denied.saturating_add(1);
        }

        let (Some(path), Some(access)) = (event.path.as_deref(), event.access) else {
            self.without_path = self.without_path.saturating_add(1);
            return;
        };
        // 同じパスに「無かった」と「開けた」の両方が来ることはある（探した後に作った等）。
        // **イベント単位で落とす**ので、開けた側が1件でもあればそのパスは候補に残る。
        // これは**パスの性質ではなくイベントの性質**なので、`ExclusionRules`ではなくここが持つ。
        if event.target_was_missing() {
            self.excluded_missing_target = self.excluded_missing_target.saturating_add(1);
            return;
        }
        // パス由来の除外は**1関数へ集約してある**（[`crate::exclusion`]）。実行像側
        // （`add_exec_candidate`）と同じ規則・同じ判定を通る（B-05/B-06）。
        if self.note_exclusion(path, CandidateKind::Access).is_some() {
            return;
        }
        self.folder.add(
            Source::Etw,
            path,
            access,
            &event.reason,
            event.timestamp_unix_ms,
        );
    }

    /// 観測された実行像1件を`fs.read_exec`の候補へ合流させる（モジュールdoc参照）。
    fn add_exec_image(&mut self, image: &str, timestamp_unix_ms: u64) {
        self.add_exec_candidate(
            image,
            Source::Etw,
            "observed as the image of a started process",
            timestamp_unix_ms,
        );
    }

    /// 実行前診断が名指しした実行ファイルを`fs.read_exec`の候補へ合流させる（モジュールdoc参照）。
    ///
    /// 出所は[`Source::Preflight`]——**OS監査由来ではない**。`Source::Etw`と書くと
    /// 「ETWが観測した」という意味になり、`generalize`はその組み合わせに
    /// 「読取と書込を区別できない推測だ」という注記まで付ける。判定の入力は宣言と
    /// 付与結果（＝preflightが扱う世界）なので、こちらが正しい。
    ///
    /// **除外規則は実行像と共有する。** 別々に書くと、片方だけが「候補に出さない」と決めた
    /// 場所を、もう片方が承認させに行く——実機E2Eが実際にその形（`curl.exe`）を捕まえている。
    pub fn add_unreachable_exec(&mut self, exe: &str, timestamp_unix_ms: u64) {
        if self.add_exec_candidate(
            exe,
            Source::Preflight,
            "named by the pre-run diagnosis as an executable this domain cannot start",
            timestamp_unix_ms,
        ) {
            self.diagnosed_exec = Some(harness_policy::normalize::normalize_path(exe));
        }
    }

    /// 実行ファイル1件を`fs.read_exec`の候補にする。**候補にしたら`true`。**
    ///
    /// **出さないものが3種類ある。** いずれも件数を数え、[`render_notes`]で必ず見せる（B-09）——
    /// 「観測されなかった」と「意図して出さなかった」が区別できないと、ユーザーは
    /// 「なぜ`cargo.exe`が候補に無いのか」を調べようがない。
    fn add_exec_candidate(
        &mut self,
        image: &str,
        source: Source,
        reason: &str,
        timestamp_unix_ms: u64,
    ) -> bool {
        // 1. 設定パスへ寄せられていない綴り（旧形式の監査ログに残るNTパス）。
        //    変換に要るボリューム対応表は昇格側にしか無いので、ここでは解けない。
        //    生のまま候補にすると、設定へ書いても一致しない値を提案することになる。
        //    **これは「像の綴り」の問題**なので、パス由来の規則（下）とは別にここが持つ。
        if !is_settings_path(image) {
            self.excluded_legacy_image_path = self.excluded_legacy_image_path.saturating_add(1);
            return false;
        }
        // 2. パス由来の除外（`.harness`・サンドボックスプロファイル・マシン全体の
        //    インストール先・このセッションのworkspace・`%TEMP%`）。**アクセス側と同じ
        //    1関数**を通す（[`crate::exclusion`]）。マシン全体のインストール先を承認すると
        //    実害がある——`preflight`がそこへACEを付けに行き、TrustedInstaller所有ノードで
        //    失敗し（D-19の限界、BUG-015）、UACを増やし、最悪パス2が丸ごと落ちる。
        if self
            .note_exclusion(image, CandidateKind::ExecImage)
            .is_some()
        {
            return false;
        }
        self.folder
            .add(source, image, FsAccess::ReadExec, reason, timestamp_unix_ms);
        true
    }

    /// JSONLとして解釈できなかった行を数える（`AuditTail::poll_fs_events`の戻り値）。
    pub fn add_unparsable(&mut self, count: usize) {
        self.unparsable_lines = self.unparsable_lines.saturating_add(count as u64);
    }

    /// 畳み込み後の候補（異なる`(パス, access)`ごとに1件）。
    pub fn candidates(&self) -> &[DeniedCandidate] {
        self.folder.candidates()
    }

    /// 許可ルールの提案。**適用はしない**（D-42: 反映は常にユーザーの明示操作）。
    ///
    /// 記録時点の宣言（[`Self::granted`]。パス2のみ）を渡すので、**既に許可済みなのに
    /// 拒否された**パスは同じキーの提案を出し直さず昇格候補へ差し替わる（D-46）。
    pub fn proposals(&self) -> Vec<RuleProposal> {
        harness_policy::generalize::generalize_with_granted(self.folder.candidates(), &self.granted)
    }

    /// 観測したプロセスをツリー順（親→子）で並べる。
    ///
    /// 親が観測範囲の外（記録対象ツリーの外側にいる`harness-policy-editor`自身など）の
    /// プロセスは根として扱う。**親が分からないものを勝手に別の親へ繋がない**——
    /// 嘘の親子関係を描くくらいなら、根が複数ある方が正直である。
    ///
    /// PID再利用で親子関係が閉路になっても**1件も落とさない**: 閉路の中のプロセスは
    /// どこからも辿れなくなるので、走査の最後に根として拾い直す（表示から黙って
    /// 消えるより、親が変に見える方がまだ調べようがある、B-09）。
    pub fn process_tree(&self) -> Vec<(usize, u32, ProcessNode)> {
        let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut roots: Vec<u32> = Vec::new();
        for (pid, node) in &self.processes {
            match node.parent_pid {
                Some(parent) if self.processes.contains_key(&parent) && parent != *pid => {
                    children.entry(parent).or_default().push(*pid);
                }
                _ => roots.push(*pid),
            }
        }

        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let walk = |start: u32,
                    out: &mut Vec<(usize, u32, ProcessNode)>,
                    visited: &mut std::collections::HashSet<u32>| {
            let mut stack = vec![(0usize, start)];
            while let Some((depth, pid)) = stack.pop() {
                // 循環（PID再利用で親子が閉路になる）を踏んでも止まらないようにする。
                if !visited.insert(pid) {
                    continue;
                }
                if let Some(node) = self.processes.get(&pid) {
                    out.push((depth, pid, node.clone()));
                }
                if let Some(kids) = children.get(&pid) {
                    for kid in kids.iter().rev() {
                        stack.push((depth + 1, *kid));
                    }
                }
            }
        };

        for root in roots {
            walk(root, &mut out, &mut visited);
        }
        // 閉路の中に居て根から辿れなかったプロセスを拾い直す（1件も落とさない）。
        for pid in self.processes.keys() {
            if !visited.contains(pid) {
                walk(*pid, &mut out, &mut visited);
            }
        }
        out
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }
}

/// 記録セッション1件を読み直して集計する。**候補を作る経路はここ1つ**である。
///
/// # なぜマニフェストを一緒に受け取るのか
///
/// 観測（`fs-audit.jsonl`）だけでは候補が決まらない。パス2の記録には、観測に**現れない**
/// 事実が2つある——起動を拒否された実行ファイル（`ProcessStart`が出ない）と、
/// そのとき何が既に許可されていたか。どちらもマニフェストにしかない（モジュールdoc）。
///
/// **`show`・`approve`・TUI・実行直後の表示が同じ関数を通ることに意味がある。** 提案idは
/// 候補の顔ぶれで決まるので、片方だけがこの合流を忘れると`--accept fs-7`が画面で見たものと
/// 別のルールを指す。[`from_log`]を`pub(crate)`に留めてあるのはそのため（B-06をコンパイラに
/// 数えさせる）。
pub fn from_session(dir: &RecordSessionDir, manifest: &RecordManifest) -> Aggregate {
    // 除外規則は**マニフェストのworkspace root**から作る（B-103）。`show`・`approve`・TUIが
    // 同じ関数を通るので、「どのセッションのworkspaceを外すか」もここ1箇所で決まる。
    let rules = crate::exclusion::ExclusionRules::for_session(&manifest.workspace_root);
    let mut aggregate = from_log(&dir.audit_log_path(), rules);
    apply_session_context(&mut aggregate, manifest);
    aggregate
}

/// 監査ログに現れない事実（実行前診断・記録時点の宣言）を集計へ載せる。
///
/// [`from_session`]と、実行直後に生の集計を持っている`record_net`が共有する
/// （合流の規則を2箇所に持たない、B-05）。**パス1では何もしない**——診断も宣言の
/// スナップショットもパス2だけが書くうえ、パス1の候補は拒否ではないので昇格の前提が無い。
pub fn apply_session_context(aggregate: &mut Aggregate, manifest: &RecordManifest) {
    if manifest.pass != 2 {
        return;
    }
    if let Some(exe) = manifest.unreachable_exec.as_deref() {
        aggregate.add_unreachable_exec(exe, manifest.started_unix_ms);
    }
    if !manifest.declared_fs.is_empty() {
        aggregate.granted = GrantedPaths::new(
            manifest
                .declared_fs
                .iter()
                .map(|rule| {
                    (
                        harness_policy::normalize::normalize_path(&rule.value),
                        rule.access,
                    )
                })
                .collect(),
        );
    }
}

/// 記録済みの監査ログ（JSONL）を読み直して集計する。
///
/// **保存済みの集計値は使わない。** 観測の正本は`fs-audit.jsonl`だけで、マニフェストは
/// 文脈しか持たない（同じ事実の正本を2つ持たない、B-13）。畳み込みの度合いが変わって
/// 何度でも見直せるのはこの性質から来ている。
///
/// **外へは出さない**（[`from_session`]のdoc）。
pub(crate) fn from_log(
    path: &std::path::Path,
    rules: crate::exclusion::ExclusionRules,
) -> Aggregate {
    let mut tail = crate::audit_tail::AuditTail::new(path);
    let mut aggregate = Aggregate::new(rules);
    let (events, skipped) = tail.poll_fs_events();
    for event in &events {
        aggregate.add_event(event);
    }
    aggregate.add_unparsable(skipped);
    aggregate
}

/// 設定ファイルへそのまま書ける綴りか（`C:/...`・UNC）。
///
/// 収集器は`image_path`を`to_settings_path`で寄せてから書くので、本来ここは常に真になる。
/// **偽になるのは、この変換が入る前に書かれた古い`fs-audit.jsonl`を読んだとき**である
/// （`\Device\HarddiskVolume3\...`のまま入っている）。読む側にボリューム対応表は無いので
/// 解けない——候補にせず件数だけ数える。
fn is_settings_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    // ドライブ指定（`C:/...`）。
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    // UNC（`//host/share/...`）。`normalize_path`が`\\`を`//`へ寄せた形。
    value.starts_with("//")
}

/// 「harnessの制御ディレクトリ配下を候補から外した」注記の見出し（件数の直前まで）。
///
/// **定数にしてあるのは、実機E2Eがこの文言を根拠に「黙って落としていない」を測るためである。**
/// テスト側がリテラルで持つと、文言を直したときに**テストだけが古い綴りを探し続けて赤くなる**
/// ——実際にそうなっていた（[BUG-153](../../../docs/bugs/BUG-153.md)。テストは`除外: .harness`を
/// 探しており、実装は`除外: harnessの制御ディレクトリ配下`へ書き直されていた）。
/// 文言を変えるならここを変える。参照している側は自動で追随する（`B-06`の「数えなくてよくする」）。
pub const EXCLUDED_CONTROL_DIR_NOTICE: &str = "除外: harnessの制御ディレクトリ配下";

/// 候補一覧の**手前**に出す注記（観測件数・除外件数・収集器からの報告・拒否の読み方）。
///
/// [`render`]（CLI）とTUIの両方が使う。TUIは候補一覧を対話的なリストで描くので一覧部分だけ
/// 自前で持つが、**注記の文言は書き直さない**——同じ事実の説明を2箇所に持つと、片方だけが
/// 直る（規則5・B-05）。
pub fn render_notes(aggregate: &Aggregate) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "観測: {}件（許可 {} / 拒否 {}）、異なるパス×access {}件、プロセス {}件\n",
        aggregate.events_seen,
        aggregate.allowed,
        aggregate.denied,
        aggregate.candidates().len(),
        aggregate.process_count(),
    ));

    if aggregate.events_seen == 0 {
        out.push_str(
            "\n監査イベントが1件も観測できませんでした。収集器が起動していないか、ETWセッションが\n\
             張れていない可能性があります（上の警告と、記録セッションの制御レコードを確認してください）。\n",
        );
    }

    if aggregate.excluded_control_dir > 0 {
        out.push_str(&format!(
            "{EXCLUDED_CONTROL_DIR_NOTICE} {}件。ここへの許可は提案しません（P-08）\n\
             （workspace内の .harness と、台帳の置き場 %APPDATA%\\harness の両方。\n\
             後者にはMCPの承認台帳と付与済みACEの台帳があり、書けると自分の許可を書き換えられます）\n",
            aggregate.excluded_control_dir
        ));
    }
    if aggregate.excluded_missing_target > 0 {
        out.push_str(&format!(
            "除外: 探しに行ったが存在しなかったパス {}件（DLL検索順・PATH探索・任意設定ファイルの\n\
             探索。無いファイルへの許可には意味が無いので候補にしません）\n",
            aggregate.excluded_missing_target
        ));
    }
    if aggregate.without_path > 0 {
        out.push_str(&format!(
            "除外: パスまたはaccess種別を持たないイベント {}件\n",
            aggregate.without_path
        ));
    }
    if let Some(exe) = &aggregate.diagnosed_exec {
        out.push_str(&format!(
            "候補に足した: 実行前診断が名指しした実行ファイル 1件（{exe}）を fs.read_exec の\n\
             候補にしました。**これは観測ではありません**——このコマンドは起動そのものを\n\
             拒否されたので、収集器の記録には現れません（起動していないため）\n"
        ));
    }
    if aggregate.excluded_machine_wide_root > 0 {
        out.push_str(&format!(
            "除外: C:/Windows・C:/Program Files 配下へのアクセス {}件\n\
             （AppContainerには既定で読み取り・実行があるので承認しても得るものがありません。\n\
             逆に承認すると、パス2の開始時に preflight がその祖先へACEを付けに行き、\n\
             TrustedInstaller所有のため昇格しても失敗して、このドメインのパス2が丸ごと\n\
             落ちます。どうしても要る場合だけ .harness/settings.json を手で編集してください）\n",
            aggregate.excluded_machine_wide_root
        ));
    }
    if aggregate.excluded_default_exec_image > 0 {
        out.push_str(&format!(
            "除外: 実行ファイルのうち {}件は C:/Windows・C:/Program Files 配下でした\n\
             （AppContainerには既定で実行権があるので fs.read_exec の候補にしません。承認すると\n\
             ACEを付けに行き、システム保護ノードで失敗してUACが増えます）\n",
            aggregate.excluded_default_exec_image
        ));
    }
    // [BUG-103] 新しい3規則。**件数は必ず出す**（B-09）。「観測できなかった」と
    // 「意図して出さなかった」が区別できないと、なぜ候補に無いのかを調べようがない。
    if aggregate.excluded_session_workspace > 0 {
        out.push_str(&format!(
            "除外: このセッションのworkspace配下 {}件\n\
             （パス2は起動時にworkspaceツリー全体へ読み書き実行を付与します。承認しても\n\
             得るものが無く、逆にセッション終了時のACE撤収がツリー全体に及んで遅くなります。\n\
             workspaceの行は候補一覧の先頭に [x] で出ています——外せません）\n",
            aggregate.excluded_session_workspace
        ));
    }
    if aggregate.excluded_ephemeral_temp > 0 {
        out.push_str(&format!(
            "除外: %TEMP% 配下 {}件\n\
             （名前にPID・時刻・乱数を含む「その実行限り」のパスです。承認しても次回は\n\
             存在しないので `path does not exist, skipped` が積み上がるだけで、%TEMP%そのものへの\n\
             許可は他のアプリの一時ファイルまで読み書き削除できることを意味します。\n\
             どうしても要る場合だけ .harness/policy.json を手で編集してください）\n",
            aggregate.excluded_ephemeral_temp
        ));
    }
    if aggregate.excluded_sandbox_profile > 0 {
        out.push_str(&format!(
            "除外: harness自身のサンドボックスプロファイル配下 {}件\n\
             （%LOCALAPPDATA%\\Packages\\harness.shell.sandbox.* 等。harnessの制御物なので\n\
             .harness と同じく候補にしません。承認すると全ストアアプリのデータ置き場へ\n\
             継承つきの読み書き削除が付きます）\n",
            aggregate.excluded_sandbox_profile
        ));
    }
    if aggregate.excluded_msix_package_data > 0 {
        out.push_str(&format!(
            "除外: %LOCALAPPDATA%\\Packages 配下 {}件\n\
             （全てのストアアプリ（MSIX/AppContainer）の専用データ置き場です。ここへ許可すると\n\
             他のアプリのデータを読み書き削除できることになります——pwsh自身もStoreパッケージです。\n\
             候補の畳み込みはharness自身のプロファイルへのアクセスをこの親へ丸めるので、\n\
             プロファイル名の除外だけでは素通りします）\n",
            aggregate.excluded_msix_package_data
        ));
    }
    if aggregate.excluded_legacy_image_path > 0 {
        out.push_str(&format!(
            "除外: 実行された像のうち {}件は設定へ書ける形に変換されていませんでした\n\
             （この変換より前に記録された監査ログです。再記録すると候補に出ます）\n",
            aggregate.excluded_legacy_image_path
        ));
    }
    if aggregate.unparsable_lines > 0 {
        out.push_str(&format!(
            "警告: 監査ログのうち解釈できなかった行 {}件\n",
            aggregate.unparsable_lines
        ));
    }
    for note in &aggregate.collector_notes {
        out.push_str(&format!("収集器からの報告: {note}\n"));
    }

    if aggregate.denied > 0 {
        out.push_str(
            "\n注意: 拒否された項目は、**このマシンの通常の権限で拒否された**ものです。\n\
             パス1は隔離せずに（Tier0で）記録するので、サンドボックスの都合による拒否は\n\
             混ざりません。したがって拒否が出ている場合、Tier2aで許可を足しても解消しない\n\
             可能性があります（そもそもそのユーザーが触れない場所である等）。\n",
        );
    }

    out
}

/// 記録結果を人が読む形へ整形する（注記＋候補一覧）。
///
/// `limit`は提案の表示件数の上限。**打ち切ったら必ずその事実と残件数を出す**（B-09）。
pub fn render(aggregate: &Aggregate, limit: usize) -> String {
    let mut out = render_notes(aggregate);
    let proposals = aggregate.proposals();

    out.push_str("\n許可ルールの候補（観測された値そのまま）:\n");
    if proposals.is_empty() {
        out.push_str("  （候補なし）\n");
    }
    for proposal in proposals.iter().take(limit) {
        out.push_str(&format!(
            "  {:<8} {} = {}  （観測 {}回）\n",
            proposal.id,
            proposal.key.dotted(),
            proposal.value,
            proposal.observed_count(),
        ));
        for warning in &proposal.warnings {
            out.push_str(&format!("           ! {warning}\n"));
        }
    }
    if proposals.len() > limit {
        out.push_str(&format!(
            "  ... 他 {}件（全件は `harness-policy-editor show --limit 0` で表示）\n",
            proposals.len() - limit
        ));
    }

    out
}

/// 観測したプロセスツリーを整形する（記録対象が何を起動したかの俯瞰）。
pub fn render_process_tree(aggregate: &Aggregate) -> String {
    let mut out = String::from("観測したプロセス:\n");
    let tree = aggregate.process_tree();
    if tree.is_empty() {
        out.push_str("  （なし）\n");
    }
    for (depth, pid, node) in tree {
        out.push_str(&format!(
            "  {}{} pid={} ({}件)\n",
            "  ".repeat(depth),
            node.image.as_deref().unwrap_or("(不明)"),
            pid,
            node.accesses,
        ));
    }
    out
}

#[cfg(test)]
#[path = "aggregate_tests.rs"]
mod aggregate_tests;
