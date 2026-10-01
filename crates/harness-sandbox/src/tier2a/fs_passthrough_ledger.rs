//! fs passthrough台帳（D5）。`--fs-allow`と`.harness/settings.json`で実際にACEを付与した
//! パスを、どのプロジェクトからでも一括撤収できるよう1台帳へ集約する。
//!
//! 元々`crates/harness-cli/src/fs_grants/ledger.rs`にあったが、ACEを実際に付与する
//! `win_appcontainer::preflight`はこのクレート内にあり、**付与した側が記録する**という
//! 形にしないと台帳に載らない付与（＝撤収経路の無い孤立ACE、BUG-017）が生まれる。
//! `harness.exe`以外の付与側——ポリシーエディタのパス2
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`）——からも記録できるよう、harness-cli→harness-sandboxの
//! 依存方向を逆流させないためここへ移動した（`traverse_ledger`とまったく同じ理由・同じ形）。
//! `harness fs list/revoke/prune`（harness-cli側）はこのモジュールの関数を呼ぶ。
//!
//! ファイル入出力（誤削除防止の2層・fail-open・名前付きmutexによるRMW直列化）は
//! `harness-grant-ledger`の`Ledger<T>`が持つ。本モジュールはこの台帳固有の
//! 「何を記録するか」だけを持つ。

use std::path::Path;

/// fs passthrough台帳（D5、ユーザグローバル、`directories`設定ディレクトリ配下）の1エントリ。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsLedgerEntry {
    pub path: String,
    pub writable: bool,
    pub granted_at_unix_secs: u64,
    /// `--force-system-acl`（D-19）で`SeRestorePrivilege`を使って強制付与したか。
    /// 撤収時も同じ特権が要るため記録する。旧台帳（このフィールド欠落）は`false`扱い（後方互換）。
    #[serde(default)]
    pub forced: bool,
    /// このパスを現在`.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`で
    /// 宣言しているワークスペースroot文字列の集合（D-27、`vm_ledger::WorkspaceResourceEntry.refcount`
    /// と同型の参照カウント）。空なら「settings.json経由の宣言者が現在いない」。
    #[serde(default)]
    pub settings_workspaces: Vec<String>,
    /// 一度でも`.harness/settings.json`経由（`--fs-allow`ではなく）で付与されたことがあるか（D-27）。
    /// `false`のままなら`--fs-allow`専用エントリであり、`reconcile_fs_ledger_for_workspace`の
    /// 自動撤収対象にしない（D2/D3のsticky挙動を維持する）。
    #[serde(default)]
    pub settings_managed: bool,
    /// このパスへACEを**実際に付与した宛先SID**（AppContainerパッケージSIDの文字列表現）の集合。
    ///
    /// # なぜ記録するのか（[BUG-101](../../../../docs/bugs/BUG-101.md)欠陥②）
    ///
    /// SIDはプロファイル名からの**一方向**導出（`DeriveAppContainerSidFromAppContainerName`）
    /// なので、プロファイルが削除された時点でSID→名前は誰にも引けなくなる。撤収側が
    /// 「このACEはharnessのものか」を名前から判定しようとすると、そこで手が届かなくなり、
    /// 実マシンに剥がせないACEが残った。**付与した時点でSIDを書き留めておけば、以後
    /// 「harness由来」は推論ではなく記録になる**（B-01: 名前を捨てる操作より前に記録を残す）。
    ///
    /// 同じパスは複数のセッションが付与し直すので**和で持つ**（上書きしない）。
    /// 旧台帳（このフィールド欠落）は空扱い——その場合の判定は
    /// `win_appcontainer::revoke_subjects`の規則0/2/4が受ける。
    #[serde(default)]
    pub granted_sids: Vec<String>,
    /// [D-63] このパスを**どの範囲で**開いたか（宣言値が`<path>/**`なら`Recursive`）。
    ///
    /// # これは「ヒント」であって撤収の根拠ではない
    ///
    /// 撤収の範囲は**対象パスのDACLに実在する継承フラグ**から決める
    /// （`win_appcontainer::revoke`）。この台帳は[BUG-103](../../../../docs/bugs/BUG-103.md)(d)で
    /// **サンドボックスから書ける**ことが実測されており、`scope: Object`を鵜呑みにすると
    /// 「台帳を書き換えて再帰ACEを撤収の対象外にする」経路になる。D-61（撤収する宛先SIDは対象パスの
    /// DACLに実在するSIDから決める）とまったく同じ原則である。
    ///
    /// 使い道は`harness fs list`の表示と、実DACLとの突き合わせ（付与が宣言どおりだったかの検算）。
    ///
    /// 旧台帳（このフィールド欠落）は`Recursive`扱い——D-63以前の付与は全て継承ACEだったので、
    /// それが**その記録が意味していた範囲**である。狭い方を既定にすると、既に実マシンに在る
    /// 継承ACEを台帳が「オブジェクト単体」と説明することになる。
    #[serde(default = "default_ledger_scope")]
    pub scope: harness_policy::GrantScope,
}

/// [`FsLedgerEntry::scope`]が欠けている旧エントリの既定（D-63以前の付与＝全て継承ACE）。
fn default_ledger_scope() -> harness_policy::GrantScope {
    harness_policy::GrantScope::Recursive
}

/// 到達不能/付与失敗だったfs passthrough候補。`harness fs list`/`harness fs denied`で表示し、
/// `.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`へ後から足すための材料にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsDeniedLedgerEntry {
    pub path: String,
    pub access: String,
    pub reason: String,
    pub last_denied_at_unix_secs: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FsLedger {
    #[serde(default)]
    pub entries: Vec<FsLedgerEntry>,
    #[serde(default)]
    pub denied_entries: Vec<FsDeniedLedgerEntry>,
}

/// 台帳の中身をどう書き換えるかは、**ファイルにもロックにも触れない純粋な操作**として
/// ここに置く。`record_*`はロックを取って永続化するだけの薄い外皮になる。
///
/// 分けている理由は単体テストである。台帳ファイルはユーザグローバルな実ファイル1つきり
/// （`%APPDATA%\harness\config\fs-passthrough-ledger.json`、`docs/DEV-ENVIRONMENT.md`が
/// 「絶対に消してはいけないファイル」に挙げているもの）で、実マシンに残したACEを追跡する
/// 唯一の記録である。**テストのために本物を触ることはできない**ので、上書き規則の側だけを
/// 切り出して固定する。
impl FsLedger {
    /// `record_fs_passthrough_grant`の中身（同一パスは上書き＝冪等、`settings_workspaces`は
    /// dedup追加、`settings_managed`は一度立ったら降ろさない、拒否記録は消す）。
    ///
    /// `granted_sid`（付与した宛先SIDの文字列）だけは**上書きではなく和**で持つ
    /// ——同じパスを別のセッションが付与し直すたびに宛先SIDが増えるので、上書きすると
    /// 前のセッションのACEを剥がす手掛かりが消える（[`FsLedgerEntry::granted_sids`]のdoc）。
    // 引数は台帳エントリの列そのものである。まとめるための構造体を新設すると
    // [`FsPassthroughGrantRecord`]とほぼ同じ型が2つ並ぶだけで、**どちらを更新すべきかが
    // 分からない形**になる（B-05: 同じ事実を2箇所に持たない）。ここは列挙のままにする。
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_grant(
        &mut self,
        path_str: String,
        writable: bool,
        forced: bool,
        settings_workspace: Option<&str>,
        granted_sid: Option<&str>,
        scope: harness_policy::GrantScope,
        granted_at: u64,
    ) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| same_ledger_path(&e.path, &path_str))
        {
            entry.writable = writable;
            entry.granted_at_unix_secs = granted_at;
            entry.forced = forced;
            // [D-63] **記録は最後の付与で上書きする**（`writable`と同じ扱い）。ここを
            // 「広い方を残す」にすると、`**`を外した宣言に直した後も台帳が`Recursive`と
            // 言い続け、実DACLとの突き合わせが恒久的にずれる。実際に残っている範囲を
            // 知りたいときの権威はDACLであって、この欄ではない。
            entry.scope = scope;
            if let Some(ws) = settings_workspace {
                if !entry.settings_workspaces.iter().any(|w| w == ws) {
                    entry.settings_workspaces.push(ws.to_string());
                }
                entry.settings_managed = true;
            }
            if let Some(sid) = granted_sid {
                if !entry.granted_sids.iter().any(|s| s == sid) {
                    entry.granted_sids.push(sid.to_string());
                }
            }
        } else {
            self.entries.push(FsLedgerEntry {
                path: path_str.clone(),
                writable,
                granted_at_unix_secs: granted_at,
                forced,
                settings_workspaces: settings_workspace
                    .map(|ws| vec![ws.to_string()])
                    .unwrap_or_default(),
                settings_managed: settings_workspace.is_some(),
                granted_sids: granted_sid.map(|s| vec![s.to_string()]).unwrap_or_default(),
                scope,
            });
        }
        // 付与できたパスは「到達不能候補」ではなくなる。両方に載ったままだと
        // `harness fs denied`が既に開いている穴を勧め続ける。
        self.denied_entries
            .retain(|e| !same_ledger_path(&e.path, &path_str));
    }

    /// `record_fs_passthrough_denied`の中身（同一`(path, access)`は回数を積む）。
    pub fn record_denied(&mut self, path_str: String, access: &str, reason: &str, denied_at: u64) {
        if let Some(entry) = self
            .denied_entries
            .iter_mut()
            .find(|e| same_ledger_path(&e.path, &path_str) && e.access == access)
        {
            entry.reason = reason.to_string();
            entry.last_denied_at_unix_secs = denied_at;
            entry.count = entry.count.saturating_add(1);
        } else {
            self.denied_entries.push(FsDeniedLedgerEntry {
                path: path_str,
                access: access.to_string(),
                reason: reason.to_string(),
                last_denied_at_unix_secs: denied_at,
                count: 1,
            });
        }
    }
}

/// 台帳ファイル（`%APPDATA%\harness\config\fs-passthrough-ledger.json`）。横断的な穴を
/// 1台帳に集約し、どのプロジェクトからでも全撤収できるようにする（D5）。
///
/// ファイル入出力（誤削除防止の2層・fail-open）と、複数`harness.exe`同時起動下での
/// read-modify-write直列化（D-27）は`harness-grant-ledger`の`Ledger<T>`が持つ。
pub fn fs_ledger() -> &'static harness_grant_ledger::Ledger<FsLedger> {
    static LEDGER: std::sync::OnceLock<harness_grant_ledger::Ledger<FsLedger>> =
        std::sync::OnceLock::new();
    LEDGER.get_or_init(|| {
        harness_grant_ledger::Ledger::in_config_dir(
            "fs-passthrough-ledger.json",
            Some("Local\\harness-fs-passthrough-ledger"),
        )
    })
}

/// 台帳が存在しない/読めない/パースできない場合は空扱い（fail-open、起動を止めない）。
/// 単発の読取専用アクセス用。複合的なread-modify-writeには`fs_ledger().update(..)`を使うこと。
pub fn load_fs_ledger() -> FsLedger {
    fs_ledger().load()
}

/// `--fs-allow`/`.harness/settings.json`でTier2a preflightが実際にACE付与を試みたルートを
/// 台帳へ記録する（D2/D3）。同一パスは上書き（冪等）。ACE自体は「付けっぱなし」（D2）だが、
/// 台帳があるので後から`harness fs revoke`/`revoke-all`で一括撤収できる。
/// `settings_workspace`が`Some`なら、このパスが`.harness/settings.json`経由（`--fs-allow`ではなく）で
/// 宣言されたことを示し、`settings_workspaces`（D-27の参照カウント）へワークスペースrootを
/// dedup追加し`settings_managed`を立てる（一度立ったら以後trueのまま維持し、`--fs-allow`のみの
/// 再起動を挟んでも自動整合対象であり続ける）。
pub fn record_fs_passthrough_grant(
    path: &Path,
    writable: bool,
    forced: bool,
    settings_workspace: Option<&str>,
    granted_sid: Option<&str>,
    scope: harness_policy::GrantScope,
) {
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = harness_grant_ledger::now_unix_secs();
    fs_ledger().update(|ledger| {
        ledger.upsert_grant(
            path_str,
            writable,
            forced,
            settings_workspace,
            granted_sid,
            scope,
            granted_at,
        )
    });
}

/// 複数の付与を**1回の台帳更新で**記録する（`record_fs_passthrough_grant`のまとめ版）。
///
/// # なぜ要るか（実測）
///
/// `Ledger::update`は1回ごとに「ロック取得 → 全文読取 → パース → 直列化 → **`.bak`へ全文コピー**
/// → 読取専用属性を外す → 全文書込 → 読取専用へ戻す」を行います。この台帳はこの開発機で
/// **185KB**あるので、1件あたり約550KBのファイルI/Oです。ポリシーエディタが
/// workspace外のルートを668件持つドメイン（`cargo`）でパス2を走らせると、
/// これだけで**約370MB**のI/Oになり数秒かかります——**1件もACEを書いていない2回目以降でも
/// 同じだけ払います**（付与の有無に関わらず「このセッションが撤収責任を負う」記録は要るため）。
///
/// **ループの中で`update`を呼ばない。** 台帳は「1件足す」ためのAPIに見えますが、
/// 実体は全文の読み書きです。
pub fn record_fs_passthrough_grants(grants: &[FsPassthroughGrantRecord]) {
    if grants.is_empty() {
        return;
    }
    let granted_at = harness_grant_ledger::now_unix_secs();
    fs_ledger().update(|ledger| {
        for grant in grants {
            ledger.upsert_grant(
                grant.path.to_string_lossy().into_owned(),
                grant.writable,
                grant.forced,
                grant.settings_workspace.as_deref(),
                grant.granted_sid.as_deref(),
                grant.scope,
                granted_at,
            );
        }
    });
}

/// [`record_fs_passthrough_grants`]の1件ぶん。
#[derive(Debug, Clone)]
pub struct FsPassthroughGrantRecord {
    pub path: std::path::PathBuf,
    pub writable: bool,
    pub forced: bool,
    pub settings_workspace: Option<String>,
    /// ACEを付与した宛先SIDの文字列（[`FsLedgerEntry::granted_sids`]）。導出に失敗したら
    /// `None`——**記録できなかったことを付与の失敗にはしない**が、そのパスは後から
    /// 「登録簿」と「マスクの指紋」でしか判定できなくなる。
    pub granted_sid: Option<String>,
    /// [D-63] 宣言された付与範囲（[`FsLedgerEntry::scope`]。**ヒントであって撤収の根拠ではない**）。
    pub scope: harness_policy::GrantScope,
}

impl FsPassthroughGrantRecord {
    /// `preflight`の結果1件から台帳の1件を組む（[BUG-119](../../../../docs/bugs/BUG-119.md)）。
    ///
    /// # `forced`は「指定したか」ではなく「使ったか」
    ///
    /// **付与の側は既に per-path で最小になっている**——`preflight`はまず普通に
    /// `grant_ace_scoped`を試み、`Err`になったときだけ昇格経路へ回す。昇格側でも
    /// `SeRestorePrivilege`を有効化するのは回ってきたエントリだけなので、
    /// **普通に付与できたパスに対して特権は1度も使われていない。**
    ///
    /// にもかかわらず台帳へは`--force-system-acl`という**セッション全域のスイッチ**を
    /// そのまま写していた。台帳はユーザグローバルに1つきりで、`forced`は上書きなので、
    /// **別のワークスペースの1回の起動が、無関係なパスの過去の記録まで`true`へ変える。**
    /// そして`forced`は後日の`harness fs revoke`が`SeRestorePrivilege`を有効化するかを決める
    /// ——「打たない後日の起動でも特権が使われる」ところまで波及していた。
    ///
    /// **粒度の違う値を、粒度の細かい記録欄へそのまま写さない。**
    ///
    /// `declared`は宣言側の`scope`を引くためだけに使う（`forced`は**引かない**）。
    pub fn from_granted(
        granted: &harness_core::GrantedPassthrough,
        declared: Option<&crate::shell_tier::FsPassthrough>,
        settings_workspace: Option<String>,
    ) -> Self {
        Self {
            path: granted.path.clone(),
            writable: granted.writable,
            forced: granted.used_restore_privilege,
            settings_workspace,
            granted_sid: None,
            // [D-63] 引けなかったときに`Recursive`へ倒すのは、D-63以前と同じ意味にするため。
            scope: declared
                .map(|fp| fp.scope)
                .unwrap_or(harness_policy::GrantScope::Recursive),
        }
    }
}

/// 複数の拒否を1回の台帳更新で記録する（[`record_fs_passthrough_grants`]と同じ理由）。
pub fn record_fs_passthrough_denials(denials: &[(std::path::PathBuf, String, String)]) {
    if denials.is_empty() {
        return;
    }
    let denied_at = harness_grant_ledger::now_unix_secs();
    fs_ledger().update(|ledger| {
        for (path, access, reason) in denials {
            ledger.record_denied(
                path.to_string_lossy().into_owned(),
                access,
                reason,
                denied_at,
            );
        }
    });
}

pub fn record_fs_passthrough_denied(path: &Path, access: &str, reason: &str) {
    let path_str = path.to_string_lossy().into_owned();
    let denied_at = harness_grant_ledger::now_unix_secs();
    fs_ledger().update(|ledger| ledger.record_denied(path_str, access, reason, denied_at));
}

pub use harness_grant_ledger::same_ledger_path;

/// 指定パスのエントリを台帳から落とす。**返り値は実際に落とした件数**——
/// 「呼んだ」と「消えた」は別の事実で、0件を成功として報告すると
/// 撤収コマンドが嘘をつく（B-09、BUG-101の欠陥②）。
pub fn remove_fs_passthrough_grant(path: &Path) -> usize {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        let before = ledger.entries.len() + ledger.denied_entries.len();
        ledger
            .entries
            .retain(|e| !same_ledger_path(&e.path, &path_str));
        ledger
            .denied_entries
            .retain(|e| !same_ledger_path(&e.path, &path_str));
        before - (ledger.entries.len() + ledger.denied_entries.len())
    })
}

/// `should_remove`がtrueを返したパスのエントリを台帳から落とす（`harness fs prune`、D-53）。
/// `entries`と`denied_entries`の両方が対象。返り値は実際に落としたパスの一覧。
///
/// **判定（何を落とすか）は呼び出し側が持ち、本関数はロックと永続化だけを持つ。** 台帳ファイルを
/// 所有するのはこのモジュールなので、CLI側で`load`→`save`する形にはしない（複数`harness.exe`
/// 同時起動下のlost updateを避ける、R-01）。
pub fn prune_fs_ledger_entries(should_remove: impl Fn(&Path) -> bool) -> Vec<String> {
    fs_ledger().update(|ledger| {
        let mut removed = Vec::new();
        ledger.entries.retain(|e| {
            if should_remove(Path::new(&e.path)) {
                removed.push(e.path.clone());
                false
            } else {
                true
            }
        });
        ledger.denied_entries.retain(|e| {
            if should_remove(Path::new(&e.path)) {
                removed.push(e.path.clone());
                false
            } else {
                true
            }
        });
        removed
    })
}

/// `reconcile_fs_ledger_for_workspace`専用の除去。orphan候補を確定してからACE撤収を試みるまでの
/// 間（ロックを一旦手放す）に、別プロセスが同じパスを新たに宣言し直す競合（TOCTOU）を考慮し、
/// 撤収成功後もなお「settings管理下で参照者ゼロ」のままである場合だけ台帳から除去する（D-27）。
/// 競合で参照者が復活していた場合は台帳エントリを残す（ACEは撤収済みのため、次回起動の
/// `reconcile_fs_ledger_for_workspace`が再度grantを試みて整合を取り戻す）。
#[cfg(windows)]
/// 返り値は[`remove_fs_passthrough_grant`]と同じく**実際に落とした件数**。
/// 対になる2つの除去関数で戻り値の形を変えない（`CODE-STRUCTURE-RULES`§5.1）。
pub fn remove_fs_passthrough_grant_if_still_orphaned(path: &Path) -> usize {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        let before = ledger.entries.len() + ledger.denied_entries.len();
        ledger.entries.retain(|e| {
            !same_ledger_path(&e.path, &path_str)
                || (e.settings_managed && !e.settings_workspaces.is_empty())
        });
        ledger
            .denied_entries
            .retain(|e| !same_ledger_path(&e.path, &path_str));
        before - (ledger.entries.len() + ledger.denied_entries.len())
    })
}

#[cfg(test)]
mod grant_record_tests {
    use super::FsPassthroughGrantRecord;
    use crate::shell_tier::FsAccess;
    use crate::shell_tier::FsPassthrough;
    use harness_core::GrantedPassthrough;
    use harness_policy::GrantScope;
    use std::path::PathBuf;

    fn granted(used_privilege: bool) -> GrantedPassthrough {
        GrantedPassthrough {
            path: PathBuf::from(r"C:\some\path"),
            writable: false,
            subject_sid: "S-1-15-3-1111".to_string(),
            used_restore_privilege: used_privilege,
            granted_access: "read_exec".to_string(),
        }
    }

    /// `--force-system-acl`を打った**セッション**の宣言。フラグはセッション全域のスイッチなので、
    /// 特権が要らなかったパスにもこの`forced: true`が載る。
    fn declared_under_the_session_wide_flag() -> FsPassthrough {
        FsPassthrough {
            path: PathBuf::from(r"C:\some\path"),
            access: FsAccess::Read,
            forced: true,
            scope: GrantScope::Recursive,
        }
    }

    /// **[BUG-119] 禁止側。** 普通に付与できたパスは、`--force-system-acl`を打っていても
    /// 台帳へ`forced`を立てない。
    ///
    /// 立てると、この記録を索引にする後日の`harness fs revoke`が
    /// **フラグを打っていない起動でも`SeRestorePrivilege`を有効化する。**
    /// 台帳はユーザグローバルに1つきりなので、影響はそのワークスペースに閉じない。
    #[test]
    fn a_grant_that_did_not_need_the_privilege_is_not_recorded_as_forced() {
        let record = FsPassthroughGrantRecord::from_granted(
            &granted(false),
            Some(&declared_under_the_session_wide_flag()),
            None,
        );
        assert!(
            !record.forced,
            "特権を1度も使っていない付与を forced として記録している\
             （--force-system-acl はセッション全域のスイッチであって、このパスの事実ではない）"
        );
    }

    /// **[BUG-119] 許可側（対）。** 実際に特権下で書いたパスは`forced`として記録する。
    ///
    /// **この対が無いと「常に`false`」でも禁止側が通る**（`B-35`）。そして常に`false`は
    /// 「特権で書いたのに剥がせない」——D-19 不変条件5が禁じた向きそのものである。
    #[test]
    fn a_grant_that_actually_used_the_privilege_is_recorded_as_forced() {
        let record = FsPassthroughGrantRecord::from_granted(
            &granted(true),
            Some(&declared_under_the_session_wide_flag()),
            None,
        );
        assert!(record.forced);
    }

    /// 宣言が引けなくても`forced`は付与の事実から決まる（宣言側の`forced`は**見ない**）。
    #[test]
    fn the_declaration_is_only_consulted_for_the_scope() {
        let record = FsPassthroughGrantRecord::from_granted(&granted(false), None, None);
        assert!(!record.forced);
        assert_eq!(record.scope, GrantScope::Recursive);
    }
}

#[cfg(test)]
mod path_match_tests {
    use super::same_ledger_path;

    /// **BUG-101の欠陥②の回帰テスト。**
    ///
    /// この台帳は書き手によって区切り文字が揃いません——`harness fs revoke`のCLIは引数を
    /// そのまま（`C:\...`）、ポリシーエディタは設定パス由来のスラッシュ形（`C:/...`）で
    /// 記録します。実際に`%TEMP%`のエントリがスラッシュ形で入っているところへ
    /// バックスラッシュ形で`revoke`を掛け、**1件も一致しないまま`revoked:`＋exit 0**が
    /// 返りました。
    #[test]
    fn the_two_separator_spellings_written_by_different_writers_are_the_same_target() {
        assert!(same_ledger_path(
            r"C:\Users\segfo\AppData\Local\Temp",
            "C:/Users/segfo/AppData/Local/Temp"
        ));
    }

    /// Windowsのファイルシステムは大小非区別なので、比較もそれに合わせます（B-20）。
    /// 末尾の区切りも同じ対象を指します。
    #[test]
    fn case_and_trailing_separator_do_not_change_the_target() {
        assert!(same_ledger_path(
            r"C:\Users\SEGFO\.cargo",
            r"c:\users\segfo\.cargo"
        ));
        assert!(same_ledger_path(
            r"C:\Users\segfo\.cargo\",
            r"C:\Users\segfo\.cargo"
        ));
    }

    /// **対になる否定側**（B-35）。全部一致させてしまう実装では、上の3つも通ってしまい
    /// 「正規化が効いている」ことを判定できません。**別の対象は別のままである**ことを固定します。
    #[test]
    fn different_targets_are_still_different() {
        assert!(!same_ledger_path(
            r"C:\Users\segfo\.cargo",
            r"C:\Users\segfo\.rustup"
        ));
        // 前置詞一致で巻き込まない（`.cargo`の撤収が`.cargo2`を消してはいけない）。
        assert!(!same_ledger_path(
            r"C:\Users\segfo\.cargo",
            r"C:\Users\segfo\.cargo2"
        ));
        // 親は子ではない。
        assert!(!same_ledger_path(
            r"C:\Users\segfo",
            r"C:\Users\segfo\.cargo"
        ));
    }
}

#[cfg(test)]
mod fs_ledger_tests {
    use super::{FsDeniedLedgerEntry, FsLedger, FsLedgerEntry};

    const PATH: &str = r"C:\Users\segfo\.cargo";

    /// D-19以前に書かれた台帳（`forced`フィールドが無いJSON）が、`#[serde(default)]`で
    /// `forced=false`として読めることを確認する（後方互換）。台帳が読めないと既存のACEを
    /// 追跡できなくなり「付与した記憶はあるが記録が無い」孤立ACEに直結するため重要。
    #[test]
    fn legacy_ledger_without_forced_field_deserializes_as_not_forced() {
        let legacy = r#"{"entries":[
            {"path":"C:\\ProgramData\\Microsoft\\Windows\\Start Menu","writable":false,"granted_at_unix_secs":1700000000}
        ]}"#;
        let ledger: FsLedger = serde_json::from_str(legacy).expect("legacy ledger must parse");
        assert_eq!(ledger.entries.len(), 1);
        assert!(ledger.denied_entries.is_empty());
        assert!(
            !ledger.entries[0].forced,
            "missing forced field must default to false"
        );
    }

    /// [D-63] **D-63以前の台帳は`Recursive`として読む。**
    ///
    /// あの頃の付与は例外なく継承ACE（`grant_ace_inheritable_access`固定）だったので、
    /// それが記録の意味である。ここを`Object`側へ倒すと、実マシンに残っている継承ACEを
    /// 台帳が「オブジェクト単体」と説明することになり、`fs list`の表示と実DACLが食い違う。
    ///
    /// 撤収がこの欄を信用しないこと自体は別に担保されている（範囲は実DACLから決める）。
    #[test]
    fn a_ledger_written_before_d63_reads_as_recursive() {
        let legacy = r#"{"entries":[
            {"path":"C:\\Users\\me\\.cargo","writable":false,"granted_at_unix_secs":1700000000}
        ]}"#;
        let ledger: FsLedger = serde_json::from_str(legacy).expect("legacy ledger must parse");
        assert_eq!(
            ledger.entries[0].scope,
            harness_policy::GrantScope::Recursive,
            "a missing scope means the entry predates D-63, and those grants were inheritable"
        );
    }

    /// [D-63] オブジェクト単体の記録がラウンドトリップする（`forced`と同じ形の固定）。
    #[test]
    fn an_object_scoped_entry_roundtrips() {
        let mut ledger = FsLedger::default();
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            None,
            harness_policy::GrantScope::Object,
            100,
        );
        let json = serde_json::to_string(&ledger).unwrap();
        let back: FsLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries[0].scope, harness_policy::GrantScope::Object);

        // **最後の付与で上書きする。** `**`を外した宣言に直したのに台帳が`Recursive`と
        // 言い続けると、実DACLとの突き合わせが恒久的にずれる。
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            None,
            harness_policy::GrantScope::Recursive,
            200,
        );
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(
            ledger.entries[0].scope,
            harness_policy::GrantScope::Recursive
        );
    }

    /// `forced=true`の台帳が正しくラウンドトリップすることを確認する。
    #[test]
    fn forced_entry_roundtrips() {
        let ledger = FsLedger {
            entries: vec![FsLedgerEntry {
                path: r"C:\ProgramData\Microsoft\Windows\Start Menu".to_string(),
                writable: false,
                granted_at_unix_secs: 1_700_000_000,
                forced: true,
                settings_workspaces: Vec::new(),
                settings_managed: false,
                granted_sids: Vec::new(),
                scope: harness_policy::GrantScope::Recursive,
            }],
            denied_entries: Vec::new(),
        };
        let json = serde_json::to_string(&ledger).unwrap();
        let back: FsLedger = serde_json::from_str(&json).unwrap();
        assert!(back.entries[0].forced);
    }

    /// 同じパスを2回付与しても**エントリは1件のまま**（冪等な上書き）。
    /// 増えると`harness fs revoke-all`が同じパスを何度も撤収しようとする。
    #[test]
    fn granting_the_same_path_twice_upserts_instead_of_appending() {
        let mut ledger = FsLedger::default();
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            None,
            harness_policy::GrantScope::Recursive,
            100,
        );
        ledger.upsert_grant(
            PATH.to_string(),
            true,
            true,
            None,
            None,
            harness_policy::GrantScope::Recursive,
            200,
        );

        assert_eq!(ledger.entries.len(), 1, "the same path must not accumulate");
        assert!(ledger.entries[0].writable, "the newest access wins");
        assert!(ledger.entries[0].forced);
        assert_eq!(ledger.entries[0].granted_at_unix_secs, 200);
    }

    /// 付与した宛先SIDは**上書きではなく和**で持つ（重複は足さない）。
    ///
    /// [BUG-101] 同じパスは起動のたびに別のセッション（＝別のpackage SID）が付与し直す。
    /// 上書きにすると、前のセッションが付けたACEを「harnessのものだ」と判定する手掛かりが
    /// 消え、そのプロファイルが削除された時点で二度と剥がせなくなる。
    #[test]
    fn the_granting_sids_accumulate_as_a_set_instead_of_being_overwritten() {
        const SID_A: &str = "S-1-15-2-1111111111-1-1-1-1-1-1";
        const SID_B: &str = "S-1-15-2-2222222222-2-2-2-2-2-2";
        let mut ledger = FsLedger::default();
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            Some(SID_A),
            harness_policy::GrantScope::Recursive,
            100,
        );
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            Some(SID_B),
            harness_policy::GrantScope::Recursive,
            200,
        );
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            Some(SID_A),
            harness_policy::GrantScope::Recursive,
            300,
        );
        // SIDを導出できなかった起動（`None`）が既存の記録を消さないこと。
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            None,
            harness_policy::GrantScope::Recursive,
            400,
        );

        assert_eq!(
            ledger.entries[0].granted_sids,
            vec![SID_A.to_string(), SID_B.to_string()],
            "every subject that ever granted this path must stay reachable"
        );
    }

    /// このフィールドを持たない**旧台帳**がそのまま読めること（`serde(default)`）。
    /// この台帳は実マシンの唯一の記録なので、スキーマ変更で読めなくなると
    /// 付与済みACEの撤収経路がまるごと失われる。
    #[test]
    fn a_ledger_written_before_granted_sids_existed_still_loads() {
        let json = r#"{"entries":[{"path":"C:\\x","writable":true,"granted_at_unix_secs":1}]}"#;
        let ledger: FsLedger = serde_json::from_str(json).expect("old ledger must still parse");
        assert_eq!(ledger.entries.len(), 1);
        assert!(ledger.entries[0].granted_sids.is_empty());
    }

    /// `settings.json`由来の宣言者（D-27の参照カウント）は**重複追加しない**。
    /// 同じworkspaceの再起動ごとに積むと、参照者ゼロの判定が永遠に成立しなくなる。
    #[test]
    fn the_declaring_workspaces_are_deduped_and_settings_managed_never_goes_back_down() {
        let mut ledger = FsLedger::default();
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            Some(r"C:\ws"),
            None,
            harness_policy::GrantScope::Recursive,
            100,
        );
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            Some(r"C:\ws"),
            None,
            harness_policy::GrantScope::Recursive,
            200,
        );
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            Some(r"C:\other"),
            None,
            harness_policy::GrantScope::Recursive,
            300,
        );

        assert_eq!(
            ledger.entries[0].settings_workspaces,
            vec![r"C:\ws".to_string(), r"C:\other".to_string()]
        );
        assert!(ledger.entries[0].settings_managed);

        // `--fs-allow`だけの再起動（settings_workspace = None）を挟んでも降ろさない。
        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            None,
            harness_policy::GrantScope::Recursive,
            400,
        );
        assert!(
            ledger.entries[0].settings_managed,
            "settings_managed must stay true once set (D-27: otherwise the entry silently drops \
             out of automatic reconciliation)"
        );
        assert_eq!(ledger.entries[0].settings_workspaces.len(), 2);
    }

    /// 付与に成功したパスは「到達不能候補」から**消える**。両方に残ると
    /// `harness fs denied`が既に開いている穴を勧め続ける。
    #[test]
    fn a_successful_grant_clears_the_denied_record_for_the_same_path() {
        let mut ledger = FsLedger::default();
        ledger.record_denied(PATH.to_string(), "read_exec", "ACCESS_DENIED", 100);
        assert_eq!(ledger.denied_entries.len(), 1);

        ledger.upsert_grant(
            PATH.to_string(),
            false,
            false,
            None,
            None,
            harness_policy::GrantScope::Recursive,
            200,
        );

        assert!(
            ledger.denied_entries.is_empty(),
            "granting must retire the denied candidate"
        );
    }

    /// 同じ`(path, access)`の拒否は**回数を積む**（別accessは別エントリ）。
    #[test]
    fn repeated_denials_increment_the_count_and_different_access_kinds_stay_separate() {
        let mut ledger = FsLedger::default();
        ledger.record_denied(PATH.to_string(), "read_exec", "first", 100);
        ledger.record_denied(PATH.to_string(), "read_exec", "second", 200);
        ledger.record_denied(PATH.to_string(), "read_write", "third", 300);

        assert_eq!(ledger.denied_entries.len(), 2);
        let read_exec = ledger
            .denied_entries
            .iter()
            .find(|e| e.access == "read_exec")
            .unwrap();
        assert_eq!(read_exec.count, 2);
        assert_eq!(read_exec.reason, "second", "the newest reason wins");
        assert_eq!(read_exec.last_denied_at_unix_secs, 200);
    }

    #[test]
    fn denied_entries_roundtrip() {
        let ledger = FsLedger {
            entries: Vec::new(),
            denied_entries: vec![FsDeniedLedgerEntry {
                path: r"C:\Users\segfo\.local\bin".to_string(),
                access: "read_exec".to_string(),
                reason: "ACE grant failed".to_string(),
                last_denied_at_unix_secs: 1_700_000_001,
                count: 2,
            }],
        };
        let json = serde_json::to_string(&ledger).unwrap();
        let back: FsLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.denied_entries[0].access, "read_exec");
        assert_eq!(back.denied_entries[0].count, 2);
    }
}
