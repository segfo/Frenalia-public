//! harness-grant-ledger: 「このマシンに対して実際に行った付与」を追跡する台帳の共通機構。
//!
//! `%APPDATA%\harness\config\*.json`（Windows。`directories::ProjectDirs::config_dir()`）に
//! 置かれる台帳が本クレートの`Ledger<T>`を共有する。
//!
//! **どの台帳が在って、どれが消えると回収不能になるかは[`CONFIG_DIR_LEDGERS`]が持つ。**
//! 各行の理由（何を記録し、消えると何が起きるか）は`docs/DEV-ENVIRONMENT.md`
//! 「クリーンアップ時に絶対に消してはいけないファイル」が正本である。
//! **件数も名前もここへ書き写さない**——2026-09-30の棚卸しで、同じ件数が5つの文書で
//! 3/4/5/6/8と全部違っており、このモジュールdocは6と書いて2本を落としていた。
//!
//! 分け方だけを言うと、**実マシンへ加えた変更を追跡するもの**（消えると孤立したACEやVMが残る）と、
//! **判断の記録**（消えても未承認へ戻るだけでfail-closed）の2種類がある。前者が保護対象になる。
//!
//! **`harness-change-ledger`とは別物**である。あちらは1セッション内のCoW変更（どのファイルを
//! 書き換えたか）を記録する揮発的なもので、こちらは**実マシンへ加えた永続的な変更**を記録する。
//!
//! ## 誤削除防止の2層
//!
//! [`Ledger::save`]は書込のたびに次の2つを行う。エージェント（コーディングツール）による
//! 無関係な一括クリーンアップの巻き込みを防ぐための措置である。
//!
//! 1. 上書き前に既存ファイルのread-onlyを解除し、`.json.bak`へコピーする（復元用）。
//! 2. 書込後にread-only属性を付ける（`-Force`無しの`Remove-Item`/`rm`による削除を防ぐ）。
//!
//! 非Windowsでは(2)を行わない。`set_readonly(true)`の意味論がプラットフォームで異なり、
//! Unixではchmodのworld-writable相当になり得て有効な防御にならないため。
//!
//! ## fail-open
//!
//! 読取（[`Ledger::load`]）は、ファイルが無い・読めない・パースできないいずれの場合も
//! `T::default()`を返す。台帳の不在で起動を止めない（`harness-config`の設定読み込みと
//! 同じ方針）。書込の失敗も無視する。
//!
//! **ただし「パースできない」だけは、`T::default()`へ倒れる前に`.json.bak`を読み直す**
//! （2026-09-03）。書込はその場上書きなので、途中で死ぬと本体は壊れる一方で控えは無事であり、
//! そこで空の台帳を返すと**その台帳の全エントリが一斉に回収名を失う**。詳細は
//! [`Ledger::load_unlocked`]。
//!
//! [`with_named_lock`]も、名前付きミューテックスを**作れなかった**ときはロック無しで
//! クロージャを走らせる。**「作れなかった」だけがfail-openの対象である**——前の持ち主が
//! 解放せずに死んだ状態（`WAIT_ABANDONED`）は所有権がこちらへ移っているので、
//! ここには含めない（[BUG-146](../../../docs/bugs/BUG-146.md)）。

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod prune;

/// 名前付きOSミューテックスで`f`を直列化する。
///
/// 複数の`harness.exe`が同時に起動している状況で、台帳のread-modify-write
/// （load→変更→save）がロストアップデートを起こさないようにするために使う（D-27）。
/// `name`は`Local\`接頭辞を含む完全なカーネルオブジェクト名を渡すこと。
///
/// ミューテックスの取得自体に失敗した場合はロック無しで`f`を実行する（fail-open、
/// 台帳操作そのものは止めない）。
///
/// 台帳以外にも使える汎用ヘルパーで、`harness-sandbox`はworkspaceのモード別mutexの
/// セットアップ（`workspace_ledger::begin_workspace_mode`）でもこれを使う。
///
/// # `WAIT_ABANDONED`は「取れなかった」ではない（[BUG-146](../../../docs/bugs/BUG-146.md)）
///
/// 前の持ち主が解放しないまま死ぬと、Windowsは次の待ち手へ`WAIT_ABANDONED`を返す。
/// これは失敗ではなく、**所有権がこちらへ移った**という通知である。以前ここは
/// `WAIT_OBJECT_0`以外をすべて失敗として扱っており、その結果 (1) 排他しないまま`f`を走らせ、
/// (2) 手に入れた所有権を解放しないままハンドルを閉じる、の2つを同時に起こしていた。
/// [`try_acquire_named_lock`]は最初から`WAIT_ABANDONED`を「取れた」と扱っており、
/// **同じ状態の扱いが2つの入口で割れていた**。
///
/// 守られていたはずの状態が途中で壊れている可能性は、`f`の側が確かめること
/// （`harness-sandbox`の`follow_the_leader`は実DACLを見てやり直す）。
#[cfg(windows)]
pub fn with_named_lock<R>(name: &str, f: impl FnOnce() -> R) -> R {
    use windows::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        CreateMutexW, ReleaseMutex, WaitForSingleObject, INFINITE,
    };

    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { CreateMutexW(None, false, windows::core::PCWSTR(wide_name.as_ptr())) };
    let Ok(handle) = handle else {
        return f();
    };
    let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
    if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return f();
    }
    let result = f();
    unsafe {
        let _ = ReleaseMutex(handle);
        let _ = CloseHandle(handle);
    }
    result
}

#[cfg(not(windows))]
pub fn with_named_lock<R>(_name: &str, f: impl FnOnce() -> R) -> R {
    f()
}

/// [`try_acquire_named_lock`]が返す値。**落とすと手放す。**
///
/// # **スレッドを跨げない**（[BUG-146](../../../docs/bugs/BUG-146.md)）
///
/// Windowsの名前付きミューテックスは**所有権が取得したスレッドに紐づく**ので、
/// 所有していないスレッドからの`ReleaseMutex`は`ERROR_NOT_OWNER`で失敗する。
/// つまりこの値は、**取ったスレッドで落とさなければ機能しない**。
///
/// 以前ここは`unsafe impl Send`が付いており、docに「取った側だけが解放する」と
/// **前提として書いてあった**。その前提は唯一の呼び出し側（`harness-sandbox`の背景準備
/// ジョブ）で破れていた——呼び出し元のスレッドで取り、背景スレッドで落としていた。
/// **前提を書くだけでは守られない**ので、`Send`を外して**コンパイラが止める**形にしてある。
/// 内部の`HANDLE`が`Send`でないため、この型も自動的に`Send`ではない。
///
/// 取ってから別スレッドで仕事をしたい場合は、**そのスレッド自身に取らせる**こと
/// （取得も解放も同じスレッドに閉じる）。
#[cfg(windows)]
pub struct NamedLock {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for NamedLock {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        unsafe {
            // **戻り値を捨てない。** 解放の失敗は、それ自体が「次の人が詰まる」という形で
            // 遅れて現れる——`ReleaseMutex`が失敗しても`CloseHandle`は成功するので、
            // 捨てると**何も起きていないように見える**（BUG-146の見つけにくさの本体、`B-10`）。
            // `Send`を外した今、安全なコードからは起こせないはずの事象である。
            // `Drop`中のpanicは巻き戻し中にプロセスを落とすので、報告だけにとどめる。
            if ReleaseMutex(self.handle).is_err() {
                eprintln!(
                    "harness: failed to release a named mutex; it must be released on the \
                     thread that acquired it (BUG-146)"
                );
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

/// 名前付きOSミューテックスを**待たずに**取る。取れなければ`None`。
///
/// # [`with_named_lock`]と何が違うのか
///
/// あちらは取れるまで待ってからクロージャを走らせる。こちらは**取れたかどうかで
/// 進路を変えたいとき**に使う——「取れたら自分が仕事をする、取れなければ相手に任せて
/// 別の道を行く」という分岐は、待ってしまうと書けない。
///
/// # 限界: **同じスレッドからは何度でも取れる**（Windowsのミューテックスは再入可能）
///
/// 所有者スレッドが同じなら`WaitForSingleObject`は即座に成功する。したがってこれは
/// **スレッドをまたぐ／プロセスをまたぐ排他**であって、同一スレッド内の二重取得は防がない。
/// 用途（別の`harness.exe`同士の leader 選出）には十分だが、**同一プロセス内の二重起動を
/// これで止めようとしないこと**——そちらは別の仕組みが要る
/// （`harness-sandbox`のジョブ一覧がその役をしている）。
///
/// # 前の持ち主が死んでいた場合（`WAIT_ABANDONED`）は**取れた**として扱う
///
/// プロセスが解放せずに落ちるとミューテックスは放棄状態になる。Windowsはそれを
/// 次の待ち手へ`WAIT_ABANDONED`で渡す——**所有権は移っている**ので、`None`を返すと
/// 「誰も持っていないのに誰も取れない」状態が永久に続く。守られていたはずの状態が
/// 途中で壊れている可能性は呼び出し側が確かめること。
#[cfg(windows)]
pub fn try_acquire_named_lock(name: &str) -> Option<NamedLock> {
    use windows::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let handle =
        unsafe { CreateMutexW(None, false, windows::core::PCWSTR(wide_name.as_ptr())) }.ok()?;
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
        return Some(NamedLock { handle });
    }
    unsafe {
        let _ = CloseHandle(handle);
    }
    None
}

/// 非Windowsでは排他しない（このリポジトリの対象機構はWindows専用）。
#[cfg(not(windows))]
pub struct NamedLock;

#[cfg(not(windows))]
pub fn try_acquire_named_lock(_name: &str) -> Option<NamedLock> {
    Some(NamedLock)
}

/// `path`のread-only属性を切り替える（Windowsの`attrib +R`/`-R`相当）。
/// 非Windowsでは何もしない（モジュールdoc「誤削除防止の2層」参照）。
#[cfg(windows)]
fn set_file_readonly(path: &Path, readonly: bool) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(windows))]
fn set_file_readonly(_path: &Path, _readonly: bool) {}

/// 1つの台帳ファイル。`T`はその台帳のペイロード型。
///
/// 台帳どうしの違いは**(ファイル名, ロック名, ペイロード型)** の3点だけなので、それらを
/// この型のフィールド/型引数として持つ。
pub struct Ledger<T> {
    /// 台帳ファイルの絶対パス。`ProjectDirs`が解決できない環境では`None`になり、
    /// その場合は読取が`T::default()`・書込がno-opになる（統合前の各実装と同じ）。
    path: Option<PathBuf>,
    /// `Some`なら[`with_named_lock`]で直列化する。`None`ならロックしない。
    ///
    /// 実運用の台帳（[`CONFIG_DIR_LEDGERS`]に載るもの）はいずれも
    /// `Local\harness-<台帳名>-ledger`形式のロック名を渡し、read-modify-writeを直列化する。
    /// `None`はAPIとしては引き続きサポートするが（テスト用途等）、実運用の台帳では使わない。
    lock_name: Option<String>,
    _payload: PhantomData<T>,
}

/// harnessのユーザースコープ設定ディレクトリ（`%APPDATA%\harness\config`）。
///
/// **ここはharnessの制御面である。** 付与済みACEの台帳（`fs-passthrough-ledger.json`・
/// `traverse-grant-ledger.json`・`tier3-vm-ledger.json`）とMCPの承認台帳
/// （`mcp-approval-ledger.json`、D-39）が入っており、サンドボックスから書けると
/// **自分の許可を書き換えられる**（P-08。`<workspace>/.harness`と同じ性質だが、
/// **綴りが全く違うので同じ判定では拾えない**）。
///
/// 解決規則を[`Ledger::in_config_dir`]と共有するために公開している——
/// 候補から除外する側（`harness_policy_editor::exclusion`）が`%APPDATA%\harness`と
/// 書き写すと、置き場を変えたときに静かにずれる（B-05）。
pub fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.config_dir().to_path_buf())
}

/// `config_dir()`に置く台帳1本の素性。
///
/// `protected`は**「消えると回収不能になるか」**であって「台帳かどうか」ではない。
/// 判定の根拠と各行の意味は[`docs/DEV-ENVIRONMENT.md`]「クリーンアップ時に絶対に
/// 消してはいけないファイル」が正本で、**ここへ文章を複製しない**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigDirLedger {
    /// `config_dir()`直下のファイル名。
    pub file_name: &'static str,
    /// 消えると実マシンへ孤立した副作用が残るなら`true`。
    pub protected: bool,
}

/// `config_dir()`に置くことを許した台帳の全件。
///
/// **この配列が「何本あるか」のコード側の正本である。** 文書側の正本は
/// `docs/DEV-ENVIRONMENT.md`で、あちらは各行の理由を持ち、こちらは名前と保護の要否だけを持つ。
/// **件数を文書へ書き写さない**——2026-09-30の棚卸しで、同じ件数が5つの文書で
/// 3/4/5/6/8と全部違っていた（`docs/STATUS.md`残課題「サンドボックス周辺 #33」）。
///
/// 増やすときは**ここと`DEV-ENVIRONMENT.md`の表を同じコミットで**直す。
///
/// # この機構が守らないもの
///
/// 歯があるのは**「未登録の名前で台帳を作れない」の1点だけ**である。次の3つは守らない。
///
/// 1. **文書との一致を検査しない。** `DEV-ENVIRONMENT.md`の表だけ古くなっても、テストは緑のまま。
///    片方だけ直せる経路が残っている（それでも件数の正本が1つになったので、ずれても
///    「どちらが正しいか」は決まる）。
/// 2. **既存8本の名前を、テストが再検査しているわけではない。** 本クレートの
///    `in_config_dir_accepts_every_registered_ledger`が回すのはこの配列の中身であって、
///    各クレートが持つファイル名の定数ではない。**定数の側を書き換えて登録を直さなければ、
///    落ちるのはその経路が実際に走ったときである**（起動時か、その機構のテスト）。
///    追加の検査を置いていないのは、`pub`を増やして規約4（可視性）と衝突させるより、
///    落ちる場所が遅れることを受け入れる方を選んだため。
/// 3. **`config_dir()`の外にある台帳は視野に入らない**（`%ProgramData%`の
///    `loopback-exemption-ledger.json`）。あちらは消えても次のセッションが引き取る。
pub const CONFIG_DIR_LEDGERS: &[ConfigDirLedger] = &[
    ConfigDirLedger { file_name: "fs-passthrough-ledger.json", protected: true },
    ConfigDirLedger { file_name: "traverse-grant-ledger.json", protected: true },
    ConfigDirLedger { file_name: "tier3-vm-ledger.json", protected: true },
    ConfigDirLedger { file_name: "workspace-grant-ledger.json", protected: true },
    ConfigDirLedger { file_name: "workspace-capability-ledger.json", protected: true },
    ConfigDirLedger { file_name: "appcontainer-session-ledger.json", protected: false },
    ConfigDirLedger { file_name: "mcp-approval-ledger.json", protected: false },
    ConfigDirLedger { file_name: "run-approval-ledger.json", protected: false },
];

/// `config_dir()`に置く台帳として登録済みか。
pub fn is_registered_config_dir_ledger(file_name: &str) -> bool {
    CONFIG_DIR_LEDGERS.iter().any(|l| l.file_name == file_name)
}

/// 消えると回収不能になる台帳のファイル名だけを返す。
pub fn protected_config_dir_ledgers() -> impl Iterator<Item = &'static str> {
    CONFIG_DIR_LEDGERS
        .iter()
        .filter(|l| l.protected)
        .map(|l| l.file_name)
}

impl<T> Ledger<T> {
    /// `%APPDATA%\harness\config\<file_name>`を指す台帳を作る。
    ///
    /// # Panics
    ///
    /// `file_name`が[`CONFIG_DIR_LEDGERS`]に無いときに落ちる。**これはプログラマの誤りであり、
    /// 実行時の入力ではない。** 落とす理由は、台帳を1本増やしたのに保護一覧へ登録しないと
    /// **クリーンアップの巻き添えで消える側に静かに入る**ためである——そして消えたことは
    /// 無言で、症状は「剥がせないACEが実マシンに残る」という形で後から出る。
    ///
    /// テストで`%APPDATA%`を汚さずに台帳を作るときは[`Ledger::at_path`]を使う（登録は要らない）。
    pub fn in_config_dir(file_name: &str, lock_name: Option<&str>) -> Self {
        assert!(
            is_registered_config_dir_ledger(file_name),
            "{file_name} is not registered in harness_grant_ledger::CONFIG_DIR_LEDGERS. \
             台帳を1本増やしたなら、その配列と docs/DEV-ENVIRONMENT.md の保護対象の表を\
             同じコミットで直すこと（消えたときに何が回収不能になるかを書く）。\
             テスト用の一時台帳なら Ledger::at_path を使う。"
        );
        Self {
            path: config_dir().map(|dir| dir.join(file_name)),
            lock_name: lock_name.map(str::to_owned),
            _payload: PhantomData,
        }
    }

    /// 明示したパスを指す台帳を作る（テストで`%APPDATA%`を汚さないための注入点）。
    pub fn at_path(path: PathBuf, lock_name: Option<&str>) -> Self {
        Self {
            path: Some(path),
            lock_name: lock_name.map(str::to_owned),
            _payload: PhantomData,
        }
    }

    /// 台帳ファイルのパス。`harness fs list`のような表示系がユーザーへ場所を示すのに使う。
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn with_lock<R>(&self, f: impl FnOnce() -> R) -> R {
        match &self.lock_name {
            Some(name) => with_named_lock(name, f),
            None => f(),
        }
    }
}

impl<T: Serialize + DeserializeOwned + Default> Ledger<T> {
    /// 台帳を読む。ファイルが無い・読めない・パースできない場合は`T::default()`
    /// （モジュールdoc「fail-open」参照）。ロック名が設定されていれば取得してから読む。
    pub fn load(&self) -> T {
        self.with_lock(|| self.load_unlocked())
    }

    /// ロックを取らずに読む。[`Ledger::update`]の内側のように、既にロックを保持している
    /// 文脈からのみ使う（同じスレッドで名前付きmutexを再取得しても手放しが1回になり
    /// 対応が崩れるため）。
    ///
    /// # 本体が壊れていたら`.json.bak`から読み直す
    ///
    /// [`write_ledger_file`]は`std::fs::write`による**その場上書き**である（一時ファイルへ
    /// 書いて差し替える形ではない）。書込の途中でプロセスが消えると、残るのは**途中まで書かれた
    /// JSON**で、`serde_json`はそれをパースできない。そのまま`T::default()`へ倒れると、
    /// **その台帳の全エントリが一斉に無名になる**——1件が失われるのではなく、実マシンに残った
    /// 全部のACEが回収名を失う（[BUG-112](../../../docs/bugs/BUG-112.md)が
    /// 1件について言っていたことの、台帳丸ごと版である）。
    ///
    /// 控えは既に毎回書いている。**足りないのは読む側だけだった**——付与と撤収、記録と回収と
    /// 同じで、対の片側しか無い機構は片側の場面で無言に失敗する（`B-01`）。
    ///
    /// 読み直すのは「**ファイルは在るがパースできない**」ときだけである。ファイルが無いのは
    /// 「まだ1件も記録していない」という正常な状態なので、控えを探しに行かない。
    pub fn load_unlocked(&self) -> T {
        let Some(path) = &self.path else {
            return T::default();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return T::default();
        };
        if let Ok(value) = serde_json::from_str(&text) {
            return value;
        }
        let backup_path = path.with_extension("json.bak");
        let Ok(backup) = std::fs::read_to_string(&backup_path) else {
            return T::default();
        };
        match serde_json::from_str(&backup) {
            Ok(value) => {
                // **黙って復旧しない。** 直前の書込が途中で切れたという事実そのものが、
                // 次に調べる人の手がかりである（控えは1世代しか無いので、この状態で
                // 書き込むと控えが「壊れた本体」で上書きされる）。
                eprintln!(
                    "harness: {} could not be parsed; recovered from {} (the previous write was \
                     cut short). Entries written after that backup are lost.",
                    path.display(),
                    backup_path.display()
                );
                value
            }
            Err(_) => T::default(),
        }
    }

    /// 台帳を書く（誤削除防止の2層つき、モジュールdoc参照）。
    pub fn save(&self, ledger: &T) {
        self.with_lock(|| self.save_unlocked(ledger));
    }

    /// ロックを取らずに書く（[`Ledger::load_unlocked`]と同じ注意）。
    pub fn save_unlocked(&self, ledger: &T) {
        let Some(path) = &self.path else {
            return;
        };
        if let Ok(s) = serde_json::to_string_pretty(ledger) {
            write_ledger_file(path, &s);
        }
    }

    /// read-modify-writeを1つのロック区間で行う。
    ///
    /// `load`してから`save`するまでの間に他プロセスが書き込むと更新が失われるため、
    /// エントリの追加・削除は必ずこれを通すこと。
    ///
    /// # 中身が変わらなければ書かない（[BUG-108](../../../docs/bugs/BUG-108.md)）
    ///
    /// `f`が台帳を1バイトも変えなかったときは**ファイルへ触らない**。書けば
    /// [`write_ledger_file`]が既存内容を`.json.bak`へコピーするので、**無変更の書込は
    /// 唯一の復旧コピーを「直前の同じ内容」で置き換えて消費する**——`.bak`の復旧価値が
    /// 静かにゼロになる。実際に`appcontainer-session-ledger.json`と`.bak`が同一ハッシュに
    /// なっている状態を実機で観測した。
    ///
    /// この経路を通る呼び出しは多くが無変更である。`begin_session`は「エントリが既にあれば
    /// 何もしない」冪等な処理だが`update`は通るし、`record_granted_paths`も記録済みのパスなら
    /// 何も足さない。1回あたり全文の読取＋`.bak`への全文コピー＋全文書込を払っていた
    /// （[BUG-092](../../../docs/bugs/BUG-092.md)で測った台帳は66KB・185KB）。
    ///
    /// **スキップしてもread-only属性は付け直す。** 誤削除防止の2層（モジュールdoc）のうち
    /// (2)は書込の副産物なので、書かない経路を作ると黙って落ちる（B-02: 片側に入れた
    /// 最適化は、それが担っていた副作用ごと消していないかを見る）。
    ///
    /// パースできないファイルは`load`が`T::default()`へ倒れるため、`f`が何も変えなければ
    /// **壊れたファイルはそのまま残る**（既定値で上書きして`.bak`まで潰すより、復旧できる
    /// 側へ倒す）。同じ理由で、**ファイルがまだ無いときに空の台帳を作ることもしない**
    /// ——記録すべきものが1件も無いのだから、作る意味が無い。
    ///
    /// **[`Ledger::save`]は無条件に書く。** あちらは呼び出し側が値を持って「書く」と決めた
    /// 経路で、比較のための読取が要る。実運用でこれを直接呼ぶのは`harness-cognition`の
    /// recall watermarkだけである（`save_traverse_ledger`・`save_workspace_ledger`は
    /// 呼び出し元が無い）。
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.with_lock(|| {
            let mut ledger = self.load_unlocked();
            let before = serde_json::to_string_pretty(&ledger).ok();
            let result = f(&mut ledger);
            let after = serde_json::to_string_pretty(&ledger).ok();
            // 直列化に失敗した場合（`before`か`after`が`None`）は比較できないので、
            // 従来どおり書きに行く——「比べられなかった」を「同じだった」へ畳まない（B-10）。
            if before.is_some() && before == after {
                if let Some(path) = &self.path {
                    set_file_readonly(path, true);
                }
                return result;
            }
            self.save_unlocked(&ledger);
            result
        })
    }
}

/// 台帳ファイルへの書込を、誤削除防止の2層を通して行う（モジュールdoc参照）。
fn write_ledger_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if path.exists() {
        set_file_readonly(path, false);
        let backup_path = path.with_extension("json.bak");
        let _ = std::fs::copy(path, &backup_path);
    }
    if std::fs::write(path, contents).is_ok() {
        set_file_readonly(path, true);
    }
}

/// UNIXエポック秒。各台帳のエントリが`granted_at_unix_secs`として持つ。
/// システム時刻がエポック以前を指す異常時は0を返す（既存4実装と同じ）。
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 台帳のパス文字列どうしが**同じファイルシステム上の対象**を指すかを判定する（B-19）。
///
/// # なぜ全台帳で共有するのか
///
/// これらの台帳は書き手が1つではありません——`harness fs`のCLIは引数をそのまま
/// （`C:\Users\...`）、ポリシーエディタは設定パス由来のスラッシュ形（`C:/Users/...`）で
/// 記録します。素の文字列比較だと、**同じディレクトリが2つのエントリとして積もり**、
/// 撤収は片方しか消しません。実際にtraverse台帳には
/// `C:\Users\segfo\AppData\Local\Temp`と`C:/Users/segfo/AppData/Local/Temp`が
/// 並んで存在していました（BUG-101）。
///
/// 同じ判定を台帳ごとに書き写すと、片方だけ直って静かにずれます
/// （`CODE-STRUCTURE-RULES`§5.0）。**記録側と撤収側の両方**がこの1つを通します（B-02）。
///
/// Windowsのファイルシステムは大小非区別なので、比較もそれに合わせます。
pub fn same_ledger_path(a: &str, b: &str) -> bool {
    fn key(s: &str) -> String {
        s.replace('/', "\\").trim_end_matches('\\').to_lowercase()
    }
    key(a) == key(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestLedger {
        entries: Vec<String>,
    }

    fn ledger_at(dir: &Path) -> Ledger<TestLedger> {
        Ledger::at_path(dir.join("ledger.json"), None)
    }

    /// **`update`は1回ごとに台帳の全文を読み書きする**（さらに`.bak`へ全文コピーし、
    /// 読取専用属性を外して書き戻す）。「1件足す」APIに見えるが実体はこれなので、
    /// **ループの中で呼ぶとエントリ数の2乗でI/Oが増える**。
    ///
    /// 実運用でこれを踏んだ: ポリシーエディタのパス2が、workspace外のルート668件を
    /// 1件ずつ`update`していた。台帳は実測185KB／66KBあり、合わせて約500MBのI/Oになって
    /// 準備が数秒かかっていた（[BUG-092](../../../docs/bugs/BUG-092.md)）。
    ///
    /// このテストは**その性質を数字で固定する**——N件を1回の`update`でまとめたときの
    /// 書込バイト数が、N回に分けたときより桁で小さいこと。**「まとめて書く方が速い」は
    /// 直感だが、桁が違うことは測らないと分からない。**
    #[test]
    fn updating_once_per_entry_costs_quadratically_more_io_than_batching() {
        fn bytes_written(dir: &Path, batched: bool, entries: usize) -> u64 {
            let ledger = ledger_at(dir);
            // 台帳が育った状態から測る（現実の台帳は既に数百件入っている）。
            ledger.update(|l| {
                for i in 0..entries {
                    l.entries
                        .push(format!("C:/Users/me/.cargo/registry/package-{i}"));
                }
            });
            let size = std::fs::metadata(dir.join("ledger.json")).unwrap().len();

            let added: Vec<String> = (0..entries).map(|i| format!("C:/extra/{i}")).collect();
            if batched {
                ledger.update(|l| l.entries.extend(added.iter().cloned()));
                size
            } else {
                for one in &added {
                    ledger.update(|l| l.entries.push(one.clone()));
                }
                size * entries as u64
            }
        }

        const N: usize = 200;
        let batched_dir = tempfile::tempdir().unwrap();
        let per_entry_dir = tempfile::tempdir().unwrap();
        let batched = bytes_written(batched_dir.path(), true, N);
        let per_entry = bytes_written(per_entry_dir.path(), false, N);

        assert!(
            per_entry > batched * (N as u64 / 2),
            "per-entry update should cost roughly N times more writes than one batched update \
             (batched={batched} bytes, per-entry~{per_entry} bytes). If this ever becomes \
             comparable, the cost model in the doc above is wrong and the batching in \
             preflight/record_net can be simplified away."
        );
        // 中身は同じであること（速さのために記録を落としていない）。
        assert_eq!(
            ledger_at(batched_dir.path()).load().entries.len(),
            ledger_at(per_entry_dir.path()).load().entries.len()
        );
    }

    // --- 以下5件は harness-sandbox::traverse_ledger から移設した characterization test。
    //     統合前に既存実装に対して緑であることを確認済み（規則6）。

    #[test]
    fn creates_missing_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("deeper").join("ledger.json");
        write_ledger_file(&path, "{}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
    }

    #[test]
    fn first_write_creates_no_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, r#"{"entries":[]}"#);
        assert!(!tmp.path().join("ledger.json.bak").exists());
    }

    #[test]
    fn overwrite_backs_up_the_previous_contents_to_json_bak() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "OLD");
        write_ledger_file(&path, "NEW");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "NEW");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("ledger.json.bak")).unwrap(),
            "OLD"
        );
    }

    #[cfg(windows)]
    #[test]
    fn write_leaves_the_file_readonly_and_can_still_overwrite_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "first");
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
        write_ledger_file(&path, "second");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
    }

    #[cfg(not(windows))]
    #[test]
    fn readonly_attribute_is_not_touched_on_non_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "first");
        assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());
    }

    /// 控えが**そもそも無い**ときの話（1度も書いていない台帳が壊れている等）。控えは在るが
    /// それも読めない場合は`a_ledger_with_no_usable_backup_still_falls_open_to_default`、
    /// 控えが使える場合は`a_ledger_cut_short_mid_write_is_recovered_from_its_backup`が見る。
    #[test]
    fn corrupt_or_missing_json_loads_as_the_default_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());

        assert_eq!(ledger.load(), TestLedger::default());

        std::fs::write(tmp.path().join("ledger.json"), "{ this is not json").unwrap();
        assert_eq!(ledger.load(), TestLedger::default());
    }

    // --- ここから下は`Ledger<T>`が新たに提供するAPIの分。

    #[test]
    fn save_then_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());
        let value = TestLedger {
            entries: vec!["a".to_string(), "b".to_string()],
        };
        ledger.save(&value);
        assert_eq!(ledger.load(), value);
    }

    #[test]
    fn update_reads_modifies_and_writes_in_one_step() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());
        ledger.update(|l| l.entries.push("first".to_string()));
        let returned = ledger.update(|l| {
            l.entries.push("second".to_string());
            l.entries.len()
        });
        assert_eq!(returned, 2);
        assert_eq!(ledger.load().entries, vec!["first", "second"]);
    }

    /// **[BUG-108] 何も変わらなかった`update`は、復旧用`.bak`を消費しない。**
    ///
    /// 書けば[`write_ledger_file`]が既存内容を`.bak`へコピーするので、無変更の書込は
    /// 「直前の同じ内容」で唯一の復旧コピーを置き換える＝`.bak`の復旧価値が静かに消える。
    /// 実機の`appcontainer-session-ledger.json`は、まさに本体と`.bak`が同一ハッシュだった。
    #[test]
    fn an_update_that_changes_nothing_leaves_the_file_and_its_backup_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());
        let path = tmp.path().join("ledger.json");
        let backup = tmp.path().join("ledger.json.bak");

        ledger.update(|l| l.entries.push("first".to_string()));
        ledger.update(|l| l.entries.push("second".to_string()));
        let before = std::fs::read_to_string(&path).unwrap();
        let backup_before = std::fs::read_to_string(&backup).unwrap();

        // 冪等な更新（既にあるものは足さない）は、この台帳の日常的な呼ばれ方である
        // （`begin_session`・`record_granted_paths`はどちらもこの形）。
        ledger.update(|l| {
            if !l.entries.iter().any(|e| e == "second") {
                l.entries.push("second".to_string());
            }
        });

        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(
            std::fs::read_to_string(&backup).unwrap(),
            backup_before,
            "無変更の書込で`.bak`が「直前の同じ内容」に置き換わってはいけない（BUG-108）"
        );
        assert_ne!(
            backup_before, before,
            "この時点で`.bak`は1つ前の状態を保持しているはず（テスト自身の前提）"
        );
    }

    /// **対になる許可側**（B-35）。中身が変われば従来どおり書き、`.bak`も更新する。
    /// これが無いと「常に書かない」実装でも上のテストが通り、台帳が機能しなくなったことに
    /// 気付けない。
    #[test]
    fn an_update_that_changes_something_still_writes_and_backs_up() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());

        ledger.update(|l| l.entries.push("first".to_string()));
        assert_eq!(ledger.load().entries, vec!["first"]);
        ledger.update(|l| l.entries.push("second".to_string()));

        assert_eq!(ledger.load().entries, vec!["first", "second"]);
        assert!(
            std::fs::read_to_string(tmp.path().join("ledger.json.bak"))
                .unwrap()
                .contains("first"),
            "変更を書いたときは、直前の内容が`.bak`へ退避されていなければならない"
        );
        // 誤削除防止の2層のうち(2)。スキップ経路を足したときに落ちやすいので対で固定する。
        #[cfg(windows)]
        assert!(std::fs::metadata(tmp.path().join("ledger.json"))
            .unwrap()
            .permissions()
            .readonly());
    }

    /// **スキップしてもread-only属性は付け直す**（誤削除防止の2層のうち(2)）。
    /// 書込の副産物だった属性復元が、書かない経路を作ったことで黙って落ちないように固定する。
    #[cfg(windows)]
    #[test]
    fn a_skipped_update_still_restores_the_readonly_attribute() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());
        let path = tmp.path().join("ledger.json");

        ledger.update(|l| l.entries.push("x".to_string()));
        set_file_readonly(&path, false);
        assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());

        ledger.update(|_l| {});

        assert!(
            std::fs::metadata(&path).unwrap().permissions().readonly(),
            "書かない経路でも、`-Force`無しの削除を防ぐ読取専用属性は戻す"
        );
    }

    #[test]
    fn a_ledger_without_a_resolvable_path_is_a_no_op_rather_than_an_error() {
        let ledger: Ledger<TestLedger> = Ledger {
            path: None,
            lock_name: None,
            _payload: PhantomData,
        };
        ledger.save(&TestLedger {
            entries: vec!["ignored".to_string()],
        });
        assert_eq!(ledger.load(), TestLedger::default());
        assert!(ledger.path().is_none());
    }

    /// ロック名を設定した場合も、単一プロセス内では素直に読み書きできる
    /// （名前付きmutexは再入不可ではなく所有スレッドが再取得できるため、`update`の
    /// 内側で`load_unlocked`を使う設計が正しいことの確認も兼ねる）。
    #[cfg(windows)]
    #[test]
    fn a_locked_ledger_can_still_be_updated_from_a_single_process() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(
            tmp.path().join("ledger.json"),
            Some("Local\\harness-grant-ledger-unit-test"),
        );
        ledger.update(|l| l.entries.push("x".to_string()));
        ledger.update(|l| l.entries.push("y".to_string()));
        assert_eq!(ledger.load().entries, vec!["x", "y"]);
    }

    #[test]
    fn in_config_dir_points_at_the_named_file_under_the_harness_config_dir() {
        // 登録済みの名前を使う（`in_config_dir`は未登録の名前で落ちる）。パスを組むだけで
        // ファイルには触れないので、実マシンの台帳は読み書きしない。
        let ledger: Ledger<TestLedger> = Ledger::in_config_dir("fs-passthrough-ledger.json", None);
        // `ProjectDirs`が解決できない環境（CI等）では`None`。解決できるなら末尾が一致する。
        if let Some(path) = ledger.path() {
            assert_eq!(path.file_name().unwrap(), "fs-passthrough-ledger.json");
            assert!(path.parent().unwrap().ends_with("config"));
        }
    }

    /// 保護一覧の登録漏れを機構で止める（#33）。**許可側と拒否側を対で持つ**——
    /// 拒否側だけだと、`in_config_dir`が常に落ちる実装でも合格する（`B-35`）。
    #[test]
    fn in_config_dir_accepts_every_registered_ledger() {
        for entry in CONFIG_DIR_LEDGERS {
            let ledger: Ledger<TestLedger> = Ledger::in_config_dir(entry.file_name, None);
            if let Some(path) = ledger.path() {
                assert_eq!(path.file_name().unwrap(), entry.file_name);
            }
        }
    }

    #[test]
    #[should_panic(expected = "is not registered")]
    fn in_config_dir_refuses_an_unregistered_ledger_name() {
        let _: Ledger<TestLedger> = Ledger::in_config_dir("brand-new-ledger.json", None);
    }

    /// 名前の重複は「登録したつもりで別の行を見ていた」を作る。
    #[test]
    fn config_dir_ledgers_are_unique() {
        let mut names: Vec<&str> = CONFIG_DIR_LEDGERS.iter().map(|l| l.file_name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "CONFIG_DIR_LEDGERSにファイル名の重複がある");
    }

    /// `at_path`は登録を要求しない（テストが`%APPDATA%`を汚さずに台帳を作るための注入点）。
    /// **ここが閉まっていると、上の拒否側を避ける道が無くなってテストが書けなくなる。**
    #[test]
    fn at_path_does_not_require_registration() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(tmp.path().join("whatever.json"), None);
        ledger.update(|l| l.entries.push("x".to_string()));
        assert_eq!(ledger.load().entries, vec!["x"]);
    }

    /// R-01: 名前付きロックが実際に並行`update`を直列化することの確認（`traverse-grant`・
    /// `workspace-grant`にロック名を追加する根拠）。名前付きmutexはプロセス跨ぎだが同一
    /// プロセス内のスレッド間でも機能するため、実プロセスを起動せず`std::thread`で検証できる。
    /// テスト専用のロック名を使い、実運用の台帳のロックとは衝突させない。
    #[cfg(windows)]
    #[test]
    fn a_named_lock_serializes_concurrent_updates_across_threads() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(
            tmp.path().join("ledger.json"),
            Some("Local\\harness-grant-ledger-concurrency-test"),
        );
        let thread_count = 20;
        std::thread::scope(|scope| {
            for i in 0..thread_count {
                let ledger = &ledger;
                scope.spawn(move || {
                    ledger.update(|l| l.entries.push(format!("entry-{i}")));
                });
            }
        });
        assert_eq!(ledger.load().entries.len(), thread_count);
    }

    /// ロック名`None`でも`update`を複数スレッドから呼んで壊れない（パニックしない・
    /// 台帳が読める状態を保つ）ことを確認する。`None`はAPIとして引き続きサポートするため、
    /// この経路自体は壊していないことの確認であり、ロストアップデートが起き得ることは
    /// 妨げない（件数の完全一致は主張しない）。
    #[test]
    fn update_without_a_lock_name_does_not_corrupt_the_ledger_under_concurrent_writers() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(tmp.path().join("ledger.json"), None);
        let thread_count = 20;
        std::thread::scope(|scope| {
            for i in 0..thread_count {
                let ledger = &ledger;
                scope.spawn(move || {
                    ledger.update(|l| l.entries.push(format!("entry-{i}")));
                });
            }
        });
        assert!(ledger.load().entries.len() <= thread_count);
    }

    // --- ここから3件は [BUG-146]。名前付きミューテックスの所有権がスレッドに紐づくこと、
    //     およびその帰結を固定する。**実プロセスもACLも触らないので`#[ignore]`にしない。**

    /// テスト同士がぶつからない名前を作る（同一プロセスで並行に走るため）。
    #[cfg(windows)]
    fn unique_test_lock_name(label: &str) -> String {
        format!(
            "Local\\harness-grant-ledger-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    /// **[BUG-146] `NamedLock`はスレッドを跨げない。これをコンパイラに保証させる。**
    ///
    /// 以前は`unsafe impl Send`が付いており、「取った側だけが解放する」という前提を
    /// docに**書いてあるだけ**だった。その前提は唯一の呼び出し側で破れていて、
    /// 待っている別プロセスがleaderのプロセス終了まで動き出せなくなっていた。
    /// **前提は書くだけでは守られない**ので、型で禁止したことをここで固定する。
    ///
    /// 負のトレイト境界は安定版Rustに無いので、**固有implがトレイトimplより優先して
    /// 解決される**性質を使う（`T: Send`のときだけ固有implの`true`が選ばれる）。
    /// 対で`Send`な型も見る（`B-35`）——この仕掛け自体が壊れると、何もかもが
    /// 「`Send`でない」と読めてしまい、上の判定が意味を失う。
    #[cfg(windows)]
    #[test]
    // **定数であること自体がこのテストの主張である。** `SEND`はコンパイル時に解決され、
    // どちらのimplが選ばれたかがそのまま`Send`かどうかを表す——clippyの
    // 「assertionが定数」は、ここでは指摘ではなく期待どおりの状態を指している。
    #[allow(clippy::assertions_on_constants)]
    fn the_lock_guard_cannot_move_between_threads() {
        struct IsSend<T>(PhantomData<T>);
        trait MaybeSend {
            const SEND: bool = false;
        }
        impl<T> MaybeSend for IsSend<T> {}
        impl<T: Send> IsSend<T> {
            const SEND: bool = true;
        }

        assert!(
            IsSend::<i32>::SEND,
            "この判定の仕掛けが壊れている（`Send`な型まで「`Send`でない」と出ている）"
        );
        assert!(
            !IsSend::<NamedLock>::SEND,
            "NamedLockに`Send`を付け直してはいけない。Windowsの名前付きミューテックスは \
             所有権が取得したスレッドに紐づき、別スレッドからの解放は失敗する。 \
             取ってから別スレッドで仕事をしたいなら、そのスレッド自身に取らせること（BUG-146）"
        );
    }

    /// **[BUG-146] 取ったスレッドで落とせば、待っている相手は動き出す。**
    ///
    /// 上の1件と対で見る（`B-35`）——「跨げない」だけを固定すると、**解放そのものが
    /// 壊れていても緑になる**。待ち手を実際に立ててから測るのは、誰も待っていない場合に
    /// 症状が出ないためである（`ReleaseMutex`が失敗しても`CloseHandle`は成功し、
    /// 他にハンドルが無ければオブジェクトごと消えて次の取得が成功してしまう）。
    #[cfg(windows)]
    #[test]
    fn a_waiter_is_released_when_the_guard_is_dropped_on_the_acquiring_thread() {
        use std::sync::mpsc;
        use std::time::Duration;

        let name = unique_test_lock_name("release-same-thread");
        let guard = try_acquire_named_lock(&name).expect("nobody holds it yet");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let waiter = {
            let name = name.clone();
            std::thread::spawn(move || {
                let _ = entered_tx.send(());
                with_named_lock(&name, || {
                    let _ = done_tx.send(());
                });
            })
        };
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter thread must start");
        // 待ち手が実際に待ちへ入るまでの猶予（入る前に解放すると、測りたい状況にならない）。
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "the waiter must still be blocked while the lock is held; otherwise this \
             measurement is not measuring a waiter at all"
        );

        drop(guard);

        assert!(
            done_rx.recv_timeout(Duration::from_secs(3)).is_ok(),
            "the waiter must be released as soon as the holder drops the guard on the thread \
             that acquired it"
        );
        waiter.join().expect("the waiter thread must not panic");
    }

    /// **[BUG-146] 前の持ち主が解放せずに死んだミューテックスは、引き継いで解放する。**
    ///
    /// `WAIT_ABANDONED`は「取れなかった」ではなく「所有権がこちらへ移った」である。
    /// [`with_named_lock`]はこれを失敗として扱っており、(1)排他せずにクロージャを走らせ、
    /// (2)受け取った所有権を解放しないまま閉じる、の2つを同時に起こしていた。
    ///
    /// **確認は必ず別スレッドから行う。** 名前付きミューテックスは所有者スレッドに対して
    /// 再入可能なので、同じスレッドから取り直すと**直っていない実装でも成功する**。
    #[cfg(windows)]
    #[test]
    fn a_lock_abandoned_by_a_dead_thread_is_taken_over_and_released() {
        let name = unique_test_lock_name("abandoned");

        // 所有者スレッドを立て、**解放せずに**終わらせる（＝放棄状態を作る）。
        // `forget`はハンドルも残すので、カーネルオブジェクトはこのプロセスが終わるまで
        // 生きる——全ハンドルが閉じてオブジェクトごと消えると、次の`CreateMutexW`が
        // **新品を作ってしまい**、放棄状態ではないものを測ることになる。
        {
            let name = name.clone();
            std::thread::spawn(move || {
                let guard = try_acquire_named_lock(&name).expect("nobody holds it yet");
                std::mem::forget(guard);
            })
            .join()
            .expect("the owner thread must not panic");
        }

        assert_eq!(
            with_named_lock(&name, || 42),
            42,
            "the closure must run either way; what differs is whether it ran under the lock"
        );

        let taken_by_another_thread = {
            let name = name.clone();
            std::thread::spawn(move || try_acquire_named_lock(&name).is_some())
                .join()
                .expect("the probe thread must not panic")
        };
        assert!(
            taken_by_another_thread,
            "after taking over an abandoned lock, `with_named_lock` must release it. \
             Treating WAIT_ABANDONED as a failure leaves the ownership stranded on the \
             waiting thread, and nobody else can ever take it (BUG-146)"
        );
    }

    /// **書込が途中で切れた台帳は、控えから読み直す。**
    ///
    /// 壊れた状態を一文で: **1件の記録が失われるのではなく、その台帳に載っていた全部の
    /// エントリが一斉に回収名を失う。** 書込は`std::fs::write`によるその場上書きなので、
    /// 強制終了・電源断はこの状態を作り得る（[BUG-112](../../../docs/bugs/BUG-112.md)が
    /// 1件について言っていたことの台帳丸ごと版）。
    #[test]
    fn a_ledger_cut_short_mid_write_is_recovered_from_its_backup() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = ledger_at(dir.path());
        ledger.update(|l| l.entries.push("C:/kept".to_string()));
        // 2回目の書込で`.bak`が「1回目の内容」になる（`write_ledger_file`は上書き前に複製する）。
        ledger.update(|l| l.entries.push("C:/kept-too".to_string()));
        let before = ledger.load();
        assert_eq!(before.entries.len(), 2, "precondition: both entries landed");

        // 途中で切れた書込を再現する（本体だけを壊し、控えは触らない）。
        let path = dir.path().join("ledger.json");
        set_file_readonly(&path, false);
        let truncated = {
            let full = std::fs::read_to_string(&path).unwrap();
            full[..full.len() / 2].to_string()
        };
        std::fs::write(&path, &truncated).unwrap();
        assert!(
            serde_json::from_str::<TestLedger>(&truncated).is_err(),
            "the probe must actually be unparseable, otherwise this test proves nothing"
        );

        assert_eq!(
            ledger.load().entries,
            vec!["C:/kept".to_string()],
            "a torn write must fall back to the backup instead of reporting an empty ledger"
        );
    }

    /// 対の反対側: **控えも読めないなら、従来どおり空へ倒れる**（fail-open）。
    /// ここが片側だけだと、「壊れていたら常に何かを返す」実装でも上のテストは緑になる。
    #[test]
    fn a_ledger_with_no_usable_backup_still_falls_open_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = ledger_at(dir.path());
        std::fs::write(dir.path().join("ledger.json"), "{ this is not json").unwrap();
        std::fs::write(dir.path().join("ledger.json.bak"), "nor is this").unwrap();
        assert_eq!(ledger.load(), TestLedger::default());
    }
}
