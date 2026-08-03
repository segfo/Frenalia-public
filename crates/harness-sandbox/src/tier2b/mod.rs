//! Tier2b（Linux）: bubblewrap（user+mount+network namespace + OverlayFS）。
//!
//! Tier2a（Windows AppContainer）と同格の「OSレベル分離」で、プラットフォームが違うだけ。
//! `plans/DESIGN-SANDBOX.md` §6.2。**実機未検証**（この開発機はWindows専用）。

pub mod linux_bwrap;
