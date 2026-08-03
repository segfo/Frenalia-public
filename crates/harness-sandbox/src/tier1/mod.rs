//! Tier1（Windows）: 制限トークン + 低Integrity Level + Job Object。
//!
//! Tier2a（AppContainer）が使えない環境への降格先。`plans/DESIGN-SANDBOX.md` §6.3/§4.3。
//! 既知の限界（低ILは既定で中ILオブジェクトをread可＝機密性は守らない）は
//! `win_restricted`のモジュールdocに明記してある。

pub mod win_restricted;
