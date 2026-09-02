//! The types a `malicious` verdict may name: code built to harm, where
//! intent is what separates it from a bug. Every type in this directory
//! answers `"malicious"` from `verdict`.

mod obfuscation;

pub(crate) use obfuscation::Obfuscation;
