//! jaword-core: portable crypto, generation and access-control logic.
//! No I/O, no async, no platform code, so it can be compiled for servers,
//! desktop CLIs, WebAssembly (browser extension) and mobile bindings.
#![forbid(unsafe_code)]

pub mod access;
pub mod crypto;
pub mod generate;
