//! NanaLive Link receiver state machine and platform integration.

#[cfg(any(windows, test))]
mod frame_matcher;
pub mod pairing;
pub mod receiver;

#[cfg(test)]
mod compositor_contract;

#[cfg(windows)]
pub mod windows;
