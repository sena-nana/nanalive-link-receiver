//! Windows hardware media and Spout pipeline.

mod pipeline;
mod tray;

pub use pipeline::{HardwarePipeline, PipelineTelemetry, PublishResult, PublishedFrame};
pub use tray::{TrayController, TrayState};
