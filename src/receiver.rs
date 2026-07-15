use nanalive_link_protocol::{
    AlphaCodec, ColorCodec, ControlMessage, ControlPayload, FrameSynchronizer, MediaCapabilities,
    MediaChunkHeader, MediaConfiguration, MediaFlow, MediaReassembler, PROTOCOL_VERSION_V1,
    ProtocolError, ReassemblyOutcome, ReceiverReport, SyncOutcome, decode_a8t1,
};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

const MAX_WIDTH: u32 = 1_920;
const MAX_HEIGHT: u32 = 1_080;
const MAX_FPS: u32 = 60;
const MAX_INCOMPLETE_FRAMES: usize = 2;
const MAX_DROPPED_FRAME_TOMBSTONES: usize = 8;
const MAX_PLAYOUT_HORIZON: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    AwaitingHello,
    AwaitingConfiguration,
    Configured,
    Streaming,
    Stopped,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedFrame {
    pub generation: u16,
    pub frame_id: u32,
    pub pts_us: u64,
    pub width: u32,
    pub height: u32,
    pub h264: Vec<u8>,
    pub alpha: Vec<u8>,
    pub playout_at: Instant,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiverDiagnostics {
    pub incomplete_frames: u64,
    pub dropped_frames: u64,
    pub late_frames: u64,
    pub replaced_ready_frames: u64,
    pub completed_frames: u64,
    pub decode_failures: u64,
    pub idr_requests: u64,
    pub last_complete_color_frame: Option<u32>,
    pub last_complete_alpha_frame: Option<u32>,
    pub last_published_frame: Option<u32>,
    pub rtt_us: u32,
    pub jitter_us: u32,
    pub playout_latency_us: u32,
    pub receive_to_publish_latency_us: u32,
    pub alpha_decode_cpu_us: u32,
    pub color_decode_submit_cpu_us: u32,
    pub composite_enqueue_cpu_us: u32,
    pub spout_publish_cpu_us: u32,
    pub complete_frame_fps: u32,
    pub jitter_buffer_depth: u16,
    pub latest_frame_drops: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiverError {
    Protocol(ProtocolError),
    InvalidControl(&'static str),
    UnsupportedConfiguration,
    InconsistentAlpha,
}

impl fmt::Display for ReceiverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "protocol error: {error}"),
            Self::InvalidControl(message) => write!(formatter, "invalid control state: {message}"),
            Self::UnsupportedConfiguration => {
                formatter.write_str("unsupported media configuration")
            }
            Self::InconsistentAlpha => {
                formatter.write_str("alpha metadata does not match the synchronized color frame")
            }
        }
    }
}

impl std::error::Error for ReceiverError {}

impl From<ProtocolError> for ReceiverError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Clone, Copy, Debug)]
struct InflightFrame {
    deadline: Instant,
    insertion_order: u64,
    first_received_at: Instant,
}

pub struct ReceiverCore {
    phase: SessionPhase,
    sender_capabilities: Option<MediaCapabilities>,
    configuration: Option<MediaConfiguration>,
    reassembler: MediaReassembler,
    synchronizer: FrameSynchronizer,
    inflight_frames: BTreeMap<(u16, u32), InflightFrame>,
    dropped_frames: BTreeMap<(u16, u32), Instant>,
    next_insertion_order: u64,
    clock_anchor: Option<(u64, Instant)>,
    latest_ready: Option<PreparedFrame>,
    frame_received_at: BTreeMap<u32, Instant>,
    request_idr_pending: bool,
    diagnostics: ReceiverDiagnostics,
    adaptive: AdaptiveController,
    published_window: VecDeque<Instant>,
}

impl ReceiverCore {
    pub fn new() -> Result<Self, ReceiverError> {
        Ok(Self {
            phase: SessionPhase::AwaitingHello,
            sender_capabilities: None,
            configuration: None,
            // The receiver bound is expressed in synchronized frames. Each frame can
            // contribute one Color and one Alpha flow to the reassembler.
            reassembler: MediaReassembler::new(MAX_INCOMPLETE_FRAMES * 2)?,
            synchronizer: FrameSynchronizer::new(MAX_INCOMPLETE_FRAMES)?,
            inflight_frames: BTreeMap::new(),
            dropped_frames: BTreeMap::new(),
            next_insertion_order: 0,
            clock_anchor: None,
            latest_ready: None,
            frame_received_at: BTreeMap::new(),
            request_idr_pending: false,
            diagnostics: ReceiverDiagnostics::default(),
            adaptive: AdaptiveController::default(),
            published_window: VecDeque::new(),
        })
    }

    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn configuration(&self) -> Option<&MediaConfiguration> {
        self.configuration.as_ref()
    }

    pub const fn diagnostics(&self) -> &ReceiverDiagnostics {
        &self.diagnostics
    }

    pub fn capabilities() -> MediaCapabilities {
        MediaCapabilities {
            protocol_versions: vec![PROTOCOL_VERSION_V1],
            color_codecs: vec![ColorCodec::H264],
            alpha_codecs: vec![AlphaCodec::A8T1],
            max_width: MAX_WIDTH,
            max_height: MAX_HEIGHT,
            max_fps: MAX_FPS,
            hardware_decode: true,
            local_spout: true,
        }
    }

    pub fn handle_control(
        &mut self,
        message: ControlMessage,
    ) -> Result<Vec<ControlMessage>, ReceiverError> {
        if message.version != PROTOCOL_VERSION_V1 {
            return Err(ReceiverError::InvalidControl(
                "unsupported protocol version",
            ));
        }
        match message.payload {
            ControlPayload::Hello {
                supported_versions, ..
            } => {
                if !supported_versions.contains(&PROTOCOL_VERSION_V1) {
                    return Err(ReceiverError::InvalidControl("no common protocol version"));
                }
                self.phase = SessionPhase::AwaitingConfiguration;
                Ok(vec![ControlMessage::v1(ControlPayload::Capabilities(
                    Self::capabilities(),
                ))])
            }
            ControlPayload::Configure(configuration) => {
                self.apply_configuration(configuration, false)?;
                Ok(Vec::new())
            }
            ControlPayload::Reconfigure(configuration) => {
                self.apply_configuration(configuration, true)?;
                Ok(Vec::new())
            }
            ControlPayload::Capabilities(capabilities) => {
                if self.phase != SessionPhase::AwaitingConfiguration {
                    return Err(ReceiverError::InvalidControl(
                        "sender capabilities outside negotiation",
                    ));
                }
                capabilities.validate()?;
                if !capabilities
                    .protocol_versions
                    .contains(&PROTOCOL_VERSION_V1)
                    || !capabilities.color_codecs.contains(&ColorCodec::H264)
                    || !capabilities.alpha_codecs.contains(&AlphaCodec::A8T1)
                {
                    return Err(ReceiverError::UnsupportedConfiguration);
                }
                self.sender_capabilities = Some(capabilities);
                Ok(Vec::new())
            }
            ControlPayload::Start => {
                if self.configuration.is_none() {
                    return Err(ReceiverError::InvalidControl("start before configure"));
                }
                self.phase = SessionPhase::Streaming;
                Ok(Vec::new())
            }
            ControlPayload::Stop => {
                self.phase = SessionPhase::Stopped;
                self.reset_media_state()?;
                Ok(Vec::new())
            }
            ControlPayload::Ping { nonce, sent_at_us } => {
                Ok(vec![ControlMessage::v1(ControlPayload::Pong {
                    nonce,
                    sent_at_us,
                })])
            }
            ControlPayload::Goodbye { .. } => {
                self.phase = SessionPhase::Closed;
                self.reset_media_state()?;
                Ok(Vec::new())
            }
            ControlPayload::RequestIdr { .. }
            | ControlPayload::ReceiverReport(_)
            | ControlPayload::Pong { .. }
            | ControlPayload::Error { .. }
            | ControlPayload::Unknown { .. } => Err(ReceiverError::InvalidControl(
                "sender emitted a receiver-only or unknown control message",
            )),
        }
    }

    pub fn push_media_datagram(
        &mut self,
        datagram: &[u8],
        received_at: Instant,
    ) -> Result<(), ReceiverError> {
        if self.phase != SessionPhase::Streaming {
            return Err(ReceiverError::InvalidControl(
                "media received while not streaming",
            ));
        }
        let configuration = self
            .configuration
            .as_ref()
            .ok_or(ReceiverError::InvalidControl(
                "media received before configure",
            ))?
            .clone();
        let header = MediaChunkHeader::decode(datagram)?;
        if header.generation != configuration.generation {
            self.diagnostics.dropped_frames = self.diagnostics.dropped_frames.saturating_add(1);
            return Ok(());
        }
        let deadline = self.playout_deadline(header.pts_us, received_at, configuration.fps);
        let frame_key = (header.generation, header.frame_id);
        self.expire(received_at);
        if self.dropped_frames.contains_key(&frame_key) {
            return Ok(());
        }
        self.track_inflight_frame(frame_key, deadline, received_at);
        match self
            .reassembler
            .push_datagram(datagram, received_at, deadline)?
        {
            ReassemblyOutcome::Pending { .. } | ReassemblyOutcome::Duplicate => {}
            ReassemblyOutcome::Completed(frame) => {
                if frame.flow == MediaFlow::Color {
                    self.diagnostics.last_complete_color_frame = Some(frame.frame_id);
                } else if frame.flow == MediaFlow::Alpha {
                    self.diagnostics.last_complete_alpha_frame = Some(frame.frame_id);
                }
                if let SyncOutcome::Completed(pair) = self.synchronizer.push(frame)? {
                    let decode_started = Instant::now();
                    let alpha = decode_a8t1(&pair.alpha)?;
                    self.diagnostics.alpha_decode_cpu_us = elapsed_us(decode_started.elapsed());
                    if alpha.generation != pair.generation
                        || alpha.frame_id != pair.frame_id
                        || alpha.pts_us != pair.pts_us
                        || alpha.width != configuration.width
                        || alpha.height != configuration.height
                    {
                        return Err(ReceiverError::InconsistentAlpha);
                    }
                    let ready = PreparedFrame {
                        generation: pair.generation,
                        frame_id: pair.frame_id,
                        pts_us: pair.pts_us,
                        width: alpha.width,
                        height: alpha.height,
                        h264: pair.color,
                        alpha: alpha.alpha,
                        playout_at: deadline,
                    };
                    let first_received_at = self
                        .inflight_frames
                        .remove(&(pair.generation, pair.frame_id))
                        .map_or(received_at, |frame| frame.first_received_at);
                    self.frame_received_at
                        .insert(pair.frame_id, first_received_at);
                    while self.frame_received_at.len() > MAX_INCOMPLETE_FRAMES {
                        if let Some(oldest) = self.frame_received_at.keys().next().copied() {
                            self.frame_received_at.remove(&oldest);
                        }
                    }
                    if self.latest_ready.replace(ready).is_some() {
                        self.diagnostics.replaced_ready_frames =
                            self.diagnostics.replaced_ready_frames.saturating_add(1);
                        self.diagnostics.dropped_frames =
                            self.diagnostics.dropped_frames.saturating_add(1);
                        self.diagnostics.latest_frame_drops =
                            self.diagnostics.latest_frame_drops.saturating_add(1);
                    }
                    self.diagnostics.completed_frames =
                        self.diagnostics.completed_frames.saturating_add(1);
                    self.refresh_jitter_buffer_depth();
                }
            }
            ReassemblyOutcome::DroppedExpired => {
                self.drop_incomplete_frame(frame_key, true);
            }
            ReassemblyOutcome::DroppedOldGeneration => {
                self.diagnostics.dropped_frames = self.diagnostics.dropped_frames.saturating_add(1);
            }
        }
        self.refresh_jitter_buffer_depth();
        Ok(())
    }

    pub fn expire(&mut self, now: Instant) {
        let _ = self.reassembler.expire(now);
        let expired: Vec<_> = self
            .inflight_frames
            .iter()
            .filter_map(|(key, frame)| (frame.deadline <= now).then_some(*key))
            .collect();
        for key in expired {
            self.drop_incomplete_frame(key, true);
        }
        self.dropped_frames.retain(|_, deadline| *deadline > now);
        self.refresh_jitter_buffer_depth();
    }

    pub fn take_latest_frame(&mut self, now: Instant) -> Option<PreparedFrame> {
        if self
            .latest_ready
            .as_ref()
            .is_some_and(|frame| frame.playout_at <= now)
        {
            let frame = self.latest_ready.take();
            self.refresh_jitter_buffer_depth();
            frame
        } else {
            None
        }
    }

    pub fn ready_queue_depth(&self) -> u16 {
        u16::from(self.latest_ready.is_some())
    }

    pub fn note_decode_failure(&mut self) {
        self.diagnostics.decode_failures = self.diagnostics.decode_failures.saturating_add(1);
        self.diagnostics.dropped_frames = self.diagnostics.dropped_frames.saturating_add(1);
        self.queue_idr_request();
    }

    pub fn note_published(&mut self, frame_id: u32, published_at: Instant) {
        self.diagnostics.last_published_frame = Some(frame_id);
        if let Some(received_at) = self.frame_received_at.remove(&frame_id) {
            let latency = u32::try_from(
                published_at
                    .saturating_duration_since(received_at)
                    .as_micros(),
            )
            .unwrap_or(u32::MAX);
            self.diagnostics.playout_latency_us = latency;
            self.diagnostics.receive_to_publish_latency_us = latency;
        }
        self.published_window.push_back(published_at);
        while self.published_window.front().is_some_and(|instant| {
            published_at.saturating_duration_since(*instant) > Duration::from_secs(1)
        }) {
            self.published_window.pop_front();
        }
        self.diagnostics.complete_frame_fps =
            u32::try_from(self.published_window.len()).unwrap_or(u32::MAX);
    }

    pub fn note_spout_skipped(&mut self) {
        self.diagnostics.dropped_frames = self.diagnostics.dropped_frames.saturating_add(1);
        self.diagnostics.latest_frame_drops = self.diagnostics.latest_frame_drops.saturating_add(1);
    }

    pub fn update_pipeline_diagnostics(
        &mut self,
        color_decode_submit_cpu_us: u32,
        composite_enqueue_cpu_us: u32,
        spout_publish_cpu_us: u32,
    ) {
        self.diagnostics.color_decode_submit_cpu_us = color_decode_submit_cpu_us;
        self.diagnostics.composite_enqueue_cpu_us = composite_enqueue_cpu_us;
        self.diagnostics.spout_publish_cpu_us = spout_publish_cpu_us;
    }

    pub fn update_network_diagnostics(
        &mut self,
        rtt_us: u64,
        jitter_us: u64,
        estimated_send_rate_bps: Option<u64>,
    ) {
        self.diagnostics.rtt_us = u32::try_from(rtt_us).unwrap_or(u32::MAX);
        self.diagnostics.jitter_us = u32::try_from(jitter_us).unwrap_or(u32::MAX);
        self.adaptive.observe(
            self.diagnostics.incomplete_frames,
            self.diagnostics.rtt_us,
            estimated_send_rate_bps,
        );
    }

    pub fn take_idr_request(&mut self) -> Option<ControlMessage> {
        if !self.request_idr_pending {
            return None;
        }
        self.request_idr_pending = false;
        self.configuration.as_ref().map(|configuration| {
            ControlMessage::v1(ControlPayload::RequestIdr {
                generation: configuration.generation,
            })
        })
    }

    pub fn receiver_report(
        &mut self,
        decode_queue_depth: u16,
        hardware_decode_active: bool,
    ) -> ControlMessage {
        let now = Instant::now();
        while self
            .published_window
            .front()
            .is_some_and(|instant| now.saturating_duration_since(*instant) > Duration::from_secs(1))
        {
            self.published_window.pop_front();
        }
        self.diagnostics.complete_frame_fps =
            u32::try_from(self.published_window.len()).unwrap_or(u32::MAX);
        let configuration = self.configuration.as_ref();
        ControlMessage::v1(ControlPayload::ReceiverReport(ReceiverReport {
            generation: configuration.map_or(0, |value| value.generation),
            last_complete_color_frame: self.diagnostics.last_complete_color_frame,
            last_complete_alpha_frame: self.diagnostics.last_complete_alpha_frame,
            incomplete_frames: self.diagnostics.incomplete_frames,
            dropped_frames: self.diagnostics.dropped_frames,
            decode_queue_depth,
            playout_latency_us: self.diagnostics.playout_latency_us,
            rtt_us: self.diagnostics.rtt_us,
            jitter_us: self.diagnostics.jitter_us,
            hardware_decode_active,
            requested_bitrate_bps: self.adaptive.requested_bitrate_bps,
            requested_fps: self.adaptive.requested_fps,
            requested_alpha_codec: AlphaCodec::A8T1,
        }))
    }

    pub fn reset_for_reconnect(&mut self) -> Result<(), ReceiverError> {
        self.phase = SessionPhase::AwaitingHello;
        self.sender_capabilities = None;
        self.configuration = None;
        self.adaptive = AdaptiveController::default();
        self.reset_media_state()
    }

    fn apply_configuration(
        &mut self,
        configuration: MediaConfiguration,
        reconfigure: bool,
    ) -> Result<(), ReceiverError> {
        configuration.validate_v1()?;
        let sender = self
            .sender_capabilities
            .as_ref()
            .ok_or(ReceiverError::InvalidControl(
                "configure before sender capabilities",
            ))?;
        if configuration.width > MAX_WIDTH
            || configuration.height > MAX_HEIGHT
            || configuration.fps > MAX_FPS
            || configuration.width > sender.max_width
            || configuration.height > sender.max_height
            || configuration.fps > sender.max_fps
        {
            return Err(ReceiverError::UnsupportedConfiguration);
        }
        if reconfigure {
            self.adaptive
                .reconfigure(&configuration, self.diagnostics.incomplete_frames);
        } else {
            self.adaptive =
                AdaptiveController::new(&configuration, self.diagnostics.incomplete_frames);
        }
        self.configuration = Some(configuration);
        self.phase = SessionPhase::Configured;
        self.reset_media_state()
    }

    fn reset_media_state(&mut self) -> Result<(), ReceiverError> {
        self.reassembler = MediaReassembler::new(MAX_INCOMPLETE_FRAMES * 2)?;
        self.synchronizer = FrameSynchronizer::new(MAX_INCOMPLETE_FRAMES)?;
        self.inflight_frames.clear();
        self.dropped_frames.clear();
        self.clock_anchor = None;
        self.latest_ready = None;
        self.frame_received_at.clear();
        self.request_idr_pending = false;
        self.published_window.clear();
        self.refresh_jitter_buffer_depth();
        Ok(())
    }

    fn playout_deadline(&mut self, pts_us: u64, received_at: Instant, fps: u32) -> Instant {
        let frame_delay = Duration::from_micros(1_000_000 / u64::from(fps.max(1)));
        let Some((anchor_pts, anchor_time)) = self.clock_anchor else {
            self.clock_anchor = Some((pts_us, received_at));
            return received_at.checked_add(frame_delay).unwrap_or(received_at);
        };
        let Some(offset_us) = pts_us.checked_sub(anchor_pts) else {
            self.clock_anchor = Some((pts_us, received_at));
            return received_at.checked_add(frame_delay).unwrap_or(received_at);
        };
        let media_offset = Duration::from_micros(offset_us);
        if media_offset > MAX_PLAYOUT_HORIZON {
            self.clock_anchor = Some((pts_us, received_at));
            return received_at.checked_add(frame_delay).unwrap_or(received_at);
        }
        anchor_time
            .checked_add(media_offset)
            .and_then(|instant| instant.checked_add(frame_delay))
            .unwrap_or_else(|| received_at.checked_add(frame_delay).unwrap_or(received_at))
    }

    fn track_inflight_frame(&mut self, key: (u16, u32), deadline: Instant, received_at: Instant) {
        if let Some(frame) = self.inflight_frames.get_mut(&key) {
            frame.deadline = frame.deadline.min(deadline);
            return;
        }
        while self.inflight_frames.len() >= MAX_INCOMPLETE_FRAMES {
            let oldest = self
                .inflight_frames
                .iter()
                .min_by_key(|(_, frame)| frame.insertion_order)
                .map(|(key, _)| *key)
                .expect("bounded inflight frame map is non-empty");
            self.drop_incomplete_frame(oldest, false);
        }
        let insertion_order = self.next_insertion_order;
        self.next_insertion_order = self.next_insertion_order.wrapping_add(1);
        self.inflight_frames.insert(
            key,
            InflightFrame {
                deadline,
                insertion_order,
                first_received_at: received_at,
            },
        );
        self.refresh_jitter_buffer_depth();
    }

    fn drop_incomplete_frame(&mut self, key: (u16, u32), late: bool) {
        let Some(frame) = self.inflight_frames.remove(&key) else {
            return;
        };
        self.diagnostics.incomplete_frames = self.diagnostics.incomplete_frames.saturating_add(1);
        self.diagnostics.dropped_frames = self.diagnostics.dropped_frames.saturating_add(1);
        if late {
            self.diagnostics.late_frames = self.diagnostics.late_frames.saturating_add(1);
        }
        self.queue_idr_request();
        self.dropped_frames.insert(
            key,
            frame
                .deadline
                .checked_add(MAX_PLAYOUT_HORIZON)
                .unwrap_or(frame.deadline),
        );
        while self.dropped_frames.len() > MAX_DROPPED_FRAME_TOMBSTONES {
            let oldest = *self
                .dropped_frames
                .keys()
                .next()
                .expect("non-empty dropped frame map");
            self.dropped_frames.remove(&oldest);
        }
        self.refresh_jitter_buffer_depth();
    }

    fn refresh_jitter_buffer_depth(&mut self) {
        let depth = self
            .inflight_frames
            .len()
            .saturating_add(usize::from(self.latest_ready.is_some()));
        self.diagnostics.jitter_buffer_depth = u16::try_from(depth).unwrap_or(u16::MAX);
    }

    fn queue_idr_request(&mut self) {
        if !self.request_idr_pending {
            self.diagnostics.idr_requests = self.diagnostics.idr_requests.saturating_add(1);
            self.request_idr_pending = true;
        }
    }
}

fn elapsed_us(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

#[derive(Default)]
struct AdaptiveController {
    nominal_bitrate_bps: u32,
    nominal_fps: u32,
    requested_bitrate_bps: u32,
    requested_fps: u32,
    previous_incomplete: u64,
    healthy_intervals: u8,
}

impl AdaptiveController {
    fn new(configuration: &MediaConfiguration, previous_incomplete: u64) -> Self {
        Self {
            nominal_bitrate_bps: configuration.target_bitrate_bps,
            nominal_fps: configuration.fps,
            requested_bitrate_bps: configuration.target_bitrate_bps,
            requested_fps: configuration.fps,
            previous_incomplete,
            ..Self::default()
        }
    }

    fn reconfigure(&mut self, configuration: &MediaConfiguration, previous_incomplete: u64) {
        self.nominal_bitrate_bps = self
            .nominal_bitrate_bps
            .max(configuration.target_bitrate_bps);
        self.nominal_fps = self.nominal_fps.max(configuration.fps);
        self.requested_bitrate_bps = configuration.target_bitrate_bps;
        self.requested_fps = configuration.fps;
        self.previous_incomplete = previous_incomplete;
        self.healthy_intervals = 0;
    }

    fn observe(&mut self, incomplete: u64, rtt_us: u32, estimated_send_rate_bps: Option<u64>) {
        if self.nominal_bitrate_bps == 0 {
            return;
        }
        // `dropped_frames` also includes intentional latest-only replacement,
        // old-generation datagrams after reconfiguration and local publish
        // skips. Only incomplete media assembly is a network-loss signal.
        let loss = incomplete > self.previous_incomplete;
        self.previous_incomplete = incomplete;
        let constrained_rate = estimated_send_rate_bps
            .filter(|rate| *rate > 0)
            .filter(|rate| *rate < u64::from(self.requested_bitrate_bps));
        let unhealthy = loss || rtt_us > 150_000 || constrained_rate.is_some();
        if unhealthy {
            self.healthy_intervals = 0;
            let floor = 1_000_000.min(self.nominal_bitrate_bps);
            let rate_target = constrained_rate
                .map(|rate| rate.saturating_mul(80) / 100)
                .and_then(|rate| u32::try_from(rate).ok())
                .unwrap_or_else(|| self.requested_bitrate_bps.saturating_mul(80) / 100)
                .max(floor);
            if rate_target < self.requested_bitrate_bps {
                self.requested_bitrate_bps = rate_target;
            } else if loss || rtt_us > 150_000 {
                self.requested_fps = lower_fps(self.requested_fps);
            }
            return;
        }

        self.healthy_intervals = self.healthy_intervals.saturating_add(1);
        if self.healthy_intervals < 5 {
            return;
        }
        self.healthy_intervals = 0;
        if self.requested_bitrate_bps < self.nominal_bitrate_bps {
            let step = (self.nominal_bitrate_bps / 10).max(1);
            self.requested_bitrate_bps = self
                .requested_bitrate_bps
                .saturating_add(step)
                .min(self.nominal_bitrate_bps);
        } else if self.requested_fps < self.nominal_fps {
            self.requested_fps = (self.requested_fps + 6).min(self.nominal_fps);
        }
    }
}

fn lower_fps(fps: u32) -> u32 {
    match fps {
        31.. => 30,
        25..=30 => 24,
        _ => fps.max(15),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanalive_link_protocol::{
        AlphaFrame, MEDIA_VERSION_V1, MediaFlags, encode_a8t1, fragment_media_frame,
    };

    fn configure(core: &mut ReceiverCore, generation: u16) {
        core.handle_control(ControlMessage::v1(ControlPayload::Hello {
            endpoint_nonce: [1; 16],
            supported_versions: vec![PROTOCOL_VERSION_V1],
        }))
        .unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Capabilities(
            MediaCapabilities {
                protocol_versions: vec![PROTOCOL_VERSION_V1],
                color_codecs: vec![ColorCodec::H264],
                alpha_codecs: vec![AlphaCodec::A8T1],
                max_width: MAX_WIDTH,
                max_height: MAX_HEIGHT,
                max_fps: MAX_FPS,
                hardware_decode: false,
                local_spout: false,
            },
        )))
        .unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Configure(
            MediaConfiguration {
                generation,
                width: 2,
                height: 2,
                fps: 60,
                color_codec: ColorCodec::H264,
                alpha_codec: AlphaCodec::A8T1,
                target_bitrate_bps: 1_000_000,
                max_bitrate_bps: 2_000_000,
            },
        )))
        .unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Start))
            .unwrap();
    }

    fn frame_datagrams(
        generation: u16,
        frame_id: u32,
        pts_us: u64,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let color = fragment_media_frame(
            MediaFlow::Color,
            MediaFlags::KEYFRAME,
            generation,
            frame_id,
            pts_us,
            b"h264-access-unit",
            28,
        )
        .unwrap();
        let alpha = encode_a8t1(&AlphaFrame {
            generation,
            frame_id,
            pts_us,
            width: 2,
            height: 2,
            alpha: vec![0, 64, 128, 255],
        })
        .unwrap();
        let alpha = fragment_media_frame(
            MediaFlow::Alpha,
            MediaFlags::empty(),
            generation,
            frame_id,
            pts_us,
            &alpha,
            32,
        )
        .unwrap();
        (color, alpha)
    }

    #[test]
    fn negotiates_and_reassembles_out_of_order_color_alpha_pair() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 7);
        let now = Instant::now();
        let (mut color, mut alpha) = frame_datagrams(7, 5, 1_000);
        color.reverse();
        alpha.reverse();
        for datagram in color.into_iter().chain(alpha) {
            core.push_media_datagram(&datagram, now).unwrap();
        }
        let frame = core
            .take_latest_frame(now + Duration::from_millis(20))
            .unwrap();
        assert_eq!(frame.h264, b"h264-access-unit");
        assert_eq!(frame.alpha, vec![0, 64, 128, 255]);
        assert_eq!(core.diagnostics().completed_frames, 1);
    }

    #[test]
    fn latest_complete_pair_replaces_undecoded_older_pair() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 1);
        let now = Instant::now();
        for id in [1, 2] {
            let (color, alpha) = frame_datagrams(1, id, u64::from(id) * 16_667);
            for datagram in color.into_iter().chain(alpha) {
                core.push_media_datagram(&datagram, now).unwrap();
            }
        }
        assert_eq!(
            core.take_latest_frame(now + Duration::from_millis(40))
                .unwrap()
                .frame_id,
            2
        );
        assert_eq!(core.diagnostics().replaced_ready_frames, 1);
    }

    #[test]
    fn queue_depth_query_does_not_consume_ready_frame() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 1);
        let now = Instant::now();
        let (color, alpha) = frame_datagrams(1, 3, 0);
        for datagram in color.into_iter().chain(alpha) {
            core.push_media_datagram(&datagram, now).unwrap();
        }
        assert_eq!(core.ready_queue_depth(), 1);
        assert_eq!(core.ready_queue_depth(), 1);
        assert_eq!(
            core.take_latest_frame(now + Duration::from_millis(20))
                .unwrap()
                .frame_id,
            3
        );
    }

    #[test]
    fn mutsuki_protocol_bound_control_stream_round_trips_negotiation() {
        use mutsuki_link::{
            Connection, EndpointId, MemoryTransportConfig, ProtocolId, memory_transport_pair,
        };

        let endpoint = |value| EndpointId::from_bytes([value; 16]);
        let (mut sender, mut receiver) =
            memory_transport_pair(endpoint(1), endpoint(2), MemoryTransportConfig::default());
        let protocol = ProtocolId::new("nanalive.link.media").unwrap();
        let hello = ControlMessage::v1(ControlPayload::Hello {
            endpoint_nonce: [1; 16],
            supported_versions: vec![PROTOCOL_VERSION_V1],
        });
        sender
            .open_control_stream(protocol.clone())
            .unwrap()
            .try_send(&hello.encode().unwrap())
            .unwrap();
        let encoded = receiver
            .open_control_stream(protocol.clone())
            .unwrap()
            .try_receive()
            .unwrap()
            .unwrap();
        let mut core = ReceiverCore::new().unwrap();
        let response = core
            .handle_control(ControlMessage::decode(&encoded).unwrap())
            .unwrap()
            .remove(0);
        receiver
            .open_control_stream(protocol.clone())
            .unwrap()
            .try_send(&response.encode().unwrap())
            .unwrap();
        let encoded = sender
            .open_control_stream(protocol.clone())
            .unwrap()
            .try_receive()
            .unwrap()
            .unwrap();
        assert!(matches!(
            ControlMessage::decode(&encoded).unwrap().payload,
            ControlPayload::Capabilities(_)
        ));
        for message in [
            ControlMessage::v1(ControlPayload::Capabilities(MediaCapabilities {
                protocol_versions: vec![PROTOCOL_VERSION_V1],
                color_codecs: vec![ColorCodec::H264],
                alpha_codecs: vec![AlphaCodec::A8T1],
                max_width: 1_920,
                max_height: 1_080,
                max_fps: 60,
                hardware_decode: false,
                local_spout: false,
            })),
            ControlMessage::v1(ControlPayload::Configure(MediaConfiguration {
                generation: 1,
                width: 1_920,
                height: 1_080,
                fps: 60,
                color_codec: ColorCodec::H264,
                alpha_codec: AlphaCodec::A8T1,
                target_bitrate_bps: 10_000_000,
                max_bitrate_bps: 20_000_000,
            })),
            ControlMessage::v1(ControlPayload::Start),
        ] {
            sender
                .open_control_stream(protocol.clone())
                .unwrap()
                .try_send(&message.encode().unwrap())
                .unwrap();
            let encoded = receiver
                .open_control_stream(protocol.clone())
                .unwrap()
                .try_receive()
                .unwrap()
                .unwrap();
            core.handle_control(ControlMessage::decode(&encoded).unwrap())
                .unwrap();
        }
        assert_eq!(core.phase(), SessionPhase::Streaming);
    }

    #[test]
    fn expired_p_frame_requests_one_idr_for_current_generation() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 9);
        let now = Instant::now();
        let datagram = fragment_media_frame(
            MediaFlow::Color,
            MediaFlags::empty(),
            9,
            10,
            0,
            &[1; 20],
            30,
        )
        .unwrap()
        .remove(0);
        core.push_media_datagram(&datagram, now).unwrap();
        core.expire(now + Duration::from_millis(20));
        let request = core.take_idr_request().unwrap();
        assert_eq!(
            request.payload,
            ControlPayload::RequestIdr { generation: 9 }
        );
        assert!(core.take_idr_request().is_none());
    }

    #[test]
    fn complete_color_without_alpha_expires_pair_and_requests_idr() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 9);
        let now = Instant::now();
        let (color, _) = frame_datagrams(9, 10, 0);
        for datagram in color {
            core.push_media_datagram(&datagram, now).unwrap();
        }
        assert_eq!(core.synchronizer.pending_frames(), 1);
        assert_eq!(core.diagnostics().jitter_buffer_depth, 1);
        core.expire(now + Duration::from_millis(20));
        assert_eq!(core.diagnostics().incomplete_frames, 1);
        assert_eq!(core.diagnostics().jitter_buffer_depth, 0);
        assert!(matches!(
            core.take_idr_request().unwrap().payload,
            ControlPayload::RequestIdr { generation: 9 }
        ));
    }

    #[test]
    fn complete_alpha_without_color_is_bounded_and_requests_idr() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 3);
        let now = Instant::now();
        let (_, alpha) = frame_datagrams(3, 4, 0);
        for datagram in alpha {
            core.push_media_datagram(&datagram, now).unwrap();
        }
        core.expire(now + Duration::from_millis(20));
        assert_eq!(core.diagnostics().incomplete_frames, 1);
        assert!(core.take_idr_request().is_some());
        assert!(core.inflight_frames.is_empty());
    }

    #[test]
    fn extreme_pts_reanchors_without_panicking_or_extending_frame_state() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 1);
        let now = Instant::now();
        for (frame_id, pts_us) in [(1, 0), (2, u64::MAX)] {
            let datagram = fragment_media_frame(
                MediaFlow::Color,
                MediaFlags::empty(),
                1,
                frame_id,
                pts_us,
                &[1; 20],
                30,
            )
            .unwrap()
            .remove(0);
            core.push_media_datagram(&datagram, now).unwrap();
        }
        assert!(core.inflight_frames.len() <= MAX_INCOMPLETE_FRAMES);
        assert!(
            core.inflight_frames
                .values()
                .all(|frame| frame.deadline <= now + MAX_PLAYOUT_HORIZON)
        );
    }

    #[test]
    fn sustained_distinct_incomplete_frames_keep_all_receiver_state_bounded() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 1);
        let now = Instant::now();
        for frame_id in 0..100 {
            let datagram = fragment_media_frame(
                MediaFlow::Color,
                MediaFlags::empty(),
                1,
                frame_id,
                u64::from(frame_id) * 1_000,
                &[1; 100],
                30,
            )
            .unwrap()
            .remove(0);
            core.push_media_datagram(&datagram, now).unwrap();
            assert!(core.inflight_frames.len() <= MAX_INCOMPLETE_FRAMES);
            assert!(core.reassembler.pending_frames() <= MAX_INCOMPLETE_FRAMES * 2);
            assert!(core.synchronizer.pending_frames() <= MAX_INCOMPLETE_FRAMES);
            assert!(core.dropped_frames.len() <= MAX_DROPPED_FRAME_TOMBSTONES);
            assert!(usize::from(core.diagnostics().jitter_buffer_depth) <= MAX_INCOMPLETE_FRAMES);
        }
        assert!(core.take_idr_request().is_some());
    }

    #[test]
    fn reconfigure_discards_old_generation_and_resets_latest_queue() {
        let mut core = ReceiverCore::new().unwrap();
        configure(&mut core, 1);
        let (color, alpha) = frame_datagrams(1, 1, 0);
        for datagram in color.into_iter().chain(alpha) {
            core.push_media_datagram(&datagram, Instant::now()).unwrap();
        }
        let mut next = core.configuration().unwrap().clone();
        next.generation = 2;
        core.handle_control(ControlMessage::v1(ControlPayload::Reconfigure(next)))
            .unwrap();
        assert!(
            core.take_latest_frame(Instant::now() + Duration::from_secs(1))
                .is_none()
        );
        assert_eq!(core.phase(), SessionPhase::Configured);
    }

    #[test]
    fn ping_and_report_are_real_protocol_messages() {
        let mut core = ReceiverCore::new().unwrap();
        let pong = core
            .handle_control(ControlMessage::v1(ControlPayload::Ping {
                nonce: 4,
                sent_at_us: 8,
            }))
            .unwrap();
        assert_eq!(
            pong[0].payload,
            ControlPayload::Pong {
                nonce: 4,
                sent_at_us: 8
            }
        );
        configure(&mut core, 1);
        let received_at = Instant::now();
        let (color, alpha) = frame_datagrams(1, 9, 0);
        for datagram in color.into_iter().chain(alpha) {
            core.push_media_datagram(&datagram, received_at).unwrap();
        }
        let frame = core
            .take_latest_frame(received_at + Duration::from_millis(20))
            .unwrap();
        core.note_published(frame.frame_id, received_at + Duration::from_millis(20));
        core.update_network_diagnostics(500, 20, Some(2_000_000));
        let report = core.receiver_report(1, false);
        let ControlPayload::ReceiverReport(report) = report.payload else {
            panic!("receiver report expected")
        };
        assert_eq!(report.rtt_us, 500);
        assert_eq!(report.playout_latency_us, 20_000);
        assert!(!report.hardware_decode_active);
    }

    #[test]
    fn adaptive_report_lowers_bitrate_before_fps_and_recovers_with_debounce() {
        let mut core = ReceiverCore::new().unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Hello {
            endpoint_nonce: [1; 16],
            supported_versions: vec![PROTOCOL_VERSION_V1],
        }))
        .unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Capabilities(
            MediaCapabilities {
                protocol_versions: vec![PROTOCOL_VERSION_V1],
                color_codecs: vec![ColorCodec::H264],
                alpha_codecs: vec![AlphaCodec::A8T1],
                max_width: MAX_WIDTH,
                max_height: MAX_HEIGHT,
                max_fps: MAX_FPS,
                hardware_decode: false,
                local_spout: false,
            },
        )))
        .unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Configure(
            MediaConfiguration {
                generation: 1,
                width: 1_920,
                height: 1_080,
                fps: 60,
                color_codec: ColorCodec::H264,
                alpha_codec: AlphaCodec::A8T1,
                target_bitrate_bps: 100_000_000,
                max_bitrate_bps: 100_000_000,
            },
        )))
        .unwrap();
        core.update_network_diagnostics(20_000, 100, Some(10_000_000));
        let ControlPayload::ReceiverReport(constrained) = core.receiver_report(0, true).payload
        else {
            panic!("receiver report expected")
        };
        assert_eq!(constrained.requested_bitrate_bps, 8_000_000);
        assert_eq!(constrained.requested_fps, 60);

        let mut adaptive_configuration = core.configuration().unwrap().clone();
        adaptive_configuration.generation = 2;
        adaptive_configuration.target_bitrate_bps = constrained.requested_bitrate_bps;
        core.handle_control(ControlMessage::v1(ControlPayload::Reconfigure(
            adaptive_configuration,
        )))
        .unwrap();
        core.handle_control(ControlMessage::v1(ControlPayload::Start))
            .unwrap();
        assert_eq!(core.phase(), SessionPhase::Streaming);
        let stale = fragment_media_frame(
            MediaFlow::Color,
            MediaFlags::empty(),
            1,
            99,
            0,
            b"old-generation",
            64,
        )
        .unwrap()
        .remove(0);
        core.push_media_datagram(&stale, Instant::now()).unwrap();
        assert!(core.diagnostics().dropped_frames > 0);

        for _ in 0..4 {
            core.update_network_diagnostics(20_000, 100, Some(200_000_000));
        }
        let ControlPayload::ReceiverReport(debounced) = core.receiver_report(0, true).payload
        else {
            panic!("receiver report expected")
        };
        assert_eq!(debounced.requested_bitrate_bps, 8_000_000);
        core.update_network_diagnostics(20_000, 100, Some(200_000_000));
        let ControlPayload::ReceiverReport(recovering) = core.receiver_report(0, true).payload
        else {
            panic!("receiver report expected")
        };
        assert_eq!(recovering.requested_bitrate_bps, 18_000_000);
        assert_eq!(recovering.requested_alpha_codec, AlphaCodec::A8T1);
    }

    #[test]
    fn media_header_decode_remains_protocol_owned() {
        let header = MediaChunkHeader {
            version: MEDIA_VERSION_V1,
            flow: MediaFlow::Color,
            flags: MediaFlags::END,
            generation: 1,
            frame_id: 2,
            pts_us: 3,
            chunk_index: 0,
            chunk_count: 1,
        };
        assert_eq!(
            MediaChunkHeader::decode(&header.encode().unwrap()).unwrap(),
            header
        );
    }
}
