use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    /// UDP address for the MutsukiLink QUIC listener.
    #[arg(long, default_value = "0.0.0.0:59631")]
    listen: SocketAddr,
    /// SHA-256 peer identity derived from the receiver Ed25519 certificate key.
    #[arg(long)]
    receiver_peer_id: Option<String>,
    /// Receiver name shown during bilateral pairing confirmation.
    #[arg(long, default_value = "NanaLive Link Receiver")]
    receiver_name: String,
    /// DNS name covered by the receiver certificate.
    #[arg(long, default_value = "nanalive-receiver.local")]
    server_name: String,
    /// Reachable QUIC socket address placed in a newly generated invitation.
    #[arg(long)]
    advertised_address: Option<String>,
    /// TLS certificate in DER form. The sender must trust this certificate.
    #[arg(long)]
    certificate_der: Option<PathBuf>,
    /// PKCS#8 TLS private key in DER form.
    #[arg(long)]
    private_key_der: Option<PathBuf>,
    /// Directory containing the generated identity, trust store, and receiver profile.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// File containing the receiver invitation previously presented to NanaLive.
    #[arg(long)]
    pairing_invitation: Option<PathBuf>,
    /// File containing the pairing exchange produced by NanaLive.
    #[arg(long)]
    pairing_exchange: Option<PathBuf>,
    /// Complete pairing after the receiver preview code was compared on both devices.
    #[arg(long)]
    confirm_pairing: bool,
    /// Optional file where a newly generated invitation is written.
    #[arg(long)]
    invitation_output: Option<PathBuf>,
    /// Persistent Mutsuki trust store for paired senders.
    #[arg(long)]
    trust_store: Option<PathBuf>,
    /// Lifetime of a generated pairing invitation.
    #[arg(long, default_value_t = 600)]
    pairing_invitation_ttl_seconds: u64,
    /// Spout sender name visible to local consumers such as OBS.
    #[arg(long, default_value = "NanaLive Link")]
    spout_name: String,
    /// Disable local mDNS advertisement of this receiver.
    #[arg(long)]
    no_mdns: bool,
}

#[cfg(not(windows))]
fn main() {
    let _ = Arguments::parse();
    eprintln!(
        "nanalive-link-receiver requires Windows 10 or later with D3D11, Media Foundation hardware H.264 decoding, and Spout 2"
    );
    std::process::exit(1);
}

#[cfg(windows)]
// Media Foundation, the D3D11 immediate context, and the balanced COM
// initialization owned by HardwarePipeline must remain on the thread that
// created them across every async suspension point.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    windows_main::run(Arguments::parse()).await
}

#[cfg(windows)]
mod windows_main {
    use super::Arguments;
    use anyhow::{Context, Result, anyhow, bail};
    use mutsuki_link::discovery::RateLimit;
    use mutsuki_link::discovery::mdns::MdnsDiscovery;
    use mutsuki_link::quic::{QuicConnection, QuicListener, QuicOptions};
    use mutsuki_link::{
        Connection, ProtocolId, RealtimeFlowId, ReceivedRealtimeDatagram, TransportErrorKind,
    };
    use nanalive_link_protocol::{ControlMessage, MediaChunkHeader, MediaFlow};
    use nanalive_link_receiver::pairing::{
        ReceiverIdentity, complete_or_load_pairing, create_invitation, default_windows_state_dir,
        mutual_tls_server_config, paired_sender_if_present, preview_pairing,
    };
    use nanalive_link_receiver::receiver::{ReceiverCore, SessionPhase};
    use nanalive_link_receiver::windows::{
        HardwarePipeline, PublishResult, TrayController, TrayState,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const COLOR_FLOW: RealtimeFlowId = RealtimeFlowId(1);
    const ALPHA_FLOW: RealtimeFlowId = RealtimeFlowId(2);
    const REPORT_INTERVAL: Duration = Duration::from_secs(1);
    const POLL_INTERVAL: Duration = Duration::from_millis(1);

    pub async fn run(arguments: Arguments) -> Result<()> {
        let state_dir = arguments.state_dir.clone().map_or_else(
            || default_windows_state_dir(std::env::var_os("LOCALAPPDATA").as_deref()),
            Ok,
        )?;
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create {}", state_dir.display()))?;
        let trust_store = arguments
            .trust_store
            .clone()
            .unwrap_or_else(|| state_dir.join("sender-trust.json"));
        let identity = match (
            arguments.certificate_der.as_ref(),
            arguments.private_key_der.as_ref(),
            arguments.receiver_peer_id.as_deref(),
        ) {
            (Some(certificate_path), Some(private_key_path), Some(peer_id)) => {
                let certificate = std::fs::read(certificate_path)
                    .with_context(|| format!("read {}", certificate_path.display()))?;
                let private_key = std::fs::read(private_key_path)
                    .with_context(|| format!("read {}", private_key_path.display()))?;
                ReceiverIdentity::load(certificate, private_key, peer_id, &arguments.server_name)?
            }
            (None, None, None) => ReceiverIdentity::load_or_create(
                &state_dir.join("receiver-identity.json"),
                &arguments.server_name,
            )?,
            _ => bail!(
                "--certificate-der, --private-key-der, and --receiver-peer-id must be supplied together"
            ),
        };
        let certificate = identity.certificate_der().to_vec();
        let private_key = identity.private_key_der().to_vec();
        let exchange = arguments
            .pairing_exchange
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
            })
            .transpose()?;
        let pairing = if let Some(exchange) = exchange.as_deref() {
            let invitation_path = arguments
                .pairing_invitation
                .as_ref()
                .context("--pairing-invitation is required with --pairing-exchange")?;
            let invitation = std::fs::read_to_string(invitation_path)
                .with_context(|| format!("read {}", invitation_path.display()))?;
            if !arguments.confirm_pairing {
                let preview = preview_pairing(
                    &identity,
                    &arguments.receiver_name,
                    &invitation,
                    exchange,
                    &trust_store,
                )?;
                println!("{}", serde_json::to_string(&preview)?);
                return Ok(());
            }
            complete_or_load_pairing(
                &identity,
                &arguments.receiver_name,
                Some(&invitation),
                exchange,
                &trust_store,
            )?
        } else if let Some(pairing) = paired_sender_if_present(&trust_store)? {
            pairing
        } else {
            let advertised_address = arguments
                .advertised_address
                .as_deref()
                .context("--advertised-address is required when generating an invitation")?;
            let advertised_socket: SocketAddr = advertised_address
                .parse()
                .context("--advertised-address must be a reachable socket address")?;
            if advertised_socket.port() != arguments.listen.port() {
                bail!("--advertised-address and --listen must use the same UDP port");
            }
            let invitation = create_invitation(
                &identity,
                &arguments.receiver_name,
                advertised_address,
                &arguments.server_name,
                arguments.pairing_invitation_ttl_seconds,
            )?;
            if let Some(path) = arguments.invitation_output.as_ref() {
                std::fs::write(path, invitation.as_bytes())
                    .with_context(|| format!("write {}", path.display()))?;
            }
            println!("{invitation}");
            run_pairing_advertisement(&arguments).await?;
            return Ok(());
        };
        if let Some(confirmation) = pairing.receiver_confirmation_json.as_deref() {
            println!("{confirmation}");
        }
        let server_config =
            mutual_tls_server_config(certificate, private_key, pairing.sender_certificate_der)?;
        let local_endpoint = identity.endpoint_id();
        let sender_endpoint = pairing.sender_endpoint_id;
        let listener = QuicListener::bind(
            arguments.listen,
            local_endpoint,
            server_config,
            QuicOptions::default(),
        )
        .context("bind MutsukiLink QUIC listener")?;
        eprintln!(
            "NanaLive Link receiver listening on {} (Spout sender: {})",
            listener.local_addr()?,
            arguments.spout_name
        );
        let discovery = if arguments.no_mdns {
            None
        } else {
            let discovery = MdnsDiscovery::new(
                Duration::from_secs(30),
                RateLimit {
                    attempts: 4,
                    window: Duration::from_secs(1),
                    max_sources: 16,
                    max_candidates: 32,
                },
            )?;
            let instance = ephemeral_discovery_name()?;
            let host = format!("{instance}.local.");
            discovery.advertise(
                "_nanalive-link._udp.local.",
                &instance,
                &host,
                listener.local_addr()?.port(),
                1,
                "quic",
            )?;
            eprintln!("advertising _nanalive-link._udp.local. via mDNS");
            Some(discovery)
        };

        let shutdown = Arc::new(AtomicBool::new(false));
        let tray = TrayController::start(Arc::clone(&shutdown))?;
        tray.set_state(TrayState::Listening(listener.local_addr()?.to_string()));
        let signal = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            signal.store(true, Ordering::Release);
        });

        while !shutdown.load(Ordering::Acquire) {
            let accepted = tokio::select! {
                result = listener.accept(sender_endpoint) => Some(result),
                () = wait_for_control(Arc::clone(&shutdown), tray.clone()) => None,
            };
            let Some(connection) = accepted else {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                continue;
            };
            match connection {
                Ok(connection) => {
                    eprintln!("sender connected from {}", connection.remote_address());
                    tray.set_state(TrayState::Connected(
                        connection.remote_address().to_string(),
                    ));
                    if let Err(error) = run_connection(
                        connection,
                        &arguments.spout_name,
                        Arc::clone(&shutdown),
                        tray.clone(),
                    )
                    .await
                    {
                        eprintln!("receiver session ended: {error:#}");
                        tray.set_state(TrayState::Error("Receiver session failed".to_owned()));
                    }
                    if !shutdown.load(Ordering::Acquire) {
                        tray.set_state(TrayState::Listening(listener.local_addr()?.to_string()));
                    }
                }
                Err(error) => {
                    eprintln!("MutsukiLink accept failed: {error}");
                    tray.set_state(TrayState::Error("Unable to accept sender".to_owned()));
                }
            }
        }
        drop(discovery);
        Ok(())
    }

    async fn run_pairing_advertisement(arguments: &Arguments) -> Result<()> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let tray = TrayController::start(Arc::clone(&shutdown))?;
        tray.set_state(TrayState::Listening("Pairing available".to_owned()));
        let signal = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            signal.store(true, Ordering::Release);
        });
        let discovery = if arguments.no_mdns {
            None
        } else {
            let discovery = MdnsDiscovery::new(
                Duration::from_secs(30),
                RateLimit {
                    attempts: 4,
                    window: Duration::from_secs(1),
                    max_sources: 16,
                    max_candidates: 32,
                },
            )?;
            let instance = ephemeral_discovery_name()?;
            let host = format!("{instance}.local.");
            discovery.advertise(
                "_nanalive-link._udp.local.",
                &instance,
                &host,
                arguments.listen.port(),
                1,
                "quic",
            )?;
            eprintln!("pairing candidate advertised with an ephemeral discovery identity");
            Some(discovery)
        };
        let deadline =
            Instant::now() + Duration::from_secs(arguments.pairing_invitation_ttl_seconds);
        while !shutdown.load(Ordering::Acquire)
            && !tray.take_reconnect()
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(discovery);
        if Instant::now() >= deadline {
            eprintln!("pairing invitation expired; discovery advertisement stopped");
        } else {
            eprintln!("pairing invitation cancelled; discovery advertisement stopped");
        }
        Ok(())
    }

    fn ephemeral_discovery_name() -> Result<String> {
        use ring::rand::{SecureRandom, SystemRandom};

        let mut token = [0u8; 8];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| anyhow!("generate ephemeral discovery identity"))?;
        let mut encoded = String::with_capacity(16);
        for byte in token {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("write discovery token");
        }
        Ok(format!("nanalive-link-{encoded}"))
    }

    async fn run_connection(
        mut connection: QuicConnection,
        spout_name: &str,
        shutdown: Arc<AtomicBool>,
        tray: TrayController,
    ) -> Result<()> {
        let mut core = ReceiverCore::new()?;
        let mut pipeline: Option<(u16, HardwarePipeline)> = None;
        let mut next_report = Instant::now() + REPORT_INTERVAL;
        let mut jitter = JitterEstimator::default();

        while !shutdown.load(Ordering::Acquire) && !tray.take_reconnect() {
            let now = Instant::now();
            drain_control(&mut connection, &mut core, &mut pipeline).await?;
            drain_media(&mut connection, &mut core, &mut jitter)?;
            core.expire(now);

            if let Some(frame) = core.take_latest_frame(now) {
                let needs_pipeline = pipeline
                    .as_ref()
                    .is_none_or(|(generation, _)| *generation != frame.generation);
                if needs_pipeline {
                    pipeline = Some((
                        frame.generation,
                        HardwarePipeline::new(spout_name, frame.width, frame.height).context(
                            "initialize same-device D3D11 decode/composite/Spout pipeline",
                        )?,
                    ));
                    tray.set_state(TrayState::Decoding);
                }
                let active_pipeline = &mut pipeline.as_mut().expect("pipeline initialized").1;
                let publish = active_pipeline.publish(&frame);
                let pipeline_telemetry = active_pipeline.telemetry();
                core.update_pipeline_diagnostics(
                    pipeline_telemetry.color_decode_submit_cpu_us,
                    pipeline_telemetry.composite_enqueue_cpu_us,
                    pipeline_telemetry.spout_publish_cpu_us,
                );
                match publish {
                    Ok(Some(published)) if published.result == PublishResult::Sent => {
                        core.note_published(published.frame_id, Instant::now());
                        tray.set_state(TrayState::SpoutActive(spout_name.to_owned()));
                    }
                    Ok(Some(_)) => core.note_spout_skipped(),
                    Ok(None) => {}
                    Err(error) => {
                        eprintln!(
                            "hardware pipeline rejected frame {}: {error:#}",
                            frame.frame_id
                        );
                        core.note_decode_failure();
                        pipeline = None;
                        tray.set_state(TrayState::Error("Media pipeline unavailable".to_owned()));
                    }
                }
            }

            if let Some(request) = core.take_idr_request() {
                send_control(&mut connection, request).await?;
            }
            if now >= next_report {
                let telemetry = connection.realtime_telemetry();
                core.update_network_diagnostics(
                    telemetry.rtt_us.unwrap_or(0),
                    jitter.jitter_us(),
                    telemetry.estimated_send_rate_bps,
                );
                let decode_queue_depth = pipeline
                    .as_ref()
                    .map_or(0, |(_, pipeline)| pipeline.decode_queue_depth());
                let report = core.receiver_report(decode_queue_depth, pipeline.is_some());
                send_control(&mut connection, report).await?;
                let diagnostics = core.diagnostics();
                eprintln!(
                    "frames={} fps={} published={:?} dropped={} latest_drops={} incomplete={} decode_failures={} receive_to_publish={}us jitter_depth={} rtt={}us jitter={}us alpha_decode_cpu={}us mf_submit_output_cpu={}us composite_enqueue_cpu={}us spout_publish_cpu={}us",
                    diagnostics.completed_frames,
                    diagnostics.complete_frame_fps,
                    diagnostics.last_published_frame,
                    diagnostics.dropped_frames,
                    diagnostics.latest_frame_drops,
                    diagnostics.incomplete_frames,
                    diagnostics.decode_failures,
                    diagnostics.receive_to_publish_latency_us,
                    diagnostics.jitter_buffer_depth,
                    diagnostics.rtt_us,
                    diagnostics.jitter_us,
                    diagnostics.alpha_decode_cpu_us,
                    diagnostics.color_decode_submit_cpu_us,
                    diagnostics.composite_enqueue_cpu_us,
                    diagnostics.spout_publish_cpu_us,
                );
                next_report = now + REPORT_INTERVAL;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        connection.abort();
        Ok(())
    }

    async fn drain_control(
        connection: &mut QuicConnection,
        core: &mut ReceiverCore,
        pipeline: &mut Option<(u16, HardwarePipeline)>,
    ) -> Result<()> {
        loop {
            let protocol = media_protocol()?;
            let received = connection
                .open_control_stream(protocol)
                .and_then(|mut stream| stream.try_receive());
            match received {
                Ok(Some(encoded)) => {
                    let message = ControlMessage::decode(&encoded)?;
                    for response in core.handle_control(message)? {
                        send_control(connection, response).await?;
                    }
                    if core.phase() != SessionPhase::Streaming {
                        *pipeline = None;
                    }
                }
                Ok(None) => return Ok(()),
                Err(error) if error.kind == TransportErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error).context("receive MutsukiLink control message"),
            }
        }
    }

    fn drain_media(
        connection: &mut QuicConnection,
        core: &mut ReceiverCore,
        jitter: &mut JitterEstimator,
    ) -> Result<()> {
        loop {
            match connection.try_receive_realtime() {
                Ok(Some(datagram)) => {
                    validate_transport_metadata(&datagram)?;
                    let header = MediaChunkHeader::decode(&datagram.payload)?;
                    jitter.observe(header.pts_us, datagram.received_at);
                    core.push_media_datagram(&datagram.payload, datagram.received_at)?;
                }
                Ok(None) => return Ok(()),
                Err(error) if error.kind == TransportErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error).context("receive MutsukiLink media datagram"),
            }
        }
    }

    fn validate_transport_metadata(datagram: &ReceivedRealtimeDatagram) -> Result<()> {
        let header = MediaChunkHeader::decode(&datagram.payload)?;
        let expected_flow = match header.flow {
            MediaFlow::Color => COLOR_FLOW,
            MediaFlow::Alpha => ALPHA_FLOW,
            MediaFlow::Unknown(_) => bail!("unknown NanaLive media flow"),
        };
        if datagram.flow != expected_flow {
            bail!("MutsukiLink flow does not match NanaLive media header");
        }
        if datagram.generation != u32::from(header.generation) {
            bail!("MutsukiLink generation does not match NanaLive media header");
        }
        Ok(())
    }

    async fn send_control(connection: &mut QuicConnection, message: ControlMessage) -> Result<()> {
        let encoded = message.encode()?;
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            let protocol = media_protocol()?;
            let sent = connection
                .open_control_stream(protocol)
                .and_then(|mut stream| stream.try_send(&encoded));
            match sent {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.kind == TransportErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                Err(error) => return Err(error).context("send MutsukiLink control message"),
            }
        }
    }

    fn media_protocol() -> Result<ProtocolId> {
        ProtocolId::new("nanalive.link.media").map_err(|error| anyhow!(error.to_string()))
    }

    async fn wait_for_control(shutdown: Arc<AtomicBool>, tray: TrayController) {
        while !shutdown.load(Ordering::Acquire) && !tray.take_reconnect() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[derive(Default)]
    struct JitterEstimator {
        previous: Option<(u64, Instant)>,
        jitter_us: f64,
    }

    impl JitterEstimator {
        fn observe(&mut self, pts_us: u64, received_at: Instant) {
            if let Some((previous_pts, previous_received)) = self.previous {
                let media_delta = pts_us.saturating_sub(previous_pts) as f64;
                let arrival_delta = received_at
                    .saturating_duration_since(previous_received)
                    .as_micros() as f64;
                let deviation = (arrival_delta - media_delta).abs();
                self.jitter_us += (deviation - self.jitter_us) / 16.0;
            }
            self.previous = Some((pts_us, received_at));
        }

        fn jitter_us(&self) -> u64 {
            self.jitter_us.max(0.0).min(u64::MAX as f64) as u64
        }
    }
}
