# nanalive-link-receiver

Independent Windows receiver for NanaLive Link v1. It receives the reliable control stream and
latest-only media datagrams through MutsukiLink, decodes H.264 with a hardware Media Foundation
transform on D3D11, decodes A8T1 alpha, composites premultiplied BGRA on that same GPU device, and
publishes the resulting texture through Spout 2.

## Protocol and dependency pins

- [`nanalive-link-protocol`](https://github.com/sena-nana/nanalive-link-protocol)
  is the canonical v1 wire-contract repository and is pinned at full commit
  `2c3eccf05de42184500e9cb4d6daa70d3d19da26`; the receiver does not copy the
  protocol source or depend on the private NanaLive application repository.
- MutsukiLink is pinned at `2ffca07` with QUIC datagrams and mDNS discovery.
- `nanalive-spout` is pinned at `7f7dfe1` with only `gpu-dx11-texture` enabled.

Clone normally; all source dependencies are fetched from their pinned public
repositories:

```powershell
git clone https://github.com/sena-nana/nanalive-link-receiver.git
```

## Run on Windows

The receiver requires Windows 10 or later, a D3D11-aware hardware H.264 Media Foundation decoder,
and Spout 2. It deliberately has no software decoder or CPU pixel publishing fallback.

```powershell
cargo run --release -- `
  --listen 0.0.0.0:59631 `
  --receiver-name "Studio receiver" `
  --advertised-address 192.168.1.20:59631 `
  --state-dir "$env:LOCALAPPDATA\NanaLiveLinkReceiver" `
  --invitation-output receiver-invitation.json `
  --spout-name "NanaLive Link"
```

On Windows, `--state-dir` defaults to `%LOCALAPPDATA%\NanaLiveLinkReceiver`; startup fails with a
clear error if LocalAppData is unavailable. An explicit state directory remains supported. On the
first run the receiver creates and privately stores its Ed25519 identity and self-signed server
certificate there. It then writes and prints a time-limited invitation,
keeps its tray process alive, and advertises an untrusted `_nanalive-link._udp.local.` candidate until
the invitation expires or is cancelled. Each advertisement uses a random temporary instance and
host token; it never exposes the long-term peer id, endpoint id, certificate fingerprint, or pairing
challenge through discovery. Existing identity files are validated on every restart; corruption is
reported and is never replaced with a new identity. Operators may supply `--certificate-der`,
`--private-key-der`, and `--receiver-peer-id` together as an advanced identity override.

Import `receiver-invitation.json` in NanaLive, ask NanaLive to export its pairing exchange to
`sender-exchange.json`, then preview the receiver's independently computed short code:

```powershell
cargo run --release -- `
  --receiver-name "Studio receiver" `
  --state-dir "$env:LOCALAPPDATA\NanaLiveLinkReceiver" `
  --pairing-invitation receiver-invitation.json `
  --pairing-exchange sender-exchange.json
```

Compare that code with the one NanaLive displays. Only after they match, repeat the command with
`--confirm-pairing`. The receiver then emits the strict receiver-confirmation JSON, consumes the
invitation challenge, and persists both Mutsuki trust and an exact sender certificate/endpoint
profile. Production Windows trust records use Windows Credential Manager; the atomic file profile
records the exact paired certificate and recovery state. Pass the confirmation JSON back to NanaLive
to finish its side of the ceremony.

Subsequent normal starts omit all pairing files. The receiver restores the paired sender from
`sender-trust.receiver-state.json`, verifies it against the native Mutsuki trust record, and
starts QUIC with mandatory mutual TLS. It accepts only the exact paired sender certificate and the
endpoint derived from that sender's Ed25519 identity. The media listener is never started with an
untrusted or anonymous client configuration.

```powershell
cargo run --release -- `
  --listen 0.0.0.0:59631 `
  --receiver-name "Studio receiver" `
  --state-dir "$env:LOCALAPPDATA\NanaLiveLinkReceiver" `
  --spout-name "NanaLive Link"
```

The CLI reports completed, dropped, incomplete and published frames, decoder failures, RTT and
jitter once per second. `ReceiverReport` uses those observations and MutsukiLink's estimated send
rate to request bitrate reduction before FPS reduction, with a debounced recovery. A8T1 remains the
v1 alpha codec.

## Validation boundary

Platform-independent tests cover protocol-bound control negotiation, out-of-order media
reassembly, two-frame bounds, color/alpha PTS matching, one-frame playout delay, latest-only
replacement, IDR requests, adaptive reports, and the Rec.709 limited-range premultiplied-BGRA color
contract. CI compiles and tests the complete crate on `x86_64-pc-windows-msvc`, including the native
Spout dependency.

The functional tests exercise the full Mutsuki bilateral ceremony, strict wire parsing, certificate
and endpoint binding, trust persistence, trusted restart, and mTLS server configuration. A real OBS
Spout consumer remains a Windows integration acceptance item and must not be treated as verified
merely because CI compiles the D3D11 path.
