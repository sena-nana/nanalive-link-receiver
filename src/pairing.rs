use anyhow::{Context, Result, anyhow, bail};
#[cfg(any(not(windows), test))]
use mutsuki_link::pairing::FileTrustStore;
#[cfg(all(windows, not(test)))]
use mutsuki_link::pairing::SystemKeyringTrustStore;
use mutsuki_link::pairing::{
    KeyState, LinkPermission, LongTermIdentity, PairingConfirmation, PairingCrypto, PairingError,
    PairingId, PairingMethod, PairingOffer, PairingResponse, PairingSession, PairingState,
    ReplayGuard, TrustRecord, TrustStore, authorize_trusted_reconnect,
};
use mutsuki_link::{EndpointId, PeerId, ProtocolVersion};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_cert::der::Decode;

const SERVICE: &str = "nanalive-link";
const PAIRING_VERSION: u8 = 1;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_INVITATION_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const MAX_STATE_BYTES: u64 = 256 * 1024;

#[cfg(any(not(windows), test))]
fn open_trust_store(path: &Path) -> Result<FileTrustStore> {
    FileTrustStore::open(path).context("open Mutsuki development trust store")
}

#[cfg(all(windows, not(test)))]
fn open_trust_store(path: &Path) -> Result<SystemKeyringTrustStore> {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    let service = format!("nanalive-link-receiver-{}", &encode_hex(&digest)[..16]);
    SystemKeyringTrustStore::open(service).context("open Windows Credential Manager trust store")
}

pub fn default_windows_state_dir(
    local_app_data: Option<&std::ffi::OsStr>,
) -> Result<std::path::PathBuf> {
    let base = local_app_data
        .context("Windows LocalAppData is unavailable; pass --state-dir explicitly")?;
    if base.is_empty() {
        bail!("Windows LocalAppData is empty; pass --state-dir explicitly");
    }
    Ok(Path::new(base).join("NanaLiveLinkReceiver"))
}

pub struct ReceiverIdentity {
    peer_id: PeerId,
    endpoint_id: EndpointId,
    public_key: [u8; 32],
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    key_pair: Arc<Ed25519KeyPair>,
}

impl ReceiverIdentity {
    pub fn load(
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        expected_peer_id: &str,
        server_name: &str,
    ) -> Result<Self> {
        if certificate_der.is_empty() || certificate_der.len() > MAX_CERTIFICATE_BYTES {
            bail!("receiver certificate is invalid");
        }
        let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_der)
            .map_err(|_| anyhow!("receiver private key is not Ed25519 PKCS#8"))?;
        let public_key: [u8; 32] = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("receiver Ed25519 public key has an invalid length"))?;
        let certificate_key = certificate_public_key(&certificate_der)?;
        if certificate_key != public_key {
            bail!("receiver certificate does not match its private key");
        }
        validate_server_certificate(&certificate_der, server_name)?;
        let peer_bytes: [u8; 32] = Sha256::digest(public_key).into();
        if decode_fixed::<32>(expected_peer_id)? != peer_bytes {
            bail!("--receiver-peer-id does not match the receiver certificate key");
        }
        Ok(Self {
            peer_id: PeerId::from_bytes(peer_bytes),
            endpoint_id: endpoint_from_peer(peer_bytes),
            public_key,
            certificate_der,
            private_key_der,
            key_pair: Arc::new(key_pair),
        })
    }

    pub fn load_or_create(path: &Path, server_name: &str) -> Result<Self> {
        if path.exists() {
            if fs::metadata(path)?.len() > MAX_STATE_BYTES {
                bail!("receiver identity file exceeds its allowed size");
            }
            let file: ReceiverIdentityFile =
                serde_json::from_slice(&fs::read(path)?).context("parse receiver identity file")?;
            if file.version != PAIRING_VERSION {
                bail!("receiver identity file version is unsupported");
            }
            let identity = Self::load(
                decode_hex_bounded(&file.certificate_der_hex, MAX_CERTIFICATE_BYTES)?,
                decode_hex_bounded(&file.private_key_der_hex, MAX_CERTIFICATE_BYTES)?,
                &file.peer_id,
                server_name,
            )?;
            if file.endpoint_id != encode_hex(identity.endpoint_id.as_bytes()) {
                bail!("receiver identity endpoint does not match its peer identity");
            }
            return Ok(identity);
        }
        if server_name.is_empty() {
            bail!("receiver server name must be non-empty");
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .context("generate receiver Ed25519 identity")?;
        let mut parameters = rcgen::CertificateParams::new(vec![server_name.to_owned()])
            .context("create receiver certificate parameters")?;
        parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = parameters
            .self_signed(&key)
            .context("self-sign receiver certificate")?;
        let private_key_der = key.serialize_der();
        let public_key: [u8; 32] = key
            .public_key_raw()
            .try_into()
            .map_err(|_| anyhow!("generated receiver key is not Ed25519"))?;
        let peer_id: [u8; 32] = Sha256::digest(public_key).into();
        let identity = Self::load(
            certificate.der().as_ref().to_vec(),
            private_key_der,
            &encode_hex(&peer_id),
            server_name,
        )?;
        persist_private_json(
            path,
            &ReceiverIdentityFile {
                version: PAIRING_VERSION,
                peer_id: encode_hex(identity.peer_id.as_bytes()),
                endpoint_id: encode_hex(identity.endpoint_id.as_bytes()),
                certificate_der_hex: encode_hex(&identity.certificate_der),
                private_key_der_hex: encode_hex(&identity.private_key_der),
            },
        )?;
        Ok(identity)
    }

    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    fn long_term_identity(&self, display_name: String) -> LongTermIdentity {
        LongTermIdentity {
            peer_id: self.peer_id,
            public_key: self.public_key.to_vec(),
            display_name,
        }
    }

    fn crypto(&self) -> Ed25519PairingCrypto {
        Ed25519PairingCrypto(Arc::clone(&self.key_pair))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiverIdentityFile {
    version: u8,
    peer_id: String,
    endpoint_id: String,
    certificate_der_hex: String,
    private_key_der_hex: String,
}

pub struct PairingCompletion {
    pub sender_endpoint_id: EndpointId,
    pub sender_certificate_der: Vec<u8>,
    pub receiver_confirmation_json: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingPreview {
    pub sender_name: String,
    pub sender_peer_id: String,
    pub certificate_sha256: String,
    pub short_code: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiverPairingState {
    version: u8,
    paired_sender: Option<PairedSenderProfile>,
    consumed_challenges: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairedSenderProfile {
    status: ProfileStatus,
    peer_id: String,
    endpoint_id: String,
    certificate_der_hex: String,
    certificate_sha256: String,
    pairing_id: String,
    receiver_confirmation_json: String,
    sender_name: String,
    paired_at_unix_ms: u64,
    challenge_hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ProfileStatus {
    PendingTrust,
    Committed,
}

pub fn mutual_tls_server_config(
    receiver_certificate_der: Vec<u8>,
    receiver_private_key_der: Vec<u8>,
    sender_certificate_der: Vec<u8>,
) -> Result<quinn::ServerConfig> {
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;

    let mut sender_roots = RootCertStore::empty();
    sender_roots
        .add(CertificateDer::from(sender_certificate_der))
        .context("add paired sender certificate as the client trust root")?;
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(sender_roots))
        .build()
        .context("build paired-sender client certificate verifier")?;
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![CertificateDer::from(receiver_certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(receiver_private_key_der)),
        )
        .context("build mutual TLS server configuration")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).context("enable QUIC for mutual TLS")?,
    )))
}

pub fn create_invitation(
    identity: &ReceiverIdentity,
    receiver_name: &str,
    address: &str,
    server_name: &str,
    ttl_seconds: u64,
) -> Result<String> {
    if receiver_name.is_empty()
        || address.is_empty()
        || server_name.is_empty()
        || ttl_seconds == 0
        || ttl_seconds > MAX_INVITATION_LIFETIME_SECONDS
    {
        bail!("pairing invitation fields or lifetime are invalid");
    }
    let mut pairing_id = [0; 16];
    let mut challenge = [0; 32];
    SystemRandom::new()
        .fill(&mut pairing_id)
        .map_err(|_| anyhow!("generate pairing id"))?;
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| anyhow!("generate pairing challenge"))?;
    let expires_at_unix_ms = now_unix_ms()?.saturating_add(ttl_seconds.saturating_mul(1_000));
    let offer = PairingOfferWire {
        pairing_id: encode_hex(&pairing_id),
        initiator: IdentityWire::from_identity(
            &identity.long_term_identity(receiver_name.to_owned()),
        ),
        protocol_major: 1,
        protocol_minor: 0,
        challenge: encode_hex(&challenge),
        method: "bilateralConfirmation".to_owned(),
        expires_at_unix_ms,
    };
    let invitation = InvitationWire {
        version: PAIRING_VERSION,
        service: SERVICE.to_owned(),
        address: address.to_owned(),
        server_name: server_name.to_owned(),
        receiver_endpoint_id: encode_hex(identity.endpoint_id.as_bytes()),
        certificate_der_hex: encode_hex(identity.certificate_der()),
        certificate_sha256: encode_hex(&Sha256::digest(identity.certificate_der())),
        pairing_offer: offer,
    };
    serde_json::to_string(&invitation).context("serialize pairing invitation")
}

pub fn preview_pairing(
    identity: &ReceiverIdentity,
    receiver_name: &str,
    invitation_json: &str,
    exchange_json: &str,
    trust_store_path: &Path,
) -> Result<PairingPreview> {
    let state = load_receiver_state(trust_store_path)?;
    if state.paired_sender.is_some() {
        bail!("this receiver already has a paired sender");
    }
    let invitation: InvitationWire =
        serde_json::from_str(invitation_json).context("parse receiver pairing invitation")?;
    invitation.validate_for(identity)?;
    let exchange = validate_exchange(exchange_json)?;
    if invitation.pairing_offer.pairing_id != exchange.wire.pairing_response.pairing_id {
        bail!("pairing response id does not match the invitation");
    }
    reject_consumed_challenge(&state, &invitation.pairing_offer.challenge)?;
    let offer = invitation.pairing_offer.to_native()?;
    let mut session = PairingSession::initiator(
        identity.long_term_identity(receiver_name.to_owned()),
        offer.pairing_id,
        offer.protocol_version,
        offer.challenge,
        offer.method,
        offer.expires_at_unix_ms,
        false,
        16,
    )?;
    session.receive_response(exchange.response, now_unix_ms()?)?;
    let presentation = session.presentation()?;
    Ok(PairingPreview {
        sender_name: presentation.peer_name,
        sender_peer_id: encode_hex(exchange.sender_peer_id.as_bytes()),
        certificate_sha256: encode_hex(&Sha256::digest(exchange.sender_certificate_der)),
        short_code: presentation.short_code,
        expires_at_unix_ms: invitation.pairing_offer.expires_at_unix_ms,
    })
}

pub fn load_paired_sender(trust_store_path: &Path) -> Result<PairingCompletion> {
    let mut state = load_receiver_state(trust_store_path)?;
    recover_profile_trust(trust_store_path, &mut state)?;
    let profile = state
        .paired_sender
        .context("no sender has been paired with this receiver")?;
    completion_from_profile(&profile, trust_store_path, false)
}

pub fn paired_sender_if_present(trust_store_path: &Path) -> Result<Option<PairingCompletion>> {
    let mut state = load_receiver_state(trust_store_path)?;
    recover_profile_trust(trust_store_path, &mut state)?;
    state
        .paired_sender
        .as_ref()
        .map(|profile| completion_from_profile(profile, trust_store_path, false))
        .transpose()
}

pub fn complete_or_load_pairing(
    identity: &ReceiverIdentity,
    receiver_name: &str,
    invitation_json: Option<&str>,
    exchange_json: &str,
    trust_store_path: &Path,
) -> Result<PairingCompletion> {
    let exchange = validate_exchange(exchange_json)?;
    let mut state = load_receiver_state(trust_store_path)?;
    recover_profile_trust(trust_store_path, &mut state)?;
    if let Some(profile) = state.paired_sender.as_ref() {
        validate_exchange_matches_profile(&exchange, profile)?;
        return completion_from_profile(profile, trust_store_path, true);
    }
    let mut store = open_trust_store(trust_store_path)?;
    if store.get(&exchange.sender_peer_id)?.is_some() {
        bail!("sender trust exists without its strict receiver profile");
    }

    let invitation_json = invitation_json.context("first pairing requires --pairing-invitation")?;
    let invitation: InvitationWire =
        serde_json::from_str(invitation_json).context("parse receiver pairing invitation")?;
    invitation.validate_for(identity)?;
    if invitation.pairing_offer.pairing_id != exchange.wire.pairing_response.pairing_id {
        bail!("pairing response id does not match the invitation");
    }
    reject_consumed_challenge(&state, &invitation.pairing_offer.challenge)?;
    let offer = invitation.pairing_offer.to_native()?;
    let mut replay = ReplayGuard::new(64)?;
    replay.reserve(&offer.challenge)?;
    let mut session = PairingSession::initiator(
        identity.long_term_identity(receiver_name.to_owned()),
        offer.pairing_id,
        offer.protocol_version,
        offer.challenge,
        offer.method,
        offer.expires_at_unix_ms,
        false,
        16,
    )?;
    let now = now_unix_ms()?;
    session.receive_response(exchange.response, now)?;
    let receiver_short_code = session.presentation()?.short_code;
    let crypto = identity.crypto();
    let receiver_confirmation = session.confirm(&receiver_short_code, &crypto, now)?;
    session.receive_confirmation(exchange.wire.sender_confirmation.to_native()?, &crypto, now)?;
    if session.state() != PairingState::Paired {
        bail!("Mutsuki pairing did not reach Paired state");
    }
    let permissions = BTreeSet::from([
        LinkPermission::Connect,
        LinkPermission::Datagram,
        LinkPermission::OpenNamespace("nanalive.link.media".to_owned()),
    ]);
    let record = session.trust_record(
        exchange
            .wire
            .pairing_response
            .responder
            .display_name
            .clone(),
        permissions,
        now,
    )?;
    let confirmation = PairingConfirmationWire::from_native(
        &receiver_confirmation,
        &invitation.pairing_offer.pairing_id,
    );
    let confirmation_json = serde_json::to_string(&ReceiverConfirmationEnvelope {
        version: PAIRING_VERSION,
        service: SERVICE.to_owned(),
        receiver_confirmation: confirmation,
    })?;
    state.version = PAIRING_VERSION;
    state
        .consumed_challenges
        .push(challenge_digest(&invitation.pairing_offer.challenge)?);
    state.paired_sender = Some(PairedSenderProfile {
        status: ProfileStatus::PendingTrust,
        peer_id: encode_hex(exchange.sender_peer_id.as_bytes()),
        endpoint_id: encode_hex(exchange.expected_endpoint.as_bytes()),
        certificate_der_hex: encode_hex(&exchange.sender_certificate_der),
        certificate_sha256: encode_hex(&Sha256::digest(&exchange.sender_certificate_der)),
        pairing_id: invitation.pairing_offer.pairing_id,
        receiver_confirmation_json: confirmation_json.clone(),
        sender_name: exchange
            .wire
            .pairing_response
            .responder
            .display_name
            .clone(),
        paired_at_unix_ms: now,
        challenge_hash: encode_hex(&record.last_pairing_challenge_hash),
    });
    persist_receiver_state(trust_store_path, &state)?;
    store.upsert(record)?;
    state
        .paired_sender
        .as_mut()
        .expect("paired sender profile inserted")
        .status = ProfileStatus::Committed;
    persist_receiver_state(trust_store_path, &state)?;
    Ok(PairingCompletion {
        sender_endpoint_id: exchange.expected_endpoint,
        sender_certificate_der: exchange.sender_certificate_der,
        receiver_confirmation_json: Some(confirmation_json),
    })
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvitationWire {
    version: u8,
    service: String,
    address: String,
    server_name: String,
    receiver_endpoint_id: String,
    certificate_der_hex: String,
    certificate_sha256: String,
    pairing_offer: PairingOfferWire,
}

impl InvitationWire {
    fn validate_for(&self, identity: &ReceiverIdentity) -> Result<()> {
        if self.version != PAIRING_VERSION
            || self.service != SERVICE
            || self.address.is_empty()
            || self.server_name.is_empty()
            || decode_fixed::<16>(&self.receiver_endpoint_id)? != *identity.endpoint_id.as_bytes()
            || decode_hex_bounded(&self.certificate_der_hex, MAX_CERTIFICATE_BYTES)?
                != identity.certificate_der
        {
            bail!("pairing invitation does not match this receiver");
        }
        validate_fingerprint(identity.certificate_der(), &self.certificate_sha256)?;
        let initiator = self.pairing_offer.initiator.to_native()?;
        if initiator.peer_id != identity.peer_id || initiator.public_key != identity.public_key {
            bail!("pairing invitation identity does not match this receiver");
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingOfferWire {
    pairing_id: String,
    initiator: IdentityWire,
    protocol_major: u16,
    protocol_minor: u16,
    challenge: String,
    method: String,
    expires_at_unix_ms: u64,
}

impl PairingOfferWire {
    fn to_native(&self) -> Result<PairingOffer> {
        if self.method != "bilateralConfirmation" {
            bail!("unsupported pairing method");
        }
        Ok(PairingOffer {
            pairing_id: PairingId::from_bytes(decode_fixed(&self.pairing_id)?),
            initiator: self.initiator.to_native()?,
            protocol_version: ProtocolVersion::new(self.protocol_major, self.protocol_minor),
            challenge: decode_fixed(&self.challenge)?,
            method: PairingMethod::BilateralConfirmation,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityWire {
    peer_id: String,
    public_key_hex: String,
    display_name: String,
}

impl IdentityWire {
    fn from_identity(identity: &LongTermIdentity) -> Self {
        Self {
            peer_id: encode_hex(identity.peer_id.as_bytes()),
            public_key_hex: encode_hex(&identity.public_key),
            display_name: identity.display_name.clone(),
        }
    }

    fn to_native(&self) -> Result<LongTermIdentity> {
        let identity = LongTermIdentity {
            peer_id: PeerId::from_bytes(decode_fixed(&self.peer_id)?),
            public_key: decode_hex_bounded(&self.public_key_hex, 32)?,
            display_name: self.display_name.clone(),
        };
        validate_identity_peer(&identity)?;
        Ok(identity)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SenderExchangeWire {
    version: u8,
    service: String,
    sender_endpoint_id: String,
    sender_certificate_der_hex: String,
    sender_certificate_sha256: String,
    pairing_response: PairingResponseWire,
    sender_confirmation: PairingConfirmationWire,
}

impl SenderExchangeWire {
    fn validate_envelope(&self) -> Result<()> {
        if self.version != PAIRING_VERSION || self.service != SERVICE {
            bail!("sender pairing exchange version or service is invalid");
        }
        Ok(())
    }
}

struct ValidatedExchange {
    wire: SenderExchangeWire,
    response: PairingResponse,
    sender_peer_id: PeerId,
    expected_endpoint: EndpointId,
    sender_certificate_der: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingResponseWire {
    pairing_id: String,
    responder: IdentityWire,
    transcript_hash: String,
    short_code: String,
}

impl PairingResponseWire {
    fn to_native(&self) -> Result<PairingResponse> {
        Ok(PairingResponse {
            pairing_id: PairingId::from_bytes(decode_fixed(&self.pairing_id)?),
            responder: self.responder.to_native()?,
            transcript_hash: decode_fixed(&self.transcript_hash)?,
            short_code: self.short_code.clone(),
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingConfirmationWire {
    pairing_id: String,
    signer_peer_id: String,
    transcript_hash: String,
    signature_hex: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiverConfirmationEnvelope {
    version: u8,
    service: String,
    receiver_confirmation: PairingConfirmationWire,
}

impl PairingConfirmationWire {
    fn to_native(&self) -> Result<PairingConfirmation> {
        Ok(PairingConfirmation {
            pairing_id: PairingId::from_bytes(decode_fixed(&self.pairing_id)?),
            signer_peer_id: PeerId::from_bytes(decode_fixed(&self.signer_peer_id)?),
            transcript_hash: decode_fixed(&self.transcript_hash)?,
            signature: decode_hex_bounded(&self.signature_hex, 128)?,
        })
    }

    fn from_native(value: &PairingConfirmation, pairing_id: &str) -> Self {
        Self {
            pairing_id: pairing_id.to_owned(),
            signer_peer_id: encode_hex(value.signer_peer_id.as_bytes()),
            transcript_hash: encode_hex(&value.transcript_hash),
            signature_hex: encode_hex(&value.signature),
        }
    }
}

struct Ed25519PairingCrypto(Arc<Ed25519KeyPair>);

impl PairingCrypto for Ed25519PairingCrypto {
    fn sign_transcript(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>, PairingError> {
        Ok(self.0.sign(transcript_hash).as_ref().to_vec())
    }

    fn verify_transcript(
        &self,
        public_key: &[u8],
        transcript_hash: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(transcript_hash, signature)
            .is_ok()
    }
}

fn validate_identity_peer(identity: &LongTermIdentity) -> Result<()> {
    let public_key: [u8; 32] = identity
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pairing identity public key must be raw Ed25519"))?;
    let peer: [u8; 32] = Sha256::digest(public_key).into();
    if identity.peer_id.as_bytes() != &peer || identity.display_name.is_empty() {
        bail!("pairing identity does not match its public key");
    }
    Ok(())
}

fn validate_exchange(exchange_json: &str) -> Result<ValidatedExchange> {
    let wire: SenderExchangeWire =
        serde_json::from_str(exchange_json).context("parse sender pairing exchange")?;
    wire.validate_envelope()?;
    let sender_certificate_der =
        decode_hex_bounded(&wire.sender_certificate_der_hex, MAX_CERTIFICATE_BYTES)?;
    validate_fingerprint(&sender_certificate_der, &wire.sender_certificate_sha256)?;
    let sender_public_key = certificate_public_key(&sender_certificate_der)?;
    let response = wire.pairing_response.to_native()?;
    if response.responder.public_key != sender_public_key {
        bail!("sender certificate key does not match the Mutsuki pairing response");
    }
    validate_identity_peer(&response.responder)?;
    let sender_peer_id = response.responder.peer_id;
    let expected_endpoint = endpoint_from_peer(*sender_peer_id.as_bytes());
    if decode_fixed::<16>(&wire.sender_endpoint_id)? != *expected_endpoint.as_bytes() {
        bail!("sender endpoint id does not match its paired identity");
    }
    Ok(ValidatedExchange {
        wire,
        response,
        sender_peer_id,
        expected_endpoint,
        sender_certificate_der,
    })
}

fn validate_exchange_matches_profile(
    exchange: &ValidatedExchange,
    profile: &PairedSenderProfile,
) -> Result<()> {
    if profile.peer_id != encode_hex(exchange.sender_peer_id.as_bytes())
        || profile.endpoint_id != encode_hex(exchange.expected_endpoint.as_bytes())
        || profile.certificate_der_hex != encode_hex(&exchange.sender_certificate_der)
        || profile.certificate_sha256
            != encode_hex(&Sha256::digest(&exchange.sender_certificate_der))
        || profile.pairing_id != exchange.wire.pairing_response.pairing_id
    {
        bail!("pairing exchange does not match the persisted sender profile");
    }
    Ok(())
}

fn recover_profile_trust(trust_store_path: &Path, state: &mut ReceiverPairingState) -> Result<()> {
    let Some(profile) = state.paired_sender.as_mut() else {
        return Ok(());
    };
    let peer_id = PeerId::from_bytes(decode_fixed(&profile.peer_id)?);
    let certificate_der = decode_hex_bounded(&profile.certificate_der_hex, MAX_CERTIFICATE_BYTES)?;
    validate_fingerprint(&certificate_der, &profile.certificate_sha256)?;
    let public_key = certificate_public_key(&certificate_der)?;
    if peer_id.as_bytes() != &<[u8; 32]>::from(Sha256::digest(public_key))
        || decode_fixed::<16>(&profile.endpoint_id)?
            != *endpoint_from_peer(*peer_id.as_bytes()).as_bytes()
    {
        bail!("persisted sender profile identity is inconsistent");
    }
    let permissions = BTreeSet::from([
        LinkPermission::Connect,
        LinkPermission::Datagram,
        LinkPermission::OpenNamespace("nanalive.link.media".to_owned()),
    ]);
    let expected = TrustRecord {
        peer_id,
        public_key: public_key.to_vec(),
        alias: profile.sender_name.clone(),
        first_paired_at_unix_ms: profile.paired_at_unix_ms,
        permissions,
        key_state: KeyState::Active,
        last_pairing_challenge_hash: decode_fixed(&profile.challenge_hash)?,
        previous_key_fingerprints: Vec::new(),
    };
    let mut store = open_trust_store(trust_store_path)?;
    let existing = store.get(&peer_id)?;
    if let Some(existing) = existing.as_ref() {
        if existing != &expected {
            bail!("Mutsuki trust record conflicts with the persisted sender profile");
        }
    }
    if existing.is_none() && profile.status == ProfileStatus::Committed {
        bail!("Mutsuki trust record is missing for the committed sender profile");
    }
    if profile.status == ProfileStatus::PendingTrust {
        store.upsert(expected)?;
    }
    if profile.status == ProfileStatus::PendingTrust {
        profile.status = ProfileStatus::Committed;
        persist_receiver_state(trust_store_path, state)?;
    }
    Ok(())
}

fn completion_from_profile(
    profile: &PairedSenderProfile,
    trust_store_path: &Path,
    resend_confirmation: bool,
) -> Result<PairingCompletion> {
    let peer_id = PeerId::from_bytes(decode_fixed(&profile.peer_id)?);
    let endpoint_id = EndpointId::from_bytes(decode_fixed(&profile.endpoint_id)?);
    if endpoint_id != endpoint_from_peer(*peer_id.as_bytes()) {
        bail!("persisted sender endpoint does not match its peer identity");
    }
    let certificate_der = decode_hex_bounded(&profile.certificate_der_hex, MAX_CERTIFICATE_BYTES)?;
    validate_fingerprint(&certificate_der, &profile.certificate_sha256)?;
    let public_key = certificate_public_key(&certificate_der)?;
    let expected_peer: [u8; 32] = Sha256::digest(public_key).into();
    if peer_id.as_bytes() != &expected_peer {
        bail!("persisted sender certificate does not match its peer identity");
    }
    let store = open_trust_store(trust_store_path)?;
    authorize_trusted_reconnect(&store, &peer_id, &public_key)?;
    Ok(PairingCompletion {
        sender_endpoint_id: endpoint_id,
        sender_certificate_der: certificate_der,
        receiver_confirmation_json: resend_confirmation
            .then(|| profile.receiver_confirmation_json.clone()),
    })
}

fn receiver_state_path(trust_store_path: &Path) -> std::path::PathBuf {
    trust_store_path.with_extension("receiver-state.json")
}

fn load_receiver_state(trust_store_path: &Path) -> Result<ReceiverPairingState> {
    let path = receiver_state_path(trust_store_path);
    if !path.exists() {
        return Ok(ReceiverPairingState {
            version: PAIRING_VERSION,
            ..ReceiverPairingState::default()
        });
    }
    if fs::metadata(&path)?.len() > MAX_STATE_BYTES {
        bail!("receiver pairing state exceeds its allowed size");
    }
    let state: ReceiverPairingState =
        serde_json::from_slice(&fs::read(&path)?).context("parse receiver pairing state")?;
    if state.version != PAIRING_VERSION || state.consumed_challenges.len() > 64 {
        bail!("receiver pairing state is invalid");
    }
    Ok(state)
}

fn persist_receiver_state(trust_store_path: &Path, state: &ReceiverPairingState) -> Result<()> {
    let path = receiver_state_path(trust_store_path);
    persist_private_json(&path, state)
}

fn persist_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() as u64 > MAX_STATE_BYTES {
        bail!("receiver pairing state exceeds its allowed size");
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temporary, &encoded)?;
    replace_file_atomically(&temporary, path)?;
    Ok(())
}

#[cfg(unix)]
fn replace_file_atomically(temporary: &Path, destination: &Path) -> Result<()> {
    fs::rename(temporary, destination)?;
    if let Some(parent) = destination.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file_atomically(temporary: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH,
        ReplaceFileW,
    };
    use windows::core::PCWSTR;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    let destination_exists = destination.exists();
    let temporary = wide(temporary);
    let destination = wide(destination);
    unsafe {
        if destination_exists {
            ReplaceFileW(
                PCWSTR(destination.as_ptr()),
                PCWSTR(temporary.as_ptr()),
                PCWSTR::null(),
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
            .context("atomically replace persisted receiver state")?;
        } else {
            MoveFileExW(
                PCWSTR(temporary.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
            .context("atomically install persisted receiver state")?;
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn replace_file_atomically(temporary: &Path, destination: &Path) -> Result<()> {
    fs::rename(temporary, destination)?;
    Ok(())
}

fn challenge_digest(challenge_hex: &str) -> Result<String> {
    Ok(encode_hex(&Sha256::digest(decode_fixed::<32>(
        challenge_hex,
    )?)))
}

fn reject_consumed_challenge(state: &ReceiverPairingState, challenge_hex: &str) -> Result<()> {
    let digest = challenge_digest(challenge_hex)?;
    if state
        .consumed_challenges
        .iter()
        .any(|value| value == &digest)
    {
        bail!("pairing invitation challenge has already been consumed");
    }
    Ok(())
}

fn certificate_public_key(certificate_der: &[u8]) -> Result<[u8; 32]> {
    let certificate = Certificate::from_der(certificate_der).context("parse X.509 certificate")?;
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .try_into()
        .map_err(|_| anyhow!("certificate public key is not raw Ed25519"))
}

fn validate_server_certificate(certificate_der: &[u8], server_name: &str) -> Result<()> {
    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    let certificate = CertificateDer::from(certificate_der.to_vec());
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate.clone())
        .context("use receiver certificate as its trust anchor")?;
    let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("build receiver certificate verifier")?;
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| anyhow!("receiver server name is invalid"))?;
    verifier
        .verify_server_cert(&certificate, &[], &server_name, &[], UnixTime::now())
        .context("receiver certificate cannot authenticate the configured server name")?;
    Ok(())
}

fn validate_fingerprint(certificate_der: &[u8], fingerprint: &str) -> Result<()> {
    let expected: [u8; 32] = Sha256::digest(certificate_der).into();
    if decode_fixed::<32>(fingerprint)? != expected {
        bail!("certificate SHA-256 fingerprint does not match");
    }
    Ok(())
}

fn endpoint_from_peer(peer: [u8; 32]) -> EndpointId {
    let mut hash = Sha256::new();
    hash.update(b"nanalive-link-endpoint-v1");
    hash.update(peer);
    let digest = hash.finalize();
    let mut endpoint = [0; 16];
    endpoint.copy_from_slice(&digest[..16]);
    EndpointId::from_bytes(endpoint)
}

fn now_unix_ms() -> Result<u64> {
    Ok(
        u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
            .unwrap_or(u64::MAX),
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("write hex to string");
    }
    encoded
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode_hex_bounded(value, N)?
        .try_into()
        .map_err(|_| anyhow!("hex field has an invalid length"))
}

fn decode_hex_bounded(value: &str, maximum_bytes: usize) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 || value.len() > maximum_bytes.saturating_mul(2) {
        bail!("hex field exceeds its allowed size");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_hex_nibble(pair[0])?;
            let low = decode_hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("hex field contains invalid characters"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, PKCS_ED25519};
    use std::fs;

    struct CertificateMaterial {
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        public_key: [u8; 32],
    }

    fn certificate_material(server: bool) -> CertificateMaterial {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).expect("generate Ed25519 key");
        let mut params = CertificateParams::new(vec![if server {
            "receiver.local".to_owned()
        } else {
            "sender.local".to_owned()
        }])
        .expect("certificate parameters");
        params.extended_key_usages = vec![if server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        let certificate = params
            .self_signed(&key_pair)
            .expect("self-sign certificate");
        CertificateMaterial {
            certificate: certificate.der().as_ref().to_vec(),
            private_key: key_pair.serialize_der(),
            public_key: key_pair
                .public_key_raw()
                .try_into()
                .expect("raw Ed25519 public key"),
        }
    }

    fn peer_id(public_key: [u8; 32]) -> PeerId {
        PeerId::from_bytes(Sha256::digest(public_key).into())
    }

    fn temporary_trust_store() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nanalive-link-receiver-trust-{}-{nonce}.json",
            std::process::id()
        ))
    }

    #[test]
    fn bilateral_pairing_binds_certificates_persists_trust_and_allows_reconnect() {
        let receiver_material = certificate_material(true);
        let receiver_peer = peer_id(receiver_material.public_key);
        let receiver = ReceiverIdentity::load(
            receiver_material.certificate.clone(),
            receiver_material.private_key.clone(),
            &encode_hex(receiver_peer.as_bytes()),
            "receiver.local",
        )
        .expect("load receiver identity");
        let invitation_json = create_invitation(
            &receiver,
            "Studio receiver",
            "192.0.2.10:59631",
            "receiver.local",
            600,
        )
        .expect("create invitation");
        let invitation: InvitationWire =
            serde_json::from_str(&invitation_json).expect("decode invitation");
        let offer = invitation.pairing_offer.to_native().expect("native offer");

        let sender_material = certificate_material(false);
        let sender_peer = peer_id(sender_material.public_key);
        let sender_identity = LongTermIdentity {
            peer_id: sender_peer,
            public_key: sender_material.public_key.to_vec(),
            display_name: "NanaLive".to_owned(),
        };
        let sender_key =
            Arc::new(Ed25519KeyPair::from_pkcs8(&sender_material.private_key).expect("sender key"));
        let sender_crypto = Ed25519PairingCrypto(sender_key);
        let now = now_unix_ms().expect("current time");
        let (mut sender_session, response) =
            PairingSession::responder(sender_identity, offer, now, false, 16)
                .expect("create sender pairing session");
        let short_code = sender_session
            .presentation()
            .expect("pairing presentation")
            .short_code;
        let sender_confirmation = sender_session
            .confirm(&short_code, &sender_crypto, now)
            .expect("confirm sender side");
        let pairing_id = invitation.pairing_offer.pairing_id.clone();
        let exchange = SenderExchangeWire {
            version: PAIRING_VERSION,
            service: SERVICE.to_owned(),
            sender_endpoint_id: encode_hex(endpoint_from_peer(*sender_peer.as_bytes()).as_bytes()),
            sender_certificate_der_hex: encode_hex(&sender_material.certificate),
            sender_certificate_sha256: encode_hex(&Sha256::digest(&sender_material.certificate)),
            pairing_response: PairingResponseWire {
                pairing_id: pairing_id.clone(),
                responder: IdentityWire::from_identity(&response.responder),
                transcript_hash: encode_hex(&response.transcript_hash),
                short_code: response.short_code,
            },
            sender_confirmation: PairingConfirmationWire::from_native(
                &sender_confirmation,
                &pairing_id,
            ),
        };
        let exchange_json = serde_json::to_string(&exchange).expect("encode sender exchange");
        let trust_store = temporary_trust_store();

        let preview = preview_pairing(
            &receiver,
            "Studio receiver",
            &invitation_json,
            &exchange_json,
            &trust_store,
        )
        .expect("preview receiver short code");
        assert_eq!(preview.short_code, short_code);

        let completion = complete_or_load_pairing(
            &receiver,
            "Studio receiver",
            Some(&invitation_json),
            &exchange_json,
            &trust_store,
        )
        .expect("complete receiver pairing");
        let confirmation: ReceiverConfirmationEnvelope = serde_json::from_str(
            completion
                .receiver_confirmation_json
                .as_deref()
                .expect("receiver confirmation"),
        )
        .expect("decode receiver confirmation");
        sender_session
            .receive_confirmation(
                confirmation
                    .receiver_confirmation
                    .to_native()
                    .expect("native receiver confirmation"),
                &sender_crypto,
                now,
            )
            .expect("complete sender pairing");
        assert_eq!(sender_session.state(), PairingState::Paired);
        if let Some(path) = std::env::var_os("NANALIVE_LINK_FIXTURE_OUT") {
            let fixture = serde_json::json!({
                "invitation": serde_json::from_str::<serde_json::Value>(&invitation_json)
                    .expect("invitation value"),
                "exchange": serde_json::from_str::<serde_json::Value>(&exchange_json)
                    .expect("exchange value"),
                "receiverConfirmation": serde_json::from_str::<serde_json::Value>(
                    completion
                        .receiver_confirmation_json
                        .as_deref()
                        .expect("receiver confirmation fixture"),
                )
                .expect("receiver confirmation value"),
                "shortCode": short_code,
                "receiverIdentity": {
                    "serverName": "receiver.local",
                    "peerId": encode_hex(receiver_peer.as_bytes()),
                    "certificateDerHex": encode_hex(&receiver_material.certificate),
                    "privateKeyDerHex": encode_hex(&receiver_material.private_key),
                },
                "senderIdentity": {
                    "serverName": "sender.local",
                    "peerId": encode_hex(sender_peer.as_bytes()),
                    "certificateDerHex": encode_hex(&sender_material.certificate),
                    "privateKeyDerHex": encode_hex(&sender_material.private_key),
                },
            });
            fs::write(
                path,
                serde_json::to_vec_pretty(&fixture).expect("fixture JSON"),
            )
            .expect("write pairing interoperability fixture");
        }
        assert_eq!(
            completion.sender_certificate_der,
            sender_material.certificate
        );
        assert_eq!(
            completion.sender_endpoint_id,
            endpoint_from_peer(*sender_peer.as_bytes())
        );

        let reconnect = complete_or_load_pairing(
            &receiver,
            "Studio receiver",
            None,
            &exchange_json,
            &trust_store,
        )
        .expect("authorize trusted reconnect");
        assert_eq!(
            reconnect.receiver_confirmation_json,
            completion.receiver_confirmation_json
        );
        let restored = load_paired_sender(&trust_store).expect("restore paired sender profile");
        assert!(restored.receiver_confirmation_json.is_none());

        let mut interrupted = load_receiver_state(&trust_store).expect("load receiver state");
        interrupted
            .paired_sender
            .as_mut()
            .expect("paired profile")
            .status = ProfileStatus::PendingTrust;
        persist_receiver_state(&trust_store, &interrupted).expect("persist pending profile");
        let mut native_store = FileTrustStore::open(&trust_store).expect("open trust store");
        assert!(native_store.remove(&sender_peer).expect("remove trust"));
        load_paired_sender(&trust_store).expect("recover pending profile before trust write");

        let mut interrupted = load_receiver_state(&trust_store).expect("load receiver state");
        interrupted
            .paired_sender
            .as_mut()
            .expect("paired profile")
            .status = ProfileStatus::PendingTrust;
        persist_receiver_state(&trust_store, &interrupted).expect("persist pending profile");
        load_paired_sender(&trust_store).expect("recover pending profile after trust write");
        assert_eq!(
            load_receiver_state(&trust_store)
                .expect("load committed state")
                .paired_sender
                .expect("paired profile")
                .status,
            ProfileStatus::Committed
        );
        mutual_tls_server_config(
            receiver_material.certificate,
            receiver_material.private_key,
            sender_material.certificate,
        )
        .expect("build client-authenticated QUIC configuration");

        let mut native_store = FileTrustStore::open(&trust_store).expect("open trust store");
        assert!(native_store.remove(&sender_peer).expect("remove trust"));
        assert!(
            load_paired_sender(&trust_store).is_err(),
            "deleting committed native trust must revoke rather than silently re-enroll"
        );

        let _ = fs::remove_file(&trust_store);
        let _ = fs::remove_file(receiver_state_path(&trust_store));
    }

    #[test]
    fn pairing_wire_rejects_unknown_fields_and_certificate_tampering() {
        let receiver_material = certificate_material(true);
        let receiver_peer = peer_id(receiver_material.public_key);
        let receiver = ReceiverIdentity::load(
            receiver_material.certificate,
            receiver_material.private_key,
            &encode_hex(receiver_peer.as_bytes()),
            "receiver.local",
        )
        .expect("load receiver identity");
        let invitation_json = create_invitation(
            &receiver,
            "Receiver",
            "192.0.2.10:59631",
            "receiver.local",
            600,
        )
        .expect("create invitation");
        let invitation: InvitationWire =
            serde_json::from_str(&invitation_json).expect("decode invitation");
        let sender = certificate_material(false);
        let sender_peer = peer_id(sender.public_key);
        assert!(
            ReceiverIdentity::load(
                sender.certificate.clone(),
                sender.private_key.clone(),
                &encode_hex(sender_peer.as_bytes()),
                "sender.local",
            )
            .is_err()
        );
        let sender_identity = LongTermIdentity {
            peer_id: sender_peer,
            public_key: sender.public_key.to_vec(),
            display_name: "NanaLive".to_owned(),
        };
        let now = now_unix_ms().expect("current time");
        let (mut session, response) = PairingSession::responder(
            sender_identity,
            invitation.pairing_offer.to_native().expect("native offer"),
            now,
            false,
            16,
        )
        .expect("sender session");
        let crypto = Ed25519PairingCrypto(Arc::new(
            Ed25519KeyPair::from_pkcs8(&sender.private_key).expect("sender key"),
        ));
        let code = session.presentation().expect("presentation").short_code;
        let sender_confirmation = session
            .confirm(&code, &crypto, now)
            .expect("sender confirmation");
        let pairing_id = invitation.pairing_offer.pairing_id.clone();
        let exchange = SenderExchangeWire {
            version: PAIRING_VERSION,
            service: SERVICE.to_owned(),
            sender_endpoint_id: encode_hex(endpoint_from_peer(*sender_peer.as_bytes()).as_bytes()),
            sender_certificate_der_hex: encode_hex(&sender.certificate),
            sender_certificate_sha256: encode_hex(&Sha256::digest(&sender.certificate)),
            pairing_response: PairingResponseWire {
                pairing_id: pairing_id.clone(),
                responder: IdentityWire::from_identity(&response.responder),
                transcript_hash: encode_hex(&response.transcript_hash),
                short_code: response.short_code,
            },
            sender_confirmation: PairingConfirmationWire::from_native(
                &sender_confirmation,
                &pairing_id,
            ),
        };
        let trust_store = temporary_trust_store();
        let mut value = serde_json::to_value(&exchange).expect("exchange value");
        value
            .as_object_mut()
            .expect("exchange object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(
            complete_or_load_pairing(
                &receiver,
                "Receiver",
                Some(&invitation_json),
                &value.to_string(),
                &trust_store,
            )
            .is_err()
        );

        let mut tampered = serde_json::to_value(exchange).expect("exchange value");
        tampered["senderCertificateSha256"] = serde_json::Value::String("00".repeat(32));
        assert!(
            complete_or_load_pairing(
                &receiver,
                "Receiver",
                Some(&invitation_json),
                &tampered.to_string(),
                &trust_store,
            )
            .is_err()
        );
        let _ = fs::remove_file(trust_store);
    }

    #[test]
    fn generated_receiver_identity_is_stable_and_corruption_is_rejected() {
        let path = temporary_trust_store().with_extension("identity.json");
        let first = ReceiverIdentity::load_or_create(&path, "receiver.local")
            .expect("generate receiver identity");
        let first_peer = first.peer_id;
        let first_endpoint = first.endpoint_id;
        let first_certificate = first.certificate_der.clone();
        let second = ReceiverIdentity::load_or_create(&path, "receiver.local")
            .expect("reload receiver identity");
        assert_eq!(second.peer_id, first_peer);
        assert_eq!(second.endpoint_id, first_endpoint);
        assert_eq!(second.certificate_der, first_certificate);
        assert!(ReceiverIdentity::load_or_create(&path, "changed.local").is_err());
        fs::write(&path, b"{not valid identity json").expect("corrupt identity file");
        assert!(ReceiverIdentity::load_or_create(&path, "receiver.local").is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn state_directory_default_and_repeated_atomic_replacement_are_stable() {
        assert_eq!(
            default_windows_state_dir(Some(std::ffi::OsStr::new(
                "C:\\Users\\test\\AppData\\Local"
            )))
            .expect("local app data"),
            std::path::PathBuf::from("C:\\Users\\test\\AppData\\Local")
                .join("NanaLiveLinkReceiver")
        );
        assert!(default_windows_state_dir(None).is_err());
        assert!(default_windows_state_dir(Some(std::ffi::OsStr::new(""))).is_err());

        let trust_store = temporary_trust_store();
        let mut state = ReceiverPairingState {
            version: PAIRING_VERSION,
            paired_sender: None,
            consumed_challenges: vec!["11".repeat(32)],
        };
        persist_receiver_state(&trust_store, &state).expect("first state write");
        state.consumed_challenges.push("22".repeat(32));
        persist_receiver_state(&trust_store, &state).expect("atomic state replacement");
        assert_eq!(
            load_receiver_state(&trust_store)
                .expect("reloaded state")
                .consumed_challenges,
            state.consumed_challenges
        );
        let _ = fs::remove_file(receiver_state_path(&trust_store));
    }

    #[test]
    fn non_ascii_hex_is_rejected_without_panicking() {
        let result = std::panic::catch_unwind(|| decode_hex_bounded("aéx", 8));
        assert!(result.is_ok(), "invalid imported JSON must not panic");
        assert!(result.unwrap().is_err());
    }
}
