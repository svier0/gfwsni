use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Result};
use der::asn1::{Any, ObjectIdentifier, OctetString, UintRef};
use der::{Encode, Sequence};
use publicsuffix::Psl;
use rand::RngCore;
use log::info;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::OffsetDateTime;

use crate::CERT_EXPIRE;

static CA: Mutex<Option<(Certificate, KeyPair)>> = Mutex::new(None);
static PSL: OnceLock<publicsuffix::List> = OnceLock::new();
static CERT_CACHE: OnceLock<Arc<Mutex<HashMap<String, Arc<LeafCert>>>>> = OnceLock::new();
static DOH_CONFIG: Mutex<Option<Arc<ServerConfig>>> = Mutex::new(None);

#[derive(Debug)]
pub struct LeafCert {
    pub certs: Vec<CertificateDer<'static>>,
    pub key_der: PrivateKeyDer<'static>,
}

fn psl() -> &'static publicsuffix::List {
    PSL.get().unwrap()
}

/// Effective TLD + one, e.g. "www.example.com" -> "example.com"
pub fn effective_tld_plus_one(host: &str) -> Option<String> {
    let d = psl().domain(host.as_bytes())?.trim();
    std::str::from_utf8(d.as_bytes()).ok().map(ToString::to_string)
}

const RSA_ENCRYPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

#[derive(Sequence)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Any,
}

#[derive(Sequence)]
struct PrivateKeyInfo<'a> {
    version: UintRef<'a>,
    algorithm: AlgorithmIdentifier,
    private_key: OctetString,
}

/// Convert a PKCS#1 (RSAPrivateKey) DER blob into PKCS#8 (PrivateKeyInfo) DER.
fn pkcs1_to_pkcs8(pkcs1: &[u8]) -> Result<Vec<u8>> {
    let info = PrivateKeyInfo {
        version: UintRef::new(&[0])?,
        algorithm: AlgorithmIdentifier {
            algorithm: RSA_ENCRYPTION_OID,
            parameters: Any::null(),
        },
        private_key: OctetString::new(pkcs1)?,
    };
    Ok(info.to_der()?)
}

pub fn generate_ca(cert_path: &str, key_path: &str) -> Result<()> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "gfwsni CA (auto-generated)");
    let cert = params.self_signed(&key)?;
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key.serialize_pem())?;
    info!("已生成新的 CA 证书: {} / {}", cert_path, key_path);
    Ok(())
}

pub fn init(ca_cert_path: &str, ca_key_path: &str) -> Result<()> {
    let mut ca_cert_file = std::io::BufReader::new(std::fs::File::open(ca_cert_path)?);
    let ca_cert_der = rustls_pemfile::certs(&mut ca_cert_file)
        .next()
        .transpose()?
        .ok_or_else(|| anyhow!("no certificate found in {}", ca_cert_path))?;

    let mut key_file = std::io::BufReader::new(std::fs::File::open(ca_key_path)?);
    let key_der = rustls_pemfile::private_key(&mut key_file)?
        .ok_or_else(|| anyhow!("no private key found in {}", ca_key_path))?;
    let pkcs8 = match &key_der {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        PrivateKeyDer::Pkcs1(k) => pkcs1_to_pkcs8(k.secret_pkcs1_der())?,
        _ => return Err(anyhow!("unsupported CA key format, expect RSA PKCS#1 or PKCS#8")),
    };
    let issuer_key = KeyPair::try_from(&PrivatePkcs8KeyDer::from(pkcs8))?;

    let issuer_params = CertificateParams::from_ca_cert_der(&ca_cert_der)?;
    let issuer = issuer_params.self_signed(&issuer_key)?;

    PSL.set(publicsuffix::List::from_bytes(include_bytes!("public_suffix_list.dat"))?)
        .map_err(|_| anyhow!("PSL already set"))?;
    *CA.lock().unwrap() = Some((issuer, issuer_key));
    CERT_CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new())));
    Ok(())
}

pub fn reset(ca_cert_path: &str, ca_key_path: &str) -> Result<()> {
    let mut ca_cert_file = std::io::BufReader::new(std::fs::File::open(ca_cert_path)?);
    let ca_cert_der = rustls_pemfile::certs(&mut ca_cert_file)
        .next()
        .transpose()?
        .ok_or_else(|| anyhow!("no certificate found in {}", ca_cert_path))?;

    let mut key_file = std::io::BufReader::new(std::fs::File::open(ca_key_path)?);
    let key_der = rustls_pemfile::private_key(&mut key_file)?
        .ok_or_else(|| anyhow!("no private key found in {}", ca_key_path))?;
    let pkcs8 = match &key_der {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        PrivateKeyDer::Pkcs1(k) => pkcs1_to_pkcs8(k.secret_pkcs1_der())?,
        _ => return Err(anyhow!("unsupported CA key format, expect RSA PKCS#1 or PKCS#8")),
    };
    let issuer_key = KeyPair::try_from(&PrivatePkcs8KeyDer::from(pkcs8))?;

    let issuer_params = CertificateParams::from_ca_cert_der(&ca_cert_der)?;
    let issuer = issuer_params.self_signed(&issuer_key)?;

    *CA.lock().unwrap() = Some((issuer, issuer_key));
    *DOH_CONFIG.lock().unwrap() = None;
    CERT_CACHE.get().map(|c| c.lock().unwrap().clear());
    Ok(())
}

pub fn get_certificate(host: &str) -> Result<Arc<LeafCert>> {
    if host.is_empty() {
        return Err(anyhow!("no SNI info"));
    }
    {
        let cache = CERT_CACHE.get().unwrap().lock().unwrap();
        if let Some(c) = cache.get(host) {
            return Ok(c.clone());
        }
    }

    let secondary = effective_tld_plus_one(host)
        .ok_or_else(|| anyhow!("invalid hostname: {}", host))?;

    let cn = if host == secondary {
        secondary.clone()
    } else {
        let dot = host
            .find('.')
            .ok_or_else(|| anyhow!("invalid hostname: {}", host))?;
        host[dot + 1..].to_string()
    };

    {
        let cache = CERT_CACHE.get().unwrap().lock().unwrap();
        if let Some(c) = cache.get(&cn) {
            return Ok(c.clone());
        }
    }

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec![format!("*.{}", cn), cn.clone()])?;
    params.not_before = OffsetDateTime::now_utc() - time::Duration::seconds(60);
    params.not_after = OffsetDateTime::now_utc() + *CERT_EXPIRE.get().unwrap();
    let mut serial = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut serial);
    params.serial_number = Some(SerialNumber::from(serial.to_vec()));
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &cn);
    params.distinguished_name.push(DnType::CountryName, "CN");

    let ca_guard = CA.lock().unwrap();
    let (issuer, issuer_key) = ca_guard.as_ref().unwrap();
    let cert = params.signed_by(&leaf_key, issuer, issuer_key)?;
    drop(ca_guard);

    let leaf = Arc::new(LeafCert {
        certs: vec![CertificateDer::from(cert.der().to_vec())],
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    });
    CERT_CACHE.get().unwrap().lock().unwrap().insert(cn, leaf.clone());
    Ok(leaf)
}

/// Fixed server config used by the DoH endpoint (certificate valid for 127.0.0.1).
pub fn doh_server_config() -> Result<Arc<ServerConfig>> {
    if let Some(c) = DOH_CONFIG.lock().unwrap().as_ref() {
        return Ok(c.clone());
    }
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    params.not_before = OffsetDateTime::now_utc() - time::Duration::seconds(60);
    params.not_after = OffsetDateTime::now_utc() + *CERT_EXPIRE.get().unwrap();
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "gfwsni DoH");

    let ca_guard = CA.lock().unwrap();
    let (issuer, issuer_key) = ca_guard.as_ref().unwrap();
    let cert = params.signed_by(&key, issuer, issuer_key)?;
    drop(ca_guard);

    let leaf = LeafCert {
        certs: vec![CertificateDer::from(cert.der().to_vec())],
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    };
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.certs, leaf.key_der)?;
    let config = Arc::new(config);
    *DOH_CONFIG.lock().unwrap() = Some(config.clone());
    Ok(config)
}
