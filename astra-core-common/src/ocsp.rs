/// OCSP (Online Certificate Status Protocol) stapling utilities.
/// Go equivalent: `common/ocsp`

/// OCSP certificate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

impl std::fmt::Display for CertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertStatus::Good => write!(f, "good"),
            CertStatus::Revoked => write!(f, "revoked"),
            CertStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// OCSP response containing certificate status.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    pub status: CertStatus,
    pub produced_at: i64,
    pub this_update: i64,
    pub next_update: i64,
}

/// OCSP request for a specific certificate.
#[derive(Debug, Clone)]
pub struct OcspRequest {
    pub issuer_hash: Vec<u8>,
    pub serial_number: Vec<u8>,
}

impl OcspRequest {
    pub fn new(issuer_hash: Vec<u8>, serial_number: Vec<u8>) -> Self {
        OcspRequest {
            issuer_hash,
            serial_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_status_display() {
        assert_eq!(CertStatus::Good.to_string(), "good");
        assert_eq!(CertStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_ocsp_request() {
        let req = OcspRequest::new(vec![1, 2, 3], vec![4, 5, 6]);
        assert_eq!(req.issuer_hash, vec![1, 2, 3]);
        assert_eq!(req.serial_number, vec![4, 5, 6]);
    }
}
