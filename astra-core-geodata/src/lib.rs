use std::collections::HashMap;
use std::path::Path;

use prost::Message;

pub mod download;
pub use download::{
    DEFAULT_GEOIP_URL, DEFAULT_GEOSITE_URL, DownloadOptions, download_file, ensure_geo_files,
};

/// GeoIP protobuf definitions

#[derive(Clone, PartialEq, Message)]
pub struct GeoIPList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIP>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoIP {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<CIDR>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CIDR {
    #[prost(bytes, tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

/// GeoSite protobuf definitions

#[derive(Clone, PartialEq, Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

/// GeoDataManager

pub struct GeoDataManager {
    pub geoip: HashMap<String, CompiledGeoIP>,
    pub geosite: HashMap<String, CompiledGeoSite>,
}

pub struct CompiledGeoIP {
    pub country_code: String,
    pub cidr: Vec<CIDR>,
}

pub struct CompiledGeoSite {
    pub country_code: String,
    pub domains: Vec<Domain>,
}

impl GeoDataManager {
    pub fn new() -> Self {
        GeoDataManager {
            geoip: HashMap::new(),
            geosite: HashMap::new(),
        }
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(format!("geo data path does not exist: {}", path.display()));
        }

        if path.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "dat") {
                    self.load_file(&p)?;
                }
            }
        } else {
            self.load_file(path)?;
        }

        Ok(())
    }

    fn load_file(&mut self, path: &Path) -> Result<(), String> {
        let data =
            std::fs::read(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if fname.contains("geoip") || fname.contains("GeoIP") {
            let list = GeoIPList::decode(data.as_slice())
                .map_err(|e| format!("failed to decode geoip {}: {}", path.display(), e))?;
            for entry in list.entry {
                let code = entry.country_code.to_uppercase();
                tracing::info!(country = %code, cidrs = entry.cidr.len(), "loaded geoip");
                self.geoip.insert(
                    code,
                    CompiledGeoIP {
                        country_code: entry.country_code,
                        cidr: entry.cidr,
                    },
                );
            }
        } else if fname.contains("geosite") || fname.contains("GeoSite") {
            let list = GeoSiteList::decode(data.as_slice())
                .map_err(|e| format!("failed to decode geosite {}: {}", path.display(), e))?;
            for entry in list.entry {
                let code = entry.country_code.to_uppercase();
                tracing::info!(country = %code, domains = entry.domain.len(), "loaded geosite");
                self.geosite.insert(
                    code,
                    CompiledGeoSite {
                        country_code: entry.country_code,
                        domains: entry.domain,
                    },
                );
            }
        } else {
            return Err(format!("unknown geo data file: {}", path.display()));
        }

        Ok(())
    }
}

impl Default for GeoDataManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_roundtrip() {
        let cidr = CIDR {
            ip: vec![10, 0, 0, 0],
            prefix: 8,
        };
        let geoip = GeoIP {
            country_code: "CN".into(),
            cidr: vec![cidr],
        };
        let list = GeoIPList { entry: vec![geoip] };

        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();

        let decoded = GeoIPList::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.entry.len(), 1);
        assert_eq!(decoded.entry[0].country_code, "CN");
        assert_eq!(decoded.entry[0].cidr[0].ip, vec![10, 0, 0, 0]);
        assert_eq!(decoded.entry[0].cidr[0].prefix, 8);
    }

    #[test]
    fn test_geosite_roundtrip() {
        let domain = Domain {
            r#type: DomainType::Domain as i32,
            value: "google.com".into(),
        };
        let site = GeoSite {
            country_code: "GOOGLE".into(),
            domain: vec![domain],
        };
        let list = GeoSiteList { entry: vec![site] };

        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();

        let decoded = GeoSiteList::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.entry.len(), 1);
        assert_eq!(decoded.entry[0].country_code, "GOOGLE");
        assert_eq!(decoded.entry[0].domain[0].value, "google.com");
        assert_eq!(decoded.entry[0].domain[0].r#type, 2); // Domain = 2
    }

    #[test]
    fn test_load_missing_file() {
        let mut mgr = GeoDataManager::new();
        let result = mgr.load("nonexistent.dat");
        assert!(result.is_err());
    }
}
