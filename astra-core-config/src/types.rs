use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

/// An IP address or domain name parsed from a JSON string.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Address(pub String);

/// A list of strings that accepts a JSON array or a comma-separated string.
#[derive(Debug, Clone, Default)]
pub struct StringList(pub Vec<String>);

impl Serialize for StringList {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringListVisitor;
        impl<'de> Visitor<'de> for StringListVisitor {
            type Value = StringList;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string or array of strings")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<StringList, E> {
                if v.is_empty() {
                    return Ok(StringList(Vec::new()));
                }
                Ok(StringList(
                    v.split(',').map(|s| s.trim().to_string()).collect(),
                ))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<StringList, A::Error> {
                let mut list = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    list.push(s);
                }
                Ok(StringList(list))
            }
        }
        deserializer.deserialize_any(StringListVisitor)
    }
}

/// "tcp", "udp", "unix", or a comma-separated list / array.
#[derive(Debug, Clone, Default)]
pub struct NetworkList(pub Vec<String>);

impl Serialize for NetworkList {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetworkList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NetworkListVisitor;
        impl<'de> Visitor<'de> for NetworkListVisitor {
            type Value = NetworkList;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a network string or array of network strings")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<NetworkList, E> {
                if v.is_empty() {
                    return Ok(NetworkList(Vec::new()));
                }
                Ok(NetworkList(
                    v.split(',').map(|s| s.trim().to_string()).collect(),
                ))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<NetworkList, A::Error> {
                let mut list = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    list.push(s);
                }
                Ok(NetworkList(list))
            }
        }
        deserializer.deserialize_any(NetworkListVisitor)
    }
}

/// A port range: "1000-2000" or a single port number.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.from && port <= self.to
    }
}

/// A list of ports: "80,443,1000-2000", a single number, or an array.
#[derive(Debug, Clone, Default)]
pub struct PortList(pub Vec<PortRange>);

impl Serialize for PortList {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as a comma-separated string
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|r| {
                if r.from == r.to {
                    r.from.to_string()
                } else {
                    format!("{}-{}", r.from, r.to)
                }
            })
            .collect();
        parts.join(",").serialize(serializer)
    }
}

impl PortList {
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }
}

impl<'de> Deserialize<'de> for PortList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PortListVisitor;
        impl<'de> Visitor<'de> for PortListVisitor {
            type Value = PortList;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a port number, range (80-443), comma-separated, or array")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<PortList, E> {
                let p = v as u16;
                Ok(PortList(vec![PortRange { from: p, to: p }]))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<PortList, E> {
                if v.is_empty() {
                    return Ok(PortList(Vec::new()));
                }
                let parts = v.split(',');
                let mut ranges = Vec::new();
                for part in parts {
                    let part = part.trim();
                    if let Some((a, b)) = part.split_once('-') {
                        let from = a.trim().parse::<u16>().map_err(de::Error::custom)?;
                        let to = b.trim().parse::<u16>().map_err(de::Error::custom)?;
                        ranges.push(PortRange { from, to });
                    } else {
                        let p = part.parse::<u16>().map_err(de::Error::custom)?;
                        ranges.push(PortRange { from: p, to: p });
                    }
                }
                Ok(PortList(ranges))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<PortList, A::Error> {
                let mut ranges = Vec::new();
                while let Some(elem) = seq.next_element::<PortListElement>()? {
                    ranges.push(elem.0);
                }
                Ok(PortList(ranges))
            }
        }
        deserializer.deserialize_any(PortListVisitor)
    }
}

#[derive(Debug, Clone)]
struct PortListElement(PortRange);

impl<'de> Deserialize<'de> for PortListElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PortListElementVisitor;
        impl<'de> Visitor<'de> for PortListElementVisitor {
            type Value = PortListElement;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a port number or range string")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<PortListElement, E> {
                let p = v as u16;
                Ok(PortListElement(PortRange { from: p, to: p }))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<PortListElement, E> {
                if let Some((a, b)) = v.split_once('-') {
                    let from = a.trim().parse::<u16>().map_err(de::Error::custom)?;
                    let to = b.trim().parse::<u16>().map_err(de::Error::custom)?;
                    Ok(PortListElement(PortRange { from, to }))
                } else {
                    let p = v.parse::<u16>().map_err(de::Error::custom)?;
                    Ok(PortListElement(PortRange { from: p, to: p }))
                }
            }
        }
        deserializer.deserialize_any(PortListElementVisitor)
    }
}

/// An int32 range: "1-100" or a single number.
#[derive(Debug, Clone, Copy, Default)]
pub struct Int32Range {
    pub from: i32,
    pub to: i32,
}

impl Serialize for Int32Range {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.from == self.to {
            self.from.serialize(serializer)
        } else {
            format!("{}-{}", self.from, self.to).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Int32Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Int32RangeVisitor;
        impl<'de> Visitor<'de> for Int32RangeVisitor {
            type Value = Int32Range;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an integer or range string like '1-100'")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Int32Range, E> {
                let n = v as i32;
                Ok(Int32Range { from: n, to: n })
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Int32Range, E> {
                let n = v as i32;
                Ok(Int32Range { from: n, to: n })
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Int32Range, E> {
                if let Some((a, b)) = v.split_once('-') {
                    let from = a.trim().parse::<i32>().map_err(de::Error::custom)?;
                    let to = b.trim().parse::<i32>().map_err(de::Error::custom)?;
                    Ok(Int32Range { from, to })
                } else {
                    let n = v.parse::<i32>().map_err(de::Error::custom)?;
                    Ok(Int32Range { from: n, to: n })
                }
            }
        }
        deserializer.deserialize_any(Int32RangeVisitor)
    }
}

/// Transport protocol string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportProtocol(pub String);

impl TransportProtocol {
    pub fn is_tcp(&self) -> bool {
        self.0 == "tcp"
    }
    pub fn is_kcp(&self) -> bool {
        self.0 == "kcp"
    }
    pub fn is_ws(&self) -> bool {
        self.0 == "ws" || self.0 == "websocket"
    }
    pub fn is_grpc(&self) -> bool {
        self.0 == "grpc"
    }
    pub fn is_quic(&self) -> bool {
        self.0 == "quic"
    }
    pub fn is_http(&self) -> bool {
        self.0 == "http"
    }
    pub fn is_h2(&self) -> bool {
        self.0 == "h2" || self.0 == "http/2"
    }
    pub fn is_splithttp(&self) -> bool {
        self.0 == "splithttp" || self.0 == "xhttp"
    }
    pub fn is_httpupgrade(&self) -> bool {
        self.0 == "httpupgrade"
    }
}

impl Default for TransportProtocol {
    fn default() -> Self {
        TransportProtocol("tcp".into())
    }
}

/// User level info embedded in proxy configs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct User {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub level: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_list_single() {
        let s: StringList = serde_json::from_str(r#""a,b,c""#).unwrap();
        assert_eq!(s.0, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_string_list_array() {
        let s: StringList = serde_json::from_str(r#"["a","b"]"#).unwrap();
        assert_eq!(s.0, vec!["a", "b"]);
    }

    #[test]
    fn test_string_list_single_item() {
        let s: StringList = serde_json::from_str(r#""hello""#).unwrap();
        assert_eq!(s.0, vec!["hello"]);
    }

    #[test]
    fn test_port_list_single() {
        let p: PortList = serde_json::from_str("443").unwrap();
        assert!(p.contains(443));
        assert!(!p.contains(80));
    }

    #[test]
    fn test_port_list_range() {
        let p: PortList = serde_json::from_str(r#""1000-2000""#).unwrap();
        assert!(p.contains(1500));
        assert!(!p.contains(999));
        assert!(p.contains(2000));
    }

    #[test]
    fn test_port_list_csv() {
        let p: PortList = serde_json::from_str(r#""80,443,8080-9090""#).unwrap();
        assert!(p.contains(80));
        assert!(p.contains(443));
        assert!(p.contains(8500));
        assert!(!p.contains(79));
    }

    #[test]
    fn test_port_list_array() {
        let p: PortList = serde_json::from_str(r#"["80","443","8000-9000"]"#).unwrap();
        assert!(p.contains(80));
        assert!(p.contains(8500));
    }

    #[test]
    fn test_int32_range_single() {
        let r: Int32Range = serde_json::from_str("42").unwrap();
        assert_eq!(r.from, 42);
        assert_eq!(r.to, 42);
    }

    #[test]
    fn test_int32_range_string() {
        let r: Int32Range = serde_json::from_str(r#""1-100""#).unwrap();
        assert_eq!(r.from, 1);
        assert_eq!(r.to, 100);
    }

    #[test]
    fn test_network_list() {
        let n: NetworkList = serde_json::from_str(r#""tcp,udp""#).unwrap();
        assert_eq!(n.0, vec!["tcp", "udp"]);
    }

    #[test]
    fn test_network_list_array() {
        let n: NetworkList = serde_json::from_str(r#"["tcp","udp"]"#).unwrap();
        assert_eq!(n.0, vec!["tcp", "udp"]);
    }

    #[test]
    fn test_address() {
        let a: Address = serde_json::from_str(r#""1.2.3.4""#).unwrap();
        assert_eq!(a.0, "1.2.3.4");
        let a: Address = serde_json::from_str(r#""example.com""#).unwrap();
        assert_eq!(a.0, "example.com");
    }
}
