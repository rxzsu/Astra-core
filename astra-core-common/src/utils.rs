use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;


/// Thread-safe map with typed keys and values.
/// Go equivalent: `common/utils.TypedSyncMap`.
pub struct SyncMap<K: Eq + Hash, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K: Eq + Hash, V> SyncMap<K, V> {
    pub fn new() -> Self {
        SyncMap { inner: RwLock::new(HashMap::new()) }
    }

    pub fn get(&self, key: &K) -> Option<V> where V: Clone {
        self.inner.read().unwrap().get(key).cloned()
    }

    pub fn set(&self, key: K, value: V) {
        self.inner.write().unwrap().insert(key, value);
    }

    pub fn remove(&self, key: &K) -> Option<V> where V: Clone {
        self.inner.write().unwrap().remove(key)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    pub fn keys(&self) -> Vec<K> where K: Clone {
        self.inner.read().unwrap().keys().cloned().collect()
    }

    pub fn iter(&self) -> Vec<(K, V)> where K: Clone, V: Clone {
        self.inner.read().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl<K: Eq + Hash, V> Default for SyncMap<K, V> {
    fn default() -> Self {
        SyncMap::new()
    }
}

/// HTTP header utilities.
/// Go equivalent: `common/utils.` HTTP helpers.
pub mod http {
    /// Default HTTP headers used in Xray requests.
    pub fn default_headers() -> Vec<(String, String)> {
        vec![
            ("User-Agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into()),
            ("Accept".into(), "*/*".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("Accept-Encoding".into(), "gzip, deflate, br".into()),
            ("Cache-Control".into(), "no-cache".into()),
            ("Pragma".into(), "no-cache".into()),
        ]
    }

    /// Generate a random padding string for HTTP headers.
    /// Used to avoid traffic fingerprinting.
    pub fn random_padding(min: usize, max: usize) -> String {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos() as u64;
        let len = if min >= max { min } else {
            let range = max - min;
            min + (nanos as usize % (range + 1))
        };
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
        let chars_len = chars.len();
        (0..len).map(|i| {
            let idx = (nanos.wrapping_add(i as u64 * 7)) as usize % chars_len;
            chars[idx]
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_map() {
        let map = SyncMap::<String, i32>::new();
        assert!(map.is_empty());
        map.set("key1".into(), 42);
        assert_eq!(map.get(&"key1".into()), Some(42));
        assert_eq!(map.len(), 1);
        map.set("key2".into(), 100);
        assert_eq!(map.keys().len(), 2);
        assert_eq!(map.remove(&"key1".into()), Some(42));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_http_padding() {
        let padding = http::random_padding(10, 20);
        assert!(padding.len() >= 10);
        assert!(padding.len() <= 20);
    }

    #[test]
    fn test_default_headers() {
        let headers = http::default_headers();
        assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
        assert!(headers.iter().any(|(k, _)| k == "Accept"));
    }
}
