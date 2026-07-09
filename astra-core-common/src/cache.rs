use std::collections::HashMap;
use std::hash::Hash;

/// Simple LRU cache implementation.
/// Maps keys to values with a fixed capacity. Evicts least recently used entries.
pub struct LruCache<K: Eq + Hash + Clone, V: Clone> {
    capacity: usize,
    map: HashMap<K, V>,
    order: Vec<K>,
}

impl<K: Eq + Hash + Clone, V: Clone> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        LruCache {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: Vec::with_capacity(capacity),
        }
    }

    /// Get a value by key. Returns `None` if not found.
    /// Moves the key to the front (most recently used).
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.map.contains_key(key) {
            // Move to front
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                let k = self.order.remove(pos);
                self.order.push(k);
            }
            self.map.get(key)
        } else {
            None
        }
    }

    /// Peek at a value without moving it to front.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Get key from value by linear scan. O(n). Moves to front. Returns None if not found.
    pub fn get_key_from_value(&mut self, value: &V) -> Option<K>
    where
        V: PartialEq,
    {
        let found_key = self
            .map
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(k, _)| k.clone());
        if let Some(ref key) = found_key
            && let Some(pos) = self.order.iter().position(|k| *k == *key)
        {
            let k = self.order.remove(pos);
            self.order.push(k);
        }
        found_key
    }

    /// Peek key from value without moving to front.
    pub fn peek_key_from_value(&self, value: &V) -> Option<&K>
    where
        V: PartialEq,
    {
        self.map.iter().find(|(_, v)| *v == value).map(|(k, _)| k)
    }

    /// Insert or update a key-value pair.
    pub fn put(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            // Update existing
            self.map.insert(key.clone(), value);
            if let Some(pos) = self.order.iter().position(|k| *k == key) {
                let k = self.order.remove(pos);
                self.order.push(k);
            }
        } else {
            if self.order.len() >= self.capacity {
                // Evict least recently used (front of order)
                if let Some(lru_key) = self.order.first().cloned() {
                    self.map.remove(&lru_key);
                    self.order.remove(0);
                }
            }
            self.map.insert(key.clone(), value);
            self.order.push(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_replace_value() {
        let mut lru = LruCache::new(2);
        lru.put(2, 6);
        lru.put(1, 5);
        lru.put(1, 2);
        assert_eq!(*lru.get(&1).unwrap(), 2);
        assert_eq!(*lru.get(&2).unwrap(), 6);
    }

    #[test]
    fn test_lru_remove_old() {
        let mut lru = LruCache::new(2);
        assert!(lru.get(&2).is_none());
        lru.put(1, 1);
        lru.put(2, 2);
        assert_eq!(*lru.get(&1).unwrap(), 1);
        lru.put(3, 3);
        assert!(lru.get(&2).is_none()); // 2 was evicted
        lru.put(4, 4);
        assert!(lru.get(&1).is_none()); // 1 was evicted
        assert_eq!(*lru.get(&3).unwrap(), 3);
        assert_eq!(*lru.get(&4).unwrap(), 4);
    }

    #[test]
    fn test_get_key_from_value() {
        let mut lru = LruCache::new(2);
        lru.put(3, 3);
        lru.put(2, 2);
        lru.get_key_from_value(&3); // moves 3 to front -> order: [2, 3]
        lru.put(1, 1); // evicts 2 (LRU at front) -> order: [3, 1]
        assert!(lru.get_key_from_value(&2).is_none()); // 2 was evicted
        assert_eq!(lru.get_key_from_value(&3).unwrap(), 3);
    }

    #[test]
    fn test_peek_key_from_value() {
        let mut lru = LruCache::new(2);
        lru.put(3, 3);
        lru.put(2, 2);
        lru.peek_key_from_value(&3); // doesn't move to front
        lru.put(1, 1); // evicts 3 (front is LRU not moved)
        assert!(lru.peek_key_from_value(&3).is_none()); // 3 was evicted
        assert_eq!(*lru.peek_key_from_value(&2).unwrap(), 2);
    }
}
