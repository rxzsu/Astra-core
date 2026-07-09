use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Simple dependency injection container.
// Go equivalent: `core.Xray` with `RequireFeatures`/`OptionalFeatures`.

lazy_static::lazy_static! {
    static ref FEATURES: RwLock<HashMap<String, Arc<dyn Any + Send + Sync>>> = RwLock::new(HashMap::new());
}

/// Register a feature by type name.
pub fn register_feature<T: Send + Sync + 'static>(feature: T) {
    let type_name = std::any::type_name::<T>().to_string();
    FEATURES.write().unwrap().insert(type_name, Arc::new(feature));
}

/// Get a feature by type. Returns `None` if not registered.
pub fn get_feature<T: Send + Sync + 'static>() -> Option<Arc<T>> {
    let type_name = std::any::type_name::<T>().to_string();
    FEATURES.read().unwrap()
        .get(type_name.as_str())
        .and_then(|f| f.clone().downcast::<T>().ok())
}

/// Require a feature, returning an error if not found (Go: `core.RequireFeatures`).
pub fn require_feature<T: Send + Sync + 'static>() -> Result<Arc<T>, String> {
    get_feature::<T>().ok_or_else(|| format!("feature {} not registered", std::any::type_name::<T>()))
}

/// Remove a feature from the registry.
pub fn remove_feature<T: Send + Sync + 'static>() {
    let type_name = std::any::type_name::<T>().to_string();
    FEATURES.write().unwrap().remove(type_name.as_str());
}

/// Check if a feature is registered.
pub fn has_feature<T: Send + Sync + 'static>() -> bool {
    get_feature::<T>().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestService {
        value: i32,
    }

    #[test]
    fn test_register_and_get() {
        let svc = TestService { value: 42 };
        register_feature(svc);
        let retrieved = require_feature::<TestService>().unwrap();
        assert_eq!(retrieved.value, 42);
        assert!(has_feature::<TestService>());
        remove_feature::<TestService>();
        assert!(!has_feature::<TestService>());
    }
}
