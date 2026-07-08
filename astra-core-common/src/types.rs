/// Utility types matching Go's `common/type.go`.
/// Provides Serializable, TypedMessage, and other base types.

/// Serializable interface (Go: `common.Serializable`).
pub trait Serializable: Send + Sync {
    fn serialize(&self) -> Result<Vec<u8>, String>;
    fn deserialize(data: &[u8]) -> Result<Self, String> where Self: Sized;
}

/// TypedMessage with type URL + value bytes (Go: `common/serial.TypedMessage`).
#[derive(Debug, Clone)]
pub struct TypedMessage {
    pub type_url: String,
    pub value: Vec<u8>,
}

impl TypedMessage {
    pub fn new(type_url: &str, value: Vec<u8>) -> Self {
        TypedMessage {
            type_url: type_url.to_string(),
            value,
        }
    }
}

/// Allocate a new typed message from a serializable value.
pub fn to_typed_message<T: Serializable>(val: &T) -> Result<TypedMessage, String> {
    let data = val.serialize()?;
    Ok(TypedMessage::new(std::any::type_name::<T>(), data))
}

/// Utility type for nullable values (Go: `*T` patterns).
#[derive(Debug, Clone)]
pub enum Nullable<T> {
    Null,
    Value(T),
}

impl<T> Nullable<T> {
    pub fn is_null(&self) -> bool {
        matches!(self, Nullable::Null)
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Nullable::Value(v) => Some(v),
            Nullable::Null => None,
        }
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(opt: Option<T>) -> Self {
        match opt {
            Some(v) => Nullable::Value(v),
            None => Nullable::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_message() {
        let msg = TypedMessage::new("xray.proxy.freedom.Config", vec![1, 2, 3]);
        assert_eq!(msg.type_url, "xray.proxy.freedom.Config");
        assert_eq!(msg.value, vec![1, 2, 3]);
    }

    #[test]
    fn test_nullable() {
        let n: Nullable<i32> = Nullable::Null;
        assert!(n.is_null());
        let v: Nullable<i32> = Nullable::Value(42);
        assert_eq!(*v.value().unwrap(), 42);
    }
}
