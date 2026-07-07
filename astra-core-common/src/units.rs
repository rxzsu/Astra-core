/// Byte size units.
pub mod bytes {
    pub const B: u64 = 1;
    pub const KB: u64 = 1024;
    pub const MB: u64 = 1024 * 1024;
    pub const GB: u64 = 1024 * 1024 * 1024;
    pub const TB: u64 = 1024 * 1024 * 1024 * 1024;

    pub fn format(size: u64) -> String {
        if size >= TB {
            format!("{:.2} TiB", size as f64 / TB as f64)
        } else if size >= GB {
            format!("{:.2} GiB", size as f64 / GB as f64)
        } else if size >= MB {
            format!("{:.2} MiB", size as f64 / MB as f64)
        } else if size >= KB {
            format!("{:.2} KiB", size as f64 / KB as f64)
        } else {
            format!("{} B", size)
        }
    }
}

/// Time duration units.
pub mod time {
    pub const MILLISECOND: u64 = 1;
    pub const SECOND: u64 = 1000;
    pub const MINUTE: u64 = 60 * 1000;
    pub const HOUR: u64 = 60 * 60 * 1000;

    pub fn format_ms(ms: u64) -> String {
        if ms >= HOUR {
            format!("{:.2}h", ms as f64 / HOUR as f64)
        } else if ms >= MINUTE {
            format!("{:.2}m", ms as f64 / MINUTE as f64)
        } else if ms >= SECOND {
            format!("{:.2}s", ms as f64 / SECOND as f64)
        } else {
            format!("{}ms", ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_format() {
        assert_eq!(bytes::format(500), "500 B");
        assert_eq!(bytes::format(1024), "1.00 KiB");
        assert_eq!(bytes::format(1048576), "1.00 MiB");
    }

    #[test]
    fn test_time_format() {
        assert_eq!(time::format_ms(500), "500ms");
        assert_eq!(time::format_ms(1500), "1.50s");
        assert_eq!(time::format_ms(120000), "2.00m");
    }
}
