//! Policy system — 1:1 port of `features/policy` + `app/policy` from Go Xray-core.

use std::collections::HashMap;
use std::time::Duration;

// ─── Core policy types (Go: features/policy/policy.go) ────────────────────

/// Timeout limits for a connection.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutPolicy {
    /// Handshake timeout (Go: 60s)
    pub handshake: Duration,
    /// Connection idle timeout (Go: 300s)
    pub connection_idle: Duration,
    /// Uplink-only timeout (Go: 1s)
    pub uplink_only: Duration,
    /// Downlink-only timeout (Go: 1s)
    pub downlink_only: Duration,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        TimeoutPolicy {
            handshake: Duration::from_secs(60),
            connection_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(1),
            downlink_only: Duration::from_secs(1),
        }
    }
}

/// Stats counter settings.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatsPolicy {
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
}

/// Buffer size settings.
#[derive(Debug, Clone, Copy)]
pub struct BufferPolicy {
    /// Per-connection buffer size in bytes. -1 for unlimited.
    pub per_connection: i32,
}

impl Default for BufferPolicy {
    fn default() -> Self {
        BufferPolicy {
            per_connection: 512 * 1024,
        }
    }
}

/// Per-user-level session policy (Go: `Session`).
#[derive(Debug, Clone, Default)]
pub struct SessionPolicy {
    pub timeouts: TimeoutPolicy,
    pub stats: StatsPolicy,
    pub buffer: BufferPolicy,
}

/// System-level stats policy (Go: `System`).
#[derive(Debug, Clone, Default)]
pub struct SystemStatsPolicy {
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SystemPolicy {
    pub stats: SystemStatsPolicy,
    pub buffer: BufferPolicy,
}

/// Override a SessionPolicy with values from another (Go: `overrideWith`).
pub fn override_session(base: &mut SessionPolicy, overrides: &SessionPolicy) {
    if overrides.timeouts.handshake != Duration::default() {
        base.timeouts.handshake = overrides.timeouts.handshake;
    }
    if overrides.timeouts.connection_idle != Duration::default() {
        base.timeouts.connection_idle = overrides.timeouts.connection_idle;
    }
    if overrides.timeouts.uplink_only != Duration::default() {
        base.timeouts.uplink_only = overrides.timeouts.uplink_only;
    }
    if overrides.timeouts.downlink_only != Duration::default() {
        base.timeouts.downlink_only = overrides.timeouts.downlink_only;
    }
    if overrides.stats.user_uplink {
        base.stats.user_uplink = true;
    }
    if overrides.stats.user_downlink {
        base.stats.user_downlink = true;
    }
    if overrides.buffer.per_connection != 0 {
        base.buffer.per_connection = overrides.buffer.per_connection;
    }
}

// ─── Policy Manager (Go: app/policy/manager.go) ───────────────────────────

/// Policy manager that resolves per-level and system policies.
#[derive(Debug, Clone, Default)]
pub struct PolicyManager {
    levels: HashMap<u32, SessionPolicy>,
    system: SystemPolicy,
}

impl PolicyManager {
    pub fn new(levels: HashMap<u32, SessionPolicy>, system: SystemPolicy) -> Self {
        PolicyManager { levels, system }
    }

    /// Get session policy for a user level (Go: `ForLevel`).
    pub fn for_level(&self, level: u32) -> SessionPolicy {
        self.levels.get(&level).cloned().unwrap_or_default()
    }

    /// Get system policy (Go: `ForSystem`).
    pub fn for_system(&self) -> &SystemPolicy {
        &self.system
    }
}

/// Build policy manager from config types.
pub fn build_policy_manager(
    config_levels: &HashMap<u32, astra_core_config::policy::Policy>,
    config_system: &Option<astra_core_config::policy::SystemPolicy>,
) -> PolicyManager {
    let mut levels = HashMap::new();
    for (&lv, p) in config_levels {
        let mut sp = SessionPolicy::default();
        if let Some(v) = p.handshake {
            sp.timeouts.handshake = Duration::from_secs(v as u64);
        }
        if let Some(v) = p.conn_idle {
            sp.timeouts.connection_idle = Duration::from_secs(v as u64);
        }
        if let Some(v) = p.uplink_only {
            sp.timeouts.uplink_only = Duration::from_secs(v as u64);
        }
        if let Some(v) = p.downlink_only {
            sp.timeouts.downlink_only = Duration::from_secs(v as u64);
        }
        sp.stats.user_uplink = p.stats_user_uplink;
        sp.stats.user_downlink = p.stats_user_downlink;
        sp.stats.user_online = p.stats_user_online;
        if let Some(v) = p.buffer_size {
            sp.buffer.per_connection = v;
        }
        levels.insert(lv, sp);
    }

    let system = match config_system {
        Some(s) => SystemPolicy {
            stats: SystemStatsPolicy {
                inbound_uplink: s.stats_inbound_uplink,
                inbound_downlink: s.stats_inbound_downlink,
                outbound_uplink: s.stats_outbound_uplink,
                outbound_downlink: s.stats_outbound_downlink,
            },
            buffer: BufferPolicy::default(),
        },
        None => SystemPolicy::default(),
    };

    PolicyManager::new(levels, system)
}
