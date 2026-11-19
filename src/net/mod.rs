//! 网络与数据面子系统：双栈绑定、TLS 证书池、单端口嗅探、流式反向代理、4x4 端口转发与 STUN 穿透。
pub mod dual_stack;
pub mod http_client;
pub mod listener;
pub mod port_forward;
pub mod reverse_proxy;
mod proxy_io;
mod proxy_body;
pub mod stun;
pub mod tls_resolver;

use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuleRuntimeStatus {
    pub name: String,
    pub enabled: bool,
    pub listen_port: u16,
    pub stack: String,
    pub proto: String,
    pub bound_v4: bool,
    pub bound_v6: bool,
    pub active_conns: usize,
    pub status: String,
    pub last_error: String,
    #[serde(skip)]
    pub quota: Option<listener::ConnectionQuota>,
}

pub type RuleStatusMap = Arc<RwLock<BTreeMap<String, RuleRuntimeStatus>>>;

pub fn new_rule_status_map() -> RuleStatusMap {
    Arc::new(RwLock::new(BTreeMap::new()))
}

pub fn update_rule_status(map: &Option<RuleStatusMap>, status: RuleRuntimeStatus) {
    if let Some(ref m) = map {
        if let Ok(mut g) = m.write() {
            g.insert(status.name.clone(), status);
        }
    }
}

pub fn snapshot_rule_statuses(map: &RuleStatusMap) -> Vec<RuleRuntimeStatus> {
    map.read()
        .map(|g| {
            g.values()
                .map(|s| {
                    let mut out = s.clone();
                    if let Some(ref q) = out.quota {
                        out.active_conns = q.active_connections();
                    }
                    out
                })
                .collect()
        })
        .unwrap_or_default()
}
