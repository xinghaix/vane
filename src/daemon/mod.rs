//! 后台守护模块：双栈地址感知、DNS 服务商接口、DDNS、ACME 证书续期、Cron 调度与多渠道通知中心。
pub mod acme;
mod acme_transport;
mod acme_dns;
mod acme_store;
pub mod cron;
pub mod ddns;
pub mod dns_provider;
pub mod dns_api;
pub mod netlink_ip;
pub mod neighbor;
pub mod split_dns;
pub mod network_events;
pub mod notify;
