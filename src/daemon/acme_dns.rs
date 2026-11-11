//! DNS-01 挑战所有权与传播检查；只删除本轮挑战的确切 TXT 值。
use super::dns_api::{DnsApi, RecordSpec, Zone};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Lease {
    pub zone_name: String,
    pub zone_id: String,
    pub name: String,
    pub value: String,
}

#[async_trait::async_trait]
pub trait ChallengeDns: Send + Sync {
    async fn prepare(&self, name: &str, value: &str) -> Result<Lease, String>;
    async fn create(&self, lease: &Lease) -> Result<(), String>;
    async fn cleanup(&self, lease: &Lease) -> Result<(), String>;
    async fn propagated(&self, name: &str, value: &str) -> Result<bool, String>;
}

#[cfg(test)]
#[path = "acme_dns_tests.rs"]
mod tests;

pub struct ProviderDns {
    pub api: DnsApi,
    resolver: hickory_resolver::TokioResolver,
}
impl ProviderDns {
    pub fn new(api: DnsApi) -> Result<Self, String> {
        let mut builder = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|_| "无法读取系统 DNS 配置")?;
        let options = builder.options_mut();
        options.cache_size = 0;
        options.attempts = 1;
        options.timeout = std::time::Duration::from_secs(3);
        options.num_concurrent_reqs = 2;
        Ok(Self {
            api,
            resolver: builder.build(),
        })
    }
}
#[async_trait::async_trait]
impl ChallengeDns for ProviderDns {
    async fn prepare(&self, name: &str, value: &str) -> Result<Lease, String> {
        let zone = self.api.zone(name).await?;
        // 已有同值记录不属于本轮，不能在清理时误删它。
        if self
            .api
            .records(&zone, name, "TXT")
            .await?
            .iter()
            .any(|record| record.content == value)
        {
            return Err("已有相同挑战 TXT，请先核对遗留订单".into());
        }
        Ok(Lease {
            zone_name: zone.name,
            zone_id: zone.id,
            name: name.into(),
            value: value.into(),
        })
    }
    async fn create(&self, lease: &Lease) -> Result<(), String> {
        self.api
            .write_record(
                &Zone {
                    id: lease.zone_id.clone(),
                    name: lease.zone_name.clone(),
                },
                &RecordSpec {
                    name: lease.name.clone(),
                    kind: "TXT".into(),
                    content: lease.value.clone(),
                    ttl: 600,
                    proxied: false,
                    line: "default".into(),
                    comment: "Vane ACME DNS-01".into(),
                },
                None,
            )
            .await?;
        Ok(())
    }
    async fn cleanup(&self, lease: &Lease) -> Result<(), String> {
        let zone = Zone {
            id: lease.zone_id.clone(),
            name: lease.zone_name.clone(),
        };
        for record in self.api.records(&zone, &lease.name, "TXT").await? {
            if record.content == lease.value {
                self.api.delete(&zone, &record.id).await?;
            }
        }
        Ok(())
    }
    async fn propagated(&self, name: &str, value: &str) -> Result<bool, String> {
        match self
            .resolver
            .txt_lookup(format!("{}.", name.trim_end_matches('.')))
            .await
        {
            Ok(records) => Ok(records
                .iter()
                .any(|record| record.txt_data().concat() == value.as_bytes())),
            Err(_) => Ok(false),
        }
    }
}
