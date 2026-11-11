//! 一次性短期票据：只保存随机票据与管理员会话的摘要，绑定用途、目标与来源网段。
use super::auth::SessionStore;
use crate::net::dual_stack::BanKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct TicketClaim {
    pub session: [u8; 32],
    pub target: String,
    pub peer: BanKey,
    expires: Instant,
}
#[derive(Default)]
pub struct SessionTickets {
    tickets: Mutex<HashMap<[u8; 32], TicketClaim>>,
}
impl SessionTickets {
    pub fn issue(&self, session: &str, target: String, peer: BanKey) -> Result<String, String> {
        let mut tickets = self.tickets.lock().map_err(|_| "票据锁损坏")?;
        tickets.retain(|_, claim| claim.expires > Instant::now());
        if tickets.len() >= 128 {
            return Err("待使用票据已达上限".into());
        }
        let mut random = [0; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "票据随机源失败")?;
        let token = URL_SAFE_NO_PAD.encode(random);
        tickets.insert(
            SessionStore::token_digest(&token),
            TicketClaim {
                session: SessionStore::token_digest(session),
                target,
                peer,
                expires: Instant::now() + Duration::from_secs(30),
            },
        );
        Ok(token)
    }
    pub fn consume(&self, token: &str, target: &str, peer: BanKey) -> Option<[u8; 32]> {
        let claim = self
            .tickets
            .lock()
            .ok()?
            .remove(&SessionStore::token_digest(token))?;
        (claim.expires > Instant::now() && claim.target == target && claim.peer == peer)
            .then_some(claim.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_target_peer_and_consumes_only_once() {
        let tickets = SessionTickets::default();
        let peer = BanKey::from_peer("192.0.2.1".parse().unwrap());
        let token = tickets
            .issue("session", "proxy.example:8443/ws".into(), peer)
            .unwrap();
        assert_eq!(
            tickets.consume(&token, "proxy.example:8443/ws", peer),
            Some(SessionStore::token_digest("session"))
        );
        assert!(tickets
            .consume(&token, "proxy.example:8443/ws", peer)
            .is_none());
        let token = tickets.issue("session", "target-a".into(), peer).unwrap();
        assert!(tickets.consume(&token, "target-b", peer).is_none());
    }
}
