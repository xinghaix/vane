//! 一次性短期票据：只保存随机票据与管理员会话的摘要，绑定用途、目标、来源网段与强因子 MFA 验证标记。
use super::auth::SessionStore;
pub use super::auth::ReauthConsumeError;
use crate::net::dual_stack::BanKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[allow(deprecated)]
use ring::constant_time;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct TicketClaim {
    pub session: [u8; 32],
    pub target: String,
    pub peer: BanKey,
    pub verified_with_mfa: bool,
    expires: Instant,
}
#[derive(Default)]
pub struct SessionTickets {
    tickets: Mutex<HashMap<[u8; 32], TicketClaim>>,
}
impl SessionTickets {
    pub fn issue(&self, session: &str, target: String, peer: BanKey) -> Result<String, String> {
        self.issue_with_mfa(session, target, peer, false)
    }

    pub fn issue_with_mfa(
        &self,
        session: &str,
        target: String,
        peer: BanKey,
        verified_with_mfa: bool,
    ) -> Result<String, String> {
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
                verified_with_mfa,
                expires: Instant::now() + Duration::from_secs(30),
            },
        );
        Ok(token)
    }

    pub fn consume(&self, token: &str, target: &str, peer: BanKey) -> Option<[u8; 32]> {
        self.consume_with_mfa(token, target, peer, false).ok()
    }

    pub fn consume_with_mfa(
        &self,
        token: &str,
        target: &str,
        peer: BanKey,
        require_mfa: bool,
    ) -> Result<[u8; 32], ReauthConsumeError> {
        let tok = token.trim();
        if tok.is_empty() {
            return Err(ReauthConsumeError::InvalidOrExpired);
        }
        let claim = self
            .tickets
            .lock()
            .map_err(|_| ReauthConsumeError::InvalidOrExpired)?
            .remove(&SessionStore::token_digest(tok))
            .ok_or(ReauthConsumeError::InvalidOrExpired)?;
        if claim.expires <= Instant::now() || claim.target != target || claim.peer != peer {
            return Err(ReauthConsumeError::InvalidOrExpired);
        }
        if require_mfa && !claim.verified_with_mfa {
            return Err(ReauthConsumeError::MfaRequired);
        }
        Ok(claim.session)
    }

    /// 签发默认未标记强因子 MFA 的一次性二次认证令牌（兼容旧调用方）。
    pub fn issue_reauth_token(&self, session_token: &str, peer_ip: IpAddr) -> Result<String, String> {
        self.issue_reauth_token_ex(session_token, peer_ip, false)
    }

    /// 签发带强因子 MFA 标记（TOTP / Passkey）的一次性二次认证令牌。
    pub fn issue_reauth_token_ex(
        &self,
        session_token: &str,
        peer_ip: IpAddr,
        verified_with_mfa: bool,
    ) -> Result<String, String> {
        self.issue_with_mfa(
            session_token,
            "reauth".to_string(),
            BanKey::from_peer(peer_ip),
            verified_with_mfa,
        )
    }

    /// 核销绑定当前会话与对端网段的二次认证令牌（不强制 MFA 标记，兼容旧调用方）。
    pub fn consume_reauth_token(
        &self,
        session_token: &str,
        reauth_token: &str,
        peer_ip: IpAddr,
    ) -> bool {
        self.consume_reauth_token_ex(session_token, reauth_token, peer_ip, false)
            .is_ok()
    }

    /// 核销绑定当前会话与对端网段的二次认证令牌，可按需强制要求强因子 MFA 验证。
    pub fn consume_reauth_token_ex(
        &self,
        session_token: &str,
        reauth_token: &str,
        peer_ip: IpAddr,
        require_mfa: bool,
    ) -> Result<(), ReauthConsumeError> {
        let tok = reauth_token.trim();
        if tok.is_empty() {
            return Err(ReauthConsumeError::InvalidOrExpired);
        }
        let expected_session = SessionStore::token_digest(session_token);
        let peer = BanKey::from_peer(peer_ip);
        let claim = self
            .tickets
            .lock()
            .map_err(|_| ReauthConsumeError::InvalidOrExpired)?
            .remove(&SessionStore::token_digest(tok))
            .ok_or(ReauthConsumeError::InvalidOrExpired)?;
        #[allow(deprecated)]
        let session_matches =
            constant_time::verify_slices_are_equal(&claim.session, &expected_session).is_ok();
        if claim.expires <= Instant::now()
            || claim.target != "reauth"
            || claim.peer != peer
            || !session_matches
        {
            return Err(ReauthConsumeError::InvalidOrExpired);
        }
        if require_mfa && !claim.verified_with_mfa {
            return Err(ReauthConsumeError::MfaRequired);
        }
        Ok(())
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

    #[test]
    fn reauth_token_enforces_mfa_flag_and_session_peer_binding() {
        let tickets = SessionTickets::default();
        let ip_a: IpAddr = "192.0.2.10".parse().unwrap();
        let ip_b: IpAddr = "192.0.2.11".parse().unwrap();

        // 仅口令签发的令牌可通过普通 Reauth，但在 require_mfa=true 时必须返回 MfaRequired
        let pw_tok = tickets.issue_reauth_token("sess-a", ip_a).unwrap();
        assert!(tickets.consume_reauth_token("sess-a", &pw_tok, ip_a));
        // 不可重放
        assert_eq!(
            tickets.consume_reauth_token_ex("sess-a", &pw_tok, ip_a, false),
            Err(ReauthConsumeError::InvalidOrExpired)
        );

        let pw_tok2 = tickets.issue_reauth_token_ex("sess-a", ip_a, false).unwrap();
        assert_eq!(
            tickets.consume_reauth_token_ex("sess-a", &pw_tok2, ip_a, true),
            Err(ReauthConsumeError::MfaRequired)
        );

        // 跨会话或跨 IP 绝不泄露 MfaRequired，统一返回 InvalidOrExpired
        let pw_tok3 = tickets.issue_reauth_token_ex("sess-a", ip_a, false).unwrap();
        assert_eq!(
            tickets.consume_reauth_token_ex("sess-b", &pw_tok3, ip_a, true),
            Err(ReauthConsumeError::InvalidOrExpired)
        );
        let pw_tok4 = tickets.issue_reauth_token_ex("sess-a", ip_a, false).unwrap();
        assert_eq!(
            tickets.consume_reauth_token_ex("sess-a", &pw_tok4, ip_b, true),
            Err(ReauthConsumeError::InvalidOrExpired)
        );

        // 强因子 MFA 签发的令牌可同时满足 require_mfa=true 与 require_mfa=false
        let mfa_tok = tickets.issue_reauth_token_ex("sess-a", ip_a, true).unwrap();
        assert_eq!(
            tickets.consume_reauth_token_ex("sess-a", &mfa_tok, ip_a, true),
            Ok(())
        );
        let mfa_tok2 = tickets.issue_reauth_token_ex("sess-a", ip_a, true).unwrap();
        assert!(tickets.consume_reauth_token("sess-a", &mfa_tok2, ip_a));
    }
}
