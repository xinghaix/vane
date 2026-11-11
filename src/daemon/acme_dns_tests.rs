use super::*;
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::{
        op::{Message, MessageType},
        rr::{
            rdata::{CNAME, TXT},
            Name, RData, Record,
        },
        xfer::Protocol,
    },
};

#[tokio::test]
async fn dns01_joins_txt_fragments_and_follows_cname_over_udp() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (count, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let request = Message::from_vec(&bytes[..count]).unwrap();
        let query = request.queries()[0].clone();
        let alias = Name::from_ascii("_acme-challenge.delegate.example.com.").unwrap();
        let mut reply = Message::new();
        reply
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .add_query(query.clone());
        reply.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::CNAME(CNAME(alias.clone())),
        ));
        reply.add_answer(Record::from_rdata(
            alias,
            60,
            RData::TXT(TXT::new(vec!["expected-".into(), "challenge".into()])),
        ));
        socket
            .send_to(&reply.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::new(address, Protocol::Udp)],
    );
    let resolver = hickory_resolver::TokioResolver::builder_with_config(
        config,
        TokioConnectionProvider::default(),
    )
    .build();
    let api = DnsApi::new(
        "test",
        &crate::config::DnsProviderConfig {
            api_token: "test".into(),
            ..Default::default()
        },
        &crate::security::vault::Vault::from_master(&[1; 32]),
    )
    .unwrap();
    let dns = ProviderDns { api, resolver };
    assert!(dns
        .propagated("_acme-challenge.home.example.com", "expected-challenge")
        .await
        .unwrap());
    assert!(!dns
        .propagated("_acme-challenge.home.example.com", "wrong")
        .await
        .unwrap());
    task.await.unwrap();
}
