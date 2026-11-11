use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn signing_matches_independent_python_vectors() {
    let parameters = [("Action","AddDomainRecord"),("DomainName","example.com"),("RR","home"),("Value","1.1.1.1")].into_iter().map(|(k,v)|(k.into(),v.into())).collect();
    assert_eq!(aliyun_signature(&parameters,"secret"),"yfN62FcCx6pUT17QLBJZ6TTJrIw=");
    let signed = tc3_authorization("id","secret","dnspod.tencentcloudapi.com",1551113065,br#"{"Domain":"example.com"}"#);
    assert!(signed.ends_with("Signature=d60a7a879edb9da2abd74efffb536777b9690d5fbb883ea9ac1fa4cf80c72a35"));
}

async fn fixture(responses: Vec<Value>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}",listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut captured = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buf = [0;4096];
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n>0);
                bytes.extend_from_slice(&buf[..n]);
                if let Some(end)=bytes.windows(4).position(|w| w==b"\r\n\r\n") {
                    let headers=String::from_utf8_lossy(&bytes[..end]);
                    let length:usize=headers.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v|v.trim().parse().ok())).unwrap_or(0);
                    if bytes.len()>=end+4+length {break;}
                }
            }
            captured.push(String::from_utf8(bytes).unwrap());
            let body=response.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
        }
        captured
    });
    (endpoint,task)
}

fn api(provider:&str) -> DnsApi {
    let vault=Vault::from_master(&[3;32]);
    let cfg=DnsProviderConfig { provider:provider.into(), api_token:vault.seal("dns_providers.test.api_token",b"test-id").unwrap(),secret_key:vault.seal("dns_providers.test.secret_key",b"secret").unwrap(),zone_name:"example.com".into(),..Default::default() };
    DnsApi::new("test",&cfg,&vault).unwrap()
}
fn spec() -> RecordSpec {
    RecordSpec { name:"home.example.com".into(),kind:"AAAA".into(),content:"2606:4700::1111".into(),ttl:600,proxied:false,line:"default".into(),comment:"test".into() }
}

#[tokio::test]
async fn cloudflare_discovers_zone_and_updates_then_deletes_record() {
    let (endpoint,task)=fixture(vec![
        json!({"success":true,"result":[{"id":"zone-id","name":"example.com"}]}),
        json!({"success":true,"result":[{"id":"record-id","name":"home.example.com","type":"AAAA","content":"2606:4700::1001"}]}),
        json!({"success":true,"result":{"id":"record-id"}}),
        json!({"success":true,"result":{"id":"record-id"}}),
    ]).await;
    let mut api=api("cloudflare");api.endpoint=endpoint;
    let zone=api.zone("home.example.com").await.unwrap();
    let id=api.upsert(&zone,&spec()).await.unwrap();
    api.delete(&zone,&id).await.unwrap();
    let requests=task.await.unwrap();
    assert!(requests[0].contains("/zones?name=example.com&"));
    assert!(requests[2].starts_with("PATCH /zones/zone-id/dns_records/record-id "));
    assert!(requests[2].contains("2606:4700::1111"));
    assert!(requests[3].starts_with("DELETE "));
    assert!(requests.iter().all(|r|r.contains("Bearer test-id")&&!r.contains("enc:v1:")));
}

#[tokio::test]
async fn aliyun_sends_signed_actual_record_operations() {
    let (endpoint,task)=fixture(vec![
        json!({"TotalCount":0,"DomainRecords":{"Record":[]}}),json!({"RecordId":"42"}),json!({"RecordId":"42"}),
    ]).await;
    let mut api=api("aliyun");api.endpoint=endpoint;
    let zone=api.zone("home.example.com").await.unwrap();
    let id=api.upsert(&zone,&spec()).await.unwrap();
    api.delete(&zone,&id).await.unwrap();
    let requests=task.await.unwrap();
    assert!(requests[0].contains("Action=DescribeDomainRecords"));
    assert!(requests[1].contains("Action=AddDomainRecord"));
    assert!(requests[1].contains("Value=2606%3A4700%3A%3A1111"));
    assert!(requests.iter().all(|r|r.contains("Signature=")&&!r.contains("secret")));
}

#[tokio::test]
async fn dnspod_sends_tc3_signed_actual_record_operations() {
    let (endpoint,task)=fixture(vec![
        json!({"Response":{"RecordCountInfo":{"TotalCount":1},"RecordList":[{"RecordId":42,"Name":"home","Type":"AAAA","Value":"2606:4700::1001"}]}}),
        json!({"Response":{"RecordId":42}}),json!({"Response":{"RequestId":"request-id"}}),
    ]).await;
    let mut api=api("dnspod");api.endpoint=endpoint;
    let zone=api.zone("home.example.com").await.unwrap();
    let id=api.upsert(&zone,&spec()).await.unwrap();
    api.delete(&zone,&id).await.unwrap();
    let requests=task.await.unwrap();
    assert!(requests[1].to_ascii_lowercase().contains("x-tc-action: modifyrecord"));
    assert!(requests[1].contains("\"RecordId\":42"));
    assert!(requests[1].contains("默认"));
    assert!(requests.iter().all(|r|r.contains("TC3-HMAC-SHA256 Credential=test-id/")&&!r.contains("secret")));
}

#[tokio::test]
async fn provider_business_failure_is_not_success() {
    let (endpoint,task)=fixture(vec![json!({"success":false,"errors":[{"message":"contains-private-token"}]})]).await;
    let mut api=api("cloudflare");api.endpoint=endpoint;
    let error=api.zone("home.example.com").await.unwrap_err();
    assert!(!error.contains("private-token"));
    task.await.unwrap();
}

#[test]
fn relative_record_names_are_zone_scoped() {
    let zone=Zone{id:"zone-id".into(),name:"example.com".into()};
    assert_eq!(relative_name("example.com",&zone).unwrap(),"@");
    assert_eq!(relative_name("_acme-challenge.home.example.com",&zone).unwrap(),"_acme-challenge.home");
    assert!(relative_name("evil-example.com",&zone).is_err());
}
