use super::*;
use axum::{extract::{Request, State}, routing::any, Router};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;

#[derive(Default)]
struct Mock { fail: AtomicBool, updates: Mutex<Vec<String>> }
async fn handler(State(state): State<Arc<Mock>>, request: Request) -> (http::StatusCode,String) {
    if request.uri().path()=="/address" { return (http::StatusCode::OK, "{\"v4\":\"1.1.1.1\",\"v6\":\"2606:4700::1111\"}".into()); }
    let uri=request.uri().to_string();
    let headers=request.headers().clone();
    let bytes=axum::body::to_bytes(request.into_body(),65536).await.unwrap();
    state.updates.lock().unwrap().push(format!("{} {:?} {}",uri,headers,String::from_utf8_lossy(&bytes)));
    if state.fail.load(Ordering::Relaxed) {(http::StatusCode::BAD_GATEWAY,"private-token".into())} else {(http::StatusCode::OK,"updated".into())}
}
async fn setup() -> (String,Arc<Mock>,JoinHandle<()>,Arc<FirewallManager>) {
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base=format!("http://{}",listener.local_addr().unwrap());
    let mock=Arc::new(Mock::default());
    let app=Router::new().fallback(any(handler)).with_state(mock.clone());
    let task=tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
    let firewall=FirewallManager::detect_and_init(crate::config::FirewallConfig{auto_manage:false,..Default::default()}).await;
    (base,mock,task,firewall)
}
fn entry(base:&str) -> DdnsConfig {
    DdnsConfig { name:"test".into(),provider:"custom_http".into(),domain:"home.example.com".into(),
        source:DdnsSource::CustomHttpExtract{url:format!("{base}/address")},token:"a&b".into(),
        custom_http:crate::config::CustomHttpTemplate {method:"POST".into(),url:format!("{base}/update?ip={{{{ip}}}}&token={{{{token}}}}"),
            headers:[("content-type".into(),"application/json".into()),("authorization".into(),"Bearer {{token}}".into())].into_iter().collect(),
            body:r#"{"ip":"{{ip}}","domain":"{{domain}}","token":"{{token}}"}"#.into(), success_keyword:"updated".into()},..Default::default() }
}

#[tokio::test]
async fn real_custom_updates_decrypt_and_report_failure_without_false_success() {
    let (base,mock,task,firewall)=setup().await;
    let vault=Vault::from_master(&[4;32]);
    let mut all=Config::default();all.ddns.push(entry(&base));
    vault.auto_seal(&mut all).unwrap();
    let runtime=Arc::new(DdnsRuntime::default());
    let status=sync_ddns_entry(&all.ddns[0],&all,&vault,&firewall,&runtime).await.unwrap();
    assert_eq!(status.status,"synced");
    assert_eq!(status.last_ipv4.as_deref(),Some("1.1.1.1"));
    assert_eq!(status.last_ipv6.as_deref(),Some("2606:4700::1111"));
    assert!(status.last_sync_unix>0);
    let updates=mock.updates.lock().unwrap().clone();
    assert_eq!(updates.len(),2);
    assert!(updates.iter().all(|text|text.contains("token=a%26b")&&text.contains("Bearer a&b")&&!text.contains("enc:v1:")));
    assert!(updates.iter().any(|text|text.contains("ip=2606%3A4700%3A%3A1111")));
    mock.fail.store(true,Ordering::Relaxed);
    let failed=sync_ddns_entry(&all.ddns[0],&all,&vault,&firewall,&runtime).await.unwrap();
    assert_eq!(failed.status,"failed");
    assert_eq!(failed.last_sync_unix,status.last_sync_unix);
    assert_eq!(failed.last_ipv4,status.last_ipv4);
    assert!(failed.ipv4.error.as_ref().unwrap().contains("502"));
    assert!(!serde_json::to_string(&failed).unwrap().contains("private-token"));
    task.abort();assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn ipv4_failure_does_not_prevent_ipv6_update() {
    let (base,mock,task,firewall)=setup().await;
    let vault=Vault::from_master(&[4;32]);
    let mut cfg=entry(&base);
    cfg.source=DdnsSource::ExternalUrl{url_v4:"http://127.0.0.1:1/address".into(),url_v6:String::new()};
    let backend=Ok(Backend::Custom(entry(&base)));
    let (v4,v6)=tokio::join!(reconcile_family(&cfg,"A",Err("地址源不可达".into()),&backend),
        reconcile_family(&cfg,"AAAA",Ok(Some("2606:4700::1111".parse().unwrap())),&backend));
    assert_eq!(v4.action,"failed");assert_eq!(v6.action,"synced");
    assert_eq!(mock.updates.lock().unwrap().len(),1);
    cfg.enabled=false;
    let status=sync_ddns_entry(&cfg,&Config::default(),&vault,&firewall,&Arc::new(DdnsRuntime::default())).await.unwrap();
    assert_eq!(status.status,"disabled");
    assert_eq!(mock.updates.lock().unwrap().len(),1);
    task.abort();assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn source_error_never_deletes_records_and_missing_ip_keeps_existing() {
    let mut cfg=DdnsConfig::default();
    cfg.on_missing_public_ip="delete_record".into();
    let backend=Err("不应访问服务商".into());
    let failed=reconcile_family(&cfg,"A",Err("查询失败".into()),&backend).await;
    assert_eq!(failed.error.as_deref(),Some("查询失败"));
    cfg.on_missing_public_ip="keep_existing".into();
    let missing=reconcile_family(&cfg,"AAAA",Ok(None),&backend).await;
    assert_eq!(missing.action,"kept_missing_ip");assert!(missing.error.is_none());
}

#[tokio::test]
async fn native_missing_address_deletes_only_requested_family_records() {
    let captured=Arc::new(Mutex::new(Vec::<String>::new()));
    let capture=captured.clone();
    let app=Router::new().fallback(any(move |request:Request| {
        let capture=capture.clone();async move {
            let path=request.uri().to_string();let method=request.method().to_string();
            capture.lock().unwrap().push(format!("{method} {path}"));
            let value=if method=="GET" {serde_json::json!({"success":true,"result":[{"id":"v6-record","name":"home.example.com","type":"AAAA","content":"2606:4700::1111"}]})}
                else {serde_json::json!({"success":true,"result":{"id":"v6-record"}})};
            axum::Json(value)
        }
    }));
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint=format!("http://{}",listener.local_addr().unwrap());
    let task=tokio::spawn(async move{axum::serve(listener,app).await.unwrap()});
    let vault=Vault::from_master(&[5;32]);
    let api=DnsApi::new("test",&crate::config::DnsProviderConfig{api_token:"test".into(),..Default::default()},&vault).unwrap().with_test_endpoint(endpoint);
    let backend=Ok(Backend::Native(api,Zone{id:"zone".into(),name:"example.com".into()}));
    let cfg=DdnsConfig{domain:"home.example.com".into(),on_missing_public_ip:"delete_record".into(),..Default::default()};
    let status=reconcile_family(&cfg,"AAAA",Ok(None),&backend).await;
    assert_eq!(status.action,"deleted");
    let requests=captured.lock().unwrap().clone();
    assert_eq!(requests.len(),2);
    assert!(requests[0].contains("type=AAAA"));
    assert_eq!(requests[1],"DELETE /zones/zone/dns_records/v6-record");
    let status=reconcile_family(&cfg,"A",Err("地址源超时".into()),&backend).await;
    assert_eq!(status.action,"failed");
    assert_eq!(captured.lock().unwrap().len(),2);
    task.abort();assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn external_address_families_report_partial_success_over_real_http() {
    let (base,mock,task,firewall)=setup().await;
    let mut cfg=entry(&base);
    cfg.source=DdnsSource::ExternalUrl{url_v4:format!("{base}/address"),url_v6:format!("{base}/address")};
    let status=sync_ddns_entry(&cfg,&Config::default(),&Vault::from_master(&[4;32]),&firewall,&Arc::new(DdnsRuntime::default())).await.unwrap();
    assert_eq!(status.status,"partial");
    assert_eq!(status.ipv4.action,"synced");
    assert_eq!(status.ipv6.action,"failed");
    assert_eq!(status.last_sync_unix,0);
    assert_eq!(mock.updates.lock().unwrap().len(),1);
    task.abort();assert!(task.await.unwrap_err().is_cancelled());
}

#[test]
fn same_rule_uses_same_mutex_and_different_rules_are_independent() {
    let runtime=DdnsRuntime::default();
    let a=runtime.rule_lock("a").unwrap();let b=runtime.rule_lock("b").unwrap();
    assert!(Arc::ptr_eq(&a,&runtime.rule_lock("a").unwrap()));
    assert!(!Arc::ptr_eq(&a,&b));
}
