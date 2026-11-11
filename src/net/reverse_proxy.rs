//! 基于 Hyper 的双栈 HTTP/1.1、HTTP/2 流式反代，连接和升级任务随监听器回收。
use crate::{config::{cidr_contains,parse_cidr,ReverseProxyConfig,ReverseProxyRule},firewall::{FirewallManager,FirewallRule},net::{dual_stack::{bind_dual_stack_tcp,StackMode},listener::ConnectionQuota,tls_resolver::{CertTable,DynamicCertResolver}}};
use super::{proxy_body::{StreamBody,Driver},proxy_io::TimedIo};
use arc_swap::ArcSwap;
use axum::body::Body;
use http::{HeaderMap,HeaderValue,Method,Request,Response,StatusCode,Uri,Version,header};
use hyper::{body::Incoming,service::service_fn};
use hyper_util::rt::{TokioIo,TokioTimer};
use std::{collections::BTreeMap,convert::Infallible,future::Future,net::{IpAddr,SocketAddr},sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
use tokio::{net::{TcpListener,TcpStream},sync::watch};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken,task::TaskTracker};

pub const HOP_BY_HOP_HEADERS:&[&str]=&["connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailer","trailers","transfer-encoding","upgrade"];

pub fn match_rule<'a>(rules: &'a [ReverseProxyRule], host: &str, path: &str) -> Option<&'a ReverseProxyRule> {
    let clean_host = host.parse::<http::uri::Authority>().map(|value|value.host().trim_matches(['[',']']).to_ascii_lowercase()).unwrap_or_else(|_|host.to_ascii_lowercase());
    rules
        .iter()
        .filter(|r| r.enabled && (r.host.eq_ignore_ascii_case(&clean_host) || r.host.strip_prefix("*.").is_some_and(|suffix|clean_host.split_once('.').is_some_and(|(_,tail)|tail.eq_ignore_ascii_case(suffix)))) && path.starts_with(&r.path_prefix))
        .max_by_key(|r| (r.path_prefix.len(), !r.host.starts_with("*.")))
}

pub fn check_rule_cidr_access(rule: &ReverseProxyRule, client_ip: IpAddr) -> bool {
    for d in &rule.denied_cidrs {
        if let Ok(cidr) = parse_cidr(d) {
            if cidr_contains(&cidr, client_ip) {
                return false;
            }
        }
    }
    if rule.allowed_cidrs.is_empty() {
        return true;
    }
    for a in &rule.allowed_cidrs {
        if let Ok(cidr) = parse_cidr(a) {
            if cidr_contains(&cidr, client_ip) {
                return true;
            }
        }
    }
    false
}

pub fn rewrite_request_path(path: &str, rule: &ReverseProxyRule) -> String {
    if !rule.strip_prefix || rule.path_prefix == "/" {
        return path.to_string();
    }
    let stripped = path.strip_prefix(&rule.path_prefix).unwrap_or(path);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{}", stripped)
    }
}

pub fn render_redirect_location(
    template: &str,
    path: &str,
    stun_addrs: &BTreeMap<String, String>,
) -> String {
    let mut out = template.replace("{{path}}", path);
    for (name, addr) in stun_addrs {
        let token = format!("{{{{stun.{}.public_addr}}}}", name);
        out = out.replace(&token, addr);
    }
    out
}

/// 授权策略由管理面实现；数据面不会接触密码或哈希。
pub trait ProxyAuthorization:Send+Sync {
    fn session(&self,headers:&HeaderMap,peer:IpAddr)->Option<[u8;32]>;
    fn websocket_ticket(&self,ticket:&str,target:&str,peer:IpAddr)->Option<[u8;32]>;
    fn session_alive(&self,session:&[u8;32])->bool;
    fn trusted_origin(&self,origin:&str,authority:&str)->bool {
        crate::web::boundary::origin_authority(origin)==crate::web::boundary::origin_authority(&format!("https://{authority}"))
            && crate::web::boundary::origin_authority(origin).is_some()
    }
}
struct NoAuthorization;
impl ProxyAuthorization for NoAuthorization {
    fn session(&self,_:&HeaderMap,_:IpAddr)->Option<[u8;32]>{None}
    fn websocket_ticket(&self,_:&str,_:&str,_:IpAddr)->Option<[u8;32]>{None}
    fn session_alive(&self,_:&[u8;32])->bool{false}
}

#[derive(Clone)]
struct TrackedExecutor {tasks:TaskTracker,cancel:CancellationToken}
impl<F> hyper::rt::Executor<F> for TrackedExecutor where F:Future+Send+'static,F::Output:Send {
    fn execute(&self,future:F){let cancel=self.cancel.clone();self.tasks.spawn(async move{tokio::select!{_=cancel.cancelled()=>{},_=future=>{}}});}
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop{fn drop(&mut self){self.0.cancel();}}
struct Context {
    rules:Arc<Vec<ReverseProxyRule>>,stun:Arc<ArcSwap<BTreeMap<String,String>>>,peer:SocketAddr,sni:Option<String>,
    auth:Arc<dyn ProxyAuthorization>,executor:TrackedExecutor,
}

pub async fn run_reverse_proxy_listener(cfg:ReverseProxyConfig,table:Arc<ArcSwap<CertTable>>,global:ConnectionQuota,firewall:Arc<FirewallManager>,stun:Arc<ArcSwap<BTreeMap<String,String>>>,shutdown:watch::Receiver<bool>)->Result<(),String>{
    run_reverse_proxy_authorized(cfg,table,global,firewall,stun,shutdown,Arc::new(NoAuthorization)).await
}
pub async fn run_reverse_proxy_authorized(cfg:ReverseProxyConfig,table:Arc<ArcSwap<CertTable>>,global:ConnectionQuota,firewall:Arc<FirewallManager>,stun:Arc<ArcSwap<BTreeMap<String,String>>>,mut shutdown:watch::Receiver<bool>,auth:Arc<dyn ProxyAuthorization>)->Result<(),String>{
    if !cfg.enabled{return firewall.remove_rule("reverse_proxy",&cfg.name).await;}
    if cfg.rules.iter().any(|rule|rule.enabled && rule.upstream_tls_mode=="insecure_skip_verify"){crate::logger::log(crate::logger::Level::Warn,"reverse_proxy","此监听器包含显式跳过上游证书校验的规则");}
    let bound=bind_dual_stack_tcp(cfg.listen_port,StackMode::parse(&cfg.stack)).map_err(|_|"反代监听端口绑定失败")?;
    if cfg.open_wan_firewall {
        if let Err(error)=firewall.upsert_rule(FirewallRule::WanInput{owner_module:"reverse_proxy".into(),rule_name:cfg.name.clone(),proto:"tcp".into(),port:cfg.listen_port,ipv4:bound.has_v4(),ipv6:bound.has_v6()}).await {
            let _=firewall.remove_rule("reverse_proxy",&cfg.name).await;return Err(error);
        }
    }
    let mut tls=rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(DynamicCertResolver::new(table,cfg.strict_sni)));
    tls.alpn_protocols=vec![b"h2".to_vec(),b"http/1.1".to_vec()];let acceptor=TlsAcceptor::from(Arc::new(tls));
    let quota=ConnectionQuota::new(cfg.max_concurrent_conns);let rules=Arc::new(cfg.rules.clone());let cancel=CancellationToken::new();let _cancel=CancelOnDrop(cancel.clone());
    let mut listeners=tokio::task::JoinSet::new();
    for listener in [bound.v4,bound.v6].into_iter().flatten(){
        listeners.spawn(accept_loop(listener,cfg.listen_port,acceptor.clone(),rules.clone(),global.clone(),quota.clone(),stun.clone(),auth.clone(),cancel.clone()));
    }
    let result=if *shutdown.borrow(){Ok(())}else{tokio::select!{_=shutdown.changed()=>Ok(()),result=listeners.join_next()=>match result{Some(Ok(result))=>result,_=>Err("反代监听任务异常结束".into())}}};
    cancel.cancel();while listeners.join_next().await.is_some(){}
    let cleanup=firewall.remove_rule("reverse_proxy",&cfg.name).await;
    result.and(cleanup)
}

async fn accept_loop(listener:TcpListener,port:u16,acceptor:TlsAcceptor,rules:Arc<Vec<ReverseProxyRule>>,global:ConnectionQuota,quota:ConnectionQuota,stun:Arc<ArcSwap<BTreeMap<String,String>>>,auth:Arc<dyn ProxyAuthorization>,cancel:CancellationToken)->Result<(),String>{
    let mut connections=tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=connections.join_next(),if !connections.is_empty()=>{},
            accepted=listener.accept()=>{
                let (mut stream,peer)=accepted.map_err(|_|"反代 accept 失败")?;
                let Some(global_permit)=global.try_acquire()else{continue};let Some(local_permit)=quota.try_acquire()else{continue};
                let acceptor=acceptor.clone();let rules=rules.clone();let stun=stun.clone();let auth=auth.clone();let cancel=cancel.child_token();
                connections.spawn(async move{
                    let (_global,_local)=(global_permit,local_permit);let _cancel=CancelOnDrop(cancel.clone());
                    let tasks=TaskTracker::new();
                    let work=async {
                        if !sniff(&mut stream,port,&rules).await?{return Ok(());}
                        let tls=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream)).await.map_err(|_|"反代 TLS 握手超时")?.map_err(|_|"反代 TLS 握手失败")?;
                        let sni=tls.get_ref().1.server_name().map(str::to_owned);
                        let write_timeout=Duration::from_secs(rules.iter().map(|rule|rule.read_timeout_secs).max().unwrap_or(120).clamp(1,86400));
                        let executor=TrackedExecutor{tasks:tasks.clone(),cancel:cancel.clone()};
                        let context=Arc::new(Context{rules,stun,peer,sni,auth,executor:executor.clone()});
                        let service=service_fn(move |request|{let context=context.clone();async move{Ok::<_,Infallible>(handle(request,context).await)}});
                        let mut builder=hyper_util::server::conn::auto::Builder::new(executor);
                        builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(32768).half_close(true);
                        builder.http2().max_concurrent_streams(16).max_send_buf_size(65536).initial_stream_window_size(65535);
                        let io=TimedIo::new(tls,write_timeout).without_read_deadline();
                        let _=builder.serve_connection_with_upgrades(TokioIo::new(io),service).await;
                        tasks.close();tasks.wait().await;Ok::<(),String>(())
                    };
                    tokio::select!{_=cancel.cancelled()=>{},_=work=>{}}
                    cancel.cancel();tasks.close();tasks.wait().await;
                });
            },
        }
    }
    while connections.join_next().await.is_some(){}Ok(())
}

async fn sniff(stream:&mut TcpStream,port:u16,rules:&[ReverseProxyRule])->Result<bool,String>{
    let mut byte=[0];let n=tokio::time::timeout(Duration::from_secs(5),stream.peek(&mut byte)).await.map_err(|_|"协议嗅探超时")?.map_err(|_|"协议嗅探失败")?;
    if n==0{return Err("空连接".into());}if byte[0]==0x16{return Ok(true);}
    let rules=Arc::new(rules.to_vec());
    let service=service_fn(move|request:Request<Incoming>|{
        let rules=rules.clone();async move {
            let response=(||{
                let authority=match authority(&request){Ok(value)=>value,Err(status)=>return empty(status)};
                let Ok(authority)=authority.parse::<http::uri::Authority>()else{return empty(StatusCode::BAD_REQUEST)};
                let host=authority.host();
                if match_rule(&rules,host,request.uri().path()).is_none(){return empty(StatusCode::NOT_FOUND);}
                let path=request.uri().path_and_query().map(|path|path.as_str()).unwrap_or("/");
                let location=if port==443{format!("https://{host}{path}")}else{format!("https://{host}:{port}{path}")};
                Response::builder().status(StatusCode::PERMANENT_REDIRECT).header(header::LOCATION,location).body(Body::empty()).unwrap_or_else(|_|empty(StatusCode::BAD_REQUEST))
            })();Ok::<_,Infallible>(response)
        }
    });
    let mut builder=hyper::server::conn::http1::Builder::new();builder.keep_alive(false).timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(3)).max_buf_size(8192);
    let _=tokio::time::timeout(Duration::from_secs(5),builder.serve_connection(TokioIo::new(stream),service)).await;Ok(false)
}

fn empty(status:StatusCode)->Response<Body>{Response::builder().status(status).body(Body::empty()).unwrap()}
fn clean_headers(headers:&mut HeaderMap){
    let nominated:Vec<_>=headers.get_all(header::CONNECTION).iter().filter_map(|value|value.to_str().ok()).flat_map(|value|value.split(',')).map(|name|name.trim().to_string()).collect();
    for name in nominated{headers.remove(name);}for name in HOP_BY_HOP_HEADERS{headers.remove(*name);}
}
fn custom_headers(headers:&mut HeaderMap,remove:&[String],set:&BTreeMap<String,String>)->Result<(),String>{
    for key in remove{headers.remove(key);}
    for (key,value) in set {
        if HOP_BY_HOP_HEADERS.contains(&key.to_ascii_lowercase().as_str())||key.eq_ignore_ascii_case("content-length")||key.eq_ignore_ascii_case("host"){return Err("禁止通过自定义头覆盖协议控制字段".into());}
        let key=http::HeaderName::from_bytes(key.as_bytes()).map_err(|_|"自定义头名称无效")?;let value=HeaderValue::from_str(value).map_err(|_|"自定义头值无效")?;headers.insert(key,value);
    }Ok(())
}
fn authority(request:&Request<Incoming>)->Result<String,StatusCode>{
    if request.version()==Version::HTTP_2 && request.uri().scheme_str()!=Some("https"){return Err(StatusCode::BAD_REQUEST);}
    if request.headers().get_all(header::HOST).iter().count()>1{return Err(StatusCode::BAD_REQUEST);}
    let host=request.headers().get(header::HOST).map(|v|v.to_str().map_err(|_|StatusCode::BAD_REQUEST)).transpose()?;
    let uri_host=request.uri().authority().map(|a|a.as_str());
    if request.version()!=Version::HTTP_2&&uri_host.is_some(){return Err(StatusCode::BAD_REQUEST);}
    if let (Some(a),Some(b))=(host,uri_host){if !a.eq_ignore_ascii_case(b){return Err(StatusCode::MISDIRECTED_REQUEST);}}
    let value=uri_host.or(host).ok_or(StatusCode::BAD_REQUEST)?;
    if crate::web::boundary::origin_authority(&format!("https://{value}")).is_none(){return Err(StatusCode::BAD_REQUEST);}
    Ok(value.into())
}
fn remove_gateway_cookie(headers:&mut HeaderMap){
    let cookies=headers.get_all(header::COOKIE).iter().filter_map(|v|v.to_str().ok()).flat_map(|v|v.split(';')).map(str::trim)
        .filter(|cookie|cookie.split_once('=').is_none_or(|(key,_)|key!="vane_session")).map(str::to_owned).collect::<Vec<_>>().join("; ");
    headers.remove(header::COOKIE);if !cookies.is_empty(){if let Ok(value)=HeaderValue::from_str(&cookies){headers.insert(header::COOKIE,value);}}
}
fn response_headers(headers:&mut HeaderMap,rule:&ReverseProxyRule)->Result<(),String>{
    clean_headers(headers);custom_headers(headers,&rule.response_headers_remove,&rule.response_headers_set)?;
    let cookies:Vec<_>=headers.get_all(header::SET_COOKIE).iter().filter(|v|v.to_str().ok().is_some_and(|v|!v.trim_start().starts_with("vane_session="))).cloned().collect();
    headers.remove(header::SET_COOKIE);for cookie in cookies{headers.append(header::SET_COOKIE,cookie);}Ok(())
}

async fn handle(mut request:Request<Incoming>,context:Arc<Context>)->Response<Body>{
    let authority=match authority(&request){Ok(value)=>value,Err(status)=>return empty(status)};
    let parsed: http::uri::Authority=match authority.parse(){Ok(value)=>value,Err(_)=>return empty(StatusCode::BAD_REQUEST)};
    let host=parsed.host().trim_matches(['[',']']);
    if context.sni.as_ref().is_some_and(|sni|!sni.eq_ignore_ascii_case(host)){return empty(StatusCode::MISDIRECTED_REQUEST);}
    let Some(rule)=match_rule(&context.rules,host,request.uri().path())else{return empty(StatusCode::NOT_FOUND)};
    if !check_rule_cidr_access(rule,context.peer.ip()){return empty(StatusCode::FORBIDDEN)};
    let session=context.auth.session(request.headers(),context.peer.ip());
    let upgrade=request.headers().get(header::UPGRADE).and_then(|v|v.to_str().ok()).is_some_and(|value|value.eq_ignore_ascii_case("websocket"));
    if rule.auth_gate&&session.is_none()&&!upgrade{return empty(StatusCode::UNAUTHORIZED);}
    if rule.auth_gate&&!matches!(*request.method(),Method::GET|Method::HEAD|Method::OPTIONS){
        if request.headers().get_all(header::ORIGIN).iter().count()!=1 || request.headers().get(header::ORIGIN).and_then(|v|v.to_str().ok()).is_none_or(|origin|!context.auth.trusted_origin(origin,&authority)){return empty(StatusCode::FORBIDDEN);}
    }
    let is_head=request.method()==Method::HEAD;
    if rule.mode=="static"{
        let mut response=Response::builder().status(rule.static_status).header(header::CONTENT_TYPE,&rule.static_content_type).header(header::CONTENT_LENGTH,rule.static_body.len())
            .body(if is_head{Body::empty()}else{Body::from(rule.static_body.clone())}).unwrap_or_else(|_|empty(StatusCode::INTERNAL_SERVER_ERROR));
        if response_headers(response.headers_mut(),rule).is_err(){return empty(StatusCode::INTERNAL_SERVER_ERROR);}return response;
    }
    if rule.mode=="redirect"{
        let location=render_redirect_location(&rule.redirect_url,request.uri().path_and_query().map(|v|v.as_str()).unwrap_or("/"),&context.stun.load());
        let mut response=Response::builder().status(rule.redirect_code).header(header::LOCATION,location).body(Body::empty()).unwrap_or_else(|_|empty(StatusCode::BAD_GATEWAY));
        if response_headers(response.headers_mut(),rule).is_err(){return empty(StatusCode::INTERNAL_SERVER_ERROR);}return response;
    }
    if request.method()==Method::CONNECT{return empty(StatusCode::METHOD_NOT_ALLOWED);}
    if upgrade && rule.mode!="proxy" {return empty(StatusCode::BAD_REQUEST);}
    if upgrade&&!rule.websocket{return empty(StatusCode::FORBIDDEN);}
    let mut websocket_session=None;
    let mut clean_query=Vec::new();let mut ticket=None;
    for part in request.uri().query().unwrap_or("").split('&').filter(|part|!part.is_empty()){
        if let Some(value)=part.strip_prefix("vane_ticket="){if ticket.replace(value.to_string()).is_some(){return empty(StatusCode::BAD_REQUEST);}}else{clean_query.push(part.to_string());}
    }
    let original_path=if clean_query.is_empty(){request.uri().path().to_string()}else{format!("{}?{}",request.uri().path(),clean_query.join("&"))};
    if upgrade {
        if request.version()!=Version::HTTP_11||request.method()!=Method::GET || request.headers().contains_key(header::TRANSFER_ENCODING) || request.headers().get(header::CONTENT_LENGTH).is_some_and(|value|value.as_bytes()!=b"0"){return empty(StatusCode::BAD_REQUEST);}
        let valid_connection=request.headers().get_all(header::CONNECTION).iter().filter_map(|v|v.to_str().ok()).any(|v|v.split(',').any(|item|item.trim().eq_ignore_ascii_case("upgrade")));
        if !valid_connection||request.headers().get_all(header::ORIGIN).iter().count()!=1{return empty(StatusCode::FORBIDDEN);}
        let Some(origin)=request.headers().get(header::ORIGIN).and_then(|v|v.to_str().ok())else{return empty(StatusCode::FORBIDDEN)};
        if !context.auth.trusted_origin(origin,&authority){return empty(StatusCode::FORBIDDEN);}
        let target=format!("{authority}{original_path}");
        websocket_session=ticket.as_ref().and_then(|ticket|context.auth.websocket_ticket(ticket,&target,context.peer.ip()));
        if websocket_session.is_none(){return empty(StatusCode::UNAUTHORIZED);}
    }
    let timeout=Duration::from_secs(rule.read_timeout_secs.clamp(1,86400));
    let limit=if rule.max_body_mb==0{None}else{Some(rule.max_body_mb.saturating_mul(1024*1024))};
    if request.headers().get(header::CONTENT_LENGTH).and_then(|v|v.to_str().ok()).and_then(|v|v.parse::<u64>().ok()).zip(limit).is_some_and(|(length,limit)|length>limit){return empty(StatusCode::PAYLOAD_TOO_LARGE);}
    let uri:Uri=match rule.upstream.parse(){Ok(uri)=>uri,Err(_)=>return empty(StatusCode::BAD_GATEWAY)};
    let socket=match tokio::time::timeout(Duration::from_secs(15),super::proxy_io::upstream(rule,&uri)).await{Ok(Ok(stream))=>stream,_=>return empty(StatusCode::BAD_GATEWAY)};
    let downstream_upgrade=upgrade.then(||hyper::upgrade::on(&mut request));
    let rewritten=rewrite_request_path(&original_path,rule);
    let base=uri.path().trim_end_matches('/');let mut path=format!("{base}{rewritten}");
    if let Some(query)=uri.query(){path.push(if path.contains('?'){'&'}else{'?'});path.push_str(query);}
    let (mut parts,incoming)=request.into_parts();parts.uri=match path.parse(){Ok(uri)=>uri,Err(_)=>return empty(StatusCode::BAD_REQUEST)};parts.version=Version::HTTP_11;
    clean_headers(&mut parts.headers);
    if rule.sanitize_forwarded_headers {
        let forged:Vec<_>=parts.headers.keys().filter(|key|key.as_str()=="forwarded"||key.as_str().starts_with("x-forwarded-")||key.as_str()=="x-real-ip").cloned().collect();
        for key in forged{parts.headers.remove(key);}
    }
    remove_gateway_cookie(&mut parts.headers);
    let gateway_bearer=parts.headers.get(header::AUTHORIZATION).and_then(|value|value.to_str().ok()).and_then(|value|value.strip_prefix("Bearer "))
        .is_some_and(|token|session==Some(crate::security::auth::SessionStore::token_digest(token)));
    if gateway_bearer{parts.headers.remove(header::AUTHORIZATION);}
    if custom_headers(&mut parts.headers,&rule.request_headers_remove,&rule.request_headers_set).is_err(){return empty(StatusCode::INTERNAL_SERVER_ERROR);}
    let upstream_host=if rule.upstream_host_header.is_empty(){uri.authority().map(|a|a.as_str()).unwrap_or("")}else{&rule.upstream_host_header};
    for (key,value) in [("host",upstream_host.to_string()),("x-real-ip",context.peer.ip().to_string()),("x-forwarded-for",context.peer.ip().to_string()),("x-forwarded-proto","https".into()),("x-forwarded-host",authority.clone())]{
        let Ok(value)=HeaderValue::from_str(&value)else{return empty(StatusCode::INTERNAL_SERVER_ERROR)};parts.headers.insert(http::HeaderName::from_static(key),value);
    }
    if upgrade{parts.headers.insert(header::CONNECTION,HeaderValue::from_static("upgrade"));parts.headers.insert(header::UPGRADE,HeaderValue::from_static("websocket"));}
    let exceeded=Arc::new(AtomicBool::new(false));let body=Body::new(StreamBody::new(incoming,limit,timeout,exceeded.clone(),None));
    let (mut sender,driver)=match hyper::client::conn::http1::handshake(TokioIo::new(TimedIo::new(socket,timeout))).await{Ok(value)=>value,Err(_)=>return empty(StatusCode::BAD_GATEWAY)};
    let cancel=context.executor.cancel.clone();let task=context.executor.tasks.spawn(async move{tokio::select!{_=cancel.cancelled()=>{},_=driver.with_upgrades()=>{}}});
    let driver=Driver(task.abort_handle());
    let mut response=match tokio::time::timeout(timeout,sender.send_request(Request::from_parts(parts,body))).await{
        Ok(Ok(response))=>response,
        _=>return empty(if exceeded.load(Ordering::Relaxed){StatusCode::PAYLOAD_TOO_LARGE}else{StatusCode::BAD_GATEWAY}),
    };
    if response.status()==StatusCode::SWITCHING_PROTOCOLS {
        if !upgrade||response.headers().get(header::UPGRADE).and_then(|v|v.to_str().ok()).is_none_or(|v|!v.eq_ignore_ascii_case("websocket")){return empty(StatusCode::BAD_GATEWAY);}
        let upstream_upgrade=hyper::upgrade::on(&mut response);let downstream_upgrade=downstream_upgrade.unwrap();let auth=context.auth.clone();let session=websocket_session.unwrap();let cancel=context.executor.cancel.clone();
        context.executor.tasks.spawn(async move{
            let _driver=driver;
            let tunnels=tokio::time::timeout(Duration::from_secs(10),async{tokio::try_join!(downstream_upgrade,upstream_upgrade)}).await;
            if let Ok(Ok((downstream,upstream)))=tunnels{
                let mut downstream=TimedIo::new(TokioIo::new(downstream),timeout);let mut upstream=TimedIo::new(TokioIo::new(upstream),timeout);
                let tunnel=tokio::io::copy_bidirectional(&mut downstream,&mut upstream);tokio::pin!(tunnel);let mut check=tokio::time::interval(Duration::from_secs(1));
                loop{tokio::select!{_=cancel.cancelled()=>break,_=&mut tunnel=>break,_=check.tick()=>if !auth.session_alive(&session){break;}}}
            }
        });
        let (mut parts,_)=response.into_parts();if response_headers(&mut parts.headers,rule).is_err(){return empty(StatusCode::BAD_GATEWAY);}
        parts.headers.insert(header::CONNECTION,HeaderValue::from_static("upgrade"));parts.headers.insert(header::UPGRADE,HeaderValue::from_static("websocket"));
        return Response::from_parts(parts,Body::empty());
    }
    let (mut parts,body)=response.into_parts();if response_headers(&mut parts.headers,rule).is_err(){return empty(StatusCode::BAD_GATEWAY);}
    Response::from_parts(parts,Body::new(StreamBody::new(body,None,timeout,Arc::new(AtomicBool::new(false)),Some(driver))))
}

#[cfg(test)]
#[path = "reverse_proxy_tests.rs"]
mod protocol_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matching_and_path_stripping() {
        let mut r1 = ReverseProxyRule {
            host: "nas.example.com".into(),
            path_prefix: "/".into(),
            upstream: "http://192.168.1.10:5000".into(),
            ..Default::default()
        };
        let mut r2 = ReverseProxyRule {
            host: "nas.example.com".into(),
            path_prefix: "/qb".into(),
            strip_prefix: true,
            upstream: "http://192.168.1.10:8080".into(),
            ..Default::default()
        };
        r1.enabled = true;
        r2.enabled = true;
        let rules = vec![r1, r2];
        let matched = match_rule(&rules, "NAS.example.com:8443", "/qb/api/v2").unwrap();
        assert_eq!(matched.path_prefix, "/qb");
        assert_eq!(rewrite_request_path("/qb/api/v2", matched), "/api/v2");
    }
}
