use super::unix_client::*;
use crate::config::DockerConfig;
use axum::{
    body::Body,
    extract::{Path as AxumPath, Request},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::path::PathBuf;
use tokio::net::UnixListener;

struct TempSock(PathBuf);
impl TempSock {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("vd_{}.sock", crate::config::random_nonce() % 1_000_000));
        let _ = std::fs::remove_file(&p);
        Self(p)
    }
}
impl Drop for TempSock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn missing_non_socket_and_symlink_return_uniform_error_without_existence_oracle() {
    let cfg = DockerConfig::default();
    let err_missing = list_containers("/tmp/vane_nonexistent_docker_99999.sock", &cfg)
        .await
        .unwrap_err();
    assert!(err_missing.contains("不存在"));

    let reg = std::env::temp_dir().join(format!("vane_not_sock_{}.txt", crate::config::random_nonce()));
    std::fs::write(&reg, b"plain").unwrap();
    let err_reg = list_containers(reg.to_str().unwrap(), &cfg).await.unwrap_err();
    let _ = std::fs::remove_file(&reg);

    let real_sock = TempSock::new();
    let _listener = UnixListener::bind(&real_sock.0).unwrap();
    let sym = std::env::temp_dir().join(format!("vane_sym_sock_{}.sock", crate::config::random_nonce()));
    std::os::unix::fs::symlink(&real_sock.0, &sym).unwrap();
    let err_sym = list_containers(sym.to_str().unwrap(), &cfg).await.unwrap_err();
    let _ = std::fs::remove_file(&sym);

    // 缺失路径、普通文件与符号链接必须返回完全一致的错误消息，消除存在性预言机
    assert_eq!(err_missing, err_reg);
    assert_eq!(err_missing, err_sym);
}

#[tokio::test]
async fn unix_socket_chunked_list_id_protection_logs_demux_and_prune_work() {
    let sock = TempSock::new();
    let listener = UnixListener::bind(&sock.0).unwrap();

    let app = Router::new()
        .route(
            "/containers/json",
            get(|| async {
                Json(json!([
                    {
                        "Id": "a1b2c3d4e5f600001111222233334444555566667777888899990000aaaabbbb",
                        "Names": ["/vane_alias", "/vane"],
                        "Image": "ghcr.io/xinghaix/vane:latest",
                        "State": "running",
                        "Status": "Up 2 hours"
                    },
                    {
                        "Id": "f0e1d2c3b4a59999888877776666555544443333222211110000ffffeeeedddd",
                        "Names": ["/jellyfin"],
                        "Image": "jellyfin/jellyfin:latest",
                        "State": "running",
                        "Status": "Up 5 hours"
                    }
                ]))
            }),
        )
        .route(
            "/containers/{id}/{action}",
            post(|AxumPath((_id, _action)): AxumPath<(String, String)>| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/containers/{id}/logs",
            get(|| async {
                // 构造两帧 Docker 8 字节多路复用流（stdout + stderr）
                let mut mux = Vec::new();
                let line1 = b"hello stdout\n";
                mux.extend_from_slice(&[1, 0, 0, 0]);
                mux.extend_from_slice(&(line1.len() as u32).to_be_bytes());
                mux.extend_from_slice(line1);
                let line2 = b"warn stderr\n";
                mux.extend_from_slice(&[2, 0, 0, 0]);
                mux.extend_from_slice(&(line2.len() as u32).to_be_bytes());
                mux.extend_from_slice(line2);
                (StatusCode::OK, Body::from(mux)).into_response()
            }),
        )
        .route(
            "/images/prune",
            post(|req: Request| async move {
                let q = req.uri().query().unwrap_or("").to_string();
                Json(json!({ "Query": q, "SpaceReclaimed": 4096 }))
            }),
        );

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let svc = app.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(move |req| {
                            let mut s = svc.clone();
                            async move { tower::Service::call(&mut s, req).await }
                        }),
                    )
                    .await;
            });
        }
    });

    let sock_str = sock.0.to_str().unwrap();
    let cfg = DockerConfig::default(); // protected_containers = ["vane"]

    let list = list_containers(sock_str, &cfg).await.unwrap();
    assert_eq!(list.len(), 2);
    assert!(list[0].protected);
    assert_eq!(list[0].all_names, vec!["vane_alias".to_string(), "vane".to_string()]);
    assert!(!list[1].protected);

    // 试图通过短 ID 或次级别名停止受保护容器 vane -> 必须被拦截！
    let err = container_action(sock_str, &cfg, "a1b2c3d4e5f6", "stop").await.unwrap_err();
    assert!(err.contains("受保护容器"));
    let err_alias = container_action(sock_str, &cfg, "vane_alias", "stop").await.unwrap_err();
    assert!(err_alias.contains("受保护容器"));

    // 非保护容器重启成功
    container_action(sock_str, &cfg, "f0e1d2c3b4a5", "restart").await.unwrap();

    // 多路复用日志解包
    let logs = container_logs(sock_str, &cfg, "jellyfin", Some(50)).await.unwrap();
    assert_eq!(logs, "hello stdout\nwarn stderr\n");

    // 镜像清理 dangling_only = false 与 true 参数区分
    let p_true = prune_images(sock_str, true).await.unwrap();
    assert!(p_true.contains("true"));
    let p_false = prune_images(sock_str, false).await.unwrap();
    assert!(p_false.contains("false"));
}
