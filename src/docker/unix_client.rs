//! 轻量级 /var/run/docker.sock 有界 HTTP/1.1 Unix Socket 客户端：
//! 支持 chunked 响应流式有界读取、容器 ID 与名称双重保护拦截、多路复用日志解帧与镜像 Prune。
use crate::config::DockerConfig;
use axum::body::Body;
use http::{Method, Request};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::net::UnixStream;

const MAX_DOCKER_JSON_BYTES: usize = 512 * 1024;
const MAX_DOCKER_LOG_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerSummary {
    pub id: String,
    #[serde(skip_serializing)]
    pub full_id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub protected: bool,
}

pub fn validate_container_ident(ident: &str) -> Result<&str, String> {
    let trimmed = ident.trim().trim_start_matches('/');
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err("容器标识长度非法".into());
    }
    if !trimmed.as_bytes()[0].is_ascii_alphanumeric()
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(format!("容器标识非法（必须以字母或数字开头）: {}", ident));
    }
    Ok(trimmed)
}

pub fn is_protected_container(name_or_id: &str, cfg: &DockerConfig) -> bool {
    let clean = name_or_id.trim().trim_start_matches('/');
    if clean.is_empty() {
        return false;
    }
    cfg.protected_containers.iter().any(|p| {
        let p_clean = p.trim().trim_start_matches('/');
        !p_clean.is_empty() && p_clean.eq_ignore_ascii_case(clean)
    })
}

async fn docker_http_request(
    socket_path: &str,
    method: Method,
    path_and_query: &str,
    max_bytes: usize,
) -> Result<(u16, Vec<u8>), String> {
    if socket_path.is_empty() || !Path::new(socket_path).exists() {
        return Err(format!("Docker Socket 不存在或未挂载: {}", socket_path));
    }
    let stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| "连接 docker.sock 超时".to_string())?
        .map_err(|e| format!("连接 docker.sock 失败: {}", e))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("Docker HTTP 握手失败: {}", e))?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("host", "localhost")
        .header("user-agent", "vane")
        .header("connection", "close")
        .body(Body::empty())
        .map_err(|e| format!("构造 Docker 请求失败: {}", e))?;

    let read_fut = async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| format!("发送 Docker 请求失败: {}", e))?;
        let status = resp.status().as_u16();
        let mut body = resp.into_body();
        let mut out = Vec::with_capacity(4096);
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|e| format!("读取 Docker 响应流失败: {}", e))?;
            if let Ok(data) = frame.into_data() {
                if out.len().saturating_add(data.len()) > max_bytes {
                    return Err(format!("Docker 响应超过 {} 字节安全上限", max_bytes));
                }
                out.extend_from_slice(&data);
            }
        }
        Ok::<_, String>((status, out))
    };

    let res = tokio::time::timeout(Duration::from_secs(15), read_fut)
        .await
        .map_err(|_| "读取 docker.sock 响应超时".to_string())?;
    conn_task.abort();
    res
}

pub async fn list_containers(socket_path: &str, cfg: &DockerConfig) -> Result<Vec<ContainerSummary>, String> {
    let (status, body) =
        docker_http_request(socket_path, Method::GET, "/containers/json?all=1", MAX_DOCKER_JSON_BYTES).await?;
    if status >= 400 {
        return Err(format!(
            "Docker API 返回错误 ({}): {}",
            status,
            String::from_utf8_lossy(&body).trim()
        ));
    }
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&body).map_err(|e| format!("解析容器列表 JSON 失败: {}", e))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let full_id = item.get("Id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let id: String = full_id.chars().take(12).collect();
        let all_names: Vec<String> = item
            .get("Names")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim_start_matches('/').to_string())
                    .collect()
            })
            .unwrap_or_default();
        let name = all_names.first().cloned().unwrap_or_default();
        let image = item.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let state = item.get("State").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let status_s = item.get("Status").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let protected = is_protected_container(&id, cfg)
            || is_protected_container(&full_id, cfg)
            || all_names.iter().any(|n| is_protected_container(n, cfg));
        out.push(ContainerSummary {
            id,
            full_id,
            name,
            image,
            state,
            status: status_s,
            protected,
        });
    }
    Ok(out)
}

/// 校验目标标识（无论传入容器名、短 ID 还是完整 64 位 ID）是否命中受保护容器列表
pub async fn ensure_not_protected(
    socket_path: &str,
    cfg: &DockerConfig,
    id_or_name: &str,
    action: &str,
) -> Result<(), String> {
    let clean = validate_container_ident(id_or_name)?;
    if is_protected_container(clean, cfg) {
        return Err(format!("受保护容器 {} 禁止执行 {} 操作", clean, action));
    }
    let containers = list_containers(socket_path, cfg).await?;
    for c in containers {
        let id_match = (clean.len() >= 6 && c.full_id.eq_ignore_ascii_case(clean))
            || (clean.len() >= 6 && c.full_id.to_ascii_lowercase().starts_with(&clean.to_ascii_lowercase()))
            || c.id.eq_ignore_ascii_case(clean)
            || c.name.eq_ignore_ascii_case(clean);
        if id_match && c.protected {
            return Err(format!("受保护容器 {} ({}) 禁止执行 {} 操作", c.name, c.id, action));
        }
    }
    Ok(())
}

pub async fn container_action(
    socket_path: &str,
    cfg: &DockerConfig,
    id_or_name: &str,
    action: &str,
) -> Result<(), String> {
    if !matches!(action, "start" | "stop" | "restart") {
        return Err(format!("不支持的容器动作: {}", action));
    }
    let clean = validate_container_ident(id_or_name)?;
    if action == "stop" || action == "restart" {
        ensure_not_protected(socket_path, cfg, clean, action).await?;
    }
    let path = format!("/containers/{}/{}", clean, action);
    let (status, body) = docker_http_request(socket_path, Method::POST, &path, MAX_DOCKER_JSON_BYTES).await?;
    if status >= 400 {
        return Err(format!(
            "Docker 操作失败 ({}): {}",
            status,
            String::from_utf8_lossy(&body).trim()
        ));
    }
    Ok(())
}

pub async fn container_logs(
    socket_path: &str,
    cfg: &DockerConfig,
    id_or_name: &str,
    tail: Option<u32>,
) -> Result<String, String> {
    let clean = validate_container_ident(id_or_name)?;
    let lines = tail.unwrap_or(cfg.log_tail_default).clamp(10, 2000);
    let ts_flag = if cfg.log_timestamps { 1 } else { 0 };
    let path = format!(
        "/containers/{}/logs?stdout=1&stderr=1&tail={}&timestamps={}",
        clean, lines, ts_flag
    );
    let (status, body) = docker_http_request(socket_path, Method::GET, &path, MAX_DOCKER_LOG_BYTES).await?;
    if status >= 400 {
        return Err(format!("读取容器日志失败 ({})", status));
    }
    let cleaned = strip_docker_stream_headers(&body);
    Ok(String::from_utf8_lossy(&cleaned).into_owned())
}

pub async fn prune_images(socket_path: &str, dangling_only: bool) -> Result<String, String> {
    let path = if dangling_only {
        "/images/prune?filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D"
    } else {
        "/images/prune?filters=%7B%22dangling%22%3A%5B%22false%22%5D%7D"
    };
    let (status, body) = docker_http_request(socket_path, Method::POST, path, MAX_DOCKER_JSON_BYTES).await?;
    if status >= 400 {
        return Err(format!("清理镜像失败 ({})", status));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

pub async fn prune_dangling_images(socket_path: &str) -> Result<String, String> {
    prune_images(socket_path, true).await
}

fn strip_docker_stream_headers(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0;
    while pos + 8 <= raw.len() {
        let stream_type = raw[pos];
        if stream_type <= 2 && raw[pos + 1] == 0 && raw[pos + 2] == 0 && raw[pos + 3] == 0 {
            let frame_len = u32::from_be_bytes([raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7]]) as usize;
            pos += 8;
            let end = (pos + frame_len).min(raw.len());
            out.extend_from_slice(&raw[pos..end]);
            pos = end;
        } else {
            return raw.to_vec();
        }
    }
    if out.is_empty() && !raw.is_empty() {
        raw.to_vec()
    } else {
        out
    }
}
