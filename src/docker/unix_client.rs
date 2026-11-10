//! 轻量级 /var/run/docker.sock Unix Socket 客户端：支持容器列表、启停/重启（含受保护容器拦截）、
//! 日志流读取与悬空镜像 Prune，内置 Socket 重建自愈。
use crate::config::DockerConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerSummary {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub protected: bool,
}

pub fn is_protected_container(name: &str, cfg: &DockerConfig) -> bool {
    let clean = name.trim_start_matches('/');
    cfg.protected_containers.iter().any(|p| p.trim_start_matches('/').eq_ignore_ascii_case(clean))
}

async fn docker_raw_request(
    socket_path: &str,
    method: &str,
    path: &str,
) -> Result<(u16, Vec<u8>), String> {
    if socket_path.is_empty() || !Path::new(socket_path).exists() {
        return Err(format!("Docker Socket 不存在或未挂载: {}", socket_path));
    }
    let mut stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| "连接 docker.sock 超时".to_string())?
        .map_err(|e| format!("连接 docker.sock 失败: {}", e))?;

    let req = format!(
        "{} {} HTTP/1.0\r\nHost: localhost\r\nUser-Agent: vane/0.1\r\nConnection: close\r\n\r\n",
        method, path
    );
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut resp = Vec::with_capacity(8192);
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut resp))
        .await
        .map_err(|_| "读取 docker.sock 响应超时".to_string())?
        .map_err(|e| e.to_string())?;

    let Some(hdr_end) = resp.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("Docker 响应格式非法".into());
    };
    let hdr = String::from_utf8_lossy(&resp[..hdr_end]);
    let status = hdr
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(500);
    Ok((status, resp[hdr_end + 4..].to_vec()))
}

pub async fn list_containers(socket_path: &str, cfg: &DockerConfig) -> Result<Vec<ContainerSummary>, String> {
    let (status, body) = match docker_raw_request(socket_path, "GET", "/containers/json?all=1").await {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    if status >= 400 {
        return Err(format!("Docker API 返回状态码 {}", status));
    }
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let id = item.get("Id").and_then(|v| v.as_str()).unwrap_or("").chars().take(12).collect::<String>();
        let name = item
            .get("Names")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        let image = item.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let state = item.get("State").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let status_s = item.get("Status").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let protected = is_protected_container(&name, cfg);
        out.push(ContainerSummary { id, name, image, state, status: status_s, protected });
    }
    Ok(out)
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
    if (action == "stop" || action == "restart") && is_protected_container(id_or_name, cfg) {
        return Err(format!("受保护容器 {} 禁止通过面板执行 {} 操作", id_or_name, action));
    }
    let path = format!("/containers/{}/{}", id_or_name, action);
    let (status, body) = docker_raw_request(socket_path, "POST", &path).await?;
    if status >= 400 {
        return Err(format!("Docker 操作失败 ({}): {}", status, String::from_utf8_lossy(&body)));
    }
    Ok(())
}

pub async fn container_logs(
    socket_path: &str,
    cfg: &DockerConfig,
    id_or_name: &str,
    tail: Option<u32>,
) -> Result<String, String> {
    let lines = tail.unwrap_or(cfg.log_tail_default).clamp(10, 2000);
    let ts_flag = if cfg.log_timestamps { 1 } else { 0 };
    let path = format!("/containers/{}/logs?stdout=1&stderr=1&tail={}&timestamps={}", id_or_name, lines, ts_flag);
    let (status, body) = docker_raw_request(socket_path, "GET", &path).await?;
    if status >= 400 {
        return Err(format!("读取容器日志失败 ({})", status));
    }
    // 剥离 Docker Multiplexed Stream 8 字节帧头
    let cleaned = strip_docker_stream_headers(&body);
    Ok(String::from_utf8_lossy(&cleaned).into_owned())
}

pub async fn prune_dangling_images(socket_path: &str) -> Result<String, String> {
    let (status, body) = docker_raw_request(socket_path, "POST", "/images/prune?filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D").await?;
    if status >= 400 {
        return Err(format!("清理镜像失败 ({})", status));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
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
    if out.is_empty() {
        raw.to_vec()
    } else {
        out
    }
}
