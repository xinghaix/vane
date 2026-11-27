//! 构建脚本：保证 web-ui/dist 存在（缺失时生成兜底 index.html），并校验前端预压缩产物。
use std::fs;
use std::path::Path;

const FALLBACK_INDEX: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Vane</title>
<link rel="manifest" href="/manifest.webmanifest">
<style>body{font-family:system-ui,sans-serif;background:#0b0d10;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}main{max-width:32rem;padding:2rem;text-align:center}code{background:#1c2026;padding:.1rem .4rem;border-radius:.3rem}</style>
</head>
<body>
<main>
<h1>Vane 网关</h1>
<p>前端资源尚未构建。请在 <code>web-ui/</code> 下执行 <code>npm run build</code> 后重新编译。</p>
<p>后端 API 已可通过 <code>/api/*</code> 访问。</p>
</main>
</body>
</html>
"#;

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn decode_b64_bytes(s: &str) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(s.len());
    let mut pad = 0usize;
    for b in s.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return None;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        vals.push(v);
    }
    let rem = vals.len() % 4;
    if rem == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    let mut chunks = vals.chunks_exact(4);
    for c in &mut chunks {
        out.push((c[0] << 2) | (c[1] >> 4));
        out.push((c[1] << 4) | (c[2] >> 2));
        out.push((c[2] << 6) | c[3]);
    }
    let tail = chunks.remainder();
    match tail.len() {
        0 => {}
        2 => out.push((tail[0] << 2) | (tail[1] >> 4)),
        3 => {
            out.push((tail[0] << 2) | (tail[1] >> 4));
            out.push((tail[1] << 4) | (tail[2] >> 2));
        }
        _ => return None,
    }
    Some(out)
}

fn parse_builtin_ed25519_pubkey(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let bytes = if trimmed.contains("-----BEGIN PUBLIC KEY-----") {
        let mut body = String::new();
        let mut in_block = false;
        let mut saw_end = false;
        for line in trimmed.lines() {
            let l = line.trim();
            if l == "-----BEGIN PUBLIC KEY-----" {
                in_block = true;
                continue;
            }
            if l == "-----END PUBLIC KEY-----" {
                saw_end = true;
                break;
            }
            if in_block && !l.is_empty() {
                body.push_str(l);
            }
        }
        if !in_block || !saw_end || body.is_empty() {
            return Err("OpenSSL Ed25519 SPKI PEM 格式无效".into());
        }
        let der = decode_b64_bytes(&body).ok_or_else(|| "PEM Base64 解码失败".to_string())?;
        if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
            return Err("PEM 不是合法的 Ed25519 SubjectPublicKeyInfo 公钥".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&der[12..]);
        out
    } else {
        let cleaned = trimmed
            .strip_prefix("ed25519:")
            .or_else(|| trimmed.strip_prefix("ED25519:"))
            .unwrap_or(trimmed)
            .trim();
        if let Some(hex_bytes) = decode_hex_32(cleaned) {
            hex_bytes
        } else {
            let decoded = decode_b64_bytes(cleaned)
                .ok_or_else(|| "需为 64 位 Hex、32 字节 Base64 或 OpenSSL Ed25519 SPKI PEM".to_string())?;
            if decoded.len() != 32 {
                return Err(format!("Ed25519 公钥解码长度必须为 32 字节（收到 {} 字节）", decoded.len()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            out
        }
    };

    if bytes.iter().all(|&b| b == 0) {
        return Err("Ed25519 公钥不能为全零".into());
    }
    let mut hex = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Ok(hex)
}

fn emit_builtin_update_pubkey() {
    println!("cargo:rerun-if-env-changed=VANE_BUILTIN_UPDATE_PUBKEY");
    let raw = std::env::var("VANE_BUILTIN_UPDATE_PUBKEY").unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        println!("cargo:rustc-env=VANE_COMPILED_UPDATE_PUBKEY=");
        return;
    }
    match parse_builtin_ed25519_pubkey(trimmed) {
        Ok(hex) => {
            println!("cargo:rustc-env=VANE_COMPILED_UPDATE_PUBKEY={hex}");
        }
        Err(e) => {
            panic!("VANE_BUILTIN_UPDATE_PUBKEY 非法: {e}");
        }
    }
}

fn main() {
    emit_builtin_update_pubkey();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let dist = Path::new(&manifest_dir).join("web-ui").join("dist");
    println!("cargo:rerun-if-changed=web-ui/dist");
    println!("cargo:rerun-if-changed=build.rs");

    if let Err(e) = fs::create_dir_all(&dist) {
        println!("cargo:warning=无法创建 web-ui/dist: {}", e);
        return;
    }
    let index = dist.join("index.html");
    if !index.exists() {
        if let Err(e) = fs::write(&index, FALLBACK_INDEX) {
            println!("cargo:warning=无法写入兜底 index.html: {}", e);
        } else {
            println!("cargo:warning=web-ui/dist 尚未构建，已生成兜底 index.html");
        }
        return;
    }
    // 校验预压缩产物：存在 index.html 但缺少 .br/.gz 时给出提示（运行期自动回退到原始文件）
    let has_br = dist.join("index.html.br").exists();
    let has_gz = dist.join("index.html.gz").exists();
    if !has_br && !has_gz {
        println!("cargo:warning=web-ui/dist 中未发现 .br/.gz 预压缩产物，将以原始文件提供服务");
    }
}
