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

fn main() {
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
