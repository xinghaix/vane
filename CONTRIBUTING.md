# 贡献指南 (Contributing Guide)

感谢关注并参与 **Vane** 的开发！

## 分支与合并规范

- `main` 分支受严格保护，**仅仓库所有者 (`@xinghaix`) 可直接推送或合并**。
- 所有外部贡献者请先 **Fork** 本仓库，在特性分支（如 `feat/xxx` 或 `fix/xxx`）完成开发后向 `main` 分支发起 **Pull Request (PR)**。
- 所有 PR 必须通过 GitHub Actions CI（`web-ui` 构建 + `cargo test` 全量测试 + `config.example.toml` 校验）并由 `@xinghaix` Code Review 后方可合并。

## 发版与持久化更新流程（维护者）

执行一键发版脚本即可同步版本号、运行全量检查并推送语义化标签：

```sh
./scripts/release.sh v0.1.0
```

GitHub Actions `Release` 工作流将自动完成多架构静态编译、生成 `SHA256SUMS`、创建 GitHub Release 并推送 `ghcr.io/xinghaix/vane` 多架构容器镜像。
