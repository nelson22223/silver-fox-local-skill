# 银狐 AVTool 本地分析 Skill

这是一份可在 macOS 或 Windows 上由 Codex 等支持 `SKILL.md` 的 coding agent 调用的离线取证 Skill。输入为 AVTool 采集 ZIP（内含 `investigation.jsonl`）或 JSONL 文件；每个采集包分别保存 SQLite 证据库，并输出可持续更新的中文 `report.md` 与原版 `silverfox-report/v2` 格式的 `report.json`。

分析脚本只使用 Python 3.10+ 标准库，不依赖 PostgreSQL、原项目 Worker 或第三方 Python 包。脚本负责导入、查询和引用校验；案件研判与报告文字由调用它的 coding agent 完成。它不会运行 ZIP 中的样本，也不会上传原始采集包。**报告完成后默认回传完整 Markdown 与 JSON 报告。** 免配置安装包已包含部署者授权的接收地址与认证配置，解压使用即可，无需接收者手动设置或逐次确认。公开源码包不含凭据，缺少配置时默认提交会明确失败，不能视为已回传。字段、打包及停用方法见[报告回传与安装包说明](references/feedback.md)。

## 安装

将本仓库完整放入 coding agent 配置的 Skill 搜索目录，使 `SKILL.md` 直接位于 `silver-fox-local/` 根目录。Codex 通常使用 `$CODEX_HOME/skills`，默认 `~/.codex/skills`；其他 agent 请按其自身文档配置。可直接阅读 [SKILL.md](SKILL.md) 和[安装与运行说明](references/setup.md)。

## 首次使用

在本目录运行环境检查，确认 Python、SQLite 和输入包结构：

```text
# macOS
python3 scripts/doctor.py --input "/path/to/analysis.zip"

# Windows PowerShell
py -3 scripts\doctor.py --input "C:\Cases\analysis.zip"
```

检查通过后，使用同一个 Python 解释器运行 `scripts/evidence.py import`。导入结果会打印 `database_path`；后续盘点、查询、报告初始化和校验都使用这个路径。具体命令见 [SKILL.md](SKILL.md)。同目录多个输入包按文件名与来源 SHA-256 分开存储，已有数据库或报告不会被覆盖。

## 报告与边界

- `report.md` 供人阅读，调查中可标注“分析中”、逐步补全证据链和缺口；新建及后续更新均使用简体中文。
- `report.json` 保留原版 v2 结构，供程序解析；它在证据审查完成后生成，并接受 Schema、计数和证据引用校验。
- 原始 ZIP/JSONL 仍是证据源。数据库保留每行原始字节及未知字段，不能用报告替代原件。
- 规则命中、单个进程名或公开 IOC 不自动证明银狐归因。结论应标明观察事实、推断与未验证环节。

项目不提供 Python 解释器，也不保证所有 coding agent 都支持自动发现 `SKILL.md`。macOS 已用真实 AVTool 附件验证导入和报告校验；GitHub Actions 的 macOS/Windows runner 已用合成输入通过环境检查及测试。真实 AVTool 附件尚未在 Windows 上完成全流程复核。原版 JSON 的七模块结构无法把所有原生工件作为主详情，相关发现应在 Markdown 中完整叙述。

## 许可证

本仓库采用 [MIT 许可证](LICENSE)。公开仓库不包含任何案件采集包、数据库、样本或客户报告。
