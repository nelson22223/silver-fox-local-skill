# 报告回传与安装包说明

报告完成后默认回传完整 Markdown、JSON 报告和证据主机名。部署者确认相关数据允许回传后，制作预置接收地址与认证配置的免配置安装包，并在发放时说明发送内容和接收服务。使用者解压使用即可，后续报告完成后不再逐次询问。本地分析仍可离线完成；回传失败会明确提示，保留本地报告。不要把令牌提交到公开仓库、日志或报告。

## 发送内容

`scripts/feedback.py` 在内存中读取并校验同一采集包的 `report.md` 与 `report.json`，然后构造 `silverfox-feedback/v1` JSON：

| 字段 | 来源 |
|---|---|
| `schema_version` | 固定为 `silverfox-feedback/v1` |
| `skill` | 固定为 `silver-fox-local` |
| `status` | 最终报告校验通过时为 `success` |
| `report_hash` | 两份报告内容的组合 SHA-256；也作为幂等键 |
| `submitted_at` | 本次提交时的 UTC 时间 |
| `source_sha256` | 证据库中的采集包哈希 |
| `customer` | `--customer` 明确提供，未提供时为 `null` |
| `hostname` | 证据库首条非空主机名，或 `--hostname` 明确覆盖 |
| `analyst_id` | `--analyst-id` 明确提供，未提供时为 `null` |
| `report_markdown` | 完整中文 Markdown 报告 |
| `report_json` | 完整 v2 JSON 报告 |

脚本不会从用户目录、域名或报告文字推断客户或分析人员。接收方可按已认证账号或显式 `analyst_id` 统计使用人数，按 `report_hash` 去重统计提交数。若所有使用者共用一个服务令牌，服务端无法仅凭令牌统计人数。脚本不发送原始 ZIP、证据库、嵌套样本或内存转储。两份报告合计超过 8 MiB 或编码后的请求超过 10 MiB 时明确失败。

## 免配置安装包

安装包包含分析脚本、Skill、回传配置和认证令牌。使用者只需将解压后的 `silver-fox-local` 目录放到 coding agent 的 Skill 搜索位置；报告完成后默认上传，无需运行配置命令。此前称为“私有分发”仅指包内含认证信息、需通过可信渠道交付，不代表另一套分析功能或收费版本。部署者已有覆盖完整报告回传的授权时即可打包。构建命令在 Skill 根目录运行，输出路径必须在公开仓库之外：

```text
python3 scripts/build_distribution.py --output "/private/path/silver-fox-local.zip" --token-source "/private/path/feedback_token" --endpoint "https://feedback.example.org/feedback" --cert-sha256 "经核对的证书 SHA-256 指纹" --acknowledge-distribution-consent
```

构建脚本不输出令牌；私有 ZIP 在 macOS/Linux 上的文件权限为 600，Windows 上需通过 ACL 限制为仅当前使用者可读。ZIP 包含 `deployment/feedback.json` 和 `deployment/token`。接收方解压时的文件权限可能变化，首次上传会在 macOS/Linux 上把随包令牌文件设为 600。ZIP 本身没有加密，拿到 ZIP 的人也能取得共享令牌；仅通过可信渠道分发，不要上传公开仓库或公开下载站。所有收件人共用此令牌，服务端只能按报告中的客户、证据主机等信息分析案件来源，不能据此准确计算不同使用者人数。若需准确人数，应向不同收件人制作不同令牌的私有 ZIP。令牌泄露时需要在服务端撤销或轮换。

本机单独配置优先于随包配置；只有使用者明确运行 `disable` 才会写入停用覆盖项，之后即使随包配置仍存在也不上传。运行 `status` 可查看实际生效的配置来源。公开源码没有 `deployment/`，不携带令牌；默认 `submit` 在配置缺失时返回非零状态，不能静默跳过并称交付完成。

## 使用方法

配置前，应向使用者展示上述字段与接收地址。服务地址确定后，在 Skill 目录执行一次启用命令；配置文件保存在使用者配置目录，记录同意时间、范围、地址及令牌来源，不保存令牌值：

```text
python3 scripts/feedback.py configure --endpoint "https://feedback.example.org/feedback" --analyst-id "已授权的人员标识" --acknowledge-full-report-transfer
python3 scripts/feedback.py status
```

需要让后续 Skill 调用自动读取令牌时，可预先将服务端分配的令牌安全保存到使用者本机的私有文件，再为 `configure` 追加 `--token-file "/path/to/private/feedback_token"`。macOS/Linux 上文件权限必须为 600 或更严格；脚本拒绝符号链接、非普通文件和含空白字符的令牌。未指定文件时，从 `SILVERFOX_FEEDBACK_TOKEN` 环境变量读取。不要把令牌写进仓库、命令参数或报告。Windows 文件应设置仅当前使用者可读的 ACL。

当前服务使用自签证书时，可在上述 `configure` 命令中追加 `--cert-sha256 "经服务器侧独立核对的证书 SHA-256 指纹"`。指纹必须从可信的服务器管理渠道核对；不能仅以本机首次联网取得的指纹为准。客户端先完成 TLS 握手并比对指纹，匹配后才发送 HTTP 请求正文；不匹配即失败。服务换证后需重新核对并更新配置。使用可信 CA 证书且证书主机名匹配时，无需此参数，也不应使用 `curl -k` 或关闭证书验证。当前自签证书没有 IP 地址 SAN，直接按系统 CA 校验该 IP 会失败。

报告完成后，Skill 先做原有 bundle 校验，再默认运行以下命令。免配置安装包直接读取随包配置并发送完整报告，不需要每次在对话中再询问。配置缺失、令牌不可读、证书不匹配或网络错误均明确失败；本地报告文件仍保留。客户标识仅在能由案件上下文可靠确认时提供，否则留空：

```text
python3 scripts/feedback.py submit --db "/path/to/case.sqlite" --markdown "/path/to/report.md" --json "/path/to/report.json" --customer "已确认的客户标识"
```

`submit-if-enabled` 仅保留给旧版调用兼容，不作为新 Skill 的交付步骤。只有明确停用时，默认 `submit` 才返回 `submitted: false` 和 `disabled_by_user`。需要查看将发送的字段时，可运行预览；预览只显示字段、哈希与大小，不显示完整报告，也不联网：

```text
python3 scripts/feedback.py preview --db "/path/to/case.sqlite" --markdown "/path/to/report.md" --json "/path/to/report.json" --customer "已授权的客户标识" --analyst-id "已授权的人员标识"
```

也可对单份报告显式提交。执行者应通过安全方式设置 `SILVERFOX_FEEDBACK_TOKEN` 环境变量：

```text
python3 scripts/feedback.py send --db "/path/to/case.sqlite" --markdown "/path/to/report.md" --json "/path/to/report.json" --customer "已授权的客户标识" --analyst-id "已授权的人员标识" --endpoint "https://feedback.example.org/feedback" --consent-to-send
```

Windows 使用通过 `doctor.py` 检查的 Python 3.10+ 解释器。不要把真实令牌写进命令参数或工单。接口需要 `HTTPS POST /feedback`、`Content-Type: application/json`、`Authorization: Bearer <令牌>`，并应以 `Idempotency-Key` 去重。脚本不跟随重定向，15 秒超时；非 2xx 状态视为失败，不输出响应正文或重试。单凭客户端附带令牌并不能构成认证，服务端必须实际校验令牌后才接收报告。

接收服务的必填字段是 `schema_version`、`skill`、`report_hash`、`status`。完整报告提交还需同时包含 `submitted_at`、`source_sha256`、`report_markdown`、`report_json`；`customer`、`hostname`、`analyst_id` 为可选字符串或 `null`。`submitted_at` 为带时区的时间，`source_sha256` 和 `report_hash` 为 64 位十六进制字符串，`report_markdown` 为字符串，`report_json` 为对象且其 `schema_version` 为 `silverfox-report/v2`。服务端请求体上限为 10 MiB，`Idempotency-Key` 必须与 `report_hash` 一致。服务端按 `report_hash` 去重；收到的是解析后的 JSON，不能仅靠这些哈希证明原始采集包或报告文件的真实性。应以实际 POST 响应和服务端落盘核查确认完整报告上传，不能仅凭健康检查作此结论。

使用者可随时运行 `python3 scripts/feedback.py disable` 停用自动回传，再用 `status` 核查。重新启用必须再次执行带同意参数的 `configure`。若环境中只有 HTTP 地址，完整客户报告不应明文发送；需先通过 HTTPS 或其他已验证的加密通道接入，再调整配置。
