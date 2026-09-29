# 在 macOS 或 Windows 上安装与运行

解压下载包，保留完整的 `silver-fox-local` 目录。`SKILL.md` 必须直接位于该目录下，与 `scripts/`、`references/` 同级；多套一层目录可能导致 agent 找不到 Skill。Codex 用户可将该目录放入配置的 Skill 目录（`$CODEX_HOME/skills`，默认 `~/.codex/skills`）。其他 coding agent 应按自身文档设置 `SKILL.md` 搜索路径，或显式指定本文件。ZIP 本身无法使不支持 Skill 发现的 agent 自动调用它。

**运行 coding agent 的主机系统**决定命令。AVTool 证据通常来自 Windows，但可以在 macOS 上分析。两种主机运行同一套 Python 代码，没有另行选择分析规则的路由。

进入解压后的 `silver-fox-local` 目录，导入案件前先运行环境检查：

| 主机 | 环境检查 | 导入 |
|---|---|
| macOS 终端 | `python3 scripts/doctor.py --input "/path/to/analysis.zip"` | `python3 scripts/evidence.py import "/path/to/analysis.zip"` |
| Windows PowerShell | `py -3 scripts\doctor.py --input "C:\Cases\analysis.zip"` | `py -3 scripts\evidence.py import "C:\Cases\analysis.zip"` |

需要 Python 3.10+。macOS 的 `python3` 或 Windows 的 `py -3` 若指向更旧版本，应改用已安装 Python 3.10+ 的绝对路径；Windows 未安装 `py` 时也可尝试 `python`。检查器输出实际解释器、版本、主机系统、SQLite 版本和错误列表；返回非零状态说明环境或输入未准备好，应先处理错误。它检查 SQLite JSON 函数和 ZIP 中是否恰有一个 `investigation.jsonl`，但不提取样本，也不分析证据。

导入后，后续命令均使用导入结果中的 `database_path`。运行 `report_bundle.py init --db "<database_path>"` 建立该包的中文 Markdown 报告，再按 `SKILL.md` 继续调查。同一目录中多个包的数据库不能交叉使用。默认数据库和报告写在输入文件旁；若该目录不可写，应选择可写案件目录，并分别指定 `--db` 与 `--output-dir`。

ZIP 提供 Skill 指令和脚本，不包含 Python 解释器。脚本没有第三方 Python 包或服务器依赖。环境检查通过只证明本机基础条件满足。公开仓库在 macOS 和 Windows runner 上用合成采集包执行测试；真实 AVTool 附件尚未在 Windows 上完成全流程复核，不能把合成测试写成真实案件验证。
