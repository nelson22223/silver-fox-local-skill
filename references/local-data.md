# 本地 AVTool 证据映射

导入器接受 `{ts, level, module, event_type, data}` 形式的 `investigation.jsonl` 记录。`events.id` 是 JSONL 中从 1 开始的原始行号。`record_json` 保留解析后的全部字段，`raw` 保留该行的原始字节；`decode_status` 标明 UTF-8、GB18030 恢复、替换解码或无效 JSON。来源 ZIP 的 SHA-256、成员列表和导入行数位于 `metadata` 与 `inventory`。

**一个数据库只对应一个输入包。** 默认名称为 `.silverfox-db/<输入名>-<来源 SHA-256 前缀>.sqlite`，同目录的多个包也不会混用数据库。可以通过 `--db` 指定路径，但已有文件不会被覆盖。导入和盘点命令都会输出 `database_path`；后续查询及报告校验必须使用该路径。跨数据库比较时，逐条标明来源包，不得把相同的记录 ID 当成同一证据。

所有命名视图保留相同的 `id`，便于报告引用。主要视图如下：

| 视图 | AVTool 事件来源 | 主要字段 |
|---|---|---|
| `browser_histories` | 存在时的 `browser_history` | `url`、`visit_time`、`browser` |
| `browser_downloads` | `browser_downloads` | `url`、`source_url`、`path`、`state`、`download_time`、`file_size`、`file_exists` |
| `last_activity_view_records` | `last_activity` | `action_time`、`description`、`filename`、`full_path`、`more_information`、`data_source` |
| `persistence_items` | `persistence_item` | `location`、`entry`、`enabled`、`image_path`、`launch_string`、`sha1` |
| `process_infos` | `process` | `p_id`、`ppid`、`name`、`path`、`cmdline`、`signing_status`、`modules` |
| `network_connections` | `network_connection` | `p_id`、`process_name`、`local_address`、`remote_address`、`state` |
| `virus_hits` | `virus_hit` | `file_path`、`rule_name`、`sha1`、`threat_level` |
| `memory_hits` | `memory_hit` | `p_id`、`process_name`、`rule_name`、`address`、`size`、`dump_path` |
| `system_infos` | `snapshot_begin` | `hostname`、`username`、`os_version`、`collection_start` |
| `native_artifacts` | `native_collection_item` | `artifact_type`、`batch_id`、`data_json` |

兼容原版 Schema 的 `autorun_items`、`dns_queries`、`dns_logs`、`virus_events`、`sample_analyses` 视图也会建立，但可能为空。空视图不证明该行为未发生，也可能是采集包没有对应来源。`native_artifacts` 包括 Prefetch、Amcache、USN 日志、SRUM、计划任务、崩溃记录、最近文件、软件安装和 DNS 缓存。导入器还建立 `prefetch_records`、`amcache_records`、`usn_journal_records`、`srum_network_records`、`scheduled_task_records`、`wer_crash_records`、`recent_file_records`、`software_install_records`、`dns_cache_records` 等分类视图，均提供 `id`、`ts`、`batch_id`、`data_json`。使用 `json_extract(data_json, '$.字段名')` 读取原始字段。

原版 JSON 的 `metrics.total_analyzed` 按七模块所对应的规范化视图行数求和：浏览器＝历史＋下载；活动＝LastActivity；持久化＝持久化项＋自启动项；进程＝进程；网络＝连接＋DNS 查询＋威胁 DNS；病毒＝扫描命中＋病毒事件＋样本分析；内存＝内存命中。校验器会与数据库核对这些计数。原版七模块没有原生工件模块，因此在 `post_run_review.coverage` 说明其覆盖情况，并在 Markdown 中充分呈现相关发现。

ZIP 可以包含嵌套样本。导入器只盘点其名称和大小，不读取或运行样本字节。若需另做样本分析，应先确定授权并保留原包。

## 常用 SQLite 查询

这里使用 SQLite 语法，不使用原项目 PostgreSQL 的 `ILIKE`、`array_agg`、`FILTER` 或类型转换。`query` 只接受只读的 `SELECT` 或 `WITH ... SELECT`，单次最多返回 200 行。`events.raw` 为二进制字段，避免对 `events` 使用 `SELECT *`。

```sql
SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC;
SELECT artifact_type, COUNT(*) AS n FROM native_artifacts GROUP BY artifact_type ORDER BY n DESC;
SELECT id, url, source_url, path, state, download_time FROM browser_downloads ORDER BY download_time;
SELECT id, action_time, description, full_path, data_source FROM last_activity_view_records WHERE description IN ('Run .EXE file','Open file or folder') ORDER BY action_time;
SELECT id, name, path, p_id, batch_id, signing_status FROM process_infos ORDER BY id;
SELECT id, rule_name, file_path, sha1, threat_level FROM virus_hits ORDER BY id;
SELECT id, process_name, p_id, rule_name, dump_path FROM memory_hits ORDER BY id;
SELECT id, json_extract(data_json, '$.executable_name') AS exe, json_extract(data_json, '$.run_count') AS runs FROM prefetch_records;
```

每类来源的 AVTool 原始字段均保留在 `data_json` 或 `record_json`。路径或时间关联通常只是调查线索，还需核对文件身份和事件先后。`network_connections.remote_address` 是原始端点文本，可能包含端口，不能一律当作纯 IP。`browser_downloads.file_size` 可能为空或 0，也不是哈希。本地包没有虚构的服务器 `task_id`；一个数据库对应一次导入。

注意 `inventory.quality.browser_download_rows_missing_core_fields`。上游 CSV 破行时，AVTool 可能生成字段不完整的下载记录。这些行连同原始字节仍被保留；不能把空的状态或路径解释为下载完成，也不能悄悄从相邻记录补造字段。
