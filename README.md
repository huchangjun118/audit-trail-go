# audit-trail-go

只追加（append-only）的操作留痕库。关键操作按发生顺序永久记录，
事后可查询具体操作内容，可证明历史自写入以来未被增删改，
出问题时可定位到最早被改动的记录序号。

## 快速开始

```go
cfg := audit.DefaultConfig("/var/lib/myapp/audit")
store, err := audit.Open(cfg)          // 打开并自动崩溃恢复
defer store.Close()

seq, _ := store.Append("alice", "transfer", payload)   // 单条追加
seqs, _ := store.AppendBatch(items)                    // 批量原子追加

recs := store.SeqRange(100, 200)       // 按序号区间查询
recs  = store.ByActor("alice")         // 按操作主体查询
recs  = store.TimeRange(from, to)      // 按时间范围查询
batch, next := store.Pull(cursor, 100) // 游标增量拉取

cp, _ := store.CreateCheckpoint()      // 固化校验点
anchor := store.Anchor()               // 本地锚定值，可对外发布
rep, _ := store.Verify()               // 从最近校验点校验到链尾
store.ApplyRetention(time.Now(), "")   // 删除过期段（或归档）
```

## 一致性语义

### 只追加与篡改检测
- 每条记录携带 `PrevHash` 与 `Hash`（SHA-256 链式哈希），任何对历史
  记录的**改写、插入、删除、截断**都会破坏链条并被 `Verify` 检测，
  报告**最早**出问题的序号与类别（modify/insert/delete/truncate/rollback）。
- 磁盘帧格式为 `[长度][CRC32][JSON 记录]`，低水平破坏（位翻转、半帧）
  由 CRC 与帧边界发现；高水平篡改（重算 CRC）由链式哈希发现；
  重算整条链则由校验点/锚定值发现。

### 并发追加与序号
- 提交由互斥锁串行化：序号严格递增、无空洞、无重复。
- 批次内序号按输入切片顺序连续分配，整批原子提交——要么全部可见，
  要么全部失败且盘上不留半批数据（失败时截断回批前位置）。
- 结果只取决于提交批次的内容与提交顺序，与并发调度、遍历顺序无关。

### 崩溃恢复
- 写入中途崩溃：重启时 `Open` 扫描段文件，截断撕裂的尾部帧，
  恢复停在最后一条**完整**记录；未完整落盘的记录不可见，序号不跳跃。
- 恢复时发现序号空洞或哈希链断裂（非撕裂损坏），返回
  `KindRecover` 错误并定位到具体序号。

### 读写并发
- 读者基于读锁下的一致快照工作，只能看到**已提交**的完整记录；
  慢读取（如慢速 `Pull`）不阻塞写入推进。

### 分段与保留
- 段按 `SegmentMaxBytes` 或 `RotationInterval` 轮转，封存后不再改写。
- `ApplyRetention` 删除（或归档）过期封存段，并为每段写入
  **保留锚点**（段区间 + 链头哈希）：删除旧段后剩余链仍可校验，
  锚点证明被删历史确实提交过。活跃段永不删除。

### 校验点与锚定
- `CreateCheckpoint` 固化当前链尾哈希；校验点之间也成链，
  文件只追加不改写。之后的 `Verify` 从最近校验点开始，只校验增量。
- `Anchor` 返回校验点链头哈希，对外发布即可证明链未被回退：
  任何使链尾回退或改写校验点之前历史的行为都会与锚定值矛盾。

### 错误分类
所有错误为 `*audit.Error`，含 `Kind`（write/verify/recover/config/notfound）、
操作名与（如适用）出问题的记录序号，可用 `errors.As` 区分。

## 配置项

| 字段 | 含义 | 默认值 |
|---|---|---|
| `Dir` | 数据目录 | 必填 |
| `SegmentMaxBytes` | 单段最大字节数，超过即切段 | 64 MiB |
| `RotationInterval` | 段轮转周期 | 1 小时 |
| `RetentionPeriod` | 段保留时长（过期可删/归档） | 7 天 |
| `MaxBatchRecords` | 单批最大条数 | 1024 |
| `Fsync` | 每次提交是否 fsync | true |

## 已知边界

- 无任何校验点/锚点时，对**最后一个段**在帧边界上的干净截断与
  正常关库不可区分；定期创建校验点并发布锚定值可消除该盲区。
- 内存中保存已提交记录索引，适合审计量级场景；超大规模可在此
  接口上演进为磁盘索引。

## 测试

```sh
go test -race ./...
```

覆盖：并发追加（序号无空洞无重复）、批量原子性、崩溃恢复（撕裂尾）、
篡改检测（改写/插入/删除/截断/整链重哈希）、旧段删除与归档、
校验点复用与只追加性、慢读取不阻塞写入。
