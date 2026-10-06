# audit-trail-go

只追加（append-only）的操作留痕库。关键操作按发生顺序永久记录，
事后既能查到具体操作内容，也能证明历史自写入以来未被增删改，
出问题时可定位到最早被改动的记录。

## 快速开始

```go
l, err := audit.Open(audit.Config{
    Dir:             "/var/lib/audit",
    SegmentMaxBytes: 64 << 20,
    SegmentMaxAge:   time.Hour,
    RetentionAge:    30 * 24 * time.Hour,
    MaxBatchSize:    1000,
    SyncEveryWrite:  true,
})

seq, _ := l.Append("alice", "transfer", []byte(`{"amount":100}`))
seqs, _ := l.AppendBatch([]audit.Entry{{Actor: "bob", Action: "login"}, ...})

rec, _  := l.Get(seq)                                  // 按序号读
recs, _ := l.Query(audit.Query{Actor: "alice"})        // 条件查询
batch, cursor, _ := l.Fetch(0, 100)                    // 游标增量拉取

err = l.Verify()                                       // 全链校验
cp, _ := l.CreateCheckpoint()                          // 固化校验点
err = l.VerifyFrom(cp)                                 // 从校验点校验
err = l.ApplyRetention()                               // 删除过期段
```

## 一致性语义

### 只追加与篡改检测

- 每条记录携带 `PrevHash`（前一条记录的链哈希）与自身 `Hash`，
  构成 SHA-256 哈希链：`H(prev || seq || ts || actor || action || payload)`。
- 对历史的任何**改写、插入、删除、截断**都会破坏链条，
  `Verify` / `VerifyFrom` 返回 `*audit.Error`（`Code == ErrCodeVerify`），
  其 `Seq` 字段给出**最早出问题的序号**。
- 注意：若攻击者改写了第 k 条并重算其哈希，断裂点会体现在第 k+1 条
  （其 `PrevHash` 不再匹配），因此定位语义是"链条最早断裂的位置"。

### 序号与提交

- 提交在互斥锁内串行化：已提交记录的序号**严格递增、无空洞、无重复**。
- `AppendBatch` 是原子提交单元：整批获得连续序号，批内顺序即切片顺序。
- 在相同输入与相同提交批次（及相同时钟）下，序号与链哈希完全可复现，
  不受并发调度与遍历顺序影响。

### 崩溃恢复

- 记录以 `[4B 长度][主体][4B CRC32]` 帧写入段文件。
- 重启时扫描所有段：最后一条**完整**记录之后的半帧（崩溃残留）被截断；
  若第一条记录就不完整，则一条记录都不保留。绝不会读到半条记录，
  恢复后序号从最后一条完整记录继续，不发生跳跃。
- 非末尾段出现不完整尾部、序号空洞或链断裂，属于**恢复不一致**，
  `Open` 返回 `Code == ErrCodeRecover` 的错误并定位序号。

### 并发读写

- 读者只在取索引快照时短暂持有读锁，随后直接（独立文件句柄）读段文件；
  **慢读者不阻塞写入推进**。
- 读者只能看到已提交（写盘并发布索引）的完整记录。
- 支持按序号区间、时间范围、操作主体查询（`Query`），
  以及从游标开始的增量拉取（`Fetch`，返回下一游标）。

### 分段与保留

- 段按大小（`SegmentMaxBytes`）或存活时间（`SegmentMaxAge`）轮转，
  封存段只读，活跃段永不删除。
- `ApplyRetention` 删除超过 `RetentionAge` 的封存段。删除前先把被删前缀
  末条记录的 `(seq, hash)` 原子写入 `truncation.json`（先证明后删除），
  剩余链以该证明为起点继续校验——被删历史"确实被提交过"始终可证。

### 校验点与本地锚定

- `CreateCheckpoint` 在当前链头固化 `(seq, hash)`，写入 `cp-<seq>.json`
  （排他创建、只读权限，生成后不会被后续写入改写）。
- 校验点之间以 `PrevCpHash` 构成**校验点链**，`VerifyCheckpointChain`
  可证明校验点序列未被回退或替换。
- `VerifyFrom(cp)` 先做**锚定**：`cp.Seq` 处记录的哈希必须等于固化值——
  即使攻击者重写校验点之前的历史并重算整条链，链头哈希也必然偏离，
  从而证明该位置的链条没有被回退过；随后只需校验校验点之后的区间。

### 错误分类

| Code | 含义 |
|---|---|
| `ErrCodeWrite` | 写入失败（含批超限、段轮转失败、fsync 失败） |
| `ErrCodeVerify` | 校验失败（检测到篡改/删除/截断），`Seq` 定位最早问题记录 |
| `ErrCodeRecover` | 恢复不一致（非末尾段残缺、序号空洞、链断裂） |
| `ErrCodeNotFound` | 记录不存在（未提交或已随过期段删除） |
| `ErrCodeConfig` / `ErrCodeClosed` | 配置非法 / 日志已关闭 |

所有错误均为 `*audit.Error`，可用 `errors.As` 区分并读取 `Seq` 定位。
写入失败不会留下部分可见的脏数据：记录先写盘再发布索引，
未发布的帧对读者不可见，并在下次 `Open` 时被截断。

## 配置项

| 字段 | 默认 | 说明 |
|---|---|---|
| `Dir` | （必填） | 数据目录 |
| `SegmentMaxBytes` | 64 MiB | 单段最大字节数，超过则轮转 |
| `SegmentMaxAge` | 1 h | 单段最长存活时间，超过则轮转 |
| `RetentionAge` | 0（不删除） | 封存段保留时长，`ApplyRetention` 时生效 |
| `MaxBatchSize` | 1000 | 单批最大条数 |
| `SyncEveryWrite` | false | 每批提交后是否 fsync（崩溃持久性 vs 吞吐） |

## 测试

```sh
go test -race ./...
```

覆盖：并发追加（序号无空洞无重复）、批提交原子性、崩溃恢复
（半帧截断、全有或全无、中间段不一致）、篡改/删除/链重算检测、
旧段删除后校验与截断证明、校验点锚定/不可改写/保留后复用、
并发读写与游标拉取、查询过滤、确定性复现。
