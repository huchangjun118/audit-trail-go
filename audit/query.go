package audit

import "time"

// Query 描述读取条件：序号区间、时间范围、操作主体。
type Query struct {
	SeqFrom  uint64    // 起始序号（含），0 表示从最早可用记录开始
	SeqTo    uint64    // 结束序号（含），0 表示到尾
	TimeFrom time.Time // 起始时间（含），零值不限
	TimeTo   time.Time // 结束时间（含），零值不限
	Actor    string    // 操作主体过滤，空不限
	Limit    int       // 最大返回条数，0 表示不限
}

// Query 按条件读取已提交的完整记录。
// 先在读锁内取索引快照，再在无锁状态下读段文件，慢查询不阻塞写入。
func (l *Log) Query(q Query) ([]*Record, error) {
	l.rmu.RLock()
	if l.closed {
		l.rmu.RUnlock()
		return nil, &Error{Code: ErrCodeClosed, Msg: "log is closed"}
	}
	from := q.SeqFrom
	if from < l.trunc.LastSeq+1 {
		from = l.trunc.LastSeq + 1
	}
	to := q.SeqTo
	if to == 0 || to > l.lastSeq {
		to = l.lastSeq
	}
	if from > to || l.lastSeq == l.trunc.LastSeq {
		l.rmu.RUnlock()
		return nil, nil
	}
	// 快照匹配的索引项。
	var snap []recordHeader
	for i := l.headIndex(from); i <= l.headIndex(to); i++ {
		h := l.heads[i]
		if !q.TimeFrom.IsZero() && h.ts.Before(q.TimeFrom) {
			continue
		}
		if !q.TimeTo.IsZero() && h.ts.After(q.TimeTo) {
			continue
		}
		if q.Actor != "" && h.actor != q.Actor {
			continue
		}
		snap = append(snap, h)
		if q.Limit > 0 && len(snap) >= q.Limit {
			break
		}
	}
	paths := make([]string, len(l.segs))
	for i, s := range l.segs {
		paths[i] = s.path
	}
	l.rmu.RUnlock()

	out := make([]*Record, 0, len(snap))
	for _, h := range snap {
		r, err := readFrameAt(paths[h.segIdx], h.offset, h.length)
		if err != nil {
			return nil, &Error{Code: ErrCodeVerify, Seq: h.seq, Msg: "read committed record", Err: err}
		}
		out = append(out, r)
	}
	return out, nil
}

// Fetch 从游标（不含 after）开始增量拉取，返回记录与下一游标。
// 返回的游标可直接用于下一次 Fetch，实现断点续拉。
func (l *Log) Fetch(after uint64, limit int) ([]*Record, uint64, error) {
	if limit <= 0 {
		limit = 100
	}
	recs, err := l.Query(Query{SeqFrom: after + 1, Limit: limit})
	if err != nil {
		return nil, 0, err
	}
	if len(recs) == 0 {
		return nil, after, nil
	}
	return recs, recs[len(recs)-1].Seq, nil
}
