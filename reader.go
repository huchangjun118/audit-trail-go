package audit

// Cursor 是增量拉取游标：下一条待读记录的序号。
type Cursor uint64

// FirstCursor 从头开始拉取。
const FirstCursor = Cursor(1)

// snapshot 返回已提交记录的一致快照。读只加读锁，
// 快照后读操作不再阻塞写入推进。
func (s *Store) snapshot() []Record {
	s.viewMu.RLock()
	defer s.viewMu.RUnlock()
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out
}

// SeqRange 返回序号在 [from, to] 闭区间内的已提交记录。
func (s *Store) SeqRange(from, to uint64) []Record {
	recs := s.snapshot()
	if from == 0 {
		from = 1
	}
	var out []Record
	for _, r := range recs {
		if r.Seq < from {
			continue
		}
		if r.Seq > to {
			break
		}
		out = append(out, r)
	}
	return out
}

// TimeRange 返回时间戳（UnixNano）在 [from, to] 闭区间内的已提交记录。
func (s *Store) TimeRange(from, to int64) []Record {
	var out []Record
	for _, r := range s.snapshot() {
		ts := r.Timestamp.UnixNano()
		if ts >= from && ts <= to {
			out = append(out, r)
		}
	}
	return out
}

// ByActor 返回指定操作主体的已提交记录，按序号升序。
func (s *Store) ByActor(actor string) []Record {
	var out []Record
	for _, r := range s.snapshot() {
		if r.Actor == actor {
			out = append(out, r)
		}
	}
	return out
}

// Pull 从游标开始增量拉取至多 limit 条，返回记录与下一游标。
// 返回的记录数不足 limit 时表示已追到当前链尾。
func (s *Store) Pull(c Cursor, limit int) ([]Record, Cursor) {
	if limit <= 0 {
		return nil, c
	}
	recs := s.snapshot()
	var out []Record
	next := c
	for _, r := range recs {
		if r.Seq < uint64(c) {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, r)
		next = Cursor(r.Seq + 1)
	}
	return out, next
}

// LastSeq 返回当前已提交的最大序号，无记录时为 0。
func (s *Store) LastSeq() uint64 {
	s.viewMu.RLock()
	defer s.viewMu.RUnlock()
	if len(s.records) == 0 {
		return 0
	}
	return s.records[len(s.records)-1].Seq
}
