package audit

import "time"

// Config 控制段大小、轮转周期、保留时长与单批条数等参数。
type Config struct {
	Dir             string        // 数据目录
	SegmentMaxBytes int64         // 单段最大字节数，超过则轮转
	SegmentMaxAge   time.Duration // 单段最长存活时间，超过则轮转
	RetentionAge    time.Duration // 段保留时长，过期段可删除/归档
	MaxBatchSize    int           // 单批最大条数
	SyncEveryWrite  bool          // 每批写入后是否 fsync
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.SegmentMaxBytes <= 0 {
		out.SegmentMaxBytes = 64 << 20
	}
	if out.SegmentMaxAge <= 0 {
		out.SegmentMaxAge = time.Hour
	}
	if out.MaxBatchSize <= 0 {
		out.MaxBatchSize = 1000
	}
	return out
}

func (c Config) validate() error {
	if c.Dir == "" {
		return &Error{Code: ErrCodeConfig, Msg: "Dir is required"}
	}
	return nil
}
