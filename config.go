package audit

import (
	"errors"
	"time"
)

// Config 控制段大小、轮转周期、保留时长与单批条数等参数。
type Config struct {
	Dir              string        // 数据目录
	SegmentMaxBytes  int64         // 单段最大字节数，超过即切段
	RotationInterval time.Duration // 段轮转周期，到期即切段
	RetentionPeriod  time.Duration // 段保留时长，过期段可删除/归档
	MaxBatchRecords  int           // 单批最大条数
	Fsync            bool          // 每次提交是否 fsync
}

// DefaultConfig 返回可用默认配置。
func DefaultConfig(dir string) Config {
	return Config{
		Dir:              dir,
		SegmentMaxBytes:  64 << 20,
		RotationInterval: time.Hour,
		RetentionPeriod:  7 * 24 * time.Hour,
		MaxBatchRecords:  1024,
		Fsync:            true,
	}
}

// Validate 校验配置合法性。
func (c Config) Validate() error {
	if c.Dir == "" {
		return wrapErr(KindConfig, "validate", errors.New("Dir is required"))
	}
	if c.SegmentMaxBytes <= 0 {
		return wrapErr(KindConfig, "validate", errors.New("SegmentMaxBytes must be > 0"))
	}
	if c.RotationInterval <= 0 {
		return wrapErr(KindConfig, "validate", errors.New("RotationInterval must be > 0"))
	}
	if c.MaxBatchRecords <= 0 {
		return wrapErr(KindConfig, "validate", errors.New("MaxBatchRecords must be > 0"))
	}
	return nil
}
