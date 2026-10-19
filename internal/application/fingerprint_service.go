// Package application 是应用层，负责编排领域能力，不包含具体识别规则。
package application

import (
	"context"
	"sync"

	"bannerfp/internal/domain"
)

// FingerprintService 编排批量指纹识别：负责并发控制与结果顺序保证。
type FingerprintService struct {
	matcher domain.Matcher
	workers int
}

// NewFingerprintService 创建批量识别服务。workers 小于 1 时按 1 处理。
func NewFingerprintService(matcher domain.Matcher, workers int) *FingerprintService {
	if workers < 1 {
		workers = 1
	}
	return &FingerprintService{matcher: matcher, workers: workers}
}

// Fingerprint 并发识别一批 banner，输出顺序与输入严格一致。
// 单条识别失败只会得到 unknown，不会中断整批任务。
func (s *FingerprintService) Fingerprint(ctx context.Context, items []domain.Banner) ([]domain.Fingerprint, error) {
	if len(items) == 0 {
		return []domain.Fingerprint{}, nil
	}

	results := make([]domain.Fingerprint, len(items))
	jobs := make(chan int)

	workerCount := s.workers
	if workerCount > len(items) {
		workerCount = len(items)
	}

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				// 每个 goroutine 只写自己的下标，无需额外加锁。
				results[index] = s.matcher.Identify(items[index])
			}
		}()
	}

	for index := range items {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
