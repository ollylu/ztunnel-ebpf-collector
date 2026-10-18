package asmprobe

import "time"

// BudgetPlan 是单次 case 的时间预算：deadline 从 Collect **入口**计算一次，
// CPU 工作与读取共享同一 deadline（避免 1s 工作 + 5s 读取叠加超时）。
type BudgetPlan struct {
	Entry    time.Time
	Deadline time.Time
	Burn     time.Duration
	Read     time.Duration
}

// PlanBudget 校验配置并从入口时间推导本次 case 的预算。
func PlanBudget(cfg Config, entry time.Time) (BudgetPlan, error) {
	if err := cfg.Validate(); err != nil {
		return BudgetPlan{}, err
	}
	burn := cfg.CPUBudget
	if half := cfg.Duration / 2; burn > half {
		burn = half
	}
	return BudgetPlan{
		Entry:    entry,
		Deadline: entry.Add(cfg.Duration),
		Burn:     burn,
		Read:     cfg.Duration - burn,
	}, nil
}
