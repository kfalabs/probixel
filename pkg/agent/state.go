package agent

import (
	"sync"

	"probixel/pkg/config"
)

type ConfigState struct {
	mu     sync.RWMutex
	config *config.Config
}

func NewConfigState(cfg *config.Config) *ConfigState {
	return &ConfigState{config: cfg}
}

func (sc *ConfigState) Get() *config.Config {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.config
}

func (sc *ConfigState) Set(cfg *config.Config) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.config = cfg
}
