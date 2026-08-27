package agent

import (
	"sync"
	"testing"

	"probixel/pkg/config"
)

func TestConfigState_GetSet(t *testing.T) {
	initialCfg := &config.Config{
		Global: config.GlobalConfig{
			DefaultInterval: "10s",
		},
	}
	state := NewConfigState(initialCfg)

	got := state.Get()
	if got.Global.DefaultInterval != "10s" {
		t.Errorf("expected interval 10s, got %s", got.Global.DefaultInterval)
	}

	newCfg := &config.Config{
		Global: config.GlobalConfig{
			DefaultInterval: "20s",
		},
	}
	state.Set(newCfg)

	got2 := state.Get()
	if got2.Global.DefaultInterval != "20s" {
		t.Errorf("expected interval 20s, got %s", got2.Global.DefaultInterval)
	}
}

func TestConfigState_ThreadSafety(t *testing.T) {
	initialCfg := &config.Config{Global: config.GlobalConfig{DefaultInterval: "0s"}}
	state := NewConfigState(initialCfg)
	var wg sync.WaitGroup

	// Multiple writers
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Use unique values to ensure race detector works hard
			state.Set(&config.Config{Global: config.GlobalConfig{DefaultInterval: "1s"}})
		}()
	}

	// Multiple readers
	for range 100 {
		wg.Go(func() {
			_ = state.Get()
		})
	}

	wg.Wait()
	// Just ensuring no race conditions (go test -race will catch issues)
}
