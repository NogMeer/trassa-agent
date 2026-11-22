// SPDX-License-Identifier: AGPL-3.0-only

package sysinfo

import (
	"encoding/json"
	"os"
	"testing"
)

// Общий набор с панелью (services/expected.ts).
func TestExpectedShared(t *testing.T) {
	raw, err := os.ReadFile("../../proto/testdata/service-expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Services []struct {
			Name          string   `json:"name"`
			UnitFileState string   `json:"unit_file_state"`
			ServiceType   string   `json:"service_type"`
			TriggeredBy   []string `json:"triggered_by"`
			Expected      bool     `json:"expected"`
		} `json:"services"`
		Containers []struct {
			Name           string `json:"name"`
			RestartPolicy  string `json:"restart_policy"`
			State          string `json:"state"`
			ExitCode       int32  `json:"exit_code"`
			ComposeService string `json:"compose_service"`
			Expected       bool   `json:"expected"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Services) < 10 || len(c.Containers) < 10 {
		t.Fatal("набор мал")
	}
	for _, s := range c.Services {
		if got := ServiceExpected(s.UnitFileState, s.ServiceType, s.TriggeredBy); got != s.Expected {
			t.Errorf("служба %s: %v, ждали %v", s.Name, got, s.Expected)
		}
	}
	for _, x := range c.Containers {
		if got := ContainerExpected(x.RestartPolicy, x.State, x.ExitCode, x.ComposeService); got != x.Expected {
			t.Errorf("контейнер %s: %v, ждали %v", x.Name, got, x.Expected)
		}
	}
}
