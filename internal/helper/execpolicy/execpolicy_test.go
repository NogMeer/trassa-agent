// SPDX-License-Identifier: AGPL-3.0-only

package execpolicy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type cases struct {
	Denied []struct {
		Argv []string `json:"argv"`
		Cwd  string   `json:"cwd"`
		Code string   `json:"code"`
	} `json:"denied"`
	Allowed []struct {
		Argv []string `json:"argv"`
		Cwd  string   `json:"cwd"`
	} `json:"allowed"`
}

func load(t *testing.T) cases {
	t.Helper()
	raw, err := os.ReadFile("../../../proto/testdata/exec-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var c cases
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Общий набор R28: каждая строка — тот же итог, что у панели (T4: не меньше 120 запрещённых и 60 разрешённых).
func TestSharedCases(t *testing.T) {
	c := load(t)
	if len(c.Denied) < 120 || len(c.Allowed) < 60 {
		t.Fatalf("набор мал: %d запрещённых, %d разрешённых", len(c.Denied), len(c.Allowed))
	}
	for _, d := range c.Denied {
		v := Check(d.Argv, d.Cwd, Options{})
		if v.Allowed || v.Code != d.Code {
			t.Errorf("запрещено %q (cwd %q): ждали %s, получили allowed=%v %s (%s)", d.Argv, d.Cwd, d.Code, v.Allowed, v.Code, v.Detail)
		}
	}
	for _, a := range c.Allowed {
		if v := Check(a.Argv, a.Cwd, Options{}); !v.Allowed {
			t.Errorf("разрешено %q: получили %s (%s)", a.Argv, v.Code, v.Detail)
		}
	}
}

// Предел — в единицах UTF-16, как String.length панели.
func TestShapeLimitUTF16(t *testing.T) {
	if v := CheckShape([]string{"echo", strings.Repeat("я", 1995)}); !v.Allowed {
		t.Fatal("кириллица посчитана байтами")
	}
}

// Агент: пути после ссылок — ссылка в /tmp на /etc/shadow и программа-ссылка на оболочку.
func TestResolve(t *testing.T) {
	links := map[string]string{"/tmp/x": "/etc/shadow", "/usr/local/bin/view": "/usr/bin/vim.basic", "/usr/bin/sh2": "/usr/bin/dash",
		"/srv/app": "/srv/app", "/tmp/tr": "/var/lib/trassa/agent"}
	o := Options{Resolve: func(p string) (string, bool) { r, ok := links[p]; return r, ok }}
	for _, c := range []struct {
		argv []string
		cwd  string
		code string
	}{
		{[]string{"cat", "/tmp/x"}, "", SecretsRead},
		{[]string{"cat", "x"}, "/tmp", SecretsRead},
		{[]string{"/usr/local/bin/view", "/etc/hosts"}, "", RunsCommands},
		{[]string{"/usr/bin/sh2"}, "", RunsCommands},
		{[]string{"ls", "/tmp/tr"}, "", TrassaAgent},
	} {
		if v := Check(c.argv, c.cwd, o); v.Allowed || v.Code != c.code {
			t.Errorf("%q: %+v", c.argv, v)
		}
	}
	// kill по PID процесса Trassa — только агент знает имена процессов.
	oc := Options{Comm: func(pid string) string { return map[string]string{"77": "trassa-helper", "88": "nginx"}[pid] }}
	if v := Check([]string{"kill", "-9", "77"}, "", oc); v.Allowed || v.Code != TrassaAgent {
		t.Fatalf("kill helper: %+v", v)
	}
	if v := Check([]string{"kill", "-HUP", "88"}, "", oc); !v.Allowed {
		t.Fatalf("kill nginx: %+v", v)
	}
	if v := Check([]string{"ls", "/srv/app"}, "", o); !v.Allowed {
		t.Fatalf("%+v", v)
	}
}
