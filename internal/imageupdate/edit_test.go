// SPDX-License-Identifier: AGPL-3.0-only

package imageupdate

import (
	"errors"
	"strings"
	"testing"
)

func TestFindImage(t *testing.T) {
	const doc = `# проект
name: shop
x-common: &c
  restart: unless-stopped
services:
  db:
    image: postgres:17.6
  web:
    # комментарий
    ports:
    - "80:80"
    environment:
      IMAGE: decoy:1   # чужой ключ image глубже
    image: "nginx:1.28"   # закреплено
    restart: always
  "worker":
    image: ${WORKER_IMAGE}
volumes:
  data: {}
`
	s, err := FindImage([]byte(doc), "web")
	if err != nil || s == nil || s.Value != "nginx:1.28" || s.Quote != '"' {
		t.Fatalf("web: %+v %v", s, err)
	}
	out := string(Replace([]byte(doc), s, "nginx:1.30"))
	if want := `    image: "nginx:1.30"   # закреплено`; !strings.Contains(out, want) || !strings.Contains(out, "image: postgres:17.6") || !strings.Contains(out, "IMAGE: decoy:1") {
		t.Fatalf("замена:\n%s", out)
	}
	if s, err := FindImage([]byte(doc), "db"); err != nil || s.Value != "postgres:17.6" || s.Quote != 0 {
		t.Fatalf("db: %+v %v", s, err)
	}
	if s, err := FindImage([]byte(doc), "worker"); err != nil || s.Value != "${WORKER_IMAGE}" {
		t.Fatalf("worker в кавычках имени: %+v %v", s, err)
	}
	if s, err := FindImage([]byte(doc), "absent"); err != nil || s != nil {
		t.Fatalf("нет сервиса — не ошибка: %+v %v", s, err)
	}
}

func TestFindImageRefuses(t *testing.T) {
	for name, doc := range map[string]string{
		"табуляция":       "services:\n\tweb:\n\t\timage: x:1\n",
		"поток":           "services: {web: {image: x:1}}\n",
		"якорь":           "services:\n  web:\n    image: &i x:1\n",
		"наследование":    "services:\n  web:\n    <<: *base\n",
		"extends":         "services:\n  web:\n    extends: base\n",
		"дважды image":    "services:\n  web:\n    image: x:1\n    image: x:2\n",
		"дважды сервис":   "services:\n  web:\n    image: x:1\n  web:\n    image: x:2\n",
		"многострочное":   "services:\n  web:\n    image: >\n      x:1\n",
		"несколько док.":  "services:\n  web:\n    image: x:1\n---\nservices: {}\n",
		"CRLF":            "services:\r\n  web:\r\n    image: x:1\r\n",
		"кавычка внутри":  "services:\n  web:\n    image: \"x:1'\"\n",
		"сервис в строку": "services:\n  web: {image: x:1}\n",
		"пустое image":    "services:\n  web:\n    image:\n",
	} {
		if _, err := FindImage([]byte(doc), "web"); !errors.Is(err, ErrNotEditable) {
			t.Errorf("%s: ждали отказ, получили %v", name, err)
		}
	}
}

func TestParseVar(t *testing.T) {
	for in, want := range map[string]VarRef{
		"${IMAGE}":              {Name: "IMAGE", Whole: true},
		"$IMAGE":                {Name: "IMAGE", Whole: true},
		"nginx:${TAG}":          {Name: "TAG", Repo: "nginx"},
		"ghcr.io/a/b:${TAG:-1}": {Name: "TAG", Repo: "ghcr.io/a/b"},
		"nginx:$TAG":            {Name: "TAG", Repo: "nginx"},
	} {
		v, err := ParseVar(in)
		if err != nil || v == nil || *v != want {
			t.Errorf("%s: %+v %v", in, v, err)
		}
	}
	if v, err := ParseVar("nginx:1.28"); v != nil || err != nil {
		t.Fatalf("без переменной: %+v %v", v, err)
	}
	for _, in := range []string{"${REG}/nginx:${TAG}", "nginx:${A}${B}", "nginx:1.${MINOR}", "$(id)"} {
		if _, err := ParseVar(in); !errors.Is(err, ErrNotEditable) {
			t.Errorf("%s: ждали отказ, получили %v", in, err)
		}
	}
}

func TestFindEnv(t *testing.T) {
	env := "# теги\nexport NGINX_TAG=1.28\nIMAGE='nginx:1.28'\nOTHER=x\n"
	s, err := FindEnv([]byte(env), "NGINX_TAG")
	if err != nil || s.Value != "1.28" {
		t.Fatalf("%+v %v", s, err)
	}
	if got := string(Replace([]byte(env), s, "1.30")); got != "# теги\nexport NGINX_TAG=1.30\nIMAGE='nginx:1.28'\nOTHER=x\n" {
		t.Fatalf("замена: %q", got)
	}
	if s, err := FindEnv([]byte(env), "IMAGE"); err != nil || s.Value != "nginx:1.28" || s.Quote != '\'' {
		t.Fatalf("кавычки: %+v %v", s, err)
	}
	for name, doc := range map[string]string{
		"нет":       "OTHER=1\n",
		"дважды":    "TAG=1\nTAG=2\n",
		"подстанов": "TAG=${BASE}\n",
		"пробел":    "TAG=1 2\n",
	} {
		if _, err := FindEnv([]byte(doc), "TAG"); !errors.Is(err, ErrNotEditable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := validParams()
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	bad := []func(){
		func() { ok.Container = "web;rm -rf /" },
		func() { ok.Project = "Shop" },
		func() { ok.Service = "-web" },
		func() { ok.CurrentImage = "nginx:1.28@sha256:" + strings.Repeat("a", 64) },
		func() { ok.CurrentImage = "nginx" },
		func() { ok.TargetTag = "1.30 --privileged" },
		func() { ok.TargetTag = "$(id)" },
		func() { ok.TargetTag = "-v" },
		func() { ok.WaitSec = 5 },
		func() { ok.WaitSec = 3600 },
	}
	for i, mut := range bad {
		ok = validParams()
		mut()
		if err := Validate(ok); err == nil {
			t.Errorf("случай %d принят: %+v", i, ok)
		}
	}
}
