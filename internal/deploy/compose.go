// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Compose (решение E17 п. 5): документ приходит JSON (подмножество YAML, которое compose читает как есть) —
// у агента нет разборщика YAML с якорями и слиянием ключей, поэтому расхождения разборщиков нет. Документ
// проверяется белым списком ключей, из проверенного собирается свой (с метками, журналом, no-new-privileges
// и портами на 127.0.0.1), после `compose config --no-interpolate` нормализованный вид проверяется снова.

const (
	maxComposeDepth    = 32
	maxComposeServices = 20
)

var (
	durationRe = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h))+$`)
	exposeRe   = regexp.MustCompile(`^[0-9]{1,5}(?:/(?:tcp|udp))?$`)
	userRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}(?::[A-Za-z0-9_.-]{1,64})?$`)
	labelKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	memRe      = regexp.MustCompile(`^[0-9]{1,12}(?:[bkmg]|kb|mb|gb)?$`)
)

// parseStrictJSON — JSON без повторов ключей, глубиной до 32, без хвоста.
func parseStrictJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("данные после документа")
	}
	return v, nil
}

func strictValue(d *json.Decoder, depth int) (any, error) {
	if depth > maxComposeDepth {
		return nil, errors.New("слишком глубокая вложенность")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("ключ %q дважды", k)
				}
				if m[k], err = strictValue(d, depth+1); err != nil {
					return nil, err
				}
			}
			_, err = d.Token()
			return m, err
		case '[':
			var a []any
			for d.More() {
				v, err := strictValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err = d.Token()
			return a, err
		}
		return nil, errors.New("разделитель")
	default:
		return x, nil
	}
}

// composeSpec — что агент добавляет и с чем сверяет нормализованный вид.
type composeSpec struct {
	App, Release  string
	Vars          map[string]bool // имена, на которые можно ссылаться ${NAME}: ключи env и env_plain
	Ports         map[string]int  // сервис → порт на 127.0.0.1
	ContainerPort uint32
	LogOpts       map[string]string
}

func (s *composeSpec) project() string { return "trassa-" + shortID(s.App) }

type composeChecker struct {
	s          *composeSpec
	normalized bool
	volumes    map[string]bool
	networks   map[string]bool
	services   map[string]bool
	images     []string
}

func forbidden(what string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrComposeDenied, fmt.Sprintf(what, a...))
}

// VarPrefix — имена переменных приложения в окружении процесса compose. Переменные приложения не попадают в
// окружение под своими именами: иначе DOCKER_CONFIG, PATH или LD_PRELOAD из env_plain перекрыли бы окружение
// root-процесса docker compose (подмена плагина CLI — root на сервере). Подстановки ${NAME} документа
// переписываются в ${TRASSA_V_NAME}.
const VarPrefix = "TRASSA_V_"

// checkText — строка значения: UTF-8 без NUL, до 8 КиБ, подстановки только ${NAME}/$NAME из Vars и $$.
// Возвращает строку с подстановками, переписанными на ${TRASSA_V_NAME}; в нормализованном виде (свой документ
// после compose config) допустимы только уже переписанные ${TRASSA_V_NAME}.
func (c *composeChecker) checkText(where string, v any) (string, error) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case json.Number:
		s = x.String()
	case bool:
		s = strconv.FormatBool(x)
	default:
		return "", forbidden("%s: не строка", where)
	}
	if len(s) > 8192 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return "", forbidden("%s: значение", where)
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			out.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", forbidden("%s: одиночный $", where)
		}
		var name string
		braced := false
		switch n := s[i+1]; {
		case n == '$':
			out.WriteString("$$")
			i++
			continue
		case n == '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				return "", forbidden("%s: незакрытая подстановка", where)
			}
			name, braced = s[i+2:i+2+end], true
			i += 2 + end
		case n == '_' || (n|0x20 >= 'a' && n|0x20 <= 'z'):
			j := i + 1
			for j < len(s) && (s[j] == '_' || (s[j]|0x20 >= 'a' && s[j]|0x20 <= 'z') || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			name, i = s[i+1:j], j-1
		default:
			return "", forbidden("%s: подстановка", where)
		}
		if c.normalized {
			if !braced || !strings.HasPrefix(name, VarPrefix) {
				return "", forbidden("%s: подстановка %q не переписана агентом", where, name)
			}
			name = strings.TrimPrefix(name, VarPrefix)
		}
		if !envNameRe.MatchString(name) || !c.s.Vars[name] {
			return "", forbidden("%s: подстановка %q не из переменных приложения", where, name)
		}
		out.WriteString("${" + VarPrefix + name + "}")
	}
	return out.String(), nil
}

func asMap(v any, where string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, forbidden("%s: не объект", where)
	}
	return m, nil
}

func asList(v any, where string) ([]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, forbidden("%s: не список", where)
	}
	return a, nil
}

// keysIn — все ключи из allowed.
func keysIn(m map[string]any, where string, allowed ...string) error {
	for k := range m {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
				break
			}
		}
		if !ok {
			return forbidden("%s.%s", where, k)
		}
	}
	return nil
}

// emptyRes — ресурс верхнего уровня (том, сеть) без параметров; в нормализованном виде — ещё name.
func (c *composeChecker) emptyRes(v any, where, wantName string) error {
	if v == nil {
		return nil
	}
	m, err := asMap(v, where)
	if err != nil {
		return err
	}
	if !c.normalized {
		if len(m) != 0 {
			return forbidden("%s: параметры", where)
		}
		return nil
	}
	if err := keysIn(m, where, "name", "labels", "external"); err != nil {
		return err
	}
	if n, ok := m["name"]; ok && n != wantName {
		return forbidden("%s: имя %v", where, n)
	}
	if x, ok := m["external"]; ok && x != false {
		return forbidden("%s: external", where)
	}
	return nil
}

// textList — строка или список строк (command, entrypoint, healthcheck.test) с переписанными подстановками.
func (c *composeChecker) textList(v any, where string) (any, error) {
	if v == nil {
		return nil, nil
	}
	if s, ok := v.(string); ok {
		return c.checkText(where, s)
	}
	a, err := asList(v, where)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(a))
	for i, x := range a {
		if _, ok := x.(string); !ok {
			return nil, forbidden("%s[%d]: не строка", where, i)
		}
		if out[i], err = c.checkText(fmt.Sprintf("%s[%d]", where, i), x); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *composeChecker) duration(v any, where string) error {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		if durationRe.MatchString(x) {
			return nil
		}
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return nil
		}
	}
	return forbidden("%s: срок", where)
}

// stringMap — environment и labels: объект или список "K=V"; ключи по regexp, значения — checkText.
func (c *composeChecker) stringMap(v any, where string, key *regexp.Regexp, nullOK bool) (map[string]any, error) {
	out := map[string]any{}
	add := func(k string, val any) error {
		if !key.MatchString(k) {
			return forbidden("%s: ключ %q", where, k)
		}
		if _, dup := out[k]; dup {
			return forbidden("%s: ключ %q дважды", where, k)
		}
		if val == nil {
			// «K» без значения compose берёт из окружения процесса: только переменная приложения, явной подстановкой.
			if !nullOK || !c.s.Vars[k] || c.normalized {
				return forbidden("%s.%s: без значения", where, k)
			}
			out[k] = "${" + VarPrefix + k + "}"
			return nil
		}
		s, err := c.checkText(where+"."+k, val)
		out[k] = s
		return err
	}
	switch x := v.(type) {
	case nil:
	case map[string]any:
		for k, val := range x {
			if err := add(k, val); err != nil {
				return nil, err
			}
		}
	case []any:
		for _, it := range x {
			s, ok := it.(string)
			if !ok {
				return nil, forbidden("%s: элемент", where)
			}
			k, val, has := strings.Cut(s, "=")
			var vv any
			if has {
				vv = val
			}
			if err := add(k, vv); err != nil {
				return nil, err
			}
		}
	default:
		return nil, forbidden("%s", where)
	}
	return out, nil
}

func (c *composeChecker) serviceVolumes(v any, where string) ([]any, error) {
	if v == nil {
		return nil, nil
	}
	a, err := asList(v, where)
	if err != nil {
		return nil, err
	}
	var out []any
	for i, it := range a {
		w := fmt.Sprintf("%s[%d]", where, i)
		var src, dst string
		ro := false
		switch x := it.(type) {
		case string:
			parts := strings.Split(x, ":")
			if len(parts) < 2 || len(parts) > 3 {
				return nil, forbidden("%s: только том:путь[:ro]", w)
			}
			src, dst = parts[0], parts[1]
			if len(parts) == 3 {
				if parts[2] != "ro" && parts[2] != "rw" {
					return nil, forbidden("%s: режим", w)
				}
				ro = parts[2] == "ro"
			}
		case map[string]any:
			allowed := []string{"type", "source", "target", "read_only"}
			if c.normalized {
				allowed = append(allowed, "volume")
			}
			if err := keysIn(x, w, allowed...); err != nil {
				return nil, err
			}
			if x["type"] != "volume" {
				return nil, forbidden("%s: только именованный том", w)
			}
			if vol, ok := x["volume"]; ok && vol != nil {
				if m, ok := vol.(map[string]any); !ok || len(m) != 0 {
					return nil, forbidden("%s.volume", w)
				}
			}
			src, _ = x["source"].(string)
			dst, _ = x["target"].(string)
			if r, ok := x["read_only"]; ok {
				b, isBool := r.(bool)
				if !isBool {
					return nil, forbidden("%s.read_only", w)
				}
				ro = b
			}
		default:
			return nil, forbidden("%s", w)
		}
		if !c.volumes[src] {
			return nil, forbidden("%s: том %q не объявлен (bind запрещён)", w, src)
		}
		if !strings.HasPrefix(dst, "/") || path.Clean(dst) != dst || dst == "/" || !printable(dst, 512) || strings.Contains(dst, "$") {
			return nil, forbidden("%s: путь в контейнере", w)
		}
		out = append(out, map[string]any{"type": "volume", "source": src, "target": dst, "read_only": ro})
	}
	return out, nil
}

func (c *composeChecker) dependsOn(v any, where string) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []any:
		for _, it := range x {
			if s, ok := it.(string); !ok || !c.services[s] {
				return nil, forbidden("%s: сервис %v", where, it)
			}
		}
		return x, nil
	case map[string]any:
		for name, cond := range x {
			if !c.services[name] {
				return nil, forbidden("%s: сервис %q", where, name)
			}
			m, err := asMap(cond, where+"."+name)
			if err != nil {
				return nil, err
			}
			if err := keysIn(m, where+"."+name, "condition", "required", "restart"); err != nil {
				return nil, err
			}
			switch m["condition"] {
			case nil, "service_started", "service_healthy", "service_completed_successfully":
			default:
				return nil, forbidden("%s.%s.condition", where, name)
			}
			for _, k := range []string{"required", "restart"} {
				if b, ok := m[k]; ok {
					if _, isBool := b.(bool); !isBool {
						return nil, forbidden("%s.%s.%s", where, name, k)
					}
				}
			}
		}
		return x, nil
	}
	return nil, forbidden("%s", where)
}

func (c *composeChecker) healthcheck(v any, where string) (any, error) {
	if v == nil {
		return nil, nil
	}
	m, err := asMap(v, where)
	if err != nil {
		return nil, err
	}
	if err := keysIn(m, where, "test", "interval", "timeout", "retries", "start_period", "start_interval", "disable"); err != nil {
		return nil, err
	}
	test, err := c.textList(m["test"], where+".test")
	if err != nil {
		return nil, err
	}
	if test != nil {
		m["test"] = test
	}
	for _, k := range []string{"interval", "timeout", "start_period", "start_interval"} {
		if err := c.duration(m[k], where+"."+k); err != nil {
			return nil, err
		}
	}
	if r, ok := m["retries"]; ok && r != nil {
		if n, isNum := r.(json.Number); !isNum || n.String() == "" {
			return nil, forbidden("%s.retries", where)
		}
	}
	if d, ok := m["disable"]; ok {
		if _, isBool := d.(bool); !isBool {
			return nil, forbidden("%s.disable", where)
		}
	}
	return m, nil
}

func (c *composeChecker) deployKey(v any, where string) (any, error) {
	if v == nil {
		return nil, nil
	}
	m, err := asMap(v, where)
	if err != nil {
		return nil, err
	}
	if err := keysIn(m, where, "resources"); err != nil {
		return nil, err
	}
	if m["resources"] == nil {
		return m, nil
	}
	r, err := asMap(m["resources"], where+".resources")
	if err != nil {
		return nil, err
	}
	if err := keysIn(r, where+".resources", "limits"); err != nil {
		return nil, err
	}
	if r["limits"] == nil {
		return m, nil
	}
	l, err := asMap(r["limits"], where+".resources.limits")
	if err != nil {
		return nil, err
	}
	if err := keysIn(l, where+".resources.limits", "cpus", "memory", "pids"); err != nil {
		return nil, err
	}
	for k, x := range l {
		s := ""
		switch y := x.(type) {
		case string:
			s = strings.ToLower(y)
		case json.Number:
			s = y.String()
		default:
			return nil, forbidden("%s.resources.limits.%s", where, k)
		}
		ok := false
		switch k {
		case "cpus":
			f, err := strconv.ParseFloat(s, 64)
			ok = err == nil && f > 0 && f <= 1024
		case "memory":
			ok = memRe.MatchString(s)
		case "pids":
			n, err := strconv.Atoi(s)
			ok = err == nil && n > 0 && n <= 1<<20
		}
		if !ok {
			return nil, forbidden("%s.resources.limits.%s", where, k)
		}
	}
	return m, nil
}

func (c *composeChecker) serviceNetworks(v any, where string) (any, error) {
	known := func(n string) bool { return c.networks[n] || n == "default" }
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []any:
		for _, it := range x {
			if s, ok := it.(string); !ok || !known(s) {
				return nil, forbidden("%s: сеть %v", where, it)
			}
		}
		return x, nil
	case map[string]any:
		for n, opt := range x {
			if !known(n) {
				return nil, forbidden("%s: сеть %q", where, n)
			}
			if opt != nil {
				if m, ok := opt.(map[string]any); !ok || len(m) != 0 {
					return nil, forbidden("%s.%s: параметры сети", where, n)
				}
			}
		}
		return x, nil
	}
	return nil, forbidden("%s", where)
}

func (c *composeChecker) logging() map[string]any {
	opts := map[string]any{}
	for k, v := range c.s.LogOpts {
		opts[k] = v
	}
	return map[string]any{"driver": "local", "options": opts}
}

// ports — в исходном документе запрещены (порт выбирает агент); в нормализованном — ровно добавленный агентом.
func (c *composeChecker) ports(name string, v any, where string) error {
	if !c.normalized {
		return forbidden("%s: порты назначает агент (маршрут приложения)", where)
	}
	want, routed := c.s.Ports[name]
	a, err := asList(v, where)
	if err != nil {
		return err
	}
	if !routed || len(a) != 1 {
		return forbidden("%s: лишние порты", where)
	}
	m, err := asMap(a[0], where)
	if err != nil {
		return err
	}
	if err := keysIn(m, where, "mode", "host_ip", "target", "published", "protocol"); err != nil {
		return err
	}
	pub := fmt.Sprint(m["published"])
	if m["host_ip"] != "127.0.0.1" || pub != strconv.Itoa(want) || fmt.Sprint(m["target"]) != strconv.Itoa(int(c.s.ContainerPort)) {
		return forbidden("%s: порт не 127.0.0.1:%d", where, want)
	}
	if p, ok := m["protocol"]; ok && p != "tcp" {
		return forbidden("%s.protocol", where)
	}
	if md, ok := m["mode"]; ok && md != "ingress" && md != "host" {
		return forbidden("%s.mode", where)
	}
	return nil
}

func (c *composeChecker) service(name string, v any) (map[string]any, error) {
	where := "services." + name
	m, err := asMap(v, where)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, val := range m {
		w := where + "." + k
		var res any
		switch k {
		case "image":
			s, _ := val.(string)
			if err := PinnedImage(s); err != nil {
				return nil, err
			}
			c.images = append(c.images, s)
			res = s
		case "command", "entrypoint":
			res, err = c.textList(val, w)
		case "environment":
			res, err = c.stringMap(val, w, envNameRe, true)
		case "labels":
			var lm map[string]any
			lm, err = c.stringMap(val, w, labelKeyRe, false)
			for lk, lv := range lm {
				if strings.HasPrefix(lk, "trassa.") || strings.HasPrefix(lk, "com.docker.") {
					// Метки Trassa ставит агент; в нормализованном виде они должны совпасть с его значениями.
					if !c.normalized || lv != c.trassaLabels(name)[lk] {
						return nil, forbidden("%s: метка %q", w, lk)
					}
				}
			}
			res = lm
		case "expose":
			var a []any
			if a, err = asList(val, w); err == nil {
				for _, e := range a {
					if !exposeRe.MatchString(fmt.Sprint(e)) {
						return nil, forbidden("%s: %v", w, e)
					}
				}
			}
			res = a
		case "volumes":
			res, err = c.serviceVolumes(val, w)
		case "depends_on":
			res, err = c.dependsOn(val, w)
		case "healthcheck":
			res, err = c.healthcheck(val, w)
		case "restart":
			switch s, _ := val.(string); {
			case s == "no", s == "always", s == "unless-stopped", s == "on-failure", strings.HasPrefix(s, "on-failure:") && len(s) <= 14:
				res = s
			default:
				return nil, forbidden("%s", w)
			}
		case "user":
			if s, ok := val.(string); !ok || !userRe.MatchString(s) {
				return nil, forbidden("%s", w)
			}
			res = val
		case "working_dir":
			if s, ok := val.(string); !ok || !strings.HasPrefix(s, "/") || path.Clean(s) != s || !printable(s, 512) || strings.Contains(s, "$") {
				return nil, forbidden("%s", w)
			}
			res = val
		case "deploy":
			res, err = c.deployKey(val, w)
		case "networks":
			res, err = c.serviceNetworks(val, w)
		case "stop_grace_period":
			err, res = c.duration(val, w), val
		case "ports":
			if err := c.ports(name, val, w); err != nil {
				return nil, err
			}
			continue
		case "logging":
			if !c.normalized || !jsonEqual(val, c.logging()) {
				return nil, forbidden("%s", w)
			}
			continue
		case "security_opt":
			if !c.normalized || !jsonEqual(val, []any{"no-new-privileges:true"}) {
				return nil, forbidden("%s", w)
			}
			continue
		case "pull_policy":
			if !c.normalized || val != "never" {
				return nil, forbidden("%s", w)
			}
			continue
		default:
			return nil, forbidden("%s", w)
		}
		if err != nil {
			return nil, err
		}
		if res != nil {
			out[k] = res
		}
	}
	if out["image"] == nil {
		return nil, forbidden("%s: нет image", where)
	}
	return out, nil
}

func (c *composeChecker) trassaLabels(service string) map[string]any {
	return map[string]any{LabelApp: c.s.App, LabelRelease: c.s.Release, LabelService: service}
}

func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// check — проверка документа и сборка того, что уйдёт в compose.json.
func (c *composeChecker) check(doc any) (map[string]any, error) {
	top, err := asMap(doc, "документ")
	if err != nil {
		return nil, err
	}
	allowed := []string{"services", "volumes", "networks"}
	if c.normalized {
		allowed = append(allowed, "name")
	}
	if err := keysIn(top, "", allowed...); err != nil {
		return nil, err
	}
	if n, ok := top["name"]; ok && n != c.s.project() {
		return nil, forbidden("name %v", n)
	}
	c.volumes, c.networks, c.services = map[string]bool{}, map[string]bool{}, map[string]bool{}
	outVolumes, outNetworks := map[string]any{}, map[string]any{}
	if top["volumes"] != nil {
		vm, err := asMap(top["volumes"], "volumes")
		if err != nil {
			return nil, err
		}
		for k, v := range vm {
			if !volumeRe.MatchString(k) {
				return nil, forbidden("volumes.%s", k)
			}
			want := volumeName(c.s.App, k)
			if err := c.emptyRes(v, "volumes."+k, want); err != nil {
				return nil, err
			}
			c.volumes[k] = true
			outVolumes[k] = map[string]any{"name": want, "labels": map[string]any{LabelApp: c.s.App}}
		}
	}
	if top["networks"] != nil {
		nm, err := asMap(top["networks"], "networks")
		if err != nil {
			return nil, err
		}
		for k, v := range nm {
			if !volumeRe.MatchString(k) {
				return nil, forbidden("networks.%s", k)
			}
			if err := c.emptyRes(v, "networks."+k, c.s.project()+"_"+k); err != nil {
				return nil, err
			}
			if k != "default" {
				c.networks[k] = true
			}
			outNetworks[k] = map[string]any{}
		}
	}
	sm, err := asMap(top["services"], "services")
	if err != nil {
		return nil, err
	}
	if len(sm) == 0 || len(sm) > maxComposeServices {
		return nil, forbidden("services: от 1 до %d", maxComposeServices)
	}
	for k := range sm {
		if !serviceRe.MatchString(k) {
			return nil, forbidden("services.%s", k)
		}
		c.services[k] = true
	}
	for name := range c.s.Ports {
		if !c.services[name] {
			return nil, forbidden("маршрут на сервис %q, которого нет", name)
		}
	}
	names := make([]string, 0, len(sm))
	for k := range sm {
		names = append(names, k)
	}
	sort.Strings(names)
	outServices := map[string]any{}
	for _, name := range names {
		svc, err := c.service(name, sm[name])
		if err != nil {
			return nil, err
		}
		labels, _ := svc["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
		}
		for k, v := range c.trassaLabels(name) {
			labels[k] = v
		}
		svc["labels"], svc["logging"], svc["security_opt"] = labels, c.logging(), []any{"no-new-privileges:true"}
		svc["pull_policy"] = "never"
		if svc["restart"] == nil {
			svc["restart"] = "unless-stopped"
		}
		if p, ok := c.s.Ports[name]; ok {
			svc["ports"] = []any{map[string]any{"host_ip": "127.0.0.1", "published": strconv.Itoa(p),
				"target": c.s.ContainerPort, "protocol": "tcp"}}
		}
		outServices[name] = svc
	}
	out := map[string]any{"services": outServices}
	if len(outVolumes) > 0 {
		out["volumes"] = outVolumes
	}
	if len(outNetworks) > 0 {
		out["networks"] = outNetworks
	}
	return out, nil
}

// ComposeDoc — проверенный документ compose.json и образы сервисов (первая проверка, до любого вызова compose).
func ComposeDoc(raw string, s *composeSpec) ([]byte, []string, error) {
	doc, err := parseStrictJSON([]byte(raw))
	if err != nil {
		return nil, nil, forbidden("документ не JSON: %v", err)
	}
	c := &composeChecker{s: s}
	out, err := c.check(doc)
	if err != nil {
		return nil, nil, err
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return b, c.images, err
}

// CheckNormalized — вторая проверка: вывод `compose config --format json --no-interpolate`.
func CheckNormalized(raw []byte, s *composeSpec) error {
	doc, err := parseStrictJSON(raw)
	if err != nil {
		return forbidden("нормализованный вид: %v", err)
	}
	_, err = (&composeChecker{s: s, normalized: true}).check(doc)
	return err
}
