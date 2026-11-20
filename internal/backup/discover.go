// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// Пределы списка источников (R10: результат проходит схему и лимит размера панели).
const (
	MaxDiscoverVolumes   = 200
	MaxDiscoverDatabases = 100
)

// Служебные базы, которых нет в выборе источников.
var systemDatabases = map[string]bool{
	"template0": true, "template1": true,
	"information_schema": true, "performance_schema": true, "sys": true,
}

const (
	pgListSQL    = "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1"
	pgVersionSQL = "SHOW server_version"
	mysqlListSQL = "SELECT schema_name FROM information_schema.schemata ORDER BY 1"
)

// mysqlListScript — как mysqlContainerScript, но список баз и версия сервера (две части через пустую строку).
const mysqlListScript = `p="${MYSQL_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"; ` +
	`f="${MYSQL_ROOT_PASSWORD_FILE:-${MARIADB_ROOT_PASSWORD_FILE:-}}"; ` +
	`if [ -n "$f" ]; then p="$(cat "$f")"; fi; ` +
	`c=mysql; if command -v mariadb >/dev/null 2>&1; then c=mariadb; fi; ` +
	`MYSQL_PWD="$p" "$c" -uroot -N -B -e "SELECT VERSION(); ` + mysqlListSQL + `"`

// Discover — тома Docker, базы PostgreSQL и MySQL на хосте и в контейнерах, свободное место. Чего нет (Docker,
// баз) — того нет в итоге, это не ошибка; ошибка одной базы не прячет остальные.
func (e *Env) Discover(ctx context.Context) (*agentv1.BackupDiscoverResult, []string) {
	res := &agentv1.BackupDiscoverResult{}
	var notes []string
	if free, err := FreeBytes("/"); err == nil {
		res.FreeBytes = free
	} else {
		notes = append(notes, "свободное место: "+err.Error())
	}
	vols, dbs, err := e.dockerSources(ctx)
	switch {
	case errors.Is(err, dockerapi.ErrNoDocker):
	case err != nil:
		notes = append(notes, "Docker: "+err.Error())
	}
	res.Volumes, res.Databases = vols, dbs
	res.Databases = append(res.Databases, e.hostDatabases(ctx, &notes)...)
	if len(res.Volumes) > MaxDiscoverVolumes {
		notes = append(notes, "томов больше 200: показаны первые 200")
		res.Volumes = res.Volumes[:MaxDiscoverVolumes]
	}
	if len(res.Databases) > MaxDiscoverDatabases {
		notes = append(notes, "серверов баз больше 100: показаны первые 100")
		res.Databases = res.Databases[:MaxDiscoverDatabases]
	}
	return res, notes
}

func (e *Env) dockerSources(ctx context.Context) ([]*agentv1.DiscoveredVolume, []*agentv1.DiscoveredDatabase, error) {
	var vl struct {
		Volumes []struct {
			Name   string `json:"Name"`
			Driver string `json:"Driver"`
		} `json:"Volumes"`
	}
	if err := e.dockerJSON(ctx, "/volumes", &vl); err != nil {
		return nil, nil, err
	}
	var df struct {
		Volumes []struct {
			Name      string `json:"Name"`
			UsageData struct {
				Size int64 `json:"Size"`
			} `json:"UsageData"`
		} `json:"Volumes"`
	}
	sizes := map[string]uint64{}
	if e.dockerJSON(ctx, "/system/df?type=volume", &df) == nil {
		for _, v := range df.Volumes {
			if v.UsageData.Size > 0 {
				sizes[v.Name] = uint64(v.UsageData.Size)
			}
		}
	}
	var cs []struct {
		Names  []string `json:"Names"`
		Image  string   `json:"Image"`
		State  string   `json:"State"`
		Mounts []struct {
			Type string `json:"Type"`
			Name string `json:"Name"`
		} `json:"Mounts"`
	}
	if err := e.dockerJSON(ctx, "/containers/json?all=1", &cs); err != nil {
		return nil, nil, err
	}
	users := map[string][]string{}
	var dbs []*agentv1.DiscoveredDatabase
	for _, c := range cs {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		for _, m := range c.Mounts {
			if m.Type == "volume" {
				users[m.Name] = append(users[m.Name], name)
			}
		}
		if c.State != "running" || !containerRe.MatchString(name) {
			continue
		}
		if engine := imageEngine(c.Image); engine != "" {
			dbs = append(dbs, e.containerDatabases(ctx, engine, name))
		}
	}
	var vols []*agentv1.DiscoveredVolume
	for _, v := range vl.Volumes {
		if v.Driver != "local" || !volumeRe.MatchString(v.Name) {
			continue
		}
		sort.Strings(users[v.Name])
		vols = append(vols, &agentv1.DiscoveredVolume{Name: v.Name, SizeBytes: sizes[v.Name], Containers: users[v.Name]})
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	return vols, dbs, nil
}

// imageEngine — движок по имени образа (postgres, postgis/postgis, mysql, mariadb, bitnami/postgresql…).
func imageEngine(image string) string {
	base := image
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.IndexAny(base, ":@"); i >= 0 {
		base = base[:i]
	}
	switch {
	case strings.Contains(base, "postgres") || strings.Contains(base, "postgis"):
		return "postgres"
	case strings.Contains(base, "mysql") || strings.Contains(base, "mariadb"):
		return "mysql"
	}
	return ""
}

func (e *Env) query(ctx context.Context, name string, args ...string) ([]string, error) {
	if e.Run == nil {
		return nil, errors.New("запуск программ недоступен")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := e.Run(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

func userDatabases(names []string) []string {
	var out []string
	for _, n := range names {
		if !systemDatabases[n] && dbNameRe.MatchString(n) {
			out = append(out, n)
		}
	}
	return out
}

func (e *Env) containerDatabases(ctx context.Context, engine, container string) *agentv1.DiscoveredDatabase {
	d := &agentv1.DiscoveredDatabase{Engine: engine, Container: container}
	if engine == "postgres" {
		if v, err := e.query(ctx, "docker", "exec", "-u", "postgres", container, "psql", "-X", "-At", "-c", pgVersionSQL); err == nil && len(v) > 0 {
			d.Version = v[0]
		}
		if names, err := e.query(ctx, "docker", "exec", "-u", "postgres", container, "psql", "-X", "-At", "-c", pgListSQL); err == nil {
			d.Databases = userDatabases(names)
		}
		return d
	}
	if lines, err := e.query(ctx, "docker", "exec", container, "sh", "-c", mysqlListScript); err == nil && len(lines) > 0 {
		d.Version, d.Databases = lines[0], userDatabases(lines[1:])
	}
	return d
}

// hostDatabases — серверы баз на самом хосте: PostgreSQL от postgres (peer), MySQL/MariaDB от root (сокет).
func (e *Env) hostDatabases(ctx context.Context, notes *[]string) []*agentv1.DiscoveredDatabase {
	var out []*agentv1.DiscoveredDatabase
	look := e.Look
	if look == nil {
		return nil
	}
	if psql, err := look("psql"); err == nil {
		if runuser, err := look("runuser"); err == nil {
			if names, err := e.query(ctx, runuser, "-u", "postgres", "--", psql, "-X", "-At", "-c", pgListSQL); err == nil {
				d := &agentv1.DiscoveredDatabase{Engine: "postgres", Databases: userDatabases(names)}
				if v, err := e.query(ctx, runuser, "-u", "postgres", "--", psql, "-X", "-At", "-c", pgVersionSQL); err == nil && len(v) > 0 {
					d.Version = v[0]
				}
				out = append(out, d)
			}
		}
	}
	cli, err := look("mariadb")
	if err != nil {
		cli, err = look("mysql")
	}
	if err == nil {
		if lines, err := e.query(ctx, cli, "-N", "-B", "-e", "SELECT VERSION(); "+mysqlListSQL); err == nil && len(lines) > 0 {
			out = append(out, &agentv1.DiscoveredDatabase{Engine: "mysql", Version: lines[0], Databases: userDatabases(lines[1:])})
		} else if err != nil {
			*notes = append(*notes, "MySQL на хосте не ответил: "+firstLine([]byte(err.Error())))
		}
	}
	return out
}
