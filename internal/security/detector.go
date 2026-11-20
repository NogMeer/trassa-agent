// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Детектор (E10-T7): постоянное наблюдение в помощнике, только чтение. Новые объекты (ключи, задания, юниты,
// SUID-файлы, пользователи) и признаки (процесс из временного каталога, подгрузка библиотеки, исходящие на
// подозрительные порты, неизвестный процесс долго держит CPU) дают событие security.suspicious не чаще раза в
// час на код и объект. Базовый список хранится на сервере; «Это сделал я» — операция security.baseline.accept.

// Виды объектов базового списка (атрибут baseline_kind).
const (
	KindAuthorizedKey = "AUTHORIZED_KEY"
	KindCron          = "CRON"
	KindSystemdUnit   = "SYSTEMD_UNIT"
	KindSUID          = "SUID"
	KindUser          = "USER"
	KindProcess       = "PROCESS"
)

// Пороги и периоды — решение продукта (E10, раздел 13, вопрос 16), на парке не сверены.
const (
	// FastInterval — быстрые признаки; SUIDInterval — обход файловой системы.
	FastInterval = time.Minute
	SUIDInterval = 15 * time.Minute
	// EventEvery — не чаще одного события на код и объект.
	EventEvery = time.Hour
	// MinerCPU — доля одного ядра и сколько её держать, чтобы процесс вне базового списка считался майнером.
	MinerCPU = 0.8
	MinerFor = 15 * time.Minute
	// maxPending и maxQueue — пределы ожидающих объектов и неотправленных событий.
	maxPending = 1000
	maxQueue   = 500
	// clkTck — USER_HZ ядра Linux на amd64 и arm64 (единица utime и stime в /proc/<pid>/stat).
	clkTck = 100
	// suidMaxFiles — предел обхода при поиске SUID-файлов.
	suidMaxFiles = 500000
)

// codeOf — код проверки для вида объекта.
var codeOf = map[string]string{
	KindAuthorizedKey: "COMPROMISE_KEYS_CHANGED", KindCron: "COMPROMISE_NEW_CRON", KindSystemdUnit: "COMPROMISE_NEW_CRON",
	KindSUID: "COMPROMISE_NEW_SUID", KindUser: "COMPROMISE_NEW_USER", KindProcess: "COMPROMISE_MINER_CPU",
}

// severityOf — тяжесть кода из каталога E10: CRITICAL — CRIT, HIGH и MEDIUM — WARN.
var severityOf = map[string]agentv1.EventSeverity{
	"COMPROMISE_MINER_CPU": agentv1.EventSeverity_EVENT_SEVERITY_CRIT, "COMPROMISE_LD_PRELOAD": agentv1.EventSeverity_EVENT_SEVERITY_CRIT,
}

// Item — объект базового списка.
type Item struct {
	Fingerprint string `json:"fingerprint"`
	Kind        string `json:"kind"`
	Subject     string `json:"subject"`
	Evidence    string `json:"evidence,omitempty"`
	SeenAtMs    int64  `json:"seen_at_ms"`
}

type detectorState struct {
	Baseline map[string]Item `json:"baseline"`
	// Pending — новые объекты, ещё не принятые человеком.
	Pending map[string]Item `json:"pending"`
	// SUID — последний обход SUID (он редкий; между обходами берётся этот список).
	SUID []Item `json:"suid,omitempty"`
}

// Detector — состояние наблюдения. Методы безопасны для одновременного вызова (скан, опрос событий, операция).
type Detector struct {
	Sys  *System
	Path string // /var/lib/trassa/helper/baseline.json
	Log  *slog.Logger

	mu       sync.Mutex
	loaded   bool
	st       detectorState
	lastSent map[string]time.Time
	queue    []*agentv1.Event
	cpu      map[int]*cpuSample
	lastSUID time.Time
}

type cpuSample struct {
	exe       string
	ticks     uint64
	at        time.Time
	highSince time.Time
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func (d *Detector) now() time.Time { return d.Sys.Now() }

func (d *Detector) loadLocked() error {
	if d.loaded {
		return nil
	}
	d.lastSent = map[string]time.Time{}
	d.cpu = map[int]*cpuSample{}
	b, err := os.ReadFile(d.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		d.st = detectorState{}
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(b, &d.st); err != nil {
			return fmt.Errorf("базовый список: %w", err)
		}
	}
	d.loaded = true
	return nil
}

func (d *Detector) saveLocked() error {
	b, err := json.Marshal(d.st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(d.Path, b, 0o600, fsutil.Keep)
}

// collect — объекты, которые сравниваются с базовым списком (кроме процессов: их сравнивает признак CPU).
func (d *Detector) collect(ctx context.Context, withSUID bool) ([]Item, error) {
	s := newScan(d.Sys)
	var items []Item
	keys, err := s.authorizedKeys()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		items = append(items, Item{Kind: KindAuthorizedKey, Subject: k.user + " " + k.fingerprint,
			Fingerprint: fingerprint("key", k.user, k.fingerprint), Evidence: k.user + ": ключ " + k.typ + " " + k.fingerprint + " в " + k.file})
	}
	users, err := s.Users()
	if err != nil {
		return nil, err
	}
	managed := d.Sys.accessManaged()
	for _, u := range users {
		// Учётные записи доступа Trassa (E16) созданы подписанной операцией — не признак взлома.
		if managed[u.Name] {
			continue
		}
		items = append(items, Item{Kind: KindUser, Subject: u.Name, Fingerprint: fingerprint("user", u.Name, strconv.Itoa(u.UID)),
			Evidence: fmt.Sprintf("учётная запись %s (uid %d, оболочка %s)", u.Name, u.UID, u.Shell)})
	}
	items = append(items, cronItems(d.Sys)...)
	items = append(items, unitItems(d.Sys)...)
	if withSUID {
		suid := suidItems(ctx, d.Sys)
		d.mu.Lock()
		d.st.SUID = suid
		d.lastSUID = d.now()
		d.mu.Unlock()
	}
	d.mu.Lock()
	items = append(items, d.st.SUID...)
	d.mu.Unlock()
	return items, nil
}

// cronItems — строки заданий (/etc/crontab, /etc/cron.d, crontab пользователей); переменные окружения не задания.
func cronItems(sys *System) []Item {
	files := []string{"/etc/crontab"}
	for _, dir := range []string{"/etc/cron.d", "/var/spool/cron/crontabs"} {
		ents, _ := os.ReadDir(sys.path(dir))
		for _, e := range ents {
			if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
				files = append(files, dir+"/"+e.Name())
			}
		}
	}
	var out []Item
	for _, f := range files {
		ls, err := sys.lines(f)
		if err != nil {
			continue
		}
		for _, l := range ls {
			if k, _, ok := strings.Cut(l, "="); ok && !strings.ContainsAny(k, " \t*") {
				continue
			}
			line := clip(redact.String(l), 300)
			out = append(out, Item{Kind: KindCron, Subject: clip(f+": "+line, 200), Fingerprint: fingerprint("cron", f, l),
				Evidence: "задание в " + f + ": " + line})
		}
	}
	// Задания в каталогах cron.hourly и т. п. — файлы-скрипты.
	for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		ents, _ := os.ReadDir(sys.path(dir))
		for _, e := range ents {
			if e.Name() == ".placeholder" {
				continue
			}
			p := dir + "/" + e.Name()
			sum, _ := fileSum(sys.path(p))
			out = append(out, Item{Kind: KindCron, Subject: p, Fingerprint: fingerprint("cronfile", p, sum), Evidence: "задание " + p})
		}
	}
	return out
}

// unitItems — юниты администратора в /etc/systemd/system (без своих trassa-*); содержимое входит в отпечаток.
func unitItems(sys *System) []Item {
	var out []Item
	root := sys.path("/etc/systemd/system")
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".service") || strings.HasSuffix(n, ".timer") || strings.HasSuffix(n, ".socket") ||
			strings.HasSuffix(n, ".path")) || strings.HasPrefix(n, "trassa-") {
			return nil
		}
		rel := "/etc/systemd/system/" + strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
		target := ""
		if e.Type()&fs.ModeSymlink != 0 {
			target, _ = os.Readlink(p)
			if target == "/dev/null" {
				return nil // замаскированный юнит
			}
		}
		sum, _ := fileSum(p)
		out = append(out, Item{Kind: KindSystemdUnit, Subject: rel, Fingerprint: fingerprint("unit", rel, target, sum), Evidence: "юнит systemd " + rel})
		return nil
	})
	return out
}

// Каталоги, которые обход SUID пропускает: виртуальные ФС и данные контейнеров.
var suidSkip = []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containers", "/snap"}

func suidItems(ctx context.Context, sys *System) []Item {
	var out []Item
	n := 0
	root := sys.path("/")
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(p, strings.TrimSuffix(root, "/")), "/")
		if e.IsDir() {
			for _, s := range suidSkip {
				if rel == s {
					return filepath.SkipDir
				}
			}
			return nil
		}
		n++
		if n > suidMaxFiles || ctx.Err() != nil {
			return filepath.SkipAll
		}
		if !e.Type().IsRegular() {
			return nil
		}
		fi, err := e.Info()
		if err != nil || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
			return nil
		}
		sum, _ := fileSum(p)
		out = append(out, Item{Kind: KindSUID, Subject: rel, Fingerprint: fingerprint("suid", rel, sum),
			Evidence: fmt.Sprintf("SUID/SGID-файл %s (%04o)", rel, fi.Mode().Perm())})
		return nil
	})
	return out
}

func fileSum(p string) (string, error) {
	b, err := fsutil.ReadLimited(p, 64<<20)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Step — один цикл наблюдения. Первый цикл без базового списка заполняет его текущим состоянием без событий.
func (d *Detector) Step(ctx context.Context) error {
	d.mu.Lock()
	if err := d.loadLocked(); err != nil {
		d.mu.Unlock()
		return err
	}
	withSUID := d.lastSUID.IsZero() || d.now().Sub(d.lastSUID) >= SUIDInterval
	first := d.st.Baseline == nil
	d.mu.Unlock()

	items, err := d.collect(ctx, withSUID)
	if err != nil {
		return err
	}
	procs, perr := d.Sys.Processes()

	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if first {
		d.st.Baseline = map[string]Item{}
		d.st.Pending = map[string]Item{}
		for _, it := range items {
			it.SeenAtMs = now.UnixMilli()
			d.st.Baseline[it.Fingerprint] = it
		}
		for _, p := range procs {
			fp := fingerprint("proc", p.Exe)
			d.st.Baseline[fp] = Item{Kind: KindProcess, Subject: p.Exe, Fingerprint: fp, SeenAtMs: now.UnixMilli()}
		}
		return d.saveLocked()
	}
	if d.st.Pending == nil {
		d.st.Pending = map[string]Item{}
	}
	current := map[string]bool{}
	for _, it := range items {
		current[it.Fingerprint] = true
		if _, ok := d.st.Baseline[it.Fingerprint]; ok {
			continue
		}
		if _, ok := d.st.Pending[it.Fingerprint]; !ok && len(d.st.Pending) < maxPending {
			it.SeenAtMs = now.UnixMilli()
			d.st.Pending[it.Fingerprint] = it
		}
	}
	// Объект исчез до того, как его приняли (ключ удалили) — больше не ожидает. Процессы держатся, пока жив признак.
	for fp, it := range d.st.Pending {
		if it.Kind != KindProcess && !current[fp] {
			delete(d.st.Pending, fp)
		}
	}
	if perr == nil {
		d.cpuStep(procs, now)
	}
	for _, it := range d.st.Pending {
		d.emitLocked(codeOf[it.Kind], it.Subject, it.Fingerprint, it.Kind, it.Evidence, now)
	}
	// Мгновенные признаки: принять их нельзя (на взломанном сервере их не «разрешают»), повтор — раз в час.
	if perr == nil {
		for _, p := range procs {
			if SuspiciousExec(p) {
				d.emitLocked("COMPROMISE_TMP_EXEC", p.Exe, "", "", fmt.Sprintf("процесс %d (%s) запущен из %s", p.PID, p.Comm, p.Exe), now)
			}
		}
	}
	for _, f := range checkLdPreload(ctx, newScan(d.Sys)) {
		if f.State == agentv1.CheckState_CHECK_STATE_FAIL {
			d.emitLocked("COMPROMISE_LD_PRELOAD", f.Subject, "", "", f.Evidence, now)
		}
	}
	if conns, err := outbound(d.Sys); err == nil {
		for _, c := range conns {
			d.emitLocked("COMPROMISE_OUTBOUND", c, "", "", "исходящее соединение на "+c, now)
		}
	}
	return d.saveLocked()
}

// cpuStep — доля ядра каждого процесса за интервал; процесс вне базового списка выше порога дольше MinerFor —
// ожидающий объект PROCESS (его можно принять: «это мой процесс»).
func (d *Detector) cpuStep(procs []Process, now time.Time) {
	alive := map[int]bool{}
	for _, p := range procs {
		alive[p.PID] = true
		ticks, ok := procTicks(d.Sys, p.PID)
		if !ok {
			continue
		}
		prev, had := d.cpu[p.PID]
		if !had || prev.exe != p.Exe {
			d.cpu[p.PID] = &cpuSample{exe: p.Exe, ticks: ticks, at: now}
			continue
		}
		dt := now.Sub(prev.at).Seconds()
		share := 0.0
		if dt > 0 && ticks >= prev.ticks {
			share = float64(ticks-prev.ticks) / clkTck / dt
		}
		prev.ticks, prev.at = ticks, now
		if share < MinerCPU {
			prev.highSince = time.Time{}
			continue
		}
		if prev.highSince.IsZero() {
			prev.highSince = now
		}
		fp := fingerprint("proc", p.Exe)
		if _, known := d.st.Baseline[fp]; known || now.Sub(prev.highSince) < MinerFor {
			continue
		}
		if _, ok := d.st.Pending[fp]; !ok && len(d.st.Pending) < maxPending {
			d.st.Pending[fp] = Item{Kind: KindProcess, Subject: clip(fmt.Sprintf("%d:%s", p.PID, p.Comm), 200), Fingerprint: fp, SeenAtMs: now.UnixMilli(),
				Evidence: fmt.Sprintf("процесс %d (%s, %s) держит %.0f%% ядра дольше %d мин", p.PID, p.Comm, p.Exe, share*100, int(MinerFor.Minutes()))}
		}
	}
	for pid := range d.cpu {
		if !alive[pid] {
			delete(d.cpu, pid)
		}
	}
}

// procTicks — utime + stime процесса (поля 14 и 15 /proc/<pid>/stat; имя в скобках может содержать пробелы).
func procTicks(sys *System, pid int) (uint64, bool) {
	b, err := os.ReadFile(sys.path(fmt.Sprintf("/proc/%d/stat", pid)))
	if err != nil {
		return 0, false
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b)[i+1:])
	if len(f) < 13 {
		return 0, false
	}
	u, err1 := strconv.ParseUint(f[11], 10, 64)
	st, err2 := strconv.ParseUint(f[12], 10, 64)
	return u + st, err1 == nil && err2 == nil
}

// emitLocked — событие, если по этому коду и объекту его не было последний час.
func (d *Detector) emitLocked(code, subject, fp, kind, evidence string, now time.Time) {
	key := code + "\x00" + subject
	if t, ok := d.lastSent[key]; ok && now.Sub(t) < EventEvery {
		return
	}
	d.lastSent[key] = now
	sev, ok := severityOf[code]
	if !ok {
		sev = agentv1.EventSeverity_EVENT_SEVERITY_WARN
	}
	attrs := map[string]string{"code": code, "subject": clip(redact.String(subject), 200), "state": "firing",
		"evidence": clip(redact.String(evidence), MaxEvidence)}
	if fp != "" {
		attrs["fingerprint"] = fp
		attrs["baseline_kind"] = kind
	}
	if len(d.queue) >= maxQueue {
		d.queue = d.queue[1:]
	}
	d.queue = append(d.queue, &agentv1.Event{Kind: "security.suspicious", Severity: sev, Message: code + ": " + clip(subject, 200),
		AtMs: now.UnixMilli(), Attributes: attrs})
}

// Drain — события для агента (helperrpc events.poll); очередь освобождается.
func (d *Detector) Drain() []*agentv1.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.queue
	d.queue = nil
	return out
}

// ErrUnknownFingerprint — отпечатка нет среди ожидающих объектов.
var ErrUnknownFingerprint = errors.New("BASELINE_UNKNOWN")

// Accept — «Это сделал я»: все отпечатки должны ожидать; иначе ничего не меняется. Возвращает новый digest.
func (d *Detector) Accept(fps []string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.loadLocked(); err != nil {
		return "", err
	}
	for _, fp := range fps {
		if _, ok := d.st.Pending[fp]; !ok {
			return "", fmt.Errorf("%w: %s", ErrUnknownFingerprint, fp)
		}
	}
	if d.st.Baseline == nil {
		d.st.Baseline = map[string]Item{}
	}
	for _, fp := range fps {
		it := d.st.Pending[fp]
		delete(d.st.Pending, fp)
		d.st.Baseline[fp] = it
		delete(d.lastSent, codeOf[it.Kind]+"\x00"+it.Subject)
	}
	if err := d.saveLocked(); err != nil {
		return "", err
	}
	_, digest := d.baselineLocked()
	return digest, nil
}

// ValidateAccept — схема security.baseline.accept.
func ValidateAccept(p *agentv1.SecurityBaselineAcceptParams) error {
	if len(p.GetFingerprints()) == 0 || len(p.GetFingerprints()) > maxPending {
		return fmt.Errorf("fingerprints: от 1 до %d", maxPending)
	}
	for _, f := range p.GetFingerprints() {
		if len(f) != 64 || strings.Trim(f, "0123456789abcdef") != "" {
			return fmt.Errorf("fingerprint %q: sha256 hex", f)
		}
	}
	return nil
}

func (d *Detector) baselineLocked() ([]string, string) {
	fps := make([]string, 0, len(d.st.Baseline))
	for fp := range d.st.Baseline {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	sum := sha256.Sum256([]byte(strings.Join(fps, "\n")))
	return fps, hex.EncodeToString(sum[:])
}

// pendingOf — ожидающие объекты кода (для скана).
func (d *Detector) pendingOf(code string) ([]Item, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.loadLocked(); err != nil {
		return nil, err
	}
	var out []Item
	for _, it := range d.st.Pending {
		if codeOf[it.Kind] == code {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

// Run — наблюдение до отмены ctx. Ошибка цикла пишется в журнал и не останавливает детектор.
func (d *Detector) Run(ctx context.Context) {
	t := time.NewTicker(FastInterval)
	defer t.Stop()
	for {
		if err := d.Step(ctx); err != nil && d.Log != nil {
			d.Log.Warn("детектор: цикл", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func init() {
	for _, code := range []string{"COMPROMISE_KEYS_CHANGED", "COMPROMISE_NEW_CRON", "COMPROMISE_NEW_SUID", "COMPROMISE_NEW_USER", "COMPROMISE_MINER_CPU"} {
		register(Check{Code: code, Run: func(_ context.Context, s *Scan) []Finding {
			if s.sys.Detector == nil {
				return []Finding{failed(ErrUnsupported, errors.New("детектор не запущен"))}
			}
			items, err := s.sys.Detector.pendingOf(code)
			if err != nil {
				return []Finding{failed(ErrReadFailed, err)}
			}
			var out []Finding
			for _, it := range items {
				out = append(out, fail(it.Subject, it.Evidence))
			}
			return out
		}})
	}
	snapshotParts = append(snapshotParts, func(_ context.Context, s *Scan, res *agentv1.SecurityScanResult) {
		if s.sys.Detector == nil {
			return
		}
		s.sys.Detector.mu.Lock()
		defer s.sys.Detector.mu.Unlock()
		if s.sys.Detector.loadLocked() == nil {
			res.Baseline, res.BaselineDigest = s.sys.Detector.baselineLocked()
		}
	})
}
