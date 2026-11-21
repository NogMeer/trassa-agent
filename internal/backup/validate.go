// SPDX-License-Identifier: AGPL-3.0-only

// Package backup — бэкапы restic (E13): проверка параметров, настройки плана, запуск restic, дампы баз.
// Правила проверки повторяют каталог панели (apps/api/src/modules/backups/operation-catalog.ts, paths.ts):
// помощник им не доверяет и проверяет заново (R10).
package backup

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
)

// ErrPathForbidden — путь источника или назначения запрещён (BACKUP_PATH_FORBIDDEN).
var ErrPathForbidden = errors.New("BACKUP_PATH_FORBIDDEN")

// CodePathForbidden — код отказа для ErrPathForbidden.
const CodePathForbidden = "BACKUP_PATH_FORBIDDEN"

// ForbiddenRoots — псевдо-ФС и каталоги Trassa: ни бэкап, ни восстановление их не трогают.
var ForbiddenRoots = []string{"/proc", "/sys", "/dev", "/run", "/etc/trassa", "/var/lib/trassa"}

// MaxPathLength — предел длины пути.
const MaxPathLength = 4096

// EnvNames — переменные restic с секретами; других в env нет.
var EnvNames = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "RESTIC_REST_USERNAME", "RESTIC_REST_PASSWORD"}

var (
	snapshotRe  = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	kidRe       = regexp.MustCompile(`^[0-9a-f]{16}$`)
	sourceRe    = regexp.MustCompile(`^[A-Za-z0-9 _.:@/-]{1,200}$`)
	volumeRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	containerRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]{0,127})?$`)
	// Имя базы не начинается с «-»: иначе утилита дампа прочла бы его как ключ.
	dbNameRe   = regexp.MustCompile(`^[A-Za-z0-9_$.][A-Za-z0-9_$.-]{0,63}$`)
	durationRe = regexp.MustCompile(`^(\d{1,4}[dwmy])?$`)
	subsetRe   = regexp.MustCompile(`^(\d{1,2}%|100%|\d{1,6}[KMG])$`)
	versionRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	unixUserRe = regexp.MustCompile(`^trassa-bk-[a-z0-9]{1,20}$`)
	pubKeyRe   = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]{68}(?: [^\n\r\x00]{0,100})?$`)
	rcloneRe   = regexp.MustCompile(`^rclone:([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252}):[A-Za-z0-9/_.-]{1,256}$`)
	hostKeyRe  = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]{68}$`)
	// sftp:user@host:/path (порт 22) и sftp://user@host[:port]/path (как в restic; //path — абсолютный путь).
	// Длина адреса — до 2048 (RepoURL).
	sftpRe    = regexp.MustCompile(`^sftp:([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252}):/[^\x00]+$`)
	sftpURLRe = regexp.MustCompile(`^sftp://([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252}|\[[0-9A-Fa-f:.]{2,45}\])(?::([0-9]{1,5}))?/[^\x00]+$`)
)

func hasControl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// AllowedPath — абсолютный путь без «.», «..», пустых частей и управляющих символов, не корень и не под
// ForbiddenRoots.
func AllowedPath(p string) bool {
	if !strings.HasPrefix(p, "/") || p == "/" || len(p) > MaxPathLength || !utf8.ValidString(p) || hasControl(p) {
		return false
	}
	for _, s := range strings.Split(p[1:], "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	for _, r := range ForbiddenRoots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return false
		}
	}
	return true
}

func checkPath(p string) error {
	if !AllowedPath(p) {
		return fmt.Errorf("%w: %q", ErrPathForbidden, p)
	}
	return nil
}

// allowedExclude — шаблон --exclude: 1–512 знаков без управляющих символов.
func allowedExclude(p string) bool {
	return p != "" && len(p) <= 512 && utf8.ValidString(p) && !hasControl(p)
}

// ValidSnapshotID — id снимка restic (8–64 hex).
func ValidSnapshotID(s string) bool { return snapshotRe.MatchString(s) }

func checkSealed(s *agentv1.SealedSecret, what string) error {
	if s == nil {
		return fmt.Errorf("%s: нет секрета", what)
	}
	if !kidRe.MatchString(s.GetKid()) {
		return fmt.Errorf("%s: kid", what)
	}
	// enc (32) + тег AES-GCM (16) + хотя бы байт; сверху — base64 8 КиБ панели.
	if n := len(s.GetEncCt()); n < 49 || n > 6144 {
		return fmt.Errorf("%s: длина шифротекста %d", what, n)
	}
	return nil
}

// RepoURL — адрес репозитория без учётных данных: s3:https://…, rest:https://… или rest:http://…,
// sftp:user@host:/путь. Адрес из подписанного тела всё равно отсеивается от link-local (метаданные облака):
// root-помощник не ходит туда даже по подписанной команде. Loopback разрешён — цель SERVER идёт через туннель.
func RepoURL(u string) error {
	if len(u) > 2048 || !utf8.ValidString(u) || strings.ContainsAny(u, " \t\r\n\x00") {
		return errors.New("адрес репозитория")
	}
	httpURL := func(rest string, schemes ...string) error {
		x, err := url.Parse(rest)
		if err != nil || x.User != nil || x.Hostname() == "" || x.Opaque != "" {
			return errors.New("адрес репозитория")
		}
		ok := false
		for _, s := range schemes {
			ok = ok || x.Scheme == s
		}
		if !ok {
			return errors.New("схема адреса репозитория")
		}
		if a, err := netip.ParseAddr(x.Hostname()); err == nil {
			a = a.Unmap()
			if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
				return errors.New("адрес репозитория запрещён")
			}
		}
		return nil
	}
	switch {
	case strings.HasPrefix(u, "s3:"):
		return httpURL(u[3:], "https")
	case strings.HasPrefix(u, "rest:"):
		return httpURL(u[5:], "https", "http")
	case sftpRe.MatchString(u), rcloneRe.MatchString(u):
		return nil
	case sftpURLRe.MatchString(u):
		_, _, _, err := SSHTarget(u)
		return err
	}
	return errors.New("адрес репозитория")
}

func checkRepo(r *agentv1.BackupRepo, what string) error {
	if r == nil {
		return fmt.Errorf("%s: нет", what)
	}
	if err := RepoURL(r.GetUrl()); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := checkSealed(r.GetPassword(), what+".password"); err != nil {
		return err
	}
	for name, s := range r.GetEnv() {
		if !knownEnv(name) {
			return fmt.Errorf("%s.env: %q", what, name)
		}
		if err := checkSealed(s, what+".env."+name); err != nil {
			return err
		}
	}
	return nil
}

func knownEnv(name string) bool {
	for _, n := range EnvNames {
		if n == name {
			return true
		}
	}
	return false
}

func checkPlan(id string) error {
	if !config.IsUUID(id) {
		return errors.New("plan_id")
	}
	return nil
}

func checkDeadline(ms int64) error {
	if ms < 0 {
		return errors.New("deadline_ms")
	}
	return nil
}

// ValidateInit — backup.init.
func ValidateInit(p *agentv1.BackupInitParams) error {
	if err := checkPlan(p.GetPlanId()); err != nil {
		return err
	}
	if err := checkRepo(p.GetRepo(), "repo"); err != nil {
		return err
	}
	if !versionRe.MatchString(p.GetResticVersion()) || !sha256Re.MatchString(p.GetResticSha256()) {
		return errors.New("restic_version, restic_sha256")
	}
	if !httpsURL(p.GetResticUrl()) {
		return errors.New("restic_url")
	}
	if err := CheckTool("restic", p.GetResticVersion(), p.GetResticSha256()); err != nil {
		return err
	}
	if k := p.GetSshHostKey(); k != "" && !hostKeyRe.MatchString(k) {
		return errors.New("ssh_host_key")
	}
	// Ключ хоста только закреплённый: без него ssh-цель не принимается (никакого accept-new).
	if _, _, _, err := SSHTarget(p.GetRepo().GetUrl()); err == nil && !p.GetSshKeypair() && p.GetSshHostKey() == "" {
		return errors.New("ssh_host_key: обязателен для sftp и rclone")
	}
	return nil
}

func httpsURL(u string) bool {
	x, err := url.Parse(u)
	return err == nil && x.Scheme == "https" && x.User == nil && x.Hostname() != "" && len(u) <= 2048
}

func checkTool(t *agentv1.BackupTool, what string) error {
	if t == nil || !versionRe.MatchString(t.GetVersion()) || !sha256Re.MatchString(t.GetSha256()) || !httpsURL(t.GetUrl()) {
		return fmt.Errorf("%s: версия, sha256 или адрес", what)
	}
	return nil
}

var plainPathRe = regexp.MustCompile(`^[A-Za-z0-9/_.-]+$`)

// plainPath — путь цели только из букв, цифр и /_.-: он попадает в ForceCommand, которую sshd запускает через
// оболочку пользователя.
func plainPath(p string) error {
	if !plainPathRe.MatchString(p) {
		return fmt.Errorf("%w: в пути цели допустимы только буквы, цифры и /_.-", ErrPathForbidden)
	}
	return checkPath(p)
}

func checkSource(s *agentv1.BackupSource) error {
	if !sourceRe.MatchString(s.GetName()) {
		return fmt.Errorf("источник %q: имя", s.GetName())
	}
	db := func(d *agentv1.DatabaseSource) error {
		if !containerRe.MatchString(d.GetContainer()) || !dbNameRe.MatchString(d.GetDatabase()) {
			return fmt.Errorf("источник %q: база", s.GetName())
		}
		return nil
	}
	switch v := s.GetSource().(type) {
	case *agentv1.BackupSource_Path:
		if err := checkPath(v.Path.GetPath()); err != nil {
			return err
		}
		if len(v.Path.GetExcludes()) > 100 {
			return fmt.Errorf("источник %q: исключений больше 100", s.GetName())
		}
		for _, e := range v.Path.GetExcludes() {
			if !allowedExclude(e) {
				return fmt.Errorf("источник %q: исключение", s.GetName())
			}
		}
		return nil
	case *agentv1.BackupSource_DockerVolume:
		if !volumeRe.MatchString(v.DockerVolume) {
			return fmt.Errorf("источник %q: том", s.GetName())
		}
		return nil
	case *agentv1.BackupSource_Postgres:
		return db(v.Postgres)
	case *agentv1.BackupSource_Mysql:
		return db(v.Mysql)
	}
	return fmt.Errorf("источник %q: вид не задан", s.GetName())
}

// ValidateRun — backup.run: 1–50 источников с разными именами (пустой список не «всё», R1).
func ValidateRun(p *agentv1.BackupRunParams) error {
	if err := checkPlan(p.GetPlanId()); err != nil {
		return err
	}
	if n := len(p.GetSources()); n < 1 || n > 50 {
		return errors.New("sources: от 1 до 50")
	}
	seen := map[string]bool{}
	for _, s := range p.GetSources() {
		if seen[s.GetName()] {
			return fmt.Errorf("источник %q дважды", s.GetName())
		}
		seen[s.GetName()] = true
		if err := checkSource(s); err != nil {
			return err
		}
	}
	if p.GetRateLimitKibps() > 10_000_000 {
		return errors.New("rate_limit_kibps")
	}
	return checkDeadline(p.GetDeadlineMs())
}

// ValidateVerify — backup.verify.
func ValidateVerify(p *agentv1.BackupVerifyParams) error {
	if err := checkPlan(p.GetPlanId()); err != nil {
		return err
	}
	if len(p.GetSnapshotIds()) > 50 {
		return errors.New("snapshot_ids: больше 50")
	}
	for _, s := range p.GetSnapshotIds() {
		if !ValidSnapshotID(s) {
			return errors.New("snapshot_ids")
		}
	}
	if !subsetRe.MatchString(p.GetReadDataSubset()) {
		return errors.New("read_data_subset")
	}
	if p.GetSampleFiles() > 10_000 {
		return errors.New("sample_files")
	}
	return checkDeadline(p.GetDeadlineMs())
}

// ValidateRestore — backup.restore: режим, выбор (пустой не «всё», R1), назначение только у OTHER_SERVER.
func ValidateRestore(p *agentv1.BackupRestoreParams) error {
	if err := checkPlan(p.GetPlanId()); err != nil {
		return err
	}
	if !ValidSnapshotID(p.GetSnapshotId()) {
		return errors.New("snapshot_id")
	}
	switch p.GetMode() {
	case agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, agentv1.RestoreMode_RESTORE_MODE_IN_PLACE, agentv1.RestoreMode_RESTORE_MODE_OTHER_SERVER:
	default:
		return errors.New("mode")
	}
	sel := p.GetSelection()
	explicit := len(sel.GetPaths()) + len(sel.GetDatabases())
	if sel.GetAll() == (explicit > 0) {
		return errors.New("selection: all или явный список (R1)")
	}
	if len(sel.GetPaths()) > 1000 || len(sel.GetDatabases()) > 100 {
		return errors.New("selection: слишком длинный список")
	}
	for _, x := range sel.GetPaths() {
		if err := checkPath(x); err != nil {
			return err
		}
	}
	for _, d := range sel.GetDatabases() {
		if !dbNameRe.MatchString(d) {
			return errors.New("selection.databases")
		}
	}
	other := p.GetMode() == agentv1.RestoreMode_RESTORE_MODE_OTHER_SERVER
	if other != (p.GetDestPath() != "") {
		return errors.New("dest_path только для OTHER_SERVER")
	}
	// Получатель без плана: репозиторий и restic — в операции, только для OTHER_SERVER.
	if r := p.GetRepo(); r != nil {
		if !other {
			return errors.New("repo — только для OTHER_SERVER")
		}
		if err := checkRepo(r, "repo"); err != nil {
			return err
		}
		if err := checkTool(p.GetRestic(), "restic"); err != nil {
			return err
		}
		if err := CheckTool("restic", p.GetRestic().GetVersion(), p.GetRestic().GetSha256()); err != nil {
			return err
		}
	} else if p.GetRestic() != nil {
		return errors.New("restic — только вместе с repo")
	}
	if p.GetSshKeypair() && !other {
		return errors.New("ssh_keypair — только для OTHER_SERVER")
	}
	if k := p.GetSshHostKey(); k != "" && !hostKeyRe.MatchString(k) {
		return errors.New("ssh_host_key")
	}
	if _, _, _, err := SSHTarget(p.GetRepo().GetUrl()); err == nil && p.GetSshHostKey() == "" {
		return errors.New("ssh_host_key: обязателен для sftp и rclone")
	}
	if other {
		if err := checkPath(p.GetDestPath()); err != nil {
			return err
		}
	}
	return checkDeadline(p.GetDeadlineMs())
}

// RestoreRollback — точка отката, которую требует режим: во временный каталог — без неё, иначе снапшот
// хостера (E12) или локальная копия (R13).
func RestoreRollback(p *agentv1.BackupRestoreParams, got agentv1.RollbackKind) error {
	if p.GetMode() == agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR {
		if got != agentv1.RollbackKind_ROLLBACK_KIND_NONE {
			return errors.New("rollback: во временный каталог — NONE")
		}
		return nil
	}
	if got != agentv1.RollbackKind_ROLLBACK_KIND_SNAPSHOT && got != agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY {
		return errors.New("rollback: на место — SNAPSHOT или LOCAL_COPY (R13)")
	}
	return nil
}

// ValidateSnapshots — backup.snapshots.list.
func ValidateSnapshots(p *agentv1.BackupSnapshotsParams) error { return checkPlan(p.GetPlanId()) }

// ValidateBrowse — backup.snapshot.browse: путь «/» или разрешённый, до 1000 записей.
func ValidateBrowse(p *agentv1.BackupBrowseParams) error {
	if err := checkPlan(p.GetPlanId()); err != nil {
		return err
	}
	if !ValidSnapshotID(p.GetSnapshotId()) {
		return errors.New("snapshot_id")
	}
	if p.GetPath() != "/" {
		if err := checkPath(p.GetPath()); err != nil {
			return err
		}
	}
	if p.GetLimit() < 1 || p.GetLimit() > 1000 {
		return errors.New("limit: от 1 до 1000")
	}
	return nil
}

// ValidatePrune — backup.prune: политика не пустая (R1), сроки restic.
func ValidatePrune(p *agentv1.BackupPruneParams) error {
	if err := checkPlan(p.GetPlanId()); err != nil {
		return err
	}
	r := p.GetRetention()
	if r.GetKeepLast() > 1000 {
		return errors.New("keep_last")
	}
	for _, d := range []string{r.GetKeepWithinDaily(), r.GetKeepWithinWeekly(), r.GetKeepWithinMonthly()} {
		if !durationRe.MatchString(d) {
			return errors.New("retention: срок")
		}
	}
	if r.GetKeepLast() == 0 && r.GetKeepWithinDaily() == "" && r.GetKeepWithinWeekly() == "" && r.GetKeepWithinMonthly() == "" {
		return errors.New("retention: пустая политика (R1)")
	}
	if u := p.GetTargetUnixUser(); u != "" {
		// Чистка на цели: репозиторий — каталог цели этого пользователя, адреса нет; пароль — секретом.
		if !unixUserRe.MatchString(u) {
			return errors.New("target_unix_user")
		}
		m := p.GetMaintenanceRepo()
		if m.GetUrl() != "" || len(m.GetEnv()) > 0 {
			return errors.New("maintenance_repo: у чистки на цели нет адреса и переменных")
		}
		return checkSealed(m.GetPassword(), "maintenance_repo.password")
	}
	return checkRepo(p.GetMaintenanceRepo(), "maintenance_repo")
}

// ValidateTargetEnsure — backup.target.ensure.
func ValidateTargetEnsure(p *agentv1.BackupTargetEnsureParams) error {
	if err := plainPath(p.GetPath()); err != nil {
		return err
	}
	if err := checkTool(p.GetRclone(), "rclone"); err != nil {
		return err
	}
	if err := checkTool(p.GetRestic(), "restic"); err != nil {
		return err
	}
	if err := CheckTool("rclone", p.GetRclone().GetVersion(), p.GetRclone().GetSha256()); err != nil {
		return err
	}
	if err := CheckTool("restic", p.GetRestic().GetVersion(), p.GetRestic().GetSha256()); err != nil {
		return err
	}
	if !unixUserRe.MatchString(p.GetUnixUser()) {
		return errors.New("unix_user")
	}
	if !pubKeyRe.MatchString(p.GetSourcePublicKey()) {
		return errors.New("source_public_key")
	}
	if _, err := netip.ParseAddr(p.GetSourceAddress()); err != nil || strings.Contains(p.GetSourceAddress(), "%") {
		return errors.New("source_address")
	}
	// Читатель: всё или ничего.
	if p.GetReaderPublicKey() == "" {
		if p.GetReaderAddress() != "" || p.GetReaderExpiresAtMs() != 0 {
			return errors.New("reader_*: без reader_public_key")
		}
		return nil
	}
	if !pubKeyRe.MatchString(p.GetReaderPublicKey()) || p.GetReaderPublicKey() == p.GetSourcePublicKey() {
		return errors.New("reader_public_key")
	}
	if _, err := netip.ParseAddr(p.GetReaderAddress()); err != nil || strings.Contains(p.GetReaderAddress(), "%") {
		return errors.New("reader_address")
	}
	if p.GetReaderExpiresAtMs() <= 0 {
		return errors.New("reader_expires_at_ms")
	}
	return nil
}

// MaxReaderTTL — предел доступа читателя от issued_at_ms операции.
const MaxReaderTTL = 24 * time.Hour

// ReaderExpiry — срок читателя в пределах MaxReaderTTL от выдачи операции и не в прошлом.
func ReaderExpiry(p *agentv1.BackupTargetEnsureParams, issuedAtMs int64) error {
	if p.GetReaderPublicKey() == "" {
		return nil
	}
	exp := p.GetReaderExpiresAtMs()
	if issuedAtMs <= 0 || exp <= issuedAtMs || exp-issuedAtMs > MaxReaderTTL.Milliseconds() {
		return fmt.Errorf("reader_expires_at_ms: от выдачи операции до %s", MaxReaderTTL)
	}
	return nil
}

// ValidateTargetRevokeReader — backup.target.revoke_reader.
func ValidateTargetRevokeReader(p *agentv1.BackupTargetRevokeReaderParams) error {
	if !unixUserRe.MatchString(p.GetUnixUser()) {
		return errors.New("unix_user")
	}
	return nil
}

// ValidateTargetRemove — backup.target.remove.
func ValidateTargetRemove(p *agentv1.BackupTargetRemoveParams) error {
	if !unixUserRe.MatchString(p.GetUnixUser()) {
		return errors.New("unix_user")
	}
	return plainPath(p.GetPath())
}

// ValidateUnconfigure — backup.unconfigure.
func ValidateUnconfigure(p *agentv1.BackupUnconfigureParams) error { return checkPlan(p.GetPlanId()) }

// SSHTarget — пользователь, хост и порт ssh-адреса репозитория (sftp:, sftp://, rclone:); иное — ошибка.
func SSHTarget(u string) (user, host string, port int, err error) {
	port = 22
	if m := sftpURLRe.FindStringSubmatch(u); m != nil {
		user, host = m[1], m[2]
		if strings.HasPrefix(host, "[") {
			// IPv6 только в скобках, как в URL; ssh получает адрес без скобок, known_hosts — [addr]:port.
			a, perr := netip.ParseAddr(host[1 : len(host)-1])
			if perr != nil || !a.Is6() || a.Zone() != "" {
				return "", "", 0, errors.New("адрес IPv6 цели sftp")
			}
			host = a.String()
		}
		if m[3] != "" {
			if port, err = strconv.Atoi(m[3]); err != nil || port < 1 || port > 65535 {
				return "", "", 0, errors.New("порт sftp: 1–65535")
			}
		}
		return user, host, port, nil
	}
	for _, re := range []*regexp.Regexp{sftpRe, rcloneRe} {
		if m := re.FindStringSubmatch(u); m != nil {
			return m[1], m[2], port, nil
		}
	}
	return "", "", 0, errors.New("не ssh-адрес")
}

// KnownHostsName — имя хоста в known_hosts: host для 22, [host]:port для прочих портов (sshd(8), ssh_known_hosts).
func KnownHostsName(host string, port int) string {
	if port == 22 {
		return host
	}
	return "[" + host + "]:" + strconv.Itoa(port)
}
