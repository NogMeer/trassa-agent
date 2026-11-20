// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/access"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

// enableAccess — доступ на поддельном корне: sshd -T по нашим файлам, учётные записи в памяти.
func (f *fixture) enableAccess(t *testing.T) string {
	t.Helper()
	root := filepath.Join(f.root, "host")
	for p, c := range map[string]string{
		"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n", "etc/sudoers": "@includedir /etc/sudoers.d\n",
		"etc/shells": "/bin/bash\n",
	} {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), []byte(c), 0o644)
	}
	users := map[string]bool{}
	// Откат доступа перечитывает sshd командой: в тесте — без запуска.
	f.e.Rollback.Exec = func(string, ...string) error { return nil }
	f.e.Access = &access.Env{Root: root,
		Lookup: func(n string) (*user.User, error) {
			if users[n] {
				return &user.User{Username: n, Uid: "1001", Gid: "1001"}, nil
			}
			return nil, user.UnknownUserError(n)
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "sshd":
				if args[0] == "-t" {
					return nil, nil
				}
				ca, pf := "none", "none"
				if _, err := os.Stat(filepath.Join(root, access.AccessConf)); err == nil {
					ca, pf = access.CAFile, access.PrincipalsDir+"/%u"
				}
				return []byte(fmt.Sprintf("trustedusercakeys %s\nauthorizedprincipalsfile %s\nauthorizedprincipalscommand none\n", ca, pf)), nil
			case "useradd":
				users[args[len(args)-1]] = true
			case "systemctl":
				return nil, fmt.Errorf("inactive")
			}
			return nil, nil
		}}
	return root
}

func TestAccessThroughHelper(t *testing.T) {
	f := newFixture(t)
	root := f.enableAccess(t)
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pk)
	trust := f.body(ops.TypeSSHCATrust, &agentv1.OperationParams{Params: &agentv1.OperationParams_SshcaTrust{SshcaTrust: &agentv1.SshCaTrustParams{
		CaPublicKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))}}}})
	trust.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	o := f.exec(sealed(trust))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || o.result.GetSshcaTrust().GetCaFingerprints()[0] != ssh.FingerprintSHA256(k) {
		t.Fatalf("trust: %+v", o.result)
	}
	if o.result.GetRollbackPoint() == nil {
		t.Fatal("нет точки отката")
	}
	ens := f.body(ops.TypeAccessUserEnsure, &agentv1.OperationParams{Params: &agentv1.OperationParams_AccessUserEnsure{AccessUserEnsure: &agentv1.AccessUserEnsureParams{
		UnixUser: "ops", Principals: []*agentv1.AccessPrincipal{{Name: "trassa:ws1:m1"}}}}})
	ens.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	if o := f.exec(sealed(ens)); !o.result.GetAccessUserEnsure().GetCreated() {
		t.Fatalf("user: %+v", o.result)
	}
	if _, err := os.Stat(filepath.Join(root, access.PrincipalsDir, "ops")); err != nil {
		t.Fatal("нет файла принципалов")
	}
	// root и имена Trassa — отказ своим кодом до выполнения.
	bad := f.body(ops.TypeAccessUserEnsure, &agentv1.OperationParams{Params: &agentv1.OperationParams_AccessUserEnsure{AccessUserEnsure: &agentv1.AccessUserEnsureParams{
		UnixUser: "root", Principals: []*agentv1.AccessPrincipal{{Name: "trassa:ws1:m1"}}}}})
	bad.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	expectReject(t, f, sealed(bad), access.ErrUserForbidden.Error())
	// Аварийный вход дольше 30 минут — отказ.
	g := f.body(ops.TypeAccessRescueGrant, &agentv1.OperationParams{Params: &agentv1.OperationParams_AccessRescueGrant{AccessRescueGrant: &agentv1.AccessRescueGrantParams{
		Principal: "trassa:ws1:rescue:g1"}}})
	g.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	g.GetParams().GetAccessRescueGrant().ExpiresAtMs = g.GetIssuedAtMs() + 31*60_000
	expectReject(t, f, sealed(g), ops.CodeParamsInvalid)
	st := f.body(ops.TypeAccessStateRead, &agentv1.OperationParams{Params: &agentv1.OperationParams_AccessStateRead{AccessStateRead: &agentv1.AccessStateReadParams{}}})
	if o := f.exec(sealed(st)); len(o.result.GetAccessState().GetUsers()) != 1 || !o.result.GetAccessState().GetTrustEffective() {
		t.Fatalf("state: %+v", o.result)
	}
}
