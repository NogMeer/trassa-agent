// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"aead.dev/minisign"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/update"
)

type release struct {
	srv   *httptest.Server
	files map[string][]byte
	priv  minisign.PrivateKey
	pub   string
}

func newRelease(t *testing.T, version string) *release {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	txt, _ := pub.MarshalText()
	r := &release{files: map[string][]byte{}, priv: priv, pub: string(txt)}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, ok := r.files[filepath.Base(req.URL.Path)]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	r.publish(version, version)
	return r
}

func (r *release) publish(version, comment string) {
	var sums bytes.Buffer
	for _, bin := range []string{"trassa-agent", "trassa-helper"} {
		name := bin + "-linux-" + runtime.GOARCH
		r.files[name] = []byte(bin + " " + version)
		sums.WriteString(update.SHA256Hex(r.files[name]) + "  " + name + "\n")
	}
	r.files["SHA256SUMS"] = sums.Bytes()
	rd := minisign.NewReader(bytes.NewReader(sums.Bytes()))
	buf := make([]byte, 4096)
	for {
		if _, err := rd.Read(buf); err != nil {
			break
		}
	}
	r.files["SHA256SUMS.minisig"] = rd.SignWithComments(r.priv, "trassa-agent "+comment, "")
}

func (r *release) params(version string) *agentv1.OperationParams {
	p := &agentv1.AgentUpdateParams{Version: version, SignatureUrl: r.srv.URL + "/v/SHA256SUMS.minisig"}
	for _, bin := range []string{"trassa-agent", "trassa-helper"} {
		name := bin + "-linux-" + runtime.GOARCH
		p.Artifacts = append(p.Artifacts, &agentv1.ReleaseArtifact{Os: "linux", Arch: runtime.GOARCH, Url: r.srv.URL + "/v/" + name, Sha256: update.SHA256Hex(r.files[name])})
	}
	return &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentUpdate{AgentUpdate: p}}
}

func updateFixture(t *testing.T) (*fixture, *release) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("выпуски только для amd64 и arm64")
	}
	f := newFixture(t)
	for _, b := range []string{"trassa-agent", "trassa-helper"} {
		_ = os.WriteFile(filepath.Join(f.paths.BinDir, b), []byte(b+" 1.0.0"), 0o755)
	}
	r := newRelease(t, "1.1.0")
	v, err := update.NewVerifier([]string{r.pub})
	if err != nil {
		t.Fatal(err)
	}
	f.e.Updater = &Updater{Verifier: v, Client: r.srv.Client()}
	return f, r
}

func (f *fixture) bin(name string) string {
	b, _ := os.ReadFile(filepath.Join(f.paths.BinDir, name))
	return string(b)
}

// S8: подписанный выпуск ставится, сторож заведён прежним помощником, подтверждение снимает его.
func TestUpdateSucceeds(t *testing.T) {
	f, r := updateFixture(t)
	b := f.body(ops.TypeAgentUpdate, r.params("1.1.0"))
	o := f.exec(sealed(b))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		t.Fatalf("%+v", o.result)
	}
	if f.bin("trassa-agent") != "trassa-agent 1.1.0" || f.bin("trassa-helper") != "trassa-helper 1.1.0" {
		t.Fatal("бинарники не заменены")
	}
	a, ok := f.timer.get(b.GetOperationId())
	if !ok || a.after != UpdateWatchdog || a.helper != filepath.Join(f.paths.BinPrevDir, "trassa-helper") {
		t.Fatalf("сторож: %+v", a)
	}
	if len(f.services.scheduled) != 1 {
		t.Fatal("перезапуск не запланирован")
	}
	if res, code := f.confirm(b.GetOperationId()); code != "" || res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("%q %+v", code, res)
	}
}

// Новая версия не вышла на связь: сторож возвращает прежние бинарники (UPDATE_ROLLED_BACK).
func TestUpdateWatchdog(t *testing.T) {
	f, r := updateFixture(t)
	b := f.body(ops.TypeAgentUpdate, r.params("1.1.0"))
	f.exec(sealed(b))
	f.open()
	if err := f.e.AutoRollback(context.Background(), b.GetOperationId()); err != nil {
		t.Fatal(err)
	}
	if f.bin("trassa-agent") != "trassa-agent 1.0.0" || f.bin("trassa-helper") != "trassa-helper 1.0.0" {
		t.Fatal("прежние бинарники не возвращены")
	}
	o := f.exec(sealed(b))
	if o.result.GetErrorCode() != update.CodeRolledBack {
		t.Fatalf("%+v", o.result)
	}
}

func TestUpdateRejected(t *testing.T) {
	cases := map[string]struct {
		mut  func(f *fixture, r *release) *agentv1.OperationParams
		code string
	}{
		"чужая подпись": {func(f *fixture, r *release) *agentv1.OperationParams {
			other := newRelease(t, "1.1.0")
			r.files["SHA256SUMS.minisig"] = other.files["SHA256SUMS.minisig"]
			return r.params("1.1.0")
		}, update.CodeSignatureInvalid},
		"без подписи": {func(f *fixture, r *release) *agentv1.OperationParams {
			delete(r.files, "SHA256SUMS.minisig")
			return r.params("1.1.0")
		}, update.CodeDownloadFailed},
		"старая подпись под новой версией": {func(f *fixture, r *release) *agentv1.OperationParams {
			r.publish("1.1.0", "1.0.5")
			return r.params("1.1.0")
		}, update.CodeSignatureInvalid},
		"подменённый бинарник": {func(f *fixture, r *release) *agentv1.OperationParams {
			p := r.params("1.1.0")
			r.files["trassa-agent-linux-"+runtime.GOARCH] = []byte("evil")
			return p
		}, update.CodeSignatureInvalid},
		"сумма не из SHA256SUMS": {func(f *fixture, r *release) *agentv1.OperationParams {
			r.files["trassa-agent-linux-"+runtime.GOARCH] = []byte("evil")
			return r.params("1.1.0")
		}, update.CodeSignatureInvalid},
		"понижение": {func(f *fixture, r *release) *agentv1.OperationParams {
			r.publish("0.9.0", "0.9.0")
			return r.params("0.9.0")
		}, update.CodeDowngrade},
		"та же версия": {func(f *fixture, r *release) *agentv1.OperationParams {
			r.publish("1.0.0", "1.0.0")
			return r.params("1.0.0")
		}, update.CodeDowngrade},
		"нет ключей выпуска": {func(f *fixture, r *release) *agentv1.OperationParams {
			f.e.Updater.Verifier = nil
			return r.params("1.1.0")
		}, update.CodeSignatureInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, r := updateFixture(t)
			o := f.exec(sealed(f.body(ops.TypeAgentUpdate, tc.mut(f, r))))
			if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED || o.result.GetErrorCode() != tc.code {
				t.Fatalf("ждали %s: %+v", tc.code, o.result)
			}
			if f.bin("trassa-agent") != "trassa-agent 1.0.0" {
				t.Fatal("версия изменилась")
			}
			if recs, _ := f.e.Auto.List(); len(recs) != 0 {
				t.Fatal("сторож заведён при отказе")
			}
		})
	}
}
