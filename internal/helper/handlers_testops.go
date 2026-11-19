// SPDX-License-Identifier: AGPL-3.0-only

//go:build testops

package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

// test.config_write — только в сборке с тегом testops.
func (e *Executor) extraHandlers() map[string]handler {
	return map[string]handler{ops.TypeTestConfigWrite: {preview: e.previewConfigWrite, apply: e.applyConfigWrite}}
}

func (e *Executor) previewConfigWrite(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetTestConfigWrite()
	old, err := os.ReadFile(p.GetPath())
	kind := agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY
	if errors.Is(err, os.ErrNotExist) {
		kind = agentv1.FileChangeKind_FILE_CHANGE_KIND_CREATE
	} else if err != nil {
		return nil, r.failed(CodeApplyFailed, err.Error())
	}
	return &agentv1.Preview{
		Summary: "Запись тестового файла " + p.GetPath(),
		Files:   []*agentv1.FileChange{{Path: p.GetPath(), Kind: kind, Diff: diff(string(old), p.GetContent())}},
	}, nil
}

// diff — простая построчная разница для предпросмотра (не минимальная: тестовой операции её хватает).
func diff(a, b string) string {
	var sb strings.Builder
	sb.WriteString("--- a\n+++ b\n")
	for _, l := range strings.Split(strings.TrimSuffix(a, "\n"), "\n") {
		if a != "" {
			sb.WriteString("-" + l + "\n")
		}
	}
	for _, l := range strings.Split(strings.TrimSuffix(b, "\n"), "\n") {
		if b != "" {
			sb.WriteString("+" + l + "\n")
		}
	}
	out := sb.String()
	if len(out) > 64<<10 {
		out = out[:64<<10]
	}
	return out
}

func (e *Executor) applyConfigWrite(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetTestConfigWrite()
	return e.runConfigChange(ctx, r, configChange{
		paths: []string{p.GetPath()},
		apply: func() error {
			mode := os.FileMode(0o644)
			if st, err := os.Stat(p.GetPath()); err == nil {
				mode = st.Mode().Perm()
			}
			return fsutil.WriteFileAtomic(p.GetPath(), []byte(p.GetContent()), mode, fsutil.Keep)
		},
		verify: func() error {
			got, err := os.ReadFile(p.GetPath())
			if err != nil {
				return err
			}
			if !bytes.Equal(got, []byte(p.GetContent())) {
				return fmt.Errorf("содержимое не совпало")
			}
			if p.GetBreakVerify() {
				return fmt.Errorf("проверка намеренно провалена (break_verify)")
			}
			return nil
		},
	})
}
