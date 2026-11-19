// SPDX-License-Identifier: AGPL-3.0-only

//go:build testops

package ops

import (
	"errors"
	"path"
	"strings"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// TestOps — собрана ли сборка с тегом testops.
const TestOps = true

// TypeTestConfigWrite есть только в этой сборке: строки типа нет в выпускном бинарнике (make release-check).
const TypeTestConfigWrite = "test.config_write"

// test.config_write — только для тестов точки отката и автооткатa (E05, раздел 6).
func extraSpecs() []Spec {
	return []Spec{{
		Type: TypeTestConfigWrite, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, AutoRollback: true,
		match:    func(p *agentv1.OperationParams) bool { return p.GetTestConfigWrite() != nil },
		Validate: validateTestConfigWrite,
	}}
}

// Каталоги Trassa тестовой операции недоступны: ей нельзя переписать ключи, окно nonce или точки отката.
var forbiddenPrefixes = []string{"/var/lib/trassa", "/etc/trassa", "/run/trassa", "/usr/local/bin/trassa"}

func validateTestConfigWrite(b *agentv1.OperationBody) error {
	p := b.GetParams().GetTestConfigWrite()
	fp := p.GetPath()
	if !strings.HasPrefix(fp, "/") || len(fp) > 512 || strings.ContainsRune(fp, 0) || path.Clean(fp) != fp || fp == "/" {
		return errors.New("path")
	}
	for _, part := range strings.Split(fp, "/") {
		if part == ".." {
			return errors.New("path traversal")
		}
	}
	for _, pre := range forbiddenPrefixes {
		if fp == pre || strings.HasPrefix(fp, pre+"/") || strings.HasPrefix(fp, pre) {
			return errors.New("path: каталог Trassa")
		}
	}
	if !utf8.ValidString(p.GetContent()) || utf16Len(p.GetContent()) > 64*1024 {
		return errors.New("content")
	}
	if p.GetConfirmWithin() > MaxConfirmWithin || p.GetConfirmWithin() != b.GetConfirmWithinSec() {
		return errors.New("confirm_within")
	}
	return nil
}

// utf16Len — длина строки так, как её считает z.string().max() панели (в единицах UTF-16).
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}
