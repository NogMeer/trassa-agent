// SPDX-License-Identifier: AGPL-3.0-only

//go:build !testops

package ops

// В выпускной сборке тестовых типов нет.
func extraSpecs() []Spec { return nil }

// TestOps — собрана ли сборка с тегом testops.
const TestOps = false
