// SPDX-License-Identifier: AGPL-3.0-only

package sysinfo

// Признак «должна работать» (E06, общий набор proto/testdata/service-expected.json; такое же правило в панели —
// apps/api/src/modules/services/expected.ts). Проблема — должна работать и не работает; события service.down и
// container.down агент шлёт только по таким.

// ServiceExpected — служба systemd должна работать: включена (enabled, enabled-runtime), не oneshot и не запускается
// таймером, сокетом или path-юнитом (тогда «не работает» — норма между запусками).
func ServiceExpected(unitFileState, serviceType string, triggeredBy []string) bool {
	switch unitFileState {
	case "enabled", "enabled-runtime":
	default:
		return false
	}
	return serviceType != "oneshot" && len(triggeredBy) == 0
}

// ContainerExpected — контейнер должен работать: политика always или unless-stopped; либо on-failure или служба
// compose — пока он не завершился сам с кодом 0 (одноразовая задача, миграции).
func ContainerExpected(restartPolicy, state string, exitCode int32, composeService string) bool {
	switch restartPolicy {
	case "always", "unless-stopped":
		return true
	}
	if restartPolicy != "on-failure" && composeService == "" {
		return false
	}
	finishedOK := (state == "exited" || state == "dead") && exitCode == 0
	return !finishedOK
}
