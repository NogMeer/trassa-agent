// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// ErrRulesetHash — хэш набора не совпал с подтверждённым (набор изменился после подтверждения).
var ErrRulesetHash = errors.New("FIREWALL_HASH_MISMATCH")

// firewallUnit — служба загрузки набора при старте: после штатного nftables.service (его flush ruleset стёр
// бы таблицу), до сети. Остановка снимает только таблицу Trassa.
const firewallUnit = `# Trassa: загрузка набора межсетевого экрана при старте. Файл пишет Trassa.
[Unit]
Description=Trassa firewall
DefaultDependencies=no
After=nftables.service
Before=network-pre.target
Wants=network-pre.target

# Только подтверждённый набор: неподтверждённый (ждёт связи) после перезагрузки не загружается.
ConditionPathExists=/etc/trassa/firewall.confirmed.nft

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/trassa/firewall.confirmed.nft
ExecStop=/usr/sbin/nft delete table inet trassa

[Install]
WantedBy=multi-user.target
`

// FirewallPlan — firewall.plan: DIFF — набор, его хэш и разница с загруженным файлом, проверка `nft -c`;
// IMPORT — правила ufw в формате Trassa. На сервер ничего не пишется.
func FirewallPlan(ctx context.Context, sys *System, p *agentv1.FirewallPlanParams) (*agentv1.FirewallPlanResult, error) {
	s := newScan(sys)
	res := &agentv1.FirewallPlanResult{}
	fw, err := s.Firewall(ctx)
	if err != nil {
		return nil, err
	}
	if fw.state.GetUfwActive() {
		res.Warnings = append(res.Warnings, "ufw включён: итог — пересечение правил, Trassa может закрыть, но не открыть то, что режет ufw")
	}
	if fw.state.GetFirewalldActive() {
		res.Warnings = append(res.Warnings, "firewalld работает: решение о совместной работе — вручную")
	}
	if p.GetMode() == agentv1.FirewallPlanMode_FIREWALL_PLAN_MODE_IMPORT {
		res.Imported, res.Warnings = ImportUfw(sys)
		return res, nil
	}
	if err := ValidateRuleset(p.GetRuleset()); err != nil {
		return nil, err
	}
	if err := checkLockout(ctx, s, p.GetRuleset()); err != nil {
		return nil, err
	}
	hash, err := RulesetHash(p.GetRuleset())
	if err != nil {
		return nil, err
	}
	ext, err := ExternalIfaces(sys)
	if err != nil {
		return nil, err
	}
	text, err := GenerateNft(p.GetRuleset(), hash, ext)
	if err != nil {
		return nil, err
	}
	if err := nftCheck(ctx, sys, text); err != nil {
		return nil, err
	}
	old, _ := os.ReadFile(sys.path(FirewallFile))
	res.RulesetHash, res.NftText = hash, text
	res.Diff = strings.Split(strings.TrimSuffix(lineDiffMinimal(string(old), text), "\n"), "\n")
	return res, nil
}

// nftCheck — `nft -c -f` проверяет набор без применения (файл во временном каталоге помощника).
func nftCheck(ctx context.Context, sys *System, text string) error {
	f, err := os.CreateTemp("", "trassa-nft-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if out, err := sys.run(ctx, "nft", "-c", "-f", f.Name()); err != nil {
		return fmt.Errorf("nft -c: %v %s", err, tail(out))
	}
	return nil
}

// lineDiffMinimal — строки, которых нет в другой версии (порядок набора важен, но для показа хватает).
func lineDiffMinimal(a, b string) string {
	in := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			m[l]++
		}
		return m
	}
	ma, mb := in(a), in(b)
	var sb strings.Builder
	for _, l := range strings.Split(a, "\n") {
		if a != "" && mb[l] == 0 {
			sb.WriteString("-" + l + "\n")
		}
	}
	for _, l := range strings.Split(b, "\n") {
		if ma[l] == 0 {
			sb.WriteString("+" + l + "\n")
		}
	}
	return sb.String()
}

// PlanFirewallApply — firewall.apply: хэш сверяется с подтверждённым, SSH не запирается, точка отката хранит
// файл набора, файл службы, её состояние и перезагрузку набора; проверка — таблица загружена с этим хэшем,
// SSH слушает. Подтверждение нового соединения — автооткат (confirm_within_sec).
func PlanFirewallApply(ctx context.Context, sys *System, p *agentv1.FirewallApplyParams) (*FixPlan, error) {
	s := newScan(sys)
	nftFile, unitFile := sys.path(FirewallFile), sys.path(FirewallUnitFile)
	state := rollback.State{
		NftFile: nftFile, DaemonReload: true,
		Units: []rollback.UnitState{unitState(ctx, sys, FirewallUnit)},
	}
	if p.GetMode() == agentv1.FirewallApplyMode_FIREWALL_APPLY_MODE_REMOVE {
		return &FixPlan{
			Summary: "Снять таблицу Trassa", Paths: []string{nftFile, unitFile}, State: state,
			Changes: []*agentv1.FileChange{{Path: FirewallFile, Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_DELETE}},
			Apply: func(ctx context.Context) error {
				_, _ = sys.run(ctx, "systemctl", "disable", "--", FirewallUnit)
				if err := fsutil.RemoveSync(unitFile); err != nil {
					return err
				}
				if err := fsutil.RemoveSync(nftFile); err != nil {
					return err
				}
				if _, err := sys.run(ctx, "nft", "list", "table", "inet", "trassa"); err == nil {
					if out, err := sys.run(ctx, "nft", "delete", "table", "inet", "trassa"); err != nil {
						return fmt.Errorf("nft delete table: %v %s", err, tail(out))
					}
				}
				_, _ = sys.run(ctx, "systemctl", "daemon-reload")
				return nil
			},
			Verify: func(ctx context.Context) error {
				if _, err := sys.run(ctx, "nft", "list", "table", "inet", "trassa"); err == nil {
					return errors.New("таблица inet trassa осталась")
				}
				return nil
			},
		}, nil
	}
	rs := p.GetRuleset()
	if err := ValidateRuleset(rs); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrecondition, err)
	}
	hash, err := RulesetHash(rs)
	if err != nil {
		return nil, err
	}
	if hash != p.GetRulesetHash() {
		return nil, fmt.Errorf("%w: подтверждён %s, набор даёт %s", ErrRulesetHash, p.GetRulesetHash(), hash)
	}
	if err := checkLockout(ctx, s, rs); err != nil {
		return nil, err
	}
	ext, err := ExternalIfaces(sys)
	if err != nil {
		return nil, err
	}
	text, err := GenerateNft(rs, hash, ext)
	if err != nil {
		return nil, err
	}
	old, _ := os.ReadFile(nftFile)
	return &FixPlan{
		Summary: fmt.Sprintf("Набор межсетевого экрана: правил %d, внешние интерфейсы %s", len(rs.GetRules()), strings.Join(ext, ", ")),
		Paths:   []string{nftFile, unitFile}, State: state,
		Changes: []*agentv1.FileChange{{Path: FirewallFile, Kind: changeKind(old), Diff: lineDiffMinimal(string(old), text)}},
		Notes:   []string{"Чужие таблицы (Docker, ufw) не меняются", "Без подтверждения набор вернётся сам"},
		Apply: func(ctx context.Context) error {
			if err := nftCheck(ctx, sys, text); err != nil {
				return err
			}
			if err := os.MkdirAll(dirOf(nftFile), 0o755); err != nil {
				return err
			}
			if err := fsutil.WriteFileAtomic(nftFile, []byte(text), 0o600, fsutil.Keep); err != nil {
				return err
			}
			if out, err := sys.run(ctx, "nft", "-f", nftFile); err != nil {
				return fmt.Errorf("nft -f: %v %s", err, tail(out))
			}
			if err := fsutil.WriteFileAtomic(unitFile, []byte(firewallUnit), 0o644, fsutil.Keep); err != nil {
				return err
			}
			for _, a := range [][]string{{"daemon-reload"}, {"enable", "--", FirewallUnit}} {
				if out, err := sys.run(ctx, "systemctl", a...); err != nil {
					return fmt.Errorf("systemctl %s: %v %s", a[0], err, tail(out))
				}
			}
			return nil
		},
		Verify: func(ctx context.Context) error {
			out, err := sys.run(ctx, "nft", "list", "table", "inet", "trassa")
			if err != nil {
				return fmt.Errorf("таблица inet trassa не загружена: %v", err)
			}
			if !strings.Contains(string(out), "trassa:"+hash) {
				return errors.New("загруженная таблица не совпадает с набором")
			}
			ls, err := newScan(sys).Listeners(ctx)
			if err != nil {
				return err
			}
			if !listening(ls, rs.GetSshPort()) {
				return fmt.Errorf("SSH не слушает порт %d", rs.GetSshPort())
			}
			return nil
		},
	}, nil
}

// ConfirmFirewall — после подтверждения связи: подтверждённый набор (его загружает служба при старте) равен
// текущему файлу набора; файла нет (таблица снята) — подтверждённого тоже нет.
func ConfirmFirewall(sys *System) error {
	src, dst := sys.path(FirewallFile), sys.path(FirewallConfirmedFile)
	raw, err := fsutil.ReadLimited(src, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return fsutil.RemoveSync(dst)
	}
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(dst, raw, 0o600, fsutil.Keep)
}
