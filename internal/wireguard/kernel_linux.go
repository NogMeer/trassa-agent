// SPDX-License-Identifier: AGPL-3.0-only

package wireguard

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetlinkKernel — настоящее ядро: интерфейс через netlink (vishvananda/netlink), устройство через wgctrl.
type NetlinkKernel struct{}

// probeName — пробный интерфейс для проверки поддержки (создаётся и сразу удаляется).
const probeName = "trassa-wgprobe"

func (NetlinkKernel) Probe() error {
	l := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: probeName}}
	if err := netlink.LinkAdd(l); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
			return precond(CodeUnsupported, "ядро без WireGuard")
		}
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("пробный интерфейс: %w", err)
		}
	}
	return netlink.LinkDel(l)
}

func client() (*wgctrl.Client, error) { return wgctrl.New() }

func (NetlinkKernel) Devices() ([]*wgtypes.Device, error) {
	c, err := client()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Devices()
}

func (NetlinkKernel) Device(name string) (*wgtypes.Device, error) {
	c, err := client()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Device(name)
}

func (NetlinkKernel) Configure(name string, cfg wgtypes.Config) error {
	c, err := client()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(name, cfg)
}

func (NetlinkKernel) Exists(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}

func (NetlinkKernel) Delete(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	return netlink.LinkDel(l)
}

// Ensure — интерфейс типа wireguard, ровно один адрес address (прочие снимаются), MTU, состояние up.
func (NetlinkKernel) Ensure(name, address string, mtu int) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				return precond(CodeUnsupported, "ядро без WireGuard")
			}
			return fmt.Errorf("создать %s: %w", name, err)
		}
		if l, err = netlink.LinkByName(name); err != nil {
			return err
		}
	}
	if l.Type() != "wireguard" {
		return fmt.Errorf("%s уже есть и это не WireGuard (%s)", name, l.Type())
	}
	want, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return err
	}
	for _, a := range addrs {
		if !a.Equal(*want) && a.IP.IsGlobalUnicast() {
			if err := netlink.AddrDel(l, &a); err != nil {
				return err
			}
		}
	}
	if err := netlink.AddrReplace(l, want); err != nil {
		return err
	}
	if l.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return err
		}
	}
	return netlink.LinkSetUp(l)
}

func (NetlinkKernel) Address(name string) (string, int, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return "", 0, err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return "", 0, err
	}
	for _, a := range addrs {
		if a.IP.IsGlobalUnicast() {
			ip, _ := netip.AddrFromSlice(a.IP)
			ones, _ := a.Mask.Size()
			return netip.PrefixFrom(ip.Unmap(), ones).String(), l.Attrs().MTU, nil
		}
	}
	return "", l.Attrs().MTU, nil
}
