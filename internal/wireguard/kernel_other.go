// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package wireguard

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var errNotLinux = errors.New("WireGuard в агенте — только Linux")

// NetlinkKernel на других системах не работает: агент выпускается только для Linux.
type NetlinkKernel struct{}

func (NetlinkKernel) Probe() error                           { return precond(CodeUnsupported, "не Linux") }
func (NetlinkKernel) Devices() ([]*wgtypes.Device, error)    { return nil, errNotLinux }
func (NetlinkKernel) Device(string) (*wgtypes.Device, error) { return nil, errNotLinux }
func (NetlinkKernel) Configure(string, wgtypes.Config) error { return errNotLinux }
func (NetlinkKernel) Ensure(string, string, int) error       { return errNotLinux }
func (NetlinkKernel) Delete(string) error                    { return errNotLinux }
func (NetlinkKernel) Exists(string) bool                     { return false }
func (NetlinkKernel) Address(string) (string, int, error)    { return "", 0, errNotLinux }
