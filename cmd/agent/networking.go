package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"

	ciliumPkgLink "github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/mbund/dimarchos/cmd/agent/bpf/objs"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// default size is 65536

	bigTCPGROMaxSize = 196608
	bigTCPGSOMaxSize = bigTCPGROMaxSize
)

func (s *server) Add(netnsPath, containerId, ifName string, ip net.IP) error {
	ns, err := netns.OpenPinned(netnsPath)
	if err != nil {
		return fmt.Errorf("opening netns pinned at %s: %w", netnsPath, err)
	}
	defer ns.Close()

	cniID := containerId + ":" + ifName
	netkit, peer, tmpIfName, err := setupNetkit(cniID, 1500, bigTCPGROMaxSize, bigTCPGSOMaxSize)
	if err != nil {
		return fmt.Errorf("unable to set up netkit on host side: %w", err)
	}
	defer func() {
		if err != nil {
			if err2 := netlink.LinkDel(netkit); err2 != nil {
				fmt.Println("failed to clean up and delete netkit", netkit.Name)
			}
		}
	}()

	// res := &cniTypesV1.Result{}
	// res.Interfaces = append(res.Interfaces, &cniTypesV1.Interface{
	// 	Name: netkit.Attrs().Name,
	// })

	if err := netlink.LinkSetNsFd(peer, ns.FD()); err != nil {
		return fmt.Errorf("unable to move netkit pair %q to netns %s: %w", peer, netnsPath, err)
	}

	err = setupNetkitRemoteNs(ns, tmpIfName, ifName)
	if err != nil {
		return fmt.Errorf("unable to set up netkit on container side: %w", err)
	}

	address := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}
	defaultRoute := net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}

	if err = ns.Do(func() error {
		l, err := safenetlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %w", ifName, err)
		}

		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("failed to set %q UP: %w", ifName, err)
		}

		addr := &netlink.Addr{IPNet: &address}
		if err := netlink.AddrAdd(l, addr); err != nil {
			return fmt.Errorf("failed to add addr to %q: %w", ifName, err)
		}

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &address,
		}); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route 1: %w", err)
			}
		}

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &defaultRoute,
			MTU:       1500,
			Gw:        address.IP,
		}); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route 2: %w", err)
			}
		}

		return err
	}); err != nil {
		return fmt.Errorf("unable to configure interfaces in container namespace: %w", err)
	}

	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: netkit.Index,
		Dst:       &address,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("adding route")
	}

	linkPrimary, err := link.AttachNetkit(link.NetkitOptions{
		Program:   s.bpfObjs.NetkitPrimary,
		Attach:    ebpf.AttachNetkitPrimary,
		Interface: netkit.Index,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return fmt.Errorf("attaching netkit primary: %v", err)
	}

	linkPeer, err := link.AttachNetkit(link.NetkitOptions{
		Program:   s.bpfObjs.NetkitPeer,
		Attach:    ebpf.AttachNetkitPeer,
		Interface: netkit.Index,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return fmt.Errorf("attaching netkit peer: %v", err)
	}

	s.containers = append(s.containers, container{
		id:            containerId,
		netkitPrimary: linkPrimary,
		netkitPeer:    linkPeer,
		netkitIndex:   netkit.Index,
	})

	virtualMac := generateMac()
	slog.Info("generated virtual mac", "address", virtualMac.String())

	s.bpfObjs.IpInfo.Update(
		binary.LittleEndian.Uint32(ip.To4()),
		objs.BpfIpInfo{
			Kind:    0,
			Mac:     [6]byte(virtualMac),
			Ifindex: uint32(netkit.Index),
		},
		ebpf.UpdateAny,
	)

	// return cniTypes.PrintResult(res, conf.CNIVersion)
	return nil
}

func generateMac() net.HardwareAddr {
	buf := make([]byte, 6)
	var mac net.HardwareAddr

	_, err := rand.Read(buf)
	if err != nil {
	}

	buf[0] |= 2

	mac = append(mac, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])

	return mac
}

func setupNetkit(id string, mtu, groIPv4MaxSize, gsoIPv4MaxSize int) (*netlink.Netkit, netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	lxcIfName := endpointToIfName(id)
	tmpIfName := endpointToTempIfName(id)

	netkit, link, err := setupNetkitWithNames(lxcIfName, tmpIfName, mtu, groIPv4MaxSize, gsoIPv4MaxSize)
	return netkit, link, tmpIfName, err
}

func setupNetkitWithNames(lxcIfName, peerIfName string, mtu, groIPv4MaxSize, gsoIPv4MaxSize int) (*netlink.Netkit, netlink.Link, error) {
	netkit := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:   lxcIfName,
			TxQLen: 1000,
		},
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		Scrub:      netlink.NETKIT_SCRUB_NONE,
		PeerScrub:  netlink.NETKIT_SCRUB_DEFAULT,
	}
	netkit.SetPeerAttrs(&netlink.LinkAttrs{
		Name: peerIfName,
	})

	err := netlink.LinkAdd(netkit)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create netkit pair: %w", err)
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(netkit); err != nil {
				fmt.Println("failed to clean up netkit", err, netkit.Name)
			}
		}
	}()

	peer, err := safenetlink.LinkByName(peerIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup netkit peer just created: %w", err)
	}

	if nk, ok := peer.(*netlink.Netkit); !ok {
		fmt.Println("peer does not appear to be a Netkit device", peerIfName, lxcIfName)
	} else if !nk.SupportsScrub() {
		fmt.Println("kernel does not support IFLA_NETKIT_SCRUB, some features may not work with netkit", netkit.Name)
	}

	if err = netlink.LinkSetMTU(peer, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %w", peerIfName, err)
	}

	hostNetkit, err := safenetlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup netkit just created: %w", err)
	}

	if err = netlink.LinkSetMTU(hostNetkit, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %w", lxcIfName, err)
	}

	if err = netlink.LinkSetUp(netkit); err != nil {
		return nil, nil, fmt.Errorf("unable to bring up netkit pair: %w", err)
	}

	if groIPv4MaxSize > 0 {
		if err = netlink.LinkSetGROIPv4MaxSize(hostNetkit, groIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGROIPv4MaxSize(peer, groIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				peerIfName, err)
		}
	}

	if gsoIPv4MaxSize > 0 {
		if err = netlink.LinkSetGSOIPv4MaxSize(hostNetkit, gsoIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGSOIPv4MaxSize(peer, gsoIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				peerIfName, err)
		}
	}

	return netkit, peer, nil
}

const (
	hostInterfacePrefix      = "lxc"
	temporaryInterfacePrefix = "tmp"
)

func endpointToIfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	truncateLength := uint(unix.IFNAMSIZ - len(temporaryInterfacePrefix) - 1)
	return hostInterfacePrefix + truncateString(sum, truncateLength)
}

func endpointToTempIfName(endpointID string) string {
	return temporaryInterfacePrefix + truncateString(endpointID, 5)
}

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
}

func setupNetkitRemoteNs(ns *netns.NetNS, srcIfName, dstIfName string) error {
	return ns.Do(func() error {
		err := ciliumPkgLink.Rename(srcIfName, dstIfName)
		if err != nil {
			return fmt.Errorf("failed to rename netkit from %q to %q: %w", srcIfName, dstIfName, err)
		}
		return nil
	})
}
