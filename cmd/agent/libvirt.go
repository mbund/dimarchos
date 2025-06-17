package main

import (
	"encoding/binary"
	"encoding/xml"
	"log"
	"net"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/digitalocean/go-libvirt"
	"github.com/google/uuid"
	"github.com/mbund/dimarchos/cmd/agent/bpf/objs"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"libvirt.org/go/libvirtxml"
)

func (s *server) createVM(tapObjects *objs.TapObjects, virConn *libvirt.Libvirt, name, ifName, hostMac, guestMac, disk string) {
	mac, err := net.ParseMAC(hostMac)
	if err != nil {
		log.Fatalf("failed to parse host mac")
	}

	tuntap := &netlink.Tuntap{
		Mode:   netlink.TUNTAP_MODE_TAP,
		Flags:  unix.IFF_MULTI_QUEUE | unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR,
		Queues: 2,
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
		},
	}

	err = netlink.LinkAdd(tuntap)
	if err != nil {
		log.Fatalf("failed to add %s", ifName)
	}

	err = netlink.LinkSetHardwareAddr(tuntap, mac)
	if err != nil {
		log.Fatalf("failed to set %s mac address", ifName)
	}

	err = netlink.LinkSetUp(tuntap)
	if err != nil {
		log.Fatalf("failed to set %s up", ifName)
	}

	log.Printf("%s index: %d, fds: %d", ifName, tuntap.Index, len(tuntap.Fds))

	for _, fd := range tuntap.Fds {
		var vnetLen int = 12
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), syscall.TUNSETVNETHDRSZ, uintptr(unsafe.Pointer(&vnetLen)))
		if errno != 0 {
			log.Fatalf("failed to set vnet header size: %v", err)
		}

		var offloadFlags uint = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), syscall.TUNSETOFFLOAD, uintptr(offloadFlags))
		if errno != 0 {
			log.Fatalf("failed to set offload flags: %v, errno: %v", err, errno)
		}
	}

	tcxIngressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: tuntap.Index,
		Program:   tapObjects.TcxIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("failed to attach tap tcx ingress: %v", err)
	}

	tcxEgressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: tuntap.Index,
		Program:   tapObjects.TcxEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("failed to attach tap tcx egress: %v", err)
	}

	log.Printf("attaching xdp program to tuntap index %d", tuntap.Index)
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Interface: tuntap.Index,
		Program:   tapObjects.XdpProg,
	})
	if err != nil {
		log.Fatalf("failed to attach tap xdp: %v", err)
	}

	s.vms = append(s.vms, vm{
		xdpLink:        xdpLink,
		tcxIngressLink: tcxIngressLink,
		tcxEgressLink:  tcxEgressLink,
	})

	guestMacHwAddr, err := net.ParseMAC(guestMac)
	if err != nil {
		log.Fatalf("failed to parse host mac")
	}

	ip, err := s.nextIp()
	if err != nil {
		log.Fatalf("failed to get next ip: %v", err)
	}
	tapObjects.RoutingTable.Update(
		binary.LittleEndian.Uint32(ip.To4()),
		objs.TapRoutingValue{Mac: [6]byte(guestMacHwAddr), Ifindex: uint32(tuntap.Index)},
		ebpf.UpdateAny,
	)
	log.Printf("Assigned %v %v %v %v", ifName, ip.String(), guestMac, tuntap.Index)

	domainUuid := uuid.New()

	domainSpec := libvirtxml.Domain{
		Type: "kvm",
		Name: name,
		UUID: domainUuid.String(),
		Memory: &libvirtxml.DomainMemory{
			Value: 4194304,
			Unit:  "KiB",
		},
		CurrentMemory: &libvirtxml.DomainCurrentMemory{
			Value: 4194304,
			Unit:  "KiB",
		},
		VCPU: &libvirtxml.DomainVCPU{
			Value: 2,
		},
		OS: &libvirtxml.DomainOS{
			Type: &libvirtxml.DomainOSType{
				Arch:    "x86_64",
				Machine: "q35",
				Type:    "hvm",
			},
			// BootDevices: []libvirtxml.DomainBootDevice{
			// 	{Dev: "hd"},
			// },
		},
		Features: &libvirtxml.DomainFeatureList{
			ACPI: &libvirtxml.DomainFeature{},
			APIC: &libvirtxml.DomainFeatureAPIC{},
			VMPort: &libvirtxml.DomainFeatureState{
				State: "off",
			},
		},
		CPU: &libvirtxml.DomainCPU{
			Mode: "host-passthrough",
		},
		Clock: &libvirtxml.DomainClock{
			Offset: "utc",
			Timer: []libvirtxml.DomainTimer{
				{
					Name:       "rtc",
					TickPolicy: "catchup",
				},
				{
					Name:       "pit",
					TickPolicy: "delay",
				},
				{
					Name:    "hpet",
					Present: "no",
				},
			},
		},
		PM: &libvirtxml.DomainPM{
			SuspendToMem: &libvirtxml.DomainPMPolicy{
				Enabled: "no",
			},
			SuspendToDisk: &libvirtxml.DomainPMPolicy{
				Enabled: "no",
			},
		},
		Devices: &libvirtxml.DomainDeviceList{
			Emulator: "/usr/bin/qemu-system-x86_64",
			Disks: []libvirtxml.DomainDisk{
				{
					Device: "disk",
					Driver: &libvirtxml.DomainDiskDriver{
						Name:    "qemu",
						Type:    "qcow2",
						Discard: "unmap",
					},
					Source: &libvirtxml.DomainDiskSource{
						File: &libvirtxml.DomainDiskSourceFile{
							File: disk,
						},
					},
					Target: &libvirtxml.DomainDiskTarget{
						Dev: "vda",
						Bus: "virtio",
					},
					Boot: &libvirtxml.DomainDeviceBoot{
						Order: 1,
					},
				},
				// {
				// 	Device: "cdrom",
				// 	Driver: &libvirtxml.DomainDiskDriver{
				// 		Name: "qemu",
				// 		Type: "raw",
				// 	},
				// 	Source: &libvirtxml.DomainDiskSource{
				// 		File: &libvirtxml.DomainDiskSourceFile{
				// 			File: "/var/lib/libvirt/images/ubuntu-24.04.2-desktop-amd64.iso",
				// 		},
				// 	},
				// 	Target: &libvirtxml.DomainDiskTarget{
				// 		Dev: "sda",
				// 		Bus: "sata",
				// 	},
				// 	Boot: &libvirtxml.DomainDeviceBoot{
				// 		Order: 1,
				// 	},
				// },
			},
			Controllers: []libvirtxml.DomainController{
				{
					Type:  "usb",
					Model: "qemu-xhci",
				},
				{
					Type:  "pci",
					Model: "pcie-root",
				},
				{
					Type:  "pci",
					Model: "pcie-root-port",
				},
				{
					Type:  "pci",
					Model: "pcie-root-port",
				},
			},
			Interfaces: []libvirtxml.DomainInterface{
				// {
				// 	Source: &libvirtxml.DomainInterfaceSource{
				// 		Network: &libvirtxml.DomainInterfaceSourceNetwork{
				// 			Network: "default",
				// 		},
				// 	},
				// 	MAC: &libvirtxml.DomainInterfaceMAC{
				// 		Address: "52:54:00:4b:95:7f",
				// 	},
				// 	Model: &libvirtxml.DomainInterfaceModel{
				// 		Type: "virtio",
				// 	},
				// },
				{
					Source: &libvirtxml.DomainInterfaceSource{
						Ethernet: &libvirtxml.DomainInterfaceSourceEthernet{},
					},
					Target: &libvirtxml.DomainInterfaceTarget{
						Dev:     ifName,
						Managed: "no",
					},
					Model: &libvirtxml.DomainInterfaceModel{
						Type: "virtio",
					},
					Driver: &libvirtxml.DomainInterfaceDriver{
						Queues: uint(tuntap.Queues),
						Name:   "vhost",
					},
					MAC: &libvirtxml.DomainInterfaceMAC{
						Address: guestMac,
					},
				},
			},
			Consoles: []libvirtxml.DomainConsole{
				{
					Source: &libvirtxml.DomainChardevSource{
						Pty: &libvirtxml.DomainChardevSourcePty{},
					},
				},
			},
			Channels: []libvirtxml.DomainChannel{
				{
					Source: &libvirtxml.DomainChardevSource{
						UNIX: &libvirtxml.DomainChardevSourceUNIX{
							Mode: "bind",
						},
					},
					Target: &libvirtxml.DomainChannelTarget{
						VirtIO: &libvirtxml.DomainChannelTargetVirtIO{
							Name: "org.qemu.guest_agent.0",
						},
					},
				},
				{
					Source: &libvirtxml.DomainChardevSource{
						SpiceVMC: &libvirtxml.DomainChardevSourceSpiceVMC{},
					},
					Target: &libvirtxml.DomainChannelTarget{
						VirtIO: &libvirtxml.DomainChannelTargetVirtIO{
							Name: "com.redhat.spice.0",
						},
					},
				},
			},
			Inputs: []libvirtxml.DomainInput{
				{
					Type: "tablet",
					Bus:  "usb",
				},
			},
			Graphics: []libvirtxml.DomainGraphic{
				{
					Spice: &libvirtxml.DomainGraphicSpice{
						Port:     -1,
						TLSPort:  -1,
						AutoPort: "yes",
						Image: &libvirtxml.DomainGraphicSpiceImage{
							Compression: "off",
						},
					},
				},
			},
			Sounds: []libvirtxml.DomainSound{
				{
					Model: "ich9",
				},
			},
			Videos: []libvirtxml.DomainVideo{
				{
					Model: libvirtxml.DomainVideoModel{
						Type: "virtio",
					},
				},
			},
			RedirDevs: []libvirtxml.DomainRedirDev{
				{
					Bus: "usb",
					Source: &libvirtxml.DomainChardevSource{
						SpiceVMC: &libvirtxml.DomainChardevSourceSpiceVMC{},
					},
				},
				{
					Bus: "usb",
					Source: &libvirtxml.DomainChardevSource{
						SpiceVMC: &libvirtxml.DomainChardevSourceSpiceVMC{},
					},
				},
			},
			MemBalloon: &libvirtxml.DomainMemBalloon{
				Model: "virtio",
			},
			RNGs: []libvirtxml.DomainRNG{
				{
					Model: "virtio",
					Backend: &libvirtxml.DomainRNGBackend{
						Random: &libvirtxml.DomainRNGBackendRandom{
							Device: "/dev/urandom",
						},
					},
				},
			},
		},
	}

	domainXML, err := domainSpec.Marshal()
	if err != nil {
		log.Fatalf("failed to marshal domain spec")
	}

	domain, err := virConn.DomainDefineXML(domainXML)
	if err != nil {
		log.Fatalf("failed to define domain xml: %v", err)
	}

	err = virConn.DomainCreate(domain)
	if err != nil {
		log.Fatalf("failed to create domain: %v", err)
	}
}

func getHostCapabilities(virConn *libvirt.Libvirt) (libvirtxml.Caps, error) {
	caps := libvirtxml.Caps{}
	capsXML, err := virConn.Capabilities()
	if err != nil {
		return caps, err
	}

	err = xml.Unmarshal([]byte(capsXML), &caps)
	if err != nil {
		return caps, err
	}

	return caps, nil
}
