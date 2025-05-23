//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add: add,
	}, cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"), "Dimarchos CNI plugin")
}

func add(args *skel.CmdArgs) (err error) {
	conf, err := loadNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("unable to parse CNI configuration %q: %w", string(args.StdinData), err)
	}

	res := &cniTypesV1.Result{}

	// res.Interfaces = append(res.Interfaces, &cniTypesV1.Interface{
	// 	Name: netkit.Attrs().Name,
	// })

	return cniTypes.PrintResult(res, conf.CNIVersion)
}

func loadNetConf(bytes []byte) (*cniTypes.NetConf, error) {
	conf := &cniTypes.NetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %w", err)
	}
	return conf, nil
}
