package main

// https://pkg.go.dev/github.com/libopenstorage/gossip#section-readme
// https://pkg.go.dev/github.com/hashicorp/memberlist

import (
	"net/netip"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var ifaceFag = &cli.StringFlag{
	Name:     "iface",
	Aliases:  []string{"i"},
	Required: true,
	Usage:    "interface name",
}

func main() {
	app := &cli.App{
		Name:  "tunat",
		Usage: "Tunat is EBPF based IPIP tunneling tool",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable debug logging",
			},
		},
		ExitErrHandler: func(cCtx *cli.Context, err error) {
			log.Fatal().Err(err)
		},
		Before: func(cCtx *cli.Context) error {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
			if cCtx.Bool("verbose") {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "attach",
				Aliases: []string{"a"},
				Usage:   "attach tunnel to an interface",
				Flags: []cli.Flag{
					ifaceFag,
					&cli.StringFlag{
						Name:    "src-ip",
						Aliases: []string{"s"},
						Usage:   "source IP address",
					},
					&cli.StringFlag{
						Name:    "map",
						Aliases: []string{"m"},
						Usage:   "tunnel map",
					},
					&cli.BoolFlag{
						Name:    "watch",
						Aliases: []string{"w"},
						Usage:   "Watch for stats",
					},
				},
				Action: attachAction,
				Args:   false,
			},
			{
				Name:    "detach",
				Aliases: []string{"d"},
				Usage:   "detach tunnel from an interface",
				Flags: []cli.Flag{
					ifaceFag,
				},
				// Action: detachAction,
				Args: false,
			},
			{
				Name:    "update",
				Aliases: []string{"u"},
				Usage:   "update tunnel map",
				Flags: []cli.Flag{
					ifaceFag,
				},
				ArgsUsage: "map",
				Action:    updateAction,
				Args:      true,
			},
			{
				Name:    "stats",
				Aliases: []string{"s"},
				Usage:   "watch for stats",
				Flags: []cli.Flag{
					ifaceFag,
					&cli.BoolFlag{
						Name:    "watch",
						Aliases: []string{"w"},
						Usage:   "Watch for stats",
					},
				},
				Action: statsAction,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err)
	}
}

func updateAction(cCtx *cli.Context) error {
	ifaceName := cCtx.String("iface")
	ebpfMgr, err := NewEBPFManager(ifaceName)
	if err != nil {
		return errors.Wrapf(err, "failed to create ebpf manager")
	}
	if cCtx.NArg() == 0 {
		return errors.New("no map entries provided")
	}
	entries, err := parseMapString(strings.Join(cCtx.Args().Slice(), ","))
	if err != nil {
		return errors.Wrapf(err, "failed to parse map string")
	}
	err = ebpfMgr.MapRemove(entries.ToRemove...)
	if err != nil {
		return errors.Wrapf(err, "failed to delete map")
	}
	err = ebpfMgr.MapInsert(entries.ToAdd...)
	if err != nil {
		return errors.Wrapf(err, "failed to set map")
	}
	return nil
}

func statsAction(cCtx *cli.Context) error {
	ifaceName := cCtx.String("iface")
	watch := cCtx.Bool("watch")
	ebpfMgr, err := NewEBPFManager(ifaceName)
	if err != nil {
		return errors.Wrapf(err, "failed to create ebpf manager")
	}

	ebpfMgr.DumpMap()

	if watch {
		err := ebpfMgr.MapWatch()
		if err != nil {
			return errors.Wrapf(err, "failed to watch map")
		}
	}
	return nil
}

func attachAction(cCtx *cli.Context) error {
	ifaceName := cCtx.String("iface")
	srcIP := cCtx.String("src-ip")
	mapStr := cCtx.String("map")
	watch := cCtx.Bool("watch")

	var err error
	var sourceIP netip.Addr
	if srcIP != "" {
		sourceIP, err = ParseIP4HostAddr(srcIP)
		if err != nil {
			return errors.Wrapf(err, "invalid source IP address")
		}
	}

	log.Printf("iface: %s, srcIP: %s, map: %s\n", ifaceName, srcIP, mapStr)

	ebpfMgr, err := NewEBPFManager(ifaceName)
	if err != nil {
		return errors.Wrapf(err, "failed to create ebpf manager")
	}

	err = ebpfMgr.Attach()
	if err != nil {
		return errors.Wrapf(err, "failed to attach ebpf manager")
	}

	err = ebpfMgr.SetSourceIP(sourceIP)
	if err != nil {
		return errors.Wrapf(err, "failed to set source IP address in BPF map")
	}
	if mapStr != "" {
		entries, err := parseMapString(mapStr)
		if err != nil {
			return errors.Wrapf(err, "failed to parse map string")
		}
		err = ebpfMgr.MapInsert(entries.ToAdd...)
		if err != nil {
			return errors.Wrapf(err, "failed to set map")
		}
	}

	if watch {
		err := ebpfMgr.MapWatch()
		if err != nil {
			return errors.Wrapf(err, "failed to watch map")
		}
	}

	return nil
}
