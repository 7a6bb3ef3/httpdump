package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"
)

func FindDevs(ctx *cli.Context) error {
	devs, e := pcap.FindAllDevs()
	if e != nil {
		return fmt.Errorf("pcap.FindAllDevs: %w", e)
	}
	for _, v := range devs {
		if ctx.Bool("f") {
			fmt.Printf("Name: %s\nFlags: %d\nAddr: %+v\nDesc: %s\n", v.Name, v.Flags, v.Addresses, v.Description)
			fmt.Println()
		} else {
			fmt.Println(v.Name)
		}
	}
	return nil
}
