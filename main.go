package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func handlePacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("src port: %d, dst port: %d\n", tcp.SrcPort, tcp.DstPort)
	}
}

func main() {
	fmt.Println("starting...")
	if handle, err := pcap.OpenLive("enp6s0", 1600, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and (port 80 or port 8080 or port 443)"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
			fmt.Println("heheda")
			handle.WritePacketData(packet.Data())
		}
	}
}
