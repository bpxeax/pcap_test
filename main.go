package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
)

func handlePacket(packetData []byte) {
	packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("src port: %d, dst port: %d\n", udp.SrcPort, udp.DstPort)
	}

	netFlow := packet.NetworkLayer().NetworkFlow()
	fmt.Printf("src ip: %s; dst ip: %s\n", netFlow.Src().String(), netFlow.Dst().String())

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		fmt.Printf("data: %s\n", string(appLayer.LayerContents()))
	}

}

func main() {
	fmt.Println("starting...")
	if handle, err := pcap.OpenLive("enp6s0", 1600, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and (port 10002)"); err != nil {
		panic(err)
	} else {
		if handleWrite, err := pcap.OpenLive("enp6s0", 65536, true, pcap.BlockForever); err != nil {
			panic(err)
		} else {
			for {
				data, _, err := handle.ReadPacketData()
				switch {
				case err == io.EOF:
					fmt.Println("finished!")
					return
				case err != nil:
					fmt.Printf("fail to read packet, error: %s", err)
				default:
					handlePacket(data)
					err := handleWrite.WritePacketData(data)
					if err != nil {
						fmt.Println("send error: ", err)
					}
				}
			}
		}
	}
}
