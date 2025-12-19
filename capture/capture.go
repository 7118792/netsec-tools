package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Length    int
	Payload   []byte
	LayerInfo []string
}


type PacketCapture struct {
	Interface string
	Handle    *pcap.Handle
	Filter    string
}

func NewPacketCapture(iface string) *PacketCapture {
	return &PacketCapture{
		Interface: iface,
		Filter:    "",
	}
}

func (pc *PacketCapture) Start() error {
	handle, err := pcap.OpenLive(pc.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}

	if pc.Filter != "" {
		err = handle.SetBPFFilter(pc.Filter)
		if err != nil {
			return fmt.Errorf("failed to set filter: %w", err)
		}
	}

	pc.Handle = handle
	return nil
}

func (pc *PacketCapture) CapturePackets(count int) []PacketInfo {
	if pc.Handle == nil {
		return nil
	}

	var packets []PacketInfo
	packetSource := gopacket.NewPacketSource(pc.Handle, pc.Handle.LinkType())

	for i := 0; i < count; i++ {
		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}

		info := pc.parsePacket(packet)
		packets = append(packets, info)
	}

	return packets
}

func (pc *PacketCapture) parsePacket(packet gopacket.Packet) PacketInfo {
	info := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	var layerInfo []string

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
		layerInfo = append(layerInfo, "IPv4")
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = int(tcp.SrcPort)
		info.DstPort = int(tcp.DstPort)
		layerInfo = append(layerInfo, "TCP")
		info.Payload = tcp.Payload
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = int(udp.SrcPort)
		info.DstPort = int(udp.DstPort)
		layerInfo = append(layerInfo, "UDP")
		info.Payload = udp.Payload
	}

	info.LayerInfo = layerInfo
	return info
}

func (pc *PacketCapture) SetFilter(filter string) {
	pc.Filter = filter
	if pc.Handle != nil {
		pc.Handle.SetBPFFilter(filter)
	}
}

func (pc *PacketCapture) Stop() {
	if pc.Handle != nil {
		pc.Handle.Close()
	}
}
