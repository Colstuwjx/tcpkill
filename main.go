package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var rstCount = flag.Int("n", 3, "Number of RST packets sent")
var promisc = flag.Bool("promisc", false, "Set promiscuous mode")

func init() {
	flag.Parse()
	if len(*iface) == 0 {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		if len(devs) == 0 {
			log.Fatal("interface not found")
		}
		*iface = devs[0].Name
	}
}

type tcpKill struct {
	Iface        string
	RstSendCount int
	IsPromisc    bool
}

func (tk *tcpKill) sendRST(srcMac, dstMac net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, seq uint32, handle *pcap.Handle) error {
	log.Printf("send %v:%v > %v:%v [RST] seq %v", srcIP.String(), srcPort.String(), dstIP.String(), dstPort.String(), seq)

	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	iPv4 := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		RST:     true,
	}

	if err := tcp.SetNetworkLayerForChecksum(&iPv4); err != nil {
		return err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, options, &eth, &iPv4, &tcp); err != nil {
		return err
	}

	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func (tk *tcpKill) Run() error {
	fmt.Printf("tcpkill listen on %v\n", tk.Iface)

	var handle *pcap.Handle
	var err error

	// snaplen and timeout hard-code
	if handle, err = pcap.OpenLive(tk.Iface, int32(65535), tk.IsPromisc, -1*time.Second); err != nil {
		return err
	}

	defer handle.Close()

	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			return fmt.Errorf("set BPF filter error: %v", err)
		}
	}

	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			continue
		}
		ip := ipv4Layer.(*layers.IPv4)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)

		if tcp.SYN || tcp.FIN || tcp.RST {
			continue
		}

		for i := 0; i < tk.RstSendCount; i++ {
			seq := tcp.Ack + uint32(i)*uint32(tcp.Window)
			err := tk.sendRST(eth.DstMAC, eth.SrcMAC, ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort, seq, handle)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func main() {
	tk := &tcpKill{
		Iface:        *iface,
		RstSendCount: *rstCount,
		IsPromisc:    *promisc,
	}
	if err := tk.Run(); err != nil {
		log.Fatal(err)
	}
}
