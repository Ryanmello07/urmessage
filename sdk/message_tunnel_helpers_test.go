package sdk

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/urnetwork/connect"
)

// craftIpv4Packet builds one IPv4 TCP or UDP packet with valid checksums, for the message tunnel
// tests' echoing exit. It is the core SDK's test helper of the same name and body
// (device_local_mux_security_test.go at urnetwork/sdk 6141b98d), copied when the messaging SDK
// moved here, because one module's tests cannot call another module's test code. It imports
// connect's gopacket (github.com/gopacket/gopacket), already in this module's graph through
// connect, where the core SDK imports github.com/google/gopacket; the layers this uses are the
// same in both.
func craftIpv4Packet(proto connect.IpProtocol, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, syn bool, payload []byte) []byte {
	ip := &layers.IPv4{
		Version: 4,
		TTL:     64,
		SrcIP:   srcIP.To4(),
		DstIP:   dstIP.To4(),
	}
	var transport gopacket.SerializableLayer
	switch proto {
	case connect.IpProtocolTcp:
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     syn,
			Seq:     1,
			Window:  65535,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		transport = tcp
	case connect.IpProtocolUdp:
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ip)
		transport = udp
	default:
		return nil
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, transport, gopacket.Payload(payload),
	); err != nil {
		return nil
	}
	return append([]byte(nil), buf.Bytes()...)
}
