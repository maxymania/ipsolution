/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package icmp

import "github.com/maxymania/ipsolution/ip"
import "github.com/maxymania/ipsolution/eth"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"

import "fmt"
import "net"
import "container/list"

var ENotSupp = fmt.Errorf("Protocol not supported")
var EInvalid = fmt.Errorf("Protocol violation")

type PacketOutput interface{
	WritePacketData(data []byte) error
}

type Notifyable interface{
	Notify(i interface{})
}

type IPUnreachable struct{
	FailType layers.ICMPv4TypeCode
	Addr net.IP
}

type Echo struct {
	Head,Body []byte
	Addr net.IP
}

type Host struct{
	NetN Notifyable
	EchoSocket Notifyable
	NC6 *Nd6Cache
	Host *ip.IPHost
	Mac net.HardwareAddr
	Vlan uint16
	
	/* IPv6 */
	CurHopLimit uint8
	BaseReachableTime, ReachableTime uint32
	IPv6MTU uint32
	RetransTimer uint32
}

func copymac(i net.HardwareAddr) net.HardwareAddr {
	j := make(net.HardwareAddr,len(i)); copy(j,i)
	return j
}
func copyip(i net.IP) net.IP {
	j := make(net.IP,len(i)); copy(j,i)
	return j
}
func copydat(i []byte) []byte {
	j := make([]byte,len(i)); copy(j,i)
	return j
}


func duV6ToV4(code layers.ICMPv6TypeCode) layers.ICMPv4TypeCode {
	var itc4 uint8
	switch code.Code() {
	case    layers.ICMPv6CodeNoRouteToDst,
		layers.ICMPv6CodeRejectRouteToDst,
		layers.ICMPv6CodeSrcAddressFailedPolicy:
		itc4 = layers.ICMPv4CodeSourceRoutingFailed
	case layers.ICMPv6CodeBeyondScopeOfSrc:
		itc4 = layers.ICMPv4CodeNet
	case layers.ICMPv6CodeAdminProhibited:
		/*
		 * ICMPv6 is less concise about what is prohibited or not.
		 * In this case, we must simply choose a sane default.
		 *
		 * We assume, that the Network is Administratively Prohibitet.
		 * Note, that this message is handled within the local host only.
		 */
		itc4 = layers.ICMPv4CodeNetAdminProhibited
	case layers.ICMPv6CodeAddressUnreachable:
		itc4 = layers.ICMPv4CodeHost /* Host Unreachable */
	default:
		itc4 = layers.ICMPv4CodeNet
	}
	return layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable,itc4)
}


func (h *Host) Input(e *eth.EthLayer2, i *ip.IPLayerPart, po PacketOutput) error {
	if i.IsAR {
		return ENotSupp
	}
	switch i.NextLayerType {
		case layers.LayerTypeICMPv4:
			// ICMPv4 must not be in IPv6 packet
			if i.IsV6 { return EInvalid }
			return h.input4(e,i,po)
		case layers.LayerTypeICMPv6:
			// ICMPv6 must be in IPv6 packet
			if !i.IsV6 { return EInvalid }
			return h.input6(e,i,po)
	}
	return ENotSupp
}
// ICMPv4 input function
func (h *Host) input4(e *eth.EthLayer2, i *ip.IPLayerPart, po PacketOutput) (err error) {
	var icmp layers.ICMPv4
	err = icmp.DecodeFromBytes(i.Payload,gopacket.NilDecodeFeedback); if err!=nil { return }
	
	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply,icmp.TypeCode.Code())
		// Flip addresses.
		i.V4.SrcIP,i.V4.DstIP = i.V4.DstIP,i.V4.SrcIP
		e.SrcMAC,e.DstMAC = e.DstMAC,e.SrcMAC
		
		// rewrite IPv4 fields.
		i.V4.TOS = 0
		i.V4.TTL = 64
		
		so := gopacket.SerializeOptions{true,true}
		sb := gopacket.NewSerializeBufferExpectedSize(len(icmp.Payload)+128,0)
		gopacket.SerializeLayers(sb,so,e,&i.V4,&icmp,gopacket.Payload(icmp.Payload))
	case layers.ICMPv4TypeEchoReply:
		if h.EchoSocket==nil { return }
		h.EchoSocket.Notify(&Echo{copydat(icmp.Contents),copydat(icmp.Payload),copyip(i.SrcIP)})
	case layers.ICMPv4TypeDestinationUnreachable:
		if h.NetN==nil { return }
		switch icmp.TypeCode.Code() {
		case layers.ICMPv4CodeProtocol,layers.ICMPv4CodePort:
			return
		default:
			h.NetN.Notify(&IPUnreachable{icmp.TypeCode,copyip(i.SrcIP)})
		}
	case layers.ICMPv4TypeTimeExceeded:
		if h.NetN==nil { return }
		switch icmp.TypeCode.Code() {
		case layers.ICMPv4CodeTTLExceeded:
			h.NetN.Notify(&IPUnreachable{icmp.TypeCode,copyip(i.SrcIP)})
		}
	case layers.ICMPv4TypeSourceQuench:
		if h.NetN==nil { return }
		h.NetN.Notify(&IPUnreachable{icmp.TypeCode,copyip(i.SrcIP)})
	// TODO: many ICMP requests are still ignored, harvest as needed.
	}
	return
}
// ICMPv6 input function
func (h *Host) input6(e *eth.EthLayer2, i *ip.IPLayerPart, po PacketOutput) (err error) {
	var icmp layers.ICMPv6
	err = icmp.DecodeFromBytes(i.Payload,gopacket.NilDecodeFeedback); if err!=nil { return }
	
	switch icmp.TypeCode.Type() {
	case layers.ICMPv6TypeEchoRequest:
		icmp.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply,icmp.TypeCode.Code())
		// Flip addresses.
		i.V6.SrcIP,i.V6.DstIP = i.V6.DstIP,i.V6.SrcIP
		e.SrcMAC,e.DstMAC = e.DstMAC,e.SrcMAC
		
		// rewrite IPv6 fields.
		i.V6.TrafficClass = 0
		i.V6.HopLimit = 64
		
		so := gopacket.SerializeOptions{true,true}
		sb := gopacket.NewSerializeBufferExpectedSize(len(icmp.Payload)+128,0)
		gopacket.SerializeLayers(sb,so,e,&i.V6,&icmp,gopacket.Payload(icmp.Payload))
	case layers.ICMPv6TypeEchoReply:
		if h.EchoSocket==nil { return }
		h.EchoSocket.Notify(&Echo{copydat(icmp.Contents),copydat(icmp.Payload),copyip(i.SrcIP)})
	case layers.ICMPv6TypeDestinationUnreachable:
		if h.NetN==nil { return }
		
		switch icmp.TypeCode.Code() {
		case layers.ICMPv6CodePortUnreachable:
			return
		default:
			h.NetN.Notify(&IPUnreachable{duV6ToV4(icmp.TypeCode),copyip(i.SrcIP)})
		}
	case layers.ICMPv6TypeTimeExceeded:
		if h.NetN==nil { return }
		switch icmp.TypeCode.Code() {
		case layers.ICMPv6CodeHopLimitExceeded:
			h.NetN.Notify(&IPUnreachable{
				layers.CreateICMPv4TypeCode(
					layers.ICMPv4TypeTimeExceeded,
					layers.ICMPv4CodeTTLExceeded),
				copyip(i.SrcIP)})
		}
	case layers.ICMPv6TypePacketTooBig:
		if h.NetN==nil { return }
		h.NetN.Notify(&IPUnreachable{
				layers.CreateICMPv4TypeCode(
					layers.ICMPv4TypeDestinationUnreachable,
					layers.ICMPv4CodeFragmentationNeeded),
				copyip(i.SrcIP)})
	case layers.ICMPv6TypeNeighborSolicitation:
		if h.NC6==nil { return }
		h.nd6NeighborSolicitation(i,&icmp,po)
	case layers.ICMPv6TypeNeighborAdvertisement:
		if h.NC6==nil { return }
		h.nd6NeighborAdvertisement(i,&icmp,po)
	case layers.ICMPv6TypeRouterAdvertisement:
		if h.NC6==nil { return }
		h.nd6RouterAdvertisement(i,&icmp,po)
	case layers.ICMPv6TypeRedirect:
		if h.NC6==nil { return }
		h.nd6Redirect(i,&icmp,po)
	// TODO: handle Neighbor Discovery Protocol.
	// TODO: many ICMP requests are still ignored, harvest as needed.
	}
	return
}
func (h *Host) send_IPv6(l *list.List, dst net.HardwareAddr, po PacketOutput) {
	if l.Len()==0 { return }
	var e eth.EthLayer2
	e.SrcMAC = h.Mac
	e.VLANIdentifier = h.Vlan
	e.DstMAC = dst
	e.EthernetType = layers.EthernetTypeIPv6
	
	op := gopacket.SerializeOptions{true,true}
	for elem := l.Front(); elem!=nil; elem = elem.Next() {
		switch ev := elem.Value.(type) {
		case gopacket.SerializeBuffer:
			if e.SerializeTo(ev,op)==nil {
				po.WritePacketData(ev.Bytes())
			}
		case []byte:
			ob := gopacket.NewSerializeBufferExpectedSize(len(ev)+20,0)
			err := gopacket.SerializeLayers(ob,op,&e,gopacket.Payload(ev))
			if err==nil {
				po.WritePacketData(ob.Bytes())
			}
		}
	}
}



