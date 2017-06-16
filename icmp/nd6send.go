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

import "github.com/maxymania/ipsolution/eth"
import "github.com/google/gopacket/layers"
import "github.com/google/gopacket"
import "net"
import "container/list"
import "time"
import "fmt"

var ENoGateway = fmt.Errorf("No Gateway")

func (h *Host) ResolutionV6(l *list.List, srcIP, destIP net.IP, po PacketOutput) error {
	if destIP[0]==0xff { /* Multicast */
		hwaddr := copymac(net.HardwareAddr(destIP[10:]))
		hwaddr[0] = 0x33
		hwaddr[1] = 0x33
		h.send(l,hwaddr,po,layers.EthernetTypeIPv6)
	}else{
		dip := NewIPv6Addr(destIP)
		ncache := h.NC6
		
		ncache.Redirect(&dip)
		
		/*
		 * RFC4861 7.2.
		 *   Address resolution is performed only on addresses that are
		 *   determined to be on-link and for which the sender does not
		 *   know the corresponding link-layer address (see Section 5.2).
		 *   Address resolution is never  performed on multicast addresses.
		 */
		if !h.Host.IsOnLink(dip.Array[:]) {
			nipa := h.NC6.SelectRouter()
			if nipa==nil { return ENoGateway }
			dip = *nipa
			ncache.Redirect(&dip)
		}
		
		nce := ncache.LookupValidOnly(dip.Array[:])
		defer nce.Unlock()
		
		switch nce.State {
		case ND6_NC__PHANTOM_:
			nce.State = ND6_NC_INCOMPLETE
			nce.Tstamp = time.Now()
			nce.Entry.MoveToBack()
			solp,hwa := h.nd6CreateNeighborSolicitation(srcIP,nil /* for AR */,destIP)
			
			{
				var e eth.EthLayer2
				e.SrcMAC = h.Mac
				e.VLANIdentifier = h.Vlan
				e.DstMAC = hwa
				e.EthernetType = layers.EthernetTypeIPv6
				err := e.SerializeTo(solp,gopacket.SerializeOptions{true,true})
				if err!=nil { return err }
				po.WritePacketData(solp.Bytes())
			}
			nce.PlusEntry.Remove()
			ncache.Retrans.PushBack(&nce.PlusEntry)
			
			fallthrough
		case ND6_NC_INCOMPLETE:
			nce.Sendchain.PushBackList(l)
			return nil
		case ND6_NC_STALE:
			/*
			 * RFC4861 7.3.3:
			 *   The first time a node sends a packet to a neighbor whose entry is
			 *   STALE, the sender changes the state to DELAY and sets a timer to
			 *   expire in DELAY_FIRST_PROBE_TIME seconds.
			 */
			nce.State = ND6_NC_DELAY
			nce.Tstamp = time.Now()
			nce.Entry.MoveToBack()
			
			/* Add this Cache-Entry to the Delay-List */
			nce.PlusEntry.Remove()
			ncache.Delay.PushBack(&nce.PlusEntry)
		}
		
		go h.send(l,nce.HWAddr,po,layers.EthernetTypeIPv6)
	}
	return nil
}


