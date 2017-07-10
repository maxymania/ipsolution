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

import "github.com/google/gopacket/layers"
import "net"
import "container/list"
import "time"

func (h *Host) ResolutionV4(l *list.List, srcIP, destIP net.IP, po PacketOutput) error {
	isBroadcast := func () bool { return false }
	// TODO: check multicast/broadcast.
	
	if isBroadcast() {
		hwaddr := net.HardwareAddr{0xff,0xff,0xff,0xff,0xff,0xff}
		h.send(l,hwaddr,po,layers.EthernetTypeIPv6)
	}else{
		ncache := h.ARP
		
		nce := ncache.LookupOrCreate(destIP)
		defer nce.Unlock()
		
		switch nce.State {
		case ARP__PHANTOM_:
			nce.State = ARP_INCOMPLETE
			nce.Tstamp = time.Now()
			nce.Entry.MoveToBack()
			
			h.arpSendSolicitation(srcIP,destIP,po)
			fallthrough
		case ARP_INCOMPLETE:
			nce.Sendchain.PushBackList(l)
			return nil
		}
		
		since := time.Since(nce.Tstamp)
		
		// When approaching expiration, send new ARP request
		if since > (ncache.Timeout+ncache.SoftTmoDiff) {
			h.arpSendSolicitation(srcIP,destIP,po)
		}
		
		go h.send(l,nce.HWAddr,po,layers.EthernetTypeIPv6)
	}
	return nil
}


