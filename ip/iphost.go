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



package ip

import "net"
import "time"
import "sync"
import "container/list"

type IPv6Prefix struct{
	IP [16]byte
	Len uint8
}

type IPv6PrefixEntry struct{
	Prefix IPv6Prefix
	Lifetime uint32
	Tstamp time.Time
	Onlink bool
	Slaac bool
	
	ListSync sync.Mutex
	List list.List /* a list of Key6 values */
}

type IPv6AddressEntry struct{
	Unicast, SolicitedMulticast Key6
	
	/*
	 * The prefix this IPv6 Address was derived from, if any.
	 *
	 * This field is nil for link local addresses.
	 */
	Prefix *IPv6PrefixEntry
}
type IPv4AddressEntry struct{
	Addr, Subnetmask, Gateway Key4
}

type IPHost struct {
	sync.RWMutex
	V4 map[Key4]*IPv4AddressEntry
	V6 map[Key6]*IPv6AddressEntry
	S6 map[Key6]*IPv6AddressEntry
	Prefix6 map[IPv6Prefix]*IPv6PrefixEntry
}
func (i *IPHost) Init() *IPHost{
	i.V4 = make(map[Key4]*IPv4AddressEntry)
	i.V6 = make(map[Key6]*IPv6AddressEntry)
	i.S6 = make(map[Key6]*IPv6AddressEntry)
	i.Prefix6 = make(map[IPv6Prefix]*IPv6PrefixEntry)
	return i
}
func (i *IPHost) input4(targ net.IP) (my bool) {
	var i4 Key4
	i4.Decode(targ)
	if i4==0xFFFFFFFF { return true }
	i.RLock(); defer i.RUnlock()
	_,my = i.V4[i4]
	return
}
func (i *IPHost) input6(targ net.IP) (my bool) {
	var i6 Key6
	
	if targ[0]==0xff { /* IF address is multicast */
		switch targ[1]&0xf { /* Multicast Scope. */
		/*
		 * RFC 4291 2.7
		 * 
		 * Nodes must not originate a packet to a multicast address whose scop
		 * field contains the reserved value 0; if such a packet is received, it
		 * must be silently dropped.
		 */
		// (Case 0)
		/*
		 * RFC 4291 - Errata ID: 3480
		 *
		 * Section 2.7 says: 
		 *  Interface-Local scope spans only a single interface on a node
		 *  and is useful only for loopback transmission of multicast.
		 * 
		 * It should say:
		 *  Interface-Local scope spans only a single interface on a node 
		 *  and is useful only for loopback transmission of multicast.
		 *  Packets with interface-local scope received from another node 
		 *  must be discarded.
		 *
		 * It should be explicitly stated that interface-local scoped multicast packets
		 * received from the link must be discarded.
		 * The BSD implementation currently does this, but not Linux.
		 * http://www.ietf.org/mail-archive/web/ipv6/current/msg17154.html 
		 */
		// (Case 1)
		case  0,1: return false
		default: return true
		}
	}
	
	i.RLock(); defer i.RUnlock()
	i6.Decode(targ)
	_,my = i.V6[i6]
	return
}
func (i *IPHost) Input(targ net.IP) (my bool) {
	switch len(targ) {
	case 4:
		my = i.input4(targ)
	case 16:
		my = i.input6(targ)
	}
	return
}
func (i *IPHost) addIP4Addr(ip, sn, gw net.IP) {
	var i4,s4,g4 Key4
	i4.Decode(ip)
	addr,_ := i.V4[i4]
	if addr!=nil { return }
	if len(sn)==4 {
		s4.Decode(sn)
	}else{
		s4 = 0xFFFFFF00
	}
	if len(gw)==4 {
		g4.Decode(gw)
	}else{
		g4 = i4&0xFFFFFF00
	}
	
	addr = &IPv4AddressEntry{i4,s4,g4}
	i.V4[i4] = addr
	i.V4[i4|^s4] = addr
}
func (i *IPHost) addIP6Addr(ip net.IP) {
	var i6,m6 Key6
	i6.Decode(ip)
	addr,_ := i.V6[i6]
	if addr!=nil { return }
	/* Solicited Multicast address */
	m6.Hi = 0xff02000000000000
	m6.Lo = 0x00000001ff000000|(i6.Lo&0xffffff)
	addr = new(IPv6AddressEntry)
	addr.Unicast = i6
	addr.SolicitedMulticast = m6
	i.V6[i6] = addr
	i.S6[m6] = addr
}
func (i *IPHost) AddIPAddr(ip net.IP) {
	switch len(ip) {
	case 4:
		i.addIP4Addr(ip,nil,nil)
	case 16:
		i.addIP6Addr(ip)
	}
}


