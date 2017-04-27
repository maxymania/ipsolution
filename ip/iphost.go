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

type IPv6AddressEntry struct{
	Unicast, SolicitedMulticast Key6
	
}
type IPv4AddressEntry struct{
	Addr, Subnetmask, Gateway Key4
}

type IPHost struct {
	V6 map[Key6]*IPv6AddressEntry
	V4 map[Key4]*IPv4AddressEntry
}
func (i *IPHost) Init() *IPHost{
	i.V6 = make(map[Key6]*IPv6AddressEntry)
	i.V4 = make(map[Key4]*IPv4AddressEntry)
	return i
}
func (i *IPHost) input4(targ net.IP) (my bool) {
	var i4 Key4
	i4.Decode(targ)
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



