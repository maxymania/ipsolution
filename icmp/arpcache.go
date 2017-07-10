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

import "sync"
import "net"
import "time"
import "container/list"

type IPv4Addr uint32

func NewIPv4Addr(i net.IP) (s IPv4Addr) {
	i2 := i.To4()
	if len(i2)==0 { i2 = i }
	if len(i2)>=4 {
		s  = IPv4Addr(i2[0])<<24
		s |= IPv4Addr(i2[1])<<16
		s |= IPv4Addr(i2[2])<< 8
		s |= IPv4Addr(i2[3])
	}else{
		s = IPv4Addr(0)
	}
	return
}
func (s IPv4Addr) IP() net.IP {
	return net.IP{
		byte(s>>24),
		byte(s>>16),
		byte(s>>8),
		byte(s),
	}
}


type ARP_STATE uint8
const (
	ARP__PHANTOM_ = ARP_STATE(iota)
	
	ARP_INCOMPLETE
	ARP_COMPLETE
)


type ArpCe struct {
	sync.RWMutex
	
	State  ARP_STATE
	IPAddr IPv4Addr
	HWAddr net.HardwareAddr
	
	Tstamp time.Time
	
	Entry Member
	
	Sendchain *list.List
}
func (a *ArpCe) Init() *ArpCe {
	a.Entry.Value = a
	a.State = ARP__PHANTOM_
	a.Sendchain = list.New()
	return a
}

type ArpCache struct {
	Entries List
	Maxsize int
	
	Ipmap   map[IPv4Addr]*ArpCe
	
	/*
	 * Arp cache timeout = Timeout
	 * Arp cache soft timeout = Timeout - SoftTmoDiff
	 */
	Timeout time.Duration
	SoftTmoDiff time.Duration /* Soft Timeout Difference */
	
	mutex sync.RWMutex
}
func (a *ArpCache) Init() *ArpCache {
	a.Entries.Init()
	a.Maxsize = 128000
	a.Timeout = 60 * time.Second
	a.SoftTmoDiff = 3 * time.Second
	a.Ipmap = make(map[IPv4Addr]*ArpCe)
	return a
}
// The returned *ArpCe is locked.
func (n *ArpCache) LookupOrCreate(ip net.IP) *ArpCe {
	n.mutex.Lock(); defer n.mutex.Unlock();
	sp := NewIPv4Addr(ip)
	nce,ok := n.Ipmap[sp]
	if ok { nce.Lock(); return nce }
	nce = new(ArpCe).Init()
	nce.IPAddr = sp
	n.Ipmap[sp] = nce
	for {
		roe := n.Entries.Front()
		if roe == nil { break }
		oe := roe.Value.(*ArpCe)
		if oe.State != ARP__PHANTOM_ {
		} else if n.Entries.Len() > n.Maxsize {
		} else if time.Since(oe.Tstamp) < n.Timeout {
		} else { break }
		oe.Entry.Remove()
		delete(n.Ipmap,oe.IPAddr)
	}
	n.Entries.PushBack(&nce.Entry)
	nce.Lock()
	return nce
}
func (n *ArpCache) Lookup(ip net.IP) *ArpCe {
	n.mutex.RLock(); defer n.mutex.RUnlock()
	sp := NewIPv4Addr(ip)
	nce,ok := n.Ipmap[sp]
	if !ok { return nil }
	nce.Lock()
	return nce
}
func (n *ArpCache) LookupValidOnly(ip net.IP) *ArpCe {
	n.mutex.RLock(); defer n.mutex.RUnlock();
	sp := NewIPv4Addr(ip)
	nce,ok := n.Ipmap[sp]
	if !ok { return nil }
	if nce.State == ARP__PHANTOM_ { return nil }
	nce.Lock()
	return nce
}

