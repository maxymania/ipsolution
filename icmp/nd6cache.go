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
import "math/rand"

/* --------------------------------ND6-Part--------------------------------- */

/*
 * RFC 4861:
 * 5.1.  Conceptual Data Structures
 *
 *    INCOMPLETE  Address resolution is in progress and the link-layer
 *                address of the neighbor has not yet been determined.
 *
 *    REACHABLE   Roughly speaking, the neighbor is known to have been
 *                reachable recently (within tens of seconds ago).
 *
 *    STALE       The neighbor is no longer known to be reachable but
 *                until traffic is sent to the neighbor, no attempt
 *                should be made to verify its reachability.
 *
 *    DELAY       The neighbor is no longer known to be reachable, and
 *                traffic has recently been sent to the neighbor.
 *                Rather than probe the neighbor immediately, however,
 *                delay sending probes for a short while in order to
 *                give upper-layer protocols a chance to provide
 *                reachability confirmation.
 *
 *    PROBE       The neighbor is no longer known to be reachable, and
 *                unicast Neighbor Solicitation probes are being sent to
 *                verify reachability.
 *
 */
type ND6_NC_STATE uint8
const (
	/*
	 * This states indicates, that the Entry is a 'phantom-Entry' which
	 * means, that it behaves like a non-existing Entry in the context of
	 * the means of RFC-4861 (or any other specification).
	 *
	 * Phantom-Entries are used, for example, to represent entries in the
	 * Default Router List, for which no Neigbor-Cache-Entry had been
	 * created.
	 *
	 * In order to create an RFC-4861-compliant Entry over an existing
	 * Phantom-Entry, the code MUST alter it's state into one of the states
	 * as defined by RFC 4861.
	 * Code creating Entries by eighter allocating new Entries or overwriting
	 * Phantom-Entries MUST NOT differ it's behavoir depending on wether a
	 * Phantom-Entry exists or not.
	 */
	ND6_NC__PHANTOM_ = ND6_NC_STATE(iota)
	
	
	/* RFC 4861 NC-Entry states */
	ND6_NC_INCOMPLETE
	ND6_NC_REACHABLE
	ND6_NC_STALE
	ND6_NC_DELAY
	ND6_NC_PROBE
)

type IPv6Addr struct {
	Array [16]byte
}
func NewIPv6Addr(i net.IP) (s IPv6Addr) {
	copy(s.Array[:],[]byte(i.To16()))
	return
}

/*
 * Neighbor-Cache Entry.
 *
 * RFC-4861 5.1.  Conceptual Data Structures
 *   Neighbor Cache (one for each interface)
 *      A set of entries about individual neighbors to
 *      which traffic has been sent recently.  Entries are
 *      keyed on the neighbor's on-link unicast IP address
 *      and contain such information as its link-layer
 *      address, a flag indicating whether the neighbor is
 *      a router or a host (called IsRouter in this
 *      document), a pointer to any queued packets waiting
 *      for address resolution to complete, etc.  A
 *      Neighbor Cache entry also contains information used
 *      by the Neighbor Unreachability Detection algorithm,
 *      including the reachability state, the number of
 *      unanswered probes, and the time the next Neighbor
 *      Unreachability Detection event is scheduled to take
 *      place.
 */
type Nd6Nce struct {
	
	
	State  ND6_NC_STATE
	IPAddr IPv6Addr
	HWAddr net.HardwareAddr
	
	Tstamp, RouterTstamp time.Time
	
	RouterLifetime uint16
	
	IsRouter bool
	
	Entry,RouterEntry Member /* Router-List-Entry */
	sync.RWMutex
}
func (n *Nd6Nce) Init() *Nd6Nce {
	n.Entry.Value = n
	n.RouterEntry.Value = n
	n.State = ND6_NC__PHANTOM_
	n.IsRouter = false
	return n
}


type Nd6Cache struct {
	Entries List
	Routers List
	Maxsize int
	
	Ipmap   map[IPv6Addr]*Nd6Nce
	
	mutex sync.RWMutex
	
	redirect map[IPv6Addr]IPv6Addr
	redirmtx sync.RWMutex
}
func (n *Nd6Cache) Init() *Nd6Cache {
	n.Entries.Init()
	n.Routers.Init()
	n.Maxsize = 128000
	n.Ipmap = make(map[IPv6Addr]*Nd6Nce)
	n.redirect = make(map[IPv6Addr]IPv6Addr)
	return n
}
func (n *Nd6Cache) LookupOrCreate(ip net.IP) *Nd6Nce {
	n.mutex.Lock(); defer n.mutex.Unlock();
	sp := NewIPv6Addr(ip)
	nce,ok := n.Ipmap[sp]
	if ok { return nce }
	nce = new(Nd6Nce).Init()
	nce.IPAddr = sp
	n.Ipmap[sp] = nce
	if n.Entries.Len()>n.Maxsize {
		roe := n.Entries.Front()
		if roe ==nil { goto done }
		oe := roe.Value.(*Nd6Nce)
		oe.Entry.Remove()
		delete(n.Ipmap,oe.IPAddr)
	}
done:
	n.Entries.PushBack(&nce.Entry)
	return nce
}
func (n *Nd6Cache) Lookup(ip net.IP) *Nd6Nce {
	n.mutex.RLock(); defer n.mutex.RUnlock()
	sp := NewIPv6Addr(ip)
	nce,ok := n.Ipmap[sp]
	if !ok { return nil }
	return nce
}
func (n *Nd6Cache) LookupValidOnly(ip net.IP) *Nd6Nce {
	n.mutex.RLock(); defer n.mutex.RUnlock();
	sp := NewIPv6Addr(ip)
	nce,ok := n.Ipmap[sp]
	if !ok { return nil }
	if nce.State == ND6_NC__PHANTOM_ { return nil }
	return nce
}
func (n *Nd6Cache) Redirect(i *IPv6Addr){
	n.redirmtx.RLock(); defer n.redirmtx.RUnlock()
	ii := *i
	for count := 128; count>0; count-- {
		v,ok := n.redirect[ii]
		if !ok { break }
		ii = v
	}
	*i = ii
}
func (n *Nd6Cache) AddRedirect(target,dest IPv6Addr) {
	n.redirmtx.Lock(); defer n.redirmtx.Unlock()
	if len(n.redirect)>16000 {
		p := rand.Int31n(int32(len(n.redirect)))
		for k := range n.redirect {
			if p==0 {
				delete(n.redirect,k); break
			}
			p--
		}
	}
	n.redirect[target] = dest
}

