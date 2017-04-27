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

import "github.com/hashicorp/golang-lru/simplelru"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "net"
import "sync"
import "container/ring"

type SerBuffer struct{
	Sb gopacket.SerializeBuffer
	Next *SerBuffer
}

func nilCB(key interface{}, value interface{}) {}

type ArpCache struct{
	sync.Mutex
	queue,cache *simplelru.LRU
}
func (a *ArpCache) Init(i int) {
	a.queue,_ = simplelru.NewLRU(i,nilCB)
	a.cache,_ = simplelru.NewLRU(i,nilCB)
}
func (a *ArpCache) ARP(i *IPNetif,p *IPLayerPart) (sbs []gopacket.SerializeBuffer) {
	var i4 Key4
	ip := p.SrcIP
	mac := p.SrcMac
	i4.Decode(ip)
	
	sbs = make([]gopacket.SerializeBuffer,1,16)
	switch p.AR4.Operation {
	case 1,2:
		a.Lock()
		a.cache.Add(i4,mac)
		t,ok := a.queue.Get(i4)
		a.queue.Remove(i4)
		a.Unlock()
		
		if ok {
			t.(*ring.Ring).Do(func(sbi interface{}){
				sb := sbi.(gopacket.SerializeBuffer)
				i.send(sb,mac,layers.EthernetTypeIPv4)
				sbs = append(sbs,sb)
			})
		}
	}
	if p.AR4.Operation!=1 { sbs=sbs[1:] ; return }
	var arp layers.ARP
	arp = p.AR4
	arp.Operation = 2
	arp.DstHwAddress = arp.SourceHwAddress
	arp.DstProtAddress,arp.SourceProtAddress = arp.SourceProtAddress,arp.DstProtAddress
	arp.SourceHwAddress = []byte(i.HWAddr)
	arp.SourceProtAddress = []byte(mac)
	
	sb := gopacket.NewSerializeBuffer()
	arp.SerializeTo(sb,gopacket.SerializeOptions{true,true})
	i.send(sb,p.SrcMac,layers.EthernetTypeARP)
	
	sbs[0] = sb
	return
}
func (a *ArpCache) lkup(sb gopacket.SerializeBuffer,n net.IP) (net.HardwareAddr,bool) {
	var i4 Key4
	i4.Decode(n)
	a.Lock(); defer a.Unlock()
	h,ok := a.cache.Get(i4)
	if ok { return h.(net.HardwareAddr),ok }
	if sb==nil { return nil,false }
	s := ring.New(1)
	s.Value = sb
	
	if t,ok := a.queue.Get(i4); ok {
		s.Link(t.(*ring.Ring))
	}else{
		a.queue.Add(i4,s)
	}
	
	return nil,false
}

func (a *ArpCache) Compile(i *IPNetif, sb gopacket.SerializeBuffer,n net.IP) bool {
	h,ok := a.lkup(sb,n)
	if ok { i.send(sb,h,layers.EthernetTypeIPv4) }
	return ok
}

type IPNetif struct {
	HWAddr net.HardwareAddr
	VLANIdentifier uint16
	ARP ArpCache
}
func (i *IPNetif) send(sb gopacket.SerializeBuffer,h net.HardwareAddr,lt layers.EthernetType) {
	var ep layers.Ethernet
	var dq layers.Dot1Q
	ep.SrcMAC = i.HWAddr
	ep.DstMAC = h
	dq.VLANIdentifier = i.VLANIdentifier
	dq.Type = lt
	so := gopacket.SerializeOptions{true,true}
	if i.VLANIdentifier==0 {
		ep.EthernetType = lt
		gopacket.SerializeLayers(sb,so,&ep)
	}else{
		ep.EthernetType = layers.EthernetTypeDot1Q
		gopacket.SerializeLayers(sb,so,&ep,&dq)
	}
}

