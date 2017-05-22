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
import "time"
import "container/list"

func (h *Host) arp(i *ip.IPLayerPart, po PacketOutput) {
	var sendchain *list.List
	sendchain = nil
	sh := i.AR4.SourceHwAddress
	sp := i.AR4.SourceProtAddress
	tp := i.AR4.DstProtAddress
	
	/* TODO: Check, is the source IP our IP? */
	if h.Host.Input(sh) { /* Duplicate IP Address. */ return }
	
	ncache := h.ARP
restartCache:
	ce := ncache.LookupOrCreate(sp)
	ce.Lock()
	/* This handles an extremely rare pathological case. */
	if ce.Entry.Parent()!=ncache {
		ce.Unlock()
		goto restartCache
	}
	defer ce.Unlock()
	
	isOurs := h.Host.Input(tp)
	
	if isOurs || ce.State != ARP__PHANTOM_ {
		ce.Tstamp = time.Now()
		ce.HWAddr = sh
		ce.State = ARP_COMPLETE
		sendchain = ce.Sendchain
		ce.Sendchain = list.New()
	}
	
	
	if isOurs && i.AR4.Operation==layers.ARPRequest {
		var ethout eth.EthLayer2
		var arpout layers.ARP
		ethout.VLANIdentifier = h.Vlan
		ethout.SrcMAC = h.Mac
		arpout.SourceHwAddress = h.Mac
		arpout.SourceProtAddress = tp
		
		ethout.DstMAC = sh
		arpout.DstHwAddress = sh
		arpout.DstProtAddress = sp
		
		arpout.AddrType = layers.LinkTypeEthernet
		arpout.Protocol = layers.EthernetTypeIPv4
		arpout.Operation = layers.ARPReply
		
		SB := gopacket.NewSerializeBufferExpectedSize(128,0)
		op := gopacket.SerializeOptions{true,true}
		gopacket.SerializeLayers(SB,op,&ethout,&arpout)
		po.WritePacketData(SB.Bytes())
	}
	
	if sendchain!=nil {
		h.send(sendchain,sh,po,layers.EthernetTypeIPv4)
	}
}

