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

import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "encoding/binary"

func (i *IPProtocolControlMessage) decodeV4(b []byte,df gopacket.DecodeFeedback) (error,[]byte) {
	var i4 layers.IPv4
	err := i4.DecodeFromBytes(b,df)
	if err!=nil { return err,nil }
	i.Protocol = i4.Protocol
	i.RemoteIP = copyip(i4.DstIP)
	i.LocalIP = copyip(i4.SrcIP)
	return nil,i4.Payload
}
func (i *IPProtocolControlMessage) decodeV6(b []byte,df gopacket.DecodeFeedback) (error,[]byte) {
	var i6 layers.IPv6
	var es layers.IPv6ExtensionSkipper
	err := i6.DecodeFromBytes(b,df)
	if err!=nil { return err,nil }
	//i.Protocol = i6.Protocol
	i.RemoteIP = copyip(i6.DstIP)
	i.LocalIP = copyip(i6.SrcIP)
	
	es.NextHeader = i6.NextHeader
	es.BaseLayer  = i6.BaseLayer
	for{
		switch es.NextHeader{
		case layers.IPProtocolIPv6HopByHop,layers.IPProtocolIPv6Routing,layers.IPProtocolIPv6Fragment,layers.IPProtocolIPv6Destination:
			err = es.DecodeFromBytes(es.Payload,df)
			if err!=nil { return err,nil }
			continue
		}
		break
	}
	i.Protocol = es.NextHeader
	return nil,es.Payload
}
func (i *IPProtocolControlMessage) decode(payload []byte,isV6 bool,df gopacket.DecodeFeedback) error {
	var err error
	var buf []byte
	if isV6 {
		err,buf = i.decodeV6(payload,df)
	} else {
		err,buf = i.decodeV4(payload,df)
	}
	if err!=nil { return err }
	i.LocalPort = 0
	if len(buf)>=2 {
		i.LocalPort = binary.BigEndian.Uint16(buf[0:2])
	}
	i.RemotePort = 0
	if len(buf)>=4 {
		i.RemotePort = binary.BigEndian.Uint16(buf[2:4])
	}
	return nil
}

