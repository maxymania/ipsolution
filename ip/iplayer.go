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


import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "net"
import "fmt"

type IPLayerPart struct {
	layers.BaseLayer
	V4 layers.IPv4
	V6 layers.IPv6
	AR4 layers.ARP
	ES6 layers.IPv6ExtensionSkipper
	NetworkFlow   gopacket.Flow
	NextLayerType gopacket.LayerType
	SrcIP net.IP
	DstIP net.IP
	SrcMac net.HardwareAddr
	DstMac net.HardwareAddr
	IsAR bool
	IsV6 bool
}

func (ip *IPLayerPart) DecodeType(t gopacket.LayerType,data []byte, df gopacket.DecodeFeedback) (err error) {
	err = fmt.Errorf("Unsupported Type %v",t)
	switch t{
	case layers.LayerTypeIPv4:
		err = ip.V4.DecodeFromBytes(data,df)
		ip.BaseLayer = ip.V4.BaseLayer
		ip.NetworkFlow = ip.V4.NetworkFlow()
		ip.NextLayerType = ip.V4.NextLayerType()
		ip.SrcIP = ip.V4.SrcIP
		ip.DstIP = ip.V4.DstIP
		ip.IsAR = false
		ip.IsV6 = false
	case layers.LayerTypeIPv6:
		err = ip.V6.DecodeFromBytes(data,df)
		ip.BaseLayer = ip.V6.BaseLayer
		ip.NetworkFlow = ip.V6.NetworkFlow()
		ip.NextLayerType = ip.V6.NextLayerType()
		ip.SrcIP = ip.V6.SrcIP
		ip.DstIP = ip.V6.DstIP
		ip.IsAR = false
		ip.IsV6 = true
		if err == nil {
			err = ip.decodeES6(df)
		}
	case layers.LayerTypeARP:
		err = ip.AR4.DecodeFromBytes(data,df)
		ip.SrcIP = net.IP(ip.AR4.SourceProtAddress)
		ip.DstIP = net.IP(ip.AR4.DstProtAddress)
		ip.SrcMac = net.HardwareAddr(ip.AR4.SourceHwAddress)
		ip.DstMac = net.HardwareAddr(ip.AR4.DstHwAddress)
		ip.IsAR = true
		ip.IsV6 = false
	}
	return
}
func (ip *IPLayerPart) Flow() gopacket.Flow {
	return ip.NetworkFlow
}
func (ip *IPLayerPart) PayloadType() gopacket.LayerType {
	return ip.NextLayerType
}
func (ip *IPLayerPart) String() string {
	return fmt.Sprintf("%v->%v (%v)",ip.SrcIP,ip.DstIP,ip.NextLayerType)
}

func (ip *IPLayerPart) decodeES6(df gopacket.DecodeFeedback) (err error) {
	if !ip.ES6.CanDecode().Contains(ip.NextLayerType) { return }
	payload := ip.Payload
	ip.ES6.Payload = payload
	lng := 0
	for ip.ES6.CanDecode().Contains(ip.NextLayerType) {
		err = ip.ES6.DecodeFromBytes(ip.ES6.Payload,df)
		if err!=nil { return }
		lng += len(ip.ES6.Contents)
		ip.NextLayerType = ip.ES6.NextHeader.LayerType()
	}
	ip.ES6.Contents = payload[:lng]
	
	/* Swap Extension Payload and IPv6 Payload */
	ip.Payload = ip.ES6.Payload
	ip.ES6.Payload = payload
	return
}

