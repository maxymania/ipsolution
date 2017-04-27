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



package eth


import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "fmt"

/*
Ethernet Layer + VLAN extension.
*/
type EthLayer2 struct{
	layers.Ethernet
	VLANIdentifier uint16
	vlan layers.Dot1Q
	
}
func (e *EthLayer2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (err error) {
	err = e.Ethernet.DecodeFromBytes(data,df)
	if err!=nil { return }
	if e.EthernetType == layers.EthernetTypeDot1Q {
		err = e.vlan.DecodeFromBytes(e.Payload,df)
		e.Payload = e.vlan.Payload
		e.EthernetType = e.vlan.Type
		e.VLANIdentifier = e.vlan.VLANIdentifier
	}
	return
}
func (e *EthLayer2) String() string {
	return fmt.Sprintf("%v->%v (%v)",e.SrcMAC,e.DstMAC,e.EthernetType)
}

