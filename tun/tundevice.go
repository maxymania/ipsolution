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

/* A wrapper for the github.com/songgao/water library to fit in the gopacket terminology. */
package tun

import "github.com/songgao/water"
import "github.com/google/gopacket"
import "time"

type Interface struct{
	*water.Interface
	MTU uint
}

// Opens a new TAP device.
func New(ifName string) (i Interface, err error) {
	var w *water.Interface
	w,err = water.NewTAP(ifName)
	i = Interface{w,1500}
	return
}

func (i Interface) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	var n int
	data = make([]byte,i.MTU)
	n,err = i.Read(data)
	if n<0 { n = 0 } else if n>0 { err = nil }
	data = data[:n]
	ci.Timestamp = time.Now()
	ci.CaptureLength = n
	ci.Length = n
	ci.InterfaceIndex = 0
	return
}

func (i Interface) ReadPacketDataTo(data []byte) (ci gopacket.CaptureInfo, err error) {
	var n int
	n,err = i.Read(data)
	if n<0 { n = 0 } else if n>0 { err = nil }
	ci.Timestamp = time.Now()
	ci.CaptureLength = n
	ci.Length = n
	ci.InterfaceIndex = 0
	return
}

func (i Interface) WritePacketData(pkt []byte) (err error) {
	_,err = i.Write(pkt)
	return
}

