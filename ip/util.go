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

import "encoding/binary"
import "net"

type Key4 uint32
func (k Key4) IP() net.IP {
	f := make([]byte,4)
	binary.BigEndian.PutUint32(f,uint32(k))
	return net.IP(f)
}
func (k *Key4) Decode(i net.IP) {
	*k = Key4(binary.BigEndian.Uint32([]byte(i)))
}

type Key6 struct{
	Hi,Lo uint64
}
func (k Key6) IP() net.IP {
	f := make([]byte,16)
	binary.BigEndian.PutUint64(f,k.Hi)
	binary.BigEndian.PutUint64(f[8:],k.Lo)
	return net.IP(f)
}
func (k *Key6) Decode(i net.IP) {
	k.Hi = binary.BigEndian.Uint64([]byte(i))
	k.Lo = binary.BigEndian.Uint64([]byte(i)[8:])
}
func (k Key6) Equals(o Key6) bool{
	return (k.Hi==o.Hi) && (k.Lo==o.Lo)
}

// Longest Prefix Match
func LongestPrefixV6(a,b, pivot net.IP) int {
	C := binary.BigEndian.Uint64([]byte(pivot))
	A := binary.BigEndian.Uint64([]byte(a))^C
	B := binary.BigEndian.Uint64([]byte(b))^C
	if (A==0) && (B==0) {
		C = binary.BigEndian.Uint64([]byte(pivot)[8:])
		A = binary.BigEndian.Uint64([]byte(a)[8:])^C
		B = binary.BigEndian.Uint64([]byte(b)[8:])^C
	}
	return leadzeroCmp(A,B)
}

/*
a==b =  0
a<b  = -1
a>b  =  1
*/
func leadzeroCmp(a,b uint64) int {
	// 0xffffffff00000000
	// 0xffff000000000000
	// 0xff00000000000000
	// 0xf000000000000000
	// 0xc000000000000000
	// 0x8000000000000000
	c := a|b
	//d = a&c
	if (c&0xffffffff00000000) == 0 {
		a<<=32
		b<<=32
		c<<=32
	}
	if (c&0xffff000000000000) == 0 {
		a<<=16
		b<<=16
		c<<=16
	}
	if (c&0xff00000000000000) == 0 {
		a<<=8
		b<<=8
		c<<=8
	}
	if (c&0xf000000000000000) == 0 {
		a<<=4
		b<<=4
		c<<=4
	}
	if (c&0xc000000000000000) == 0 {
		a<<=2
		b<<=2
		c<<=2
	}
	if (c&0x8000000000000000) == 0 {
		a<<=1
		b<<=1
		c<<=1
	}
	if (a&0x8000000000000000) == 0 { return -1 } /* a<b */
	if (b&0x8000000000000000) == 0 { return  1 } /* a>b */
	return 0
}


