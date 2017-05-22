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

import "container/list"
import "sync"

/* -------------------------Data-Structure-Part--------------------------- */

type List struct{
	self list.List
	mutex sync.Mutex
	Value interface{} /* Should point to the object holding this List */
}
type Member struct{
	parent *List
	self *list.Element
	Value interface{}
}
func (l *List) Len() int { return l.self.Len() }
func (l *List) Init() *List{
	l.self.Init()
	return l
}
func (l *List) PushBack(m *Member) bool {
	l.mutex.Lock(); defer l.mutex.Unlock()
	if m.parent!=nil { return false }
	m.parent = l
	m.self = l.self.PushBack(m)
	return true
}
func (l *List) PushFront(m *Member) bool {
	l.mutex.Lock(); defer l.mutex.Unlock()
	if m.parent!=nil { return false }
	m.parent = l
	m.self = l.self.PushFront(m)
	return true
}
func (l *List) Back() *Member{
	l.mutex.Lock(); defer l.mutex.Unlock()
	e := l.self.Back()
	if e==nil { return nil }
	return e.Value.(*Member)
}
func (l *List) Front() *Member{
	l.mutex.Lock(); defer l.mutex.Unlock()
	e := l.self.Front()
	if e==nil { return nil }
	return e.Value.(*Member)
}
func (l *List) MoveFrontToBack() *Member{
	l.mutex.Lock(); defer l.mutex.Unlock()
	e := l.self.Front()
	if e==nil { return nil }
	l.self.MoveToBack(e)
	return e.Value.(*Member)
}
func (l *List) Copy() []interface{} {
	l.mutex.Lock(); defer l.mutex.Unlock()
	arr := make([]interface{},0,l.self.Len())
	for e := l.self.Front(); e!=nil; e = e.Next() {
		arr = append(arr,e.Value)
	}
	return arr
}
func (l *List) CopyRaw(ol *list.List) {
	l.mutex.Lock(); defer l.mutex.Unlock()
	ol.PushBackList(&l.self)
}


func (m *Member) Container() *List { return m.parent }
func (m *Member) Parent() interface{} {
	p := m.parent
	if p==nil { return nil }
	return p.Value
}

func (m *Member) Remove() {
	p := m.parent
	if p==nil { return }
	p.mutex.Lock(); defer p.mutex.Unlock()
	
	/* Check, wether parent changed in the meantime. */
	if m.parent!=p { return }
	
	/* Check for null-pointers */
	if m.self==nil { return }
	
	p.self.Remove(m.self)
}
func (m *Member) MoveToBack() {
	p := m.parent
	if p==nil { return }
	p.mutex.Lock(); defer p.mutex.Unlock()
	
	/* Check, wether parent changed in the meantime. */
	if m.parent!=p { return }
	
	/* Check for null-pointers */
	if m.self==nil { return }
	
	p.self.MoveToBack(m.self)
}
func (m *Member) MoveToFront() {
	p := m.parent
	if p==nil { return }
	p.mutex.Lock(); defer p.mutex.Unlock()
	
	/* Check, wether parent changed in the meantime. */
	if m.parent!=p { return }
	
	/* Check for null-pointers */
	if m.self==nil { return }
	
	p.self.MoveToFront(m.self)
}
func (m *Member) Swap(other *Member) {
	p := m.parent
	if p==nil { return }
	p.mutex.Lock(); defer p.mutex.Unlock()
	
	/* Perform checks... */
	if m.parent!=p { return }
	if other.parent!=p { return }
	
	/* Perform null-pointer-checks... */
	if m.self==nil { return }
	if other.self==nil { return }
	
	m.self.Value = other
	other.self.Value = m
	
	m.self,other.self = other.self,m.self	
}


