package main

import (
	"net/netip"
)

type trieNode struct {
	child    [2]int
	terminal bool
}

type ipTrie struct {
	bits     int
	nodes    []trieNode
	prefixes int
}

func newIPTrie(bits int) *ipTrie {
	return &ipTrie{
		bits: bits,
		nodes: []trieNode{{
			child: [2]int{-1, -1},
		}},
	}
}

func (t *ipTrie) Count() int {
	if t == nil {
		return 0
	}
	return t.prefixes
}

func (t *ipTrie) Insert(p netip.Prefix) {
	if t == nil {
		return
	}

	addr := p.Masked().Addr()
	if addr.Is4() && t.bits != 32 {
		return
	}
	if addr.Is6() && t.bits != 128 {
		return
	}

	bits := p.Bits()
	if bits < 0 || bits > t.bits {
		return
	}

	raw := addr.AsSlice()
	if len(raw) == 0 {
		return
	}

	idx := 0
	for i := 0; i < bits; i++ {
		bit := bitAt(raw, i)
		next := t.nodes[idx].child[bit]
		if next == -1 {
			next = len(t.nodes)
			t.nodes[idx].child[bit] = next
			t.nodes = append(t.nodes, trieNode{child: [2]int{-1, -1}})
		}
		idx = next
	}

	if !t.nodes[idx].terminal {
		t.nodes[idx].terminal = true
		t.prefixes++
	}
}

func (t *ipTrie) Contains(addr netip.Addr) bool {
	if t == nil || len(t.nodes) == 0 || !addr.IsValid() {
		return false
	}
	if addr.Is4() && t.bits != 32 {
		return false
	}
	if addr.Is6() && t.bits != 128 {
		return false
	}

	raw := addr.AsSlice()
	if len(raw) == 0 {
		return false
	}

	idx := 0
	for i := 0; i < t.bits; i++ {
		if t.nodes[idx].terminal {
			return true
		}
		bit := bitAt(raw, i)
		next := t.nodes[idx].child[bit]
		if next == -1 {
			return false
		}
		idx = next
	}
	return t.nodes[idx].terminal
}

func bitAt(raw []byte, bitIndex int) int {
	byteIndex := bitIndex / 8
	if byteIndex >= len(raw) {
		return 0
	}
	shift := 7 - (bitIndex % 8)
	return int((raw[byteIndex] >> shift) & 1)
}

type ipSet struct {
	single4 map[[4]byte]struct{}
	single6 map[[16]byte]struct{}
	trie4   *ipTrie
	trie6   *ipTrie
}

func newIPSet() *ipSet {
	return &ipSet{
		single4: make(map[[4]byte]struct{}),
		single6: make(map[[16]byte]struct{}),
		trie4:   newIPTrie(32),
		trie6:   newIPTrie(128),
	}
}

func (s *ipSet) Insert(p netip.Prefix) {
	if s == nil {
		return
	}
	if p.IsSingleIP() {
		addr := p.Addr()
		if addr.Is4() {
			s.single4[addr.As4()] = struct{}{}
		} else {
			s.single6[addr.As16()] = struct{}{}
		}
	} else {
		if p.Addr().Is4() {
			s.trie4.Insert(p)
		} else {
			s.trie6.Insert(p)
		}
	}
}

func (s *ipSet) Contains(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	if addr.Is4() {
		if _, ok := s.single4[addr.As4()]; ok {
			return true
		}
		return s.trie4.Contains(addr)
	}
	if _, ok := s.single6[addr.As16()]; ok {
		return true
	}
	return s.trie6.Contains(addr)
}

func (s *ipSet) Count() int {
	if s == nil {
		return 0
	}
	return len(s.single4) + len(s.single6) + s.trie4.Count() + s.trie6.Count()
}
