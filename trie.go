package main

import (
	"net/netip"
)

type trieNode struct {
	child    [2]int
	terminal bool
}

// ipTrie is a simple binary trie for CIDR containment checks.
// It keeps separate instances for IPv4 (32 bits) and IPv6 (128 bits).
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
	for i := range bits {
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
