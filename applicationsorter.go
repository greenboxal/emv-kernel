package main

import "github.com/greenboxal/emv-kernel/emv"

type ApplicationSorter []*emv.ApplicationInformation

func (s ApplicationSorter) Len() int {
	return len(s)
}

func (s ApplicationSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ApplicationSorter) Less(i, j int) bool {
	p1 := s[i].Priority & 0xF
	p2 := s[j].Priority & 0xF

	return p1 < p2
}
