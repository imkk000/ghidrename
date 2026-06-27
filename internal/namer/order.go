package namer

import "github.com/imkk000/ghidrename/internal/ghidra"

func orderCalleesFirst(targets []ghidra.Function, g *ghidra.Client, cache map[string][]ghidra.Function) []ghidra.Function {
	byAddr := make(map[string]ghidra.Function, len(targets))
	for _, t := range targets {
		byAddr[t.Address] = t
	}
	visited := make(map[string]struct{})
	onStack := make(map[string]struct{})
	var order []ghidra.Function

	var visit func(addr string)
	visit = func(addr string) {
		if _, ok := visited[addr]; ok {
			return
		}
		if _, ok := onStack[addr]; ok {
			return
		}
		onStack[addr] = struct{}{}
		for _, c := range targetCallees(addr, byAddr, g, cache) {
			visit(c.Address)
		}
		delete(onStack, addr)
		visited[addr] = struct{}{}
		order = append(order, byAddr[addr])
	}
	for _, t := range targets {
		visit(t.Address)
	}
	return order
}

func targetCallees(addr string, byAddr map[string]ghidra.Function, g *ghidra.Client, cache map[string][]ghidra.Function) []ghidra.Function {
	callees, ok := cache[addr]
	if !ok {
		fetched, err := g.Callees(addr)
		if err != nil {
			fetched = nil
		}
		callees = fetched
		cache[addr] = callees
	}
	var out []ghidra.Function
	for _, c := range callees {
		if _, ok := byAddr[c.Address]; ok {
			out = append(out, c)
		}
	}
	return out
}
