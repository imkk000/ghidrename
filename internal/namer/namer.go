// Package namer orchestrates local-LLM-driven Ghidra function renaming.
package namer

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/imkk000/ghidrename/internal/ghidra"
	"github.com/imkk000/ghidrename/internal/ollama"
)

//go:embed systemprompt.md
var systemPrompt string

const (
	maxCodeChars = 6000
	maxCallees   = 25
)

type Options struct {
	Ghidra    *ghidra.Client
	Ollama    *ollama.Client
	Program   string
	Max       int
	Threshold float64
	DryRun    bool
	Journal   string
}

type journalEntry struct {
	Address string `json:"address"`
	OldName string `json:"oldName"`
	NewName string `json:"newName"`
}

type outcome int

const (
	outcomeFailed outcome = iota
	outcomeApplied
	outcomeEscalated
)

type runner struct {
	opts    Options
	cache   map[string][]ghidra.Function
	journal *os.File
}

var (
	invalidIdent = regexp.MustCompile(`[^A-Za-z0-9_]+`)
	repeatedUnd  = regexp.MustCompile(`_+`)
)

func Run(ctx context.Context, opts Options) error {
	targets, err := opts.Ghidra.ListDefaultFunctions()
	if err != nil {
		return fmt.Errorf("list functions: %w", err)
	}
	if opts.Max > 0 && len(targets) > opts.Max {
		targets = targets[:opts.Max]
	}

	r := &runner{opts: opts, cache: make(map[string][]ghidra.Function)}
	ordered := orderCalleesFirst(targets, opts.Ghidra, r.cache)
	log.Printf("ghidrename: %d functions in %s (callees-first)", len(ordered), opts.Program)

	if !opts.DryRun {
		if err := r.openJournal(opts.Journal); err != nil {
			return err
		}
		defer r.closeJournal()
	}
	r.sweep(ctx, ordered)
	return nil
}

func (r *runner) openJournal(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	r.journal = f
	return nil
}

func (r *runner) closeJournal() {
	if r.journal == nil {
		return
	}
	if err := r.journal.Close(); err != nil {
		log.Println("journal close:", err)
	}
}

func (r *runner) sweep(ctx context.Context, ordered []ghidra.Function) {
	var applied, escalated, failed int
	for _, fn := range ordered {
		switch r.process(ctx, fn) {
		case outcomeApplied:
			applied++
		case outcomeEscalated:
			escalated++
		default:
			failed++
		}
	}
	log.Printf("ghidrename: applied=%d escalated=%d failed=%d", applied, escalated, failed)
}

func (r *runner) process(ctx context.Context, fn ghidra.Function) outcome {
	code, err := r.opts.Ghidra.Decompile(fn.Address)
	if err != nil || strings.TrimSpace(code) == "" {
		return outcomeFailed
	}
	res, err := r.opts.Ollama.Name(ctx, systemPrompt, buildPrompt(code, calleeContext(fn.Address, r.cache)))
	if err != nil {
		log.Printf("  %s ollama error: %v", fn.Address, err)
		return outcomeFailed
	}
	name := sanitize(res.Name)
	if name == "" {
		return outcomeFailed
	}
	if res.Confidence < r.opts.Threshold {
		log.Printf("  ESCALATE %s ~ %s (%.2f)", fn.Address, name, res.Confidence)
		if !r.opts.DryRun {
			note(r.opts.Ghidra, fn.Address, fmt.Sprintf("TODO(review): low-conf %q (%.2f) %s", name, res.Confidence, res.Summary))
		}
		return outcomeEscalated
	}
	if r.opts.DryRun {
		log.Printf("  DRY %s -> %s (%.2f)", fn.Address, name, res.Confidence)
		return outcomeApplied
	}
	return r.apply(fn, name, res)
}

func (r *runner) apply(fn ghidra.Function, name string, res ollama.Result) outcome {
	err := r.opts.Ghidra.Rename(fn.Address, name)
	if err != nil && strings.Contains(err.Error(), "collision") {
		name += "_" + strings.TrimLeft(fn.Address, "0")
		err = r.opts.Ghidra.Rename(fn.Address, name)
	}
	if err != nil {
		log.Printf("  REJECT %s ~ %s (%v)", fn.Address, name, err)
		note(r.opts.Ghidra, fn.Address, fmt.Sprintf("TODO(review): %q rejected (%v) %s", name, err, res.Summary))
		return outcomeEscalated
	}
	note(r.opts.Ghidra, fn.Address, fmt.Sprintf("auto-named (%.2f): %s", res.Confidence, res.Summary))
	writeJournal(r.journal, journalEntry{Address: fn.Address, OldName: fn.Name, NewName: name})
	log.Printf("  %s -> %s (%.2f)", fn.Address, name, res.Confidence)
	return outcomeApplied
}

func Revert(_ context.Context, g *ghidra.Client, journalPath string) error {
	data, err := os.ReadFile(journalPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	var reverted, failed int
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e journalEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if rerr := g.Rename(e.Address, e.OldName); rerr != nil {
			failed++
			continue
		}
		note(g, e.Address, "")
		reverted++
		log.Printf("  %s -> %s", e.Address, e.OldName)
	}
	log.Printf("ghidrename: reverted=%d failed=%d", reverted, failed)
	return nil
}

func buildPrompt(code, callees string) string {
	if len(code) > maxCodeChars {
		code = code[:maxCodeChars]
	}
	if callees != "" {
		return fmt.Sprintf("Name this function.\n\n%s\n```c\n%s\n```", callees, code)
	}
	return fmt.Sprintf("Name this function.\n\n```c\n%s\n```", code)
}

func calleeContext(addr string, cache map[string][]ghidra.Function) string {
	seen := make(map[string]struct{})
	names := make([]string, 0, maxCallees)
	for _, c := range cache[addr] {
		if !informative(c.Name) {
			continue
		}
		if _, ok := seen[c.Name]; ok {
			continue
		}
		seen[c.Name] = struct{}{}
		names = append(names, c.Name)
		if len(names) >= maxCallees {
			break
		}
	}
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Known callees (already named / imported APIs):\n")
	for _, n := range names {
		b.WriteString("- ")
		b.WriteString(n)
		b.WriteByte('\n')
	}
	return b.String()
}

func informative(name string) bool {
	return name != "" && !strings.HasPrefix(name, "FUN_") && !strings.HasPrefix(name, "thunk_FUN_")
}

func sanitize(name string) string {
	name = strings.TrimSpace(name)
	name = invalidIdent.ReplaceAllString(name, "_")
	name = repeatedUnd.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		name = "Fn" + name
	}
	return name
}

func note(g *ghidra.Client, addr, text string) {
	if err := g.SetPlateComment(addr, text); err != nil {
		log.Printf("comment %s: %v", addr, err)
	}
}

func writeJournal(f *os.File, e journalEntry) {
	if f == nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, werr := f.Write(append(data, '\n')); werr != nil {
		log.Println("journal write:", werr)
	}
}
