// Command ghidrename auto-renames default Ghidra functions with a local LLM.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/imkk000/ghidrename/internal/ghidra"
	"github.com/imkk000/ghidrename/internal/namer"
	"github.com/imkk000/ghidrename/internal/ollama"
	"github.com/urfave/cli/v3"
)

func main() {
	log.SetFlags(0)
	cmd := &cli.Command{
		Name:      "ghidrename",
		Usage:     "Auto-rename default Ghidra functions with a local LLM",
		ArgsUsage: "[program-name]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "ghidra", Value: "http://127.0.0.1:8089", Usage: "GhidraMCP plugin URL"},
			&cli.StringFlag{Name: "ollama", Value: "http://localhost:11434", Usage: "Ollama URL"},
			&cli.StringFlag{Name: "model", Value: "qwen2.5-coder:7b", Usage: "Ollama model"},
			&cli.IntFlag{Name: "num-ctx", Value: 8192, Usage: "model context window"},
			&cli.StringFlag{Name: "journal", Value: ".ghidrename-journal.jsonl", Usage: "rename journal for revert"},
			&cli.IntFlag{Name: "max", Aliases: []string{"n"}, Usage: "max functions to process (0 = all)"},
			&cli.FloatFlag{Name: "threshold", Value: 0.6, Usage: "minimum confidence to apply a name"},
			&cli.BoolFlag{Name: "dry-run", Usage: "propose names without applying them"},
		},
		Action: runAction,
		Commands: []*cli.Command{
			{
				Name:   "revert",
				Usage:  "restore names recorded in the journal",
				Action: revertAction,
			},
		},
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "ghidrename:", err)
		os.Exit(1)
	}
}

func clients(cmd *cli.Command) (*ghidra.Client, *ollama.Client) {
	root := cmd.Root()
	g := ghidra.New(root.String("ghidra"))
	o := ollama.New(root.String("ollama"), root.String("model"), root.Int("num-ctx"))
	return g, o
}

func runAction(ctx context.Context, cmd *cli.Command) error {
	g, o := clients(cmd)
	program, err := g.CurrentProgram()
	if err != nil {
		return err
	}
	if want := cmd.Args().First(); want != "" && want != program {
		return fmt.Errorf("open program is %q, not %q", program, want)
	}
	return namer.Run(ctx, namer.Options{
		Ghidra:    g,
		Ollama:    o,
		Program:   program,
		Max:       cmd.Int("max"),
		Threshold: cmd.Float("threshold"),
		DryRun:    cmd.Bool("dry-run"),
		Journal:   cmd.String("journal"),
	})
}

func revertAction(ctx context.Context, cmd *cli.Command) error {
	g, _ := clients(cmd)
	return namer.Revert(ctx, g, cmd.Root().String("journal"))
}
