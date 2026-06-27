# ghidrename

Auto-rename default-named (`FUN_*`) Ghidra functions with a **free local LLM**, so you spend
expensive cloud-model tokens only on the functions the local model can't name confidently.

`ghidrename` drives two local HTTP services and runs entirely offline:

```
ghidrename ──HTTP──▶ GhidraMCP plugin (:8089)  ──▶ Ghidra   (decompile, callees, rename, comment)
          └──HTTP──▶ Ollama          (:11434)  ──▶ model    (propose a name)
```

It processes functions **callees-first** (topological order) and feeds each function's
already-named/imported callees into the prompt — a wrapper's purpose lives in what it calls,
so naming the leaves first lets their names light up the callers. High-confidence names are
applied; low-confidence ones are tagged `TODO(review)` for a human or a stronger model.

## Install

```sh
go install github.com/imkk000/ghidrename@latest
```

The binary lands in `$(go env GOBIN)` (or `$(go env GOPATH)/bin`) — put that on your `PATH`,
then call `ghidrename` from anywhere. No path arguments needed: it operates on whatever
program is currently open in Ghidra.

## Dependencies

`ghidrename` does not analyze binaries itself — it requires two services running locally.

### 1. Ghidra + GhidraMCP plugin

- [Ghidra](https://ghidra-sre.org/) with a program imported, analyzed, and **open in the
  CodeBrowser**.
- The **GhidraMCP** plugin enabled, exposing its HTTP API (default `127.0.0.1:8089`).
  Enable it via `File > Configure > Developer`. `ghidrename` talks to that HTTP server
  directly — the MCP bridge is not required.
- Verify it is reachable:
  ```sh
  curl -s http://127.0.0.1:8089/get_function_count
  ```
  A `{"function_count":...}` response means you are ready. `{"error":"No program loaded."}`
  means no program is open in the CodeBrowser.

The plugin enforces a naming policy: it rejects token-subset collisions and low-quality
names. `ghidrename` handles collisions by retrying with an address distinguisher
(`Name_<addr>`) and routes quality rejections to `TODO(review)`.

### 2. Ollama + a code model

- [Ollama](https://ollama.com/) running (default `http://localhost:11434`).
- A tool-capable code model. Default is `qwen2.5-coder:7b` (good schema-following and
  naming; runs in ~5 GB VRAM):
  ```sh
  ollama pull qwen2.5-coder:7b
  ```
  Larger models (`qwen2.5-coder:14b`, `:32b`) name better if you have the VRAM.

GPU note: install the CUDA/ROCm Ollama build (e.g. `ollama-cuda` on Arch) — the generic
package is CPU-only. Confirm GPU use with `ollama ps` (should show `100% GPU`).

## Usage

```sh
ghidrename                       # name every FUN_* in the open program
ghidrename program.exe           # same, asserting which program is open
ghidrename --max 30              # only the first 30 (good for a trial)
ghidrename --dry-run --max 30    # propose names, change nothing
ghidrename --model qwen2.5-coder:14b --threshold 0.75
ghidrename revert                # undo this tool's renames (from the journal)
```

Every applied rename is recorded in a journal (default `.ghidrename-journal.jsonl`), and
`ghidrename revert` restores the original `FUN_*` names from it.

### Options

| Flag          | Default                     | Purpose                            |
| ------------- | --------------------------- | ---------------------------------- |
| `--ghidra`    | `http://127.0.0.1:8089`     | GhidraMCP plugin URL               |
| `--ollama`    | `http://localhost:11434`    | Ollama URL                         |
| `--model`     | `qwen2.5-coder:7b`          | Ollama model                       |
| `--num-ctx`   | `8192`                      | model context window               |
| `--max`, `-n` | `0` (all)                   | max functions to process           |
| `--threshold` | `0.6`                       | minimum confidence to apply a name |
| `--dry-run`   | off                         | propose names without applying     |
| `--journal`   | `.ghidrename-journal.jsonl` | rename journal used by `revert`    |

## How it names well

The system prompt (`internal/namer/systemprompt.md`, embedded at build time) encodes the
rules that matter for decompiled code:

- **PascalCase**, verb-first for actions, noun form for accessors.
- **Ignore compiler boilerplate** — `__security_check_cookie`, `guard_check_icall`, stack
  cookies, `/* WARNING */` — which otherwise hijack names like `SecurityCheckAndExecute`.
- **Ban vague verbs** (`Process`/`Handle`/`Validate`) when a concrete operation is visible
  (`ParseVersionString`, not `ProcessString`).
- Score **confidence honestly**; wrappers and stubs stay low unless their callees make the
  purpose obvious.

## Development

```sh
task build      # go build -o bin/ghidrename .
task install    # go install .
task lint       # golangci-lint
task vuln       # govulncheck
task check      # lint + vuln
```

## Workflow

Run `ghidrename` for the bulk pass, then review the `TODO(review)` bookmarks/comments in
Ghidra for the functions it could not name confidently — those are the ones worth a human
or a stronger model. On a library-heavy binary, remember the low-address `FUN_*` are usually
CRT/runtime code; point the tool (or your attention) at the application's own call graph.
