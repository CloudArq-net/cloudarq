// Command native renders the engine's answers with the native toolchain,
// so that the differential in web/engine/diff.mjs can compare the
// WebAssembly build against it byte for byte.
//
//	native admits <policy.json>
//	native explain <policy.json> <token.json>
//	native findings <bundle.json> <owners.txt> <engine>
//
// The answer is written to standard output exactly as the WebAssembly
// module returns it: no trailing newline, because the comparison is bytes.
package main

import (
	"fmt"
	"os"

	"github.com/CloudArq-net/cloudarq/internal/report"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "native:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: native admits <policy> | native explain <policy> <token> | native findings <bundle> <owners> <engine>")
	}
	policy, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "admits":
		_, err = os.Stdout.Write(report.Admits(policy))
		return err
	case "explain":
		if len(args) < 3 {
			return fmt.Errorf("explain needs a token file")
		}
		token, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(report.Explain(policy, token))
		return err
	case "findings":
		if len(args) < 4 {
			return fmt.Errorf("findings needs an owners file and the engine's name")
		}
		owners, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(report.Findings(policy, owners, args[3]))
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}
