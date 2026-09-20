// Command native renders the explorer's answers with the native toolchain,
// so that the differential in web/diff.mjs can compare the WebAssembly
// build against it byte for byte.
//
//	native admits <policy.json>
//	native explain <policy.json> <token.json>
//
// The answer is written to standard output exactly as the page receives
// it: no trailing newline, because the comparison is bytes.
package main

import (
	"fmt"
	"os"

	"github.com/CloudArq-net/cloudarq/web/wasm/answer"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "native:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: native admits <policy> | native explain <policy> <token>")
	}
	policy, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "admits":
		_, err = os.Stdout.Write(answer.Admits(policy))
		return err
	case "explain":
		if len(args) < 3 {
			return fmt.Errorf("explain needs a token file")
		}
		token, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(answer.Explain(policy, token))
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}
