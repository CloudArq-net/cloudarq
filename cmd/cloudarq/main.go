// Command cloudarq turns a cloud trust policy into the list of who it
// admits.
//
// It answers one question, offline: it reads the document it is given,
// consults NO_COLOR, writes to standard output and standard error, and
// opens no network connection. Every word of every answer comes from
// internal/report, which is also what the explorer prints, so that the two
// surfaces cannot say different things about the same document.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is what `cloudarq version` prints; the release build sets it.
var version = "0.0.0-dev"

// The exit codes, which are a documented part of the surface: a script
// that reads them must keep working across releases.
const (
	// exitAnswered is the answer, whatever the answer. A policy that admits
	// everyone exits 0: the code says whether the question was answered,
	// never what the answer was. A non-zero exit on a wide-open policy
	// would be the command ranking what it read, which is the one thing it
	// does not do (product/CONSTITUTION.md section 3, prohibition 13).
	exitAnswered = 0
	// exitUnread is an input the engine could not read: the document, or
	// the token given to --token. The answer still goes to standard output.
	exitUnread = 1
	// exitUsage is a command line this version does not understand.
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, terminal(os.Stdout)))
}

// run is the whole command behind one seam, so that the tests can hand it
// the streams and the one thing it may not ask a pipe: whether the reader
// is a terminal.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, isTerminal bool) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "admits":
		return admits(args[1:], stdin, stdout, stderr, isTerminal)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "cloudarq", version)
		return exitAnswered
	}
	fmt.Fprintf(stderr, "cloudarq: %q is not a command.\n", args[0])
	usage(stderr)
	return exitUsage
}

// terminal reports whether the answer is going to a terminal, which is the
// only fact about the environment that changes what is written.
func terminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// usage is the whole surface, including the exit codes: a code a script
// reads is part of the contract and belongs where the contract is written.
func usage(w io.Writer) {
	fmt.Fprint(w, `usage: cloudarq admits <file|-> [flags]
       cloudarq version

admits reads an AWS trust policy and prints who it admits: one paragraph
per grant, with the claims it names, the notes the engine recorded, a token
the grant admits, and where in the document the statement is written. No
other dialect is read yet. "-" reads standard input.

  --json         print the answer as the versioned JSON schema instead
  --token <t>    read a token, decoded payload or whole, and print for each
                 grant whether it is admitted and why
  --explain      print on standard error what the command reads and calls
                 before it answers
  --offline      make no network request; the only mode there is
  --no-color     never mark the output; NO_COLOR in the environment does
                 the same, and a pipe is never marked

exit codes:
  0  the question was answered, whatever the answer
  1  an input was not read: the file could not be opened, or the document
     or the token was not what it claimed to be. The reason goes to
     standard error, and the answer to standard output whenever the engine
     was given bytes at all
  2  this command line was not understood
`)
}
