// Command cloudarq turns a cloud trust policy into the list of who it
// admits.
//
// It answers one question, offline: it reads the document it is given,
// consults NO_COLOR, writes to standard output and standard error, and
// opens no network connection. Every word of every answer comes from
// internal/report, which is also what the WebAssembly engine returns, so
// that the two cannot say different things about the same document.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// The exit codes, which are a documented part of the surface: a script
// that reads them must keep working across releases.
const (
	// exitAnswered is the answer, whatever the answer. A policy that admits
	// everyone exits 0: the code says whether the question was answered,
	// never what the answer was. A non-zero exit on a wide-open policy
	// would be the command ranking what it read, which is the one thing it
	// does not do.
	exitAnswered = 0
	// exitUnread is an input the engine could not read: the document, or
	// the token given to --token. The answer still goes to standard output.
	exitUnread = 1
	// exitUsage is a command line this version does not understand, an
	// --owner the engine does not read as an owner included.
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
		fmt.Fprintln(stdout, "cloudarq", version())
		return exitAnswered
	}
	fmt.Fprintf(stderr, "cloudarq: %+q is not a command.\n", args[0])
	usage(stderr)
	return exitUsage
}

// version is the module version Go recorded in this binary: the tag for
// `go install …@v0.1.0`, the pseudo-version of the commit for a build inside
// a git checkout.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return versionOf("")
	}
	return versionOf(info.Main.Version)
}

// versionOf is a recorded module version as the command prints it: without
// its leading v, and 0.0.0-dev when Go recorded none, which a build outside
// a module download and outside a git checkout records as "(devel)".
func versionOf(recorded string) string {
	if recorded == "" || recorded == "(devel)" {
		return "0.0.0-dev"
	}
	return strings.TrimPrefix(recorded, "v")
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
       cloudarq admits --bundle <file|-> [--owner <o>]... [--json]
       cloudarq version

admits reads an AWS trust policy and prints who it admits: the rings of
distance each grant lands in, from anyone at all to your own people, what
could narrow them that was not read, and then one paragraph per grant, with
the claims it names, the notes the engine recorded, a token the grant
admits, and where in the document the statement is written. No other
dialect is read. "-" reads standard input.

  --json         print the answer as the versioned JSON schema instead
  --owner <o>    declare an owner as yours, as github:acme, github:@123456,
                 aws:111122223333, saml:<provider ARN> or issuer:<issuer
                 URL>; repeat it for each. An owner nobody declared is a
                 named outsider, and one the engine does not read is
                 refused with exit code 2
  --token <t>    read a token, decoded payload or whole, and print for each
                 grant whether it is admitted and why
  --explain      print on standard error what the command reads and calls
                 before it answers, and after it, when a ring's place rests
                 on the engine's reading of AWS's documentation, the
                 sentences it read
  --no-color     never mark the output; NO_COLOR in the environment does
                 the same, and a pipe is never marked
  --bundle <f>   read a bundle cloudarq-collect wrote and answer every role
                 in it, each as admits answers its trust policy alone; with
                 --json, print them as findings, cloudarq.findings/v1

exit codes:
  0  the question was answered, whatever the answer
  1  an input was not read: the file could not be opened, the document or
     the token was not what it claimed to be, or the owners declared were
     past what the engine reads. The reason goes to standard error, and the
     answer to standard output whenever the engine was given bytes at all
  2  this command line was not understood, an --owner the engine does not
     read as an owner included: the flag and the reason go to standard
     error, and no answer is written
`)
}
