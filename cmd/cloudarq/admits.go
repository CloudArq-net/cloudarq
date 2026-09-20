package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/CloudArq-net/cloudarq/internal/report"
)

// admits is the flagship subcommand: `cloudarq admits policy.json`. It
// reads the document, hands it to the report and writes what comes back.
// It decides three things and nothing else — whether to mark the output,
// which rendering to write, and the exit code — because every word of the
// answer is the report's (docs/ENGINEERING.md section 1).
func admits(args []string, stdin io.Reader, stdout, stderr io.Writer, isTerminal bool) int {
	flags := flag.NewFlagSet("admits", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr) }
	asJSON := flags.Bool("json", false, "print the answer as the versioned JSON schema")
	token := flags.String("token", "", "a token, as a decoded payload or whole")
	explain := flags.Bool("explain", false, "print what the command reads and calls, on standard error")
	noColour := flags.Bool("no-color", false, "never mark the output")
	// --offline is accepted and changes nothing: it is the only mode there
	// is, and a script written today keeps working the day there is another.
	flags.Bool("offline", false, "make no network request; the only mode there is")

	paths, err := parse(flags, args)
	if err != nil {
		// The usage is not printed here: flag.ContinueOnError prints the
		// reason and then calls Usage itself, for a flag it does not know
		// and for -h alike, and a second block reads as a second failure.
		return exitUsage
	}
	if len(paths) != 1 {
		fmt.Fprintf(stderr, "cloudarq admits: one document, given as a path or as \"-\"; %d were given.\n", len(paths))
		usage(stderr)
		return exitUsage
	}
	if *explain {
		plan(stderr, paths[0], *token)
	}
	document, err := read(paths[0], stdin)
	if err != nil {
		fmt.Fprintln(stderr, "cloudarq admits:", err)
		return exitUnread
	}

	// NO_COLOR is honoured when it is set to anything but the empty string,
	// which is what no-color.org specifies; it is the only variable this
	// command reads, and a pipe is never marked whatever it says.
	options := report.Options{Colour: isTerminal && !*noColour && os.Getenv("NO_COLOR") == ""}

	if *token != "" {
		explanation := report.ExplanationOf(document, []byte(*token))
		write(stdout, explanation.JSON(), explanation.Text(options), *asJSON)
		return refusal(stderr, explanation.Error, explanation.Token.Error)
	}
	answer := report.AnswerOf(document)
	write(stdout, answer.JSON(), answer.Text(options), *asJSON)
	return refusal(stderr, answer.Error)
}

// parse reads the flags wherever they appear, so that `admits f --json`
// and `admits --json f` are the same command. The standard flag package
// stops at the first argument that is not a flag, so what follows it is
// parsed again.
func parse(flags *flag.FlagSet, args []string) ([]string, error) {
	var paths []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		rest := flags.Args()
		if len(rest) == 0 {
			return paths, nil
		}
		paths, args = append(paths, rest[0]), rest[1:]
	}
}

// read takes the document as bytes and changes nothing about them: the
// offsets, the line numbers and the digests in the answer are into these
// exact bytes, so a trimmed newline or a re-encoding would make every one
// of them wrong.
func read(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

// write puts the answer on standard output in the rendering that was
// asked for. The JSON is the engine's own bytes with one newline after
// them — the file a pipeline stores is the schema and nothing else —
// except for the characters a terminal would act on, which this command
// is the first surface to put in front of one.
//
// A failed write is deliberately not turned into an exit code here. The
// three codes are a documented part of the surface and none of them means
// "the answer could not be written"; the common failure is the reader
// closing the pipe, as `cloudarq admits p | head` does, which is not an
// error in what this command was asked. Whether a fourth code should exist
// for a write that fails for any other reason is a change to that surface
// and belongs to whoever owns it.
func write(stdout io.Writer, asJSON []byte, asText string, wantJSON bool) {
	if wantJSON {
		stdout.Write(append(inertOnATerminal(asJSON), '\n'))
		return
	}
	io.WriteString(stdout, asText)
}

// inertOnATerminal escapes the characters a terminal acts on that the
// schema leaves as it finds them. The answer's JSON is what encoding/json
// writes, which escapes the C0 range and passes the C1 range through;
// U+009B is the 8-bit control sequence introducer and does to a line what
// ESC [ does, and a Sid or a claim value is the customer's bytes. They
// cannot be dropped the way the text rendering drops them — the JSON
// carries the document's values, and a value silently shortened is a wrong
// value — so each becomes the \u00XX escape that denotes it. The answer is
// the same answer and the same schema; an answer carrying none of them is
// written byte for byte as the engine composed it.
func inertOnATerminal(b []byte) []byte {
	if !bytes.ContainsFunc(b, actedOnByATerminal) {
		return b
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)+8)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if actedOnByATerminal(r) {
			out = append(out, '\\', 'u', '0', '0', hex[r>>4], hex[r&0xf])
		} else {
			out = append(out, b[i:i+size]...)
		}
		i += size
	}
	return out
}

// actedOnByATerminal is DEL and the C1 range, which is the range the
// encoder passes through: the C0 range below it is already escaped, as
// encoding/json escapes it, and the schema is defined as those bytes.
func actedOnByATerminal(r rune) bool { return r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// refusal is the exit code, and the reason on standard error when there is
// one. The engine is total: what it could not read is stated in the answer
// rather than returned as an error, so the answer on standard output is
// complete either way and this only repeats the sentence for a reader who
// is piping the answer somewhere else.
func refusal(stderr io.Writer, reasons ...string) int {
	for _, reason := range reasons {
		if reason != "" {
			fmt.Fprintln(stderr, reason)
			return exitUnread
		}
	}
	return exitAnswered
}

// plan is what --explain prints before the command answers: docs/
// ENGINEERING.md section 9 asks for every API call to be printed before it
// is made, and the answer is that there are none. It goes to standard
// error so that standard output stays the answer.
func plan(stderr io.Writer, path, token string) {
	fmt.Fprintln(stderr, "cloudarq admits, before it answers:")
	if path == "-" {
		fmt.Fprintln(stderr, "  reads the document from standard input, and no file")
	} else {
		fmt.Fprintf(stderr, "  reads %s, and no other file\n", path)
	}
	if token != "" {
		fmt.Fprintln(stderr, "  reads the token from the command line, and no file")
	}
	fmt.Fprintln(stderr, "  consults NO_COLOR, and no other environment variable")
	fmt.Fprintln(stderr, "  makes no network request and no API call: the answer is computed here")
	fmt.Fprintln(stderr, "  writes the answer to standard output and nothing to any file")
}
