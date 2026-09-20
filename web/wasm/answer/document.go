package answer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
)

// layout is where the things a grant refers to are written: each
// statement's bytes in the parser's order, and inside each statement the
// Principal's string leaves and every condition key under its operator, each
// with the line it sits on. The parser keeps a statement's bytes but not
// their offset, and keeps no location for a principal or a condition key at
// all, so the answer reads the document a second time, with the same
// decoder, for positions only: nothing here decides what a policy means.
type layout struct {
	newlines   []int
	statements []statementLayout
}

type statementLayout struct {
	start, end    int // the statement's bytes, [start, end)
	principalLine int // 0 when the statement writes no Principal member
	leaves        []leaf
	keys          []conditionKey
}

// leaf is one string under Principal: the member it sits under, "" for a
// bare "*", its text and its line.
type leaf struct {
	member string
	text   string
	line   int
}

// conditionKey is one key under one operator block of Condition.
type conditionKey struct {
	operator, key string
	line          int
}

// layoutOf locates every statement the parser read, and what the grants
// refer to inside each. The statements found are checked against the
// parser's own bytes, so a disagreement between the two readings is an
// error, never a wrong quotation.
func layoutOf(raw []byte, d aws.Document) (layout, error) {
	root, err := read(raw)
	if err != nil {
		return layout{}, fmt.Errorf("locate the statements: %w", err)
	}
	lay := layout{newlines: newlinesIn(raw)}
	nodes := statementNodes(root)
	if len(nodes) != len(d.Statements) {
		return layout{}, fmt.Errorf("locate the statements: the document writes %d and the parser read %d", len(nodes), len(d.Statements))
	}
	for i, n := range nodes {
		if !bytes.Equal(raw[n.start:n.end], d.Statements[i].Raw) {
			return layout{}, fmt.Errorf("locate the statements: statement[%d] as located differs from the bytes the parser read", i)
		}
		lay.statements = append(lay.statements, lay.statementLayout(n))
	}
	return lay, nil
}

// statementNodes lists the values the parser reads as statements, in the
// parser's order. The parser groups the document's members by name in order
// of first appearance and reads the groups in that order: every value of a
// Statement member is a statement, an array standing for its items, and a
// scalar standing for one statement that cannot be read; every value of a
// member the grammar does not define, a misspelt Statement among them, is
// one such statement too. Version and Id are the only members that project
// nothing. Nothing here decides what a value means: the parser has already
// declared what it could not read, and the page is owed the bytes to quote.
func statementNodes(root *node) []*node {
	var names []string
	groups := map[string][]*node{}
	for _, m := range root.members {
		if _, seen := groups[m.name]; !seen {
			names = append(names, m.name)
		}
		groups[m.name] = append(groups[m.name], m.value)
	}
	var nodes []*node
	for _, name := range names {
		switch name {
		case "Version", "Id":
		case "Statement":
			for _, v := range groups[name] {
				if v.kind == kindArray {
					nodes = append(nodes, v.items...)
				} else {
					nodes = append(nodes, v)
				}
			}
		default:
			nodes = append(nodes, groups[name]...)
		}
	}
	return nodes
}

func (l layout) statementLayout(n *node) statementLayout {
	s := statementLayout{start: n.start, end: n.end}
	for _, m := range n.members {
		switch m.name {
		case "Principal":
			if s.principalLine == 0 {
				s.principalLine = l.line(m.start)
			}
			s.leaves = append(s.leaves, l.leavesOf(m.value)...)
		case "Condition":
			for _, op := range m.value.members {
				for _, key := range op.value.members {
					s.keys = append(s.keys, conditionKey{op.name, key.name, l.line(key.start)})
				}
			}
		}
	}
	return s
}

// leavesOf lists the strings a Principal value holds: the value itself when
// it is "*", or every string under each principal kind.
func (l layout) leavesOf(v *node) []leaf {
	if v.kind == kindString {
		return []leaf{{"", v.text, l.line(v.start)}}
	}
	var out []leaf
	for _, m := range v.members {
		for _, item := range m.value.strings() {
			out = append(out, leaf{m.name, item.text, l.line(item.start)})
		}
	}
	return out
}

// line is the 1-based line an offset sits on.
func (l layout) line(offset int) int {
	return sort.SearchInts(l.newlines, offset) + 1
}

// lines is how many lines the document has, counted the way the page lists
// them: one per newline, plus an unterminated last line.
func lines(raw []byte) int {
	n := bytes.Count(raw, []byte("\n"))
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		n++
	}
	return n
}

func newlinesIn(raw []byte) []int {
	var at []int
	for i, b := range raw {
		if b == '\n' {
			at = append(at, i)
		}
	}
	return at
}

// node is one value of the document as written: its bytes' span and what
// the layout needs of its contents. Objects keep every member in document
// order, duplicates included, because the parser reads them that way and a
// key the parser evaluated must be found here whichever copy it was.
type node struct {
	kind       kind
	start, end int
	text       string // a string's decoded text
	members    []member
	items      []*node
}

type member struct {
	name  string
	start int // where the name is written
	value *node
}

type kind int

const (
	kindScalar kind = iota
	kindString
	kindArray
	kindObject
)

// strings lists the string leaves of a value that is a string or a list.
func (n *node) strings() []*node {
	if n.kind == kindString {
		return []*node{n}
	}
	var out []*node
	for _, item := range n.items {
		if item.kind == kindString {
			out = append(out, item)
		}
	}
	return out
}

// reader walks the token stream and recovers each token's byte range, the
// way the parser's own reader does: the decoder reports where a token ends,
// and the first byte after the previous token that is not whitespace, ':'
// or ',' is where the next one begins.
type reader struct {
	dec *json.Decoder
	raw []byte
}

func read(raw []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return (&reader{dec, raw}).value()
}

func (r *reader) next() (tok json.Token, start, end int, err error) {
	start = int(r.dec.InputOffset())
	tok, err = r.dec.Token()
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, 0, 0, err
	}
	end = int(r.dec.InputOffset())
	for start < end && strings.IndexByte(" \t\n\r:,", r.raw[start]) >= 0 {
		start++
	}
	return tok, start, end, nil
}

func (r *reader) value() (*node, error) {
	tok, start, end, err := r.next()
	if err != nil {
		return nil, err
	}
	return r.valueOf(tok, start, end)
}

func (r *reader) valueOf(tok json.Token, start, end int) (*node, error) {
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			return r.object(start)
		}
		return r.array(start)
	case string:
		return &node{kind: kindString, start: start, end: end, text: t}, nil
	}
	return &node{kind: kindScalar, start: start, end: end}, nil
}

func (r *reader) object(start int) (*node, error) {
	n := &node{kind: kindObject, start: start}
	for {
		tok, nameStart, end, err := r.next()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim('}') {
			n.end = end
			return n, nil
		}
		v, err := r.value()
		if err != nil {
			return nil, err
		}
		// A key is always a string in a stream the decoder accepts.
		n.members = append(n.members, member{tok.(string), nameStart, v})
	}
}

func (r *reader) array(start int) (*node, error) {
	n := &node{kind: kindArray, start: start}
	for {
		tok, itemStart, end, err := r.next()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim(']') {
			n.end = end
			return n, nil
		}
		item, err := r.valueOf(tok, itemStart, end)
		if err != nil {
			return nil, err
		}
		n.items = append(n.items, item)
	}
}
