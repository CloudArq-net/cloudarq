package report

// This file is kept twice, as internal/report/caller.go for the engine and
// internal/collect/aws/caller.go for the collector, the same bytes below the
// package clause: the collector takes the person out of what AWS refused
// before it writes a bundle, and the engine does the same to every bundle it
// reads, those written before the collector did so included. Both copies
// are held to testdata/callers/cases.json, case for case, and the grammar
// below is the one testdata/callers/rationale.md sets out.
//
// It reads bytes alone, with no regular expression and no Unicode table, so
// that every build of it, native or WebAssembly, on any toolchain, gives the
// same text for the same message.

// removed stands where a person's name was. Its parentheses are characters
// no user, session, federated user or MFA device name may hold, so a name
// removed can be told from a real one; it is printable ASCII and holds no
// "arn:", so a message stripped twice reads as it does stripped once.
const removed = "(removed)"

// withoutPeople is a refusal's message without the people its ARNs name:
//
//   - an ARN starts at every "arn:", whatever stands before it, and runs to
//     the first byte outside printable ASCII, U+0021 to U+007E;
//   - split on ":" into six fields, arn:partition:service:region:account:
//     resource, the resource everything after the fifth colon, it names a
//     person when its partition is not empty, its service is iam or sts, its
//     region is empty and its resource is of one of five types;
//   - what names the person becomes removed: the session after
//     "assumed-role/<role>/", and everything after "user/" (the path with
//     the name), "federated-user/", "u2f/" and "mfa/", even when it is empty.
//
// Root, roles, groups, policies, other services' ARNs and a message without
// "arn:" are left byte for byte. Every ARN in one run of printable bytes ends
// where the run ends, so what is removed from each ends there too, and one
// token replaces the whole of it, from the first name to start in the run.
func withoutPeople(message string) string {
	var out []byte
	copied := 0 // message[:copied] is in out
	for start, end := nextARNs(message, 0); start < len(message); start, end = nextARNs(message, end) {
		if name := firstName(message[start:end]); name >= 0 {
			if out == nil {
				out = make([]byte, 0, len(message)+len(removed))
			}
			out = append(out, message[copied:start+name]...)
			out = append(out, removed...)
			copied = end
		}
	}
	if out == nil {
		return message
	}
	return string(append(out, message[copied:]...))
}

// nextARNs is the stretch of message holding the ARNs of the next run of
// printable bytes that holds any, at or after from, which is 0 or the end
// of the stretch before: message[start:end], from the run's first "arn:" to
// the run's end, or len(message) for both when no ARN is left. An ARN
// starts at every "arn:" and runs to the end of its run, so every ARN of
// the run is in the stretch, and a byte outside every stretch is in no ARN.
func nextARNs(message string, from int) (start, end int) {
	start = arnAt(message, from)
	end = start
	for end < len(message) && printableASCII(message[end]) {
		end++
	}
	return start, end
}

// arnAt is where the first "arn:" in text at or after from starts, or
// len(text) when none does: an ARN starts at every one, whatever stands
// before it.
func arnAt(text string, from int) int {
	for at := from; at+4 <= len(text); at++ {
		if text[at] == 'a' && text[at+1] == 'r' && text[at+2] == 'n' && text[at+3] == ':' {
			return at
		}
	}
	return len(text)
}

// printableASCII is whether b is U+0021 to U+007E: a byte an ARN may hold.
// Every byte of a character beyond ASCII is outside it, so a run of these
// ends where such a character starts, counted in bytes, code points or
// UTF-16 code units alike.
func printableASCII(b byte) bool {
	return b >= 0x21 && b <= 0x7e
}

// firstName is where, in arns, the ARNs of one run as nextARNs gives them,
// the first name any ARN in it holds starts, or -1 when none names a person.
// An ARN can start inside another, as in "arn:arn:aws:iam::…" or a role
// whose path holds "arn:", so every "arn:" is read, and an ARN starting at
// or after a name already found cannot start an earlier one.
func firstName(arns string) int {
	first := -1
	for at := arnAt(arns, 0); at < len(arns) && (first < 0 || at < first); at = arnAt(arns, at+1) {
		if name := personNamed(arns[at:]); name >= 0 && (first < 0 || at+name < first) {
			first = at + name
		}
	}
	return first
}

// personNamed reads arn, which starts with "arn:" and runs to the end of its
// run, as the six fields of an ARN, and returns where the name of the person
// it names starts, or -1 when it names none.
func personNamed(arn string) int {
	var colon [5]int
	found := 0
	for i := 0; i < len(arn) && found < len(colon); i++ {
		if arn[i] == ':' {
			colon[found] = i
			found++
		}
	}
	if found < len(colon) {
		return -1 // fewer than six fields
	}
	partition := arn[colon[0]+1 : colon[1]]
	service := arn[colon[1]+1 : colon[2]]
	region := arn[colon[2]+1 : colon[3]]
	if partition == "" || (service != "iam" && service != "sts") || region != "" {
		return -1
	}
	at := colon[4] + 1
	resource := arn[at:]
	for _, kind := range [...]string{"user/", "federated-user/", "u2f/", "mfa/"} {
		if hasPrefix(resource, kind) {
			return at + len(kind)
		}
	}
	const assumedRole = "assumed-role/"
	if !hasPrefix(resource, assumedRole) {
		return -1
	}
	// The role's name holds no slash, so its session starts after the first
	// slash that follows it. Without one there is no session.
	for i := len(assumedRole); i < len(resource); i++ {
		if resource[i] == '/' {
			return at + i + 1
		}
	}
	return -1
}

// hasPrefix is whether text begins with prefix, byte for byte.
func hasPrefix(text, prefix string) bool {
	return len(text) >= len(prefix) && text[:len(prefix)] == prefix
}
