# 04 — escaped characters

The Sid is written `Partn\u00e9r`, the partner's root ARN `arn:aws:iam::111122223333:r\u006fot`,
and the declared account's role `arn:aws:iam::444455556666:role\/deploy`. `aws:444455556666` is
declared as yours.

**Expected.** The partner is a named outsider with a proven fix: in statement 1 (`Partnér`, as
the Sid decodes), lines 4-9, remove `"arn:aws:iam::111122223333:r\u006fot"` from `Principal.AWS`,
quoted as it is written so that it can be found in the file. The policy then opens on "Nothing
outside your company can assume this role." Your role has the fix it would have as an outsider's,
quoted with its `\/` as written.

**Why.** Where a principal is written is read from the decoder's offsets, never searched for: the
literal's bytes run from its opening quote to just past its closing one, escapes and all, and decode
to the principal's text. The edit cuts exactly those bytes and the separator beside them, so every
other escape in the file stays as it was, and the digest is of those bytes. A carriage return
before a line feed is kept the same way; the offsets beside one are held in
`internal/parse/aws/written_test.go` and `edit_test.go`, since a file of this corpus is stored with
line feeds alone.
