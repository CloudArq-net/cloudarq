// The engine's answer, as a caller reads it. These types are the JSON
// internal/report writes, named the way it names it: a field renamed here
// and not there is a caller that reads undefined, which no type checker
// would report on its own.
//
// Every answer carries a version. These types describe version 1, and a
// caller that meets another should refuse it rather than guess at a field
// that moved.

/** A run of the sentence: its text, what the engine knows about it, and the
 *  note it refers to. `mark` is exact, beyond, unknown or code. */
export interface Span {
	text: string;
	mark?: string;
	note?: number;
}

/** Where in the document a fact was written: the line, and the operator or
 *  member that wrote it. */
export interface Written {
	line: number;
	operator?: string;
	member?: string;
}

/** A caveat or an anomaly, numbered so the sentence and the term table can
 *  point at it. */
export interface Note {
	number: number;
	kind: string;
	anomaly?: string;
	claim?: string;
	construct?: string;
	message: string;
	source: string;
}

/** One claim's constraint, in the form a renderer draws and a witness is
 *  built from. */
export interface Constraint {
	kind: string;
	value?: string;
	reason?: string;
	members?: Constraint[];
}

/** One claim of a term: what it admits, in the lattice's words and as the
 *  document writes it. */
export interface Claim {
	claim: string;
	constraint: Constraint;
	rendered: string;
	words: string;
	mark?: string;
	note?: number;
	written: Written[];
}

/** One statement of the document, located in the bytes it was pasted as. */
export interface Statement {
	index: number;
	sid: string;
	offset: number;
	length: number;
	firstLine: number;
	lastLine: number;
	sha256: string;
}

/** The document the engine read, and what it found wrong with it before any
 *  grant. */
export interface DocumentReport {
	bytes: number;
	lines: number;
	sha256: string;
	version: string;
	statements: Statement[];
	anomalies: Note[];
}

/** One sentence of the answer: its text, and its spans. */
export interface Sentence {
	sentence: string;
	spans: Span[];
}

/** A question a reader may be asked: the declaration that answers yes, as
 *  an owner's declaration carries it, and the question in words. */
export interface Question {
	declaration: string;
	sentence: string;
	spans: Span[];
}

/** One string under Principal: its text as written, the member it sits
 *  under, as "Principal.AWS", or "Principal" for a Principal that is "*"
 *  itself, and its line. `start` and `end` are the byte offsets of its
 *  literal, [start, end), given only where an edit names the one place it
 *  removes. */
export interface Leaf {
	text: string;
	member: string;
	line: number;
	start?: number;
	end?: number;
}

/** The edit a proven fix makes, where it is written, and the digest of the
 *  policy it leaves, never that policy's text. `removes` is principal,
 *  member, statement or policy, the last when the policy is replaced by one
 *  that lets no one in. */
export interface Edit {
	removes: string;
	statement: number;
	sid: string;
	firstLine: number;
	lastLine: number;
	leaf: Leaf;
	grantNumbers: number[];
	sha256: string;
}

/** How the policy could shut one population out, and whether the engine
 *  proved it. `status` is proven, unproven or words; `check` says what
 *  refused an unproven fix: leaf, effect, bound, span, parse, owner, grants,
 *  placements, condition, principal or managed. */
export interface Fix {
	status: string;
	check?: string;
	sentence: string;
	spans: Span[];
	edit?: Edit;
	shutsOut?: Sentence;
	after?: Sentence;
}

/** Who one population is and how the policy lets it in, each place the
 *  statement writes its principal, what its owners may be asked, and its
 *  fix. */
export interface Way {
	principal: Leaf[];
	who: Sentence;
	how: Sentence;
	questions?: Question[];
	fix?: Fix;
}

/** One owner a population is pinned to. `scope` is owner, repository,
 *  enterprise, account, organisation, tenant or provider; `kind` is name or
 *  id. */
export interface Owner {
	label: string;
	declaration?: string;
	scope: string;
	kind: string;
	value: string;
	name?: string;
	declared: boolean;
	recognised?: boolean;
	recyclable: boolean;
}

/** One of whom a finding's way in lets in. `kind` is platform, everyone
 *  with an account on the platform the grant's issuer is on, whose `value`
 *  is null; or aws-account, one AWS account, whose `value` is its id. */
export interface Caller {
	kind: string;
	value: string | null;
}

/** Facts about a finding's way in, each written on every finding, so that
 *  one the engine did not read says so. `noSecret` is yes or no;
 *  `ownerLeftOpen` holds the starts of an owner's name the subject writes
 *  and leaves to a wildcard, as the policy writes them, in byte order, each
 *  once and none beginning with another, and is empty where it writes
 *  none; `externalId` is required, absent, not-applicable or not-known;
 *  `management` is yes, no or not-known; `refs`, `reach` and `used` are
 *  not-read; `registrableName` and `danglingIssuer` are not-checked. */
export interface Inputs {
	noSecret: string;
	ownerLeftOpen: string[];
	externalId: string;
	refs: string;
	management: string;
	registrableName: string;
	danglingIssuer: string;
	reach: string;
	used: string;
}

/** What the engine finds of one way in when it meets a rule. `rule` is
 *  web-identity/no-owner, web-identity/owner-left-open,
 *  aws-account/no-external-id or aws-account/any-account. `id` and
 *  `pairingKey` are given to the findings of a role a scan's bundle lists,
 *  and to no finding of a policy read alone, which names no role.
 *  `callers` are who the way in lets in that the rule is about, never
 *  empty. `through` is the identity provider's ARN or the service the
 *  principal names, and null for an AWS principal. `condition` is each
 *  claim the way in's term holds, written claim=rendering, empty where it
 *  holds none. `unread` are the conditions its statement writes that the
 *  grant does not read, written "operator key values", empty where it reads
 *  every one. Either is null where it is not known, never where there are
 *  none. */
export interface Finding {
	rule: string;
	id?: string;
	pairingKey?: string;
	callers: Caller[];
	through: string | null;
	condition: string[] | null;
	unread: string[] | null;
	inputs: Inputs;
}

/** Where one term of a grant lands on its own, what decided the place, the
 *  owners that pin it, its way in, and what the engine finds of it.
 *  `place` is anyone, platform, outsider, yours, people, saml or service;
 *  `state` is exact or unknown. A population with no finding is not one the
 *  engine found clean: its state and basis say how far it was read. */
export interface Population {
	term: number;
	place: string;
	state: string;
	basis: string;
	owners: Owner[];
	way?: Way;
	finding?: Finding;
}

/** One grant: who a statement admits, and everything the answer says about
 *  it beyond the sentence. */
export interface Grant {
	number: number;
	statement: number;
	sid: string;
	issuer: string;
	issuerWritten?: Written;
	effect: string;
	exact: boolean;
	beyond: boolean;
	empty: boolean;
	top: boolean;
	admits: string;
	terms: Claim[][];
	notes: Note[];
	/** The conditions the grant's statement writes that the grant does not
	 *  read, as a finding of the grant writes them: empty where it reads
	 *  every one, and null where it is not known, never where there are
	 *  none. */
	unread: string[] | null;
	sentence: string;
	spans: Span[];
	caption: string;
	witness?: string;
	witnessHeading?: string;
	witnessCaption?: string;
	/** Where the grant lands: anyone, platform, outsider, yours, people,
	 *  saml, service, refused or nobody; `placementState` is exact or
	 *  unknown, and absent beside refused and nobody. */
	placement?: string[];
	placementState?: string;
	populations?: Population[];
}

/** What `admits` answers. `error` carries the engine's refusal; `stopped` is
 *  a mark a caller may set for an engine that trapped, and the engine never
 *  writes it. */
export interface Answer {
	v: number;
	error?: string;
	stopped?: boolean;
	document?: DocumentReport;
	grants: Grant[];
}

/** The token as the engine read it. */
export interface TokenReport {
	error?: string;
	decoded: boolean;
	claims: number;
}

/** The claim the constraint kept the token out on. */
export interface Excluded {
	claim: string;
	constraint: string;
}

/** One claim of the token against one grant. `result` is satisfies, fails,
 *  not named or not evaluated. */
export interface ClaimOutcome {
	claim: string;
	value: string;
	constraint: Constraint;
	rendered: string;
	mark?: string;
	result: string;
	why?: string;
	note?: number;
	written: Written[];
}

/** One grant's answer for the token. */
export interface Outcome {
	number: number;
	statement: number;
	sid: string;
	issuer: string;
	effect: string;
	exact: boolean;
	admitted: boolean;
	witness: boolean;
	heading: Span[];
	sentence: string;
	spans: Span[];
	excludes: Excluded | null;
	named: string[];
	claims: ClaimOutcome[];
}

/** What `explain` answers. */
export interface Explanation {
	v: number;
	error?: string;
	stopped?: boolean;
	token: TokenReport;
	heading: Span[];
	sentence: string;
	spans: Span[];
	grants: Outcome[];
}

/** The version of the answer schema these types describe. */
export const ANSWER_VERSION = 1;
