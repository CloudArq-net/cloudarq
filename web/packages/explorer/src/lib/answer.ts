// The engine's answer, as the page reads it. These types are the JSON
// internal/report writes, named the way it names it: a field renamed here
// and not there is a page that renders undefined, which no stylesheet and
// no type checker would report on their own.
//
// Every answer carries a version. The page reads version 1 and refuses any
// other rather than guessing at a field that moved.

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

/** One claim's constraint, in the form the page renders and a witness is
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

/** One grant: who a statement admits, and everything the page shows under
 *  the sentence. */
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
	sentence: string;
	spans: Span[];
	caption: string;
	witness?: string;
	witnessHeading?: string;
	witnessCaption?: string;
}

/** What `admits` answers. `error` carries the engine's refusal; `stopped` is
 *  the page's own mark for an engine that trapped, and is not the engine's
 *  field. */
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

/** The version of the answer schema this page reads. */
export const ANSWER_VERSION = 1;
