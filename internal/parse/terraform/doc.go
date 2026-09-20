// Package terraform reads what a customer's Terraform says about a
// federation trust, from the JSON that terraform show -json prints for a
// plan file or for a state, into the same trust.Grants the cloud parsers
// produce from the deployed document, each labelled with the text it came
// from and carrying, as evidence, the value Terraform wrote or the reader's
// own statement of why there was none.
//
// It exists because the day-one story for a customer on any cloud is the
// explorer and the CLI against their Terraform, and because every tool
// that reads a plan today reads it wrong in the same place: Checkov and
// Trivy build a role from "after" alone, so a policy that is known only
// after apply, the commonest real plan, a role and its OIDC provider
// created together, reads as a role with no trust policy and passes. This
// reader consults after_unknown before after, walks marks at every depth,
// reads the objects a plan deletes, forgets or leaves as they are, and
// turns what it cannot read into a Grant that admits everything, declared,
// with the reason a customer can read.
//
// Three texts exist and none is the bytes the cloud holds. HCL is author
// intent, the only text in which a duplicate key in a heredoc, key order
// and comments survive, and the only one available offline in a pull
// request; it has no values, and it is not read here (a licence decision
// on an HCL parser is pending). Plan JSON is what the provider will send:
// every value Terraform could resolve, provider-normalised, sorted keys,
// minified, with < > & escaped; what it loses is the customer's bytes and
// every value known only after apply, which is absent from after and
// present only as a mark in after_unknown. State JSON looks like the
// deployed document and is not: the AWS provider keeps the config-derived
// text whenever its own equivalence check calls the two equivalent, and
// no mark distinguishes unknown from unset. The evidence record of every
// Grant names the text, terraform/plan or terraform/state, and which
// member of a plan the value was read from, after, before or prior_state;
// the TerraformOrigin anomaly says in words that the deployed resource was
// not fetched. The origin is provenance, not inexactness, so a fully known
// value yields an exact set and no caveat, and the join, which reads
// caveats and evidence status alone, must be taught the terraform/ API
// prefix before it pairs a Grant from a plan with one read live: until
// then a plan-versus-live fan-out would print as deployed fact.
//
// The resource table in resources.go is data: which attributes of which
// resource type are handed to which cloud parser, what the target is, and
// which attributes name the resource in the evidence. A role's policy
// string goes to the AWS parser as written; a credential's or a provider's
// attributes are built into the document the Azure or GCP parser reads,
// under the API's member names, in canonical form, and that document is
// the Grant's Source and its evidence, since no customer document exists
// at that layer; a binding's members go to the GCP parser and are met with
// every provider of their pool the same document holds. The target is the
// resource itself for a role and a provider, and the application, managed
// identity or service account the credential or binding names otherwise,
// so that two credentials of one application are one target; when that
// attribute is known only after apply, the target is the address of the
// one resource instance the expression references, and the credential's
// own address when there is no single such instance.
//
// Which objects a plan holds, and what is read of each. The after value
// is read for every change but a bare delete or forget, the before value
// for a delete, as the object the plan removes, and for any change that
// forgets, since a forgotten object "will no longer be managed by
// Terraform, but will not be destroyed" and its trust continues to exist;
// a replace that forgets, ["create", "forget"] or ["forget", "create"],
// reads both. The format page lists neither forget action; they are read
// from Terraform's own internal/command/jsonplan at v1.15.5 and at main,
// and keyed on the word, so that a pair the page never lists is not read
// as a create. A managed resource the prior state holds and the plan lists
// no change for is read from the prior state: Terraform writes a no-op
// change for every resource it checked, so that a consumer can tell a
// checked resource from one "entirely excluded e.g. due to -target", and
// an excluded one exists all the same; a refresh-only plan lists no change
// at all and a targeted plan only its targets, and both would otherwise
// read as no trust. A plan's complete and errored flags are read when
// present; a document that predates them states neither and is read as
// neither, and one that states complete: false or errored: true says so
// on every grant, since its listing is a lower bound.
//
// What HashiCorp's pages do not settle, and which way each reading errs.
// The format says an unknown leaf is replaced by true in after_unknown and
// omitted or set to null in after, and says nothing about a partly unknown
// collection: recorded with Terraform 1.15.5, the builtin provider marks
// the element and an SDK provider marks the whole list or map. A mark
// anywhere beneath an attribute the parser reads therefore makes the whole
// grant admit everything, never one element or one claim, which errs wide.
// A mark beneath a member the parser does not read, a JWKS document inside
// an oidc block, is passed over. A required attribute absent or null and
// unmarked, which in a state is the only way an unknown can appear, is
// read as not stated and the grant admits everything; an optional one is
// read as unset, which for a provider's attribute_condition is Google's
// own reading, "all valid authentication credential are accepted", the
// wide one. A value the customer marked sensitive is read and evaluated,
// and neither quoted nor carried as evidence: the format says the marks
// exist "to prevent accidental display of sensitive values in user
// interfaces", so the Grant's Source and its record hold the reader's
// statement with the value's digest, and the set is exact all the same; a
// mark on a value that was not read, one known only after apply, absent
// or unreadable, is stated too, with no value to redact, and a rendered
// data document the plan marks sensitive is attached redacted the same
// way. A
// string token that is not valid UTF-8 or holds a lone UTF-16 surrogate
// escape is not decoded: encoding/json would repair either to U+FFFD and
// the cloud parsers refuse both, so the reader refuses it in their place,
// with the byte named, rather than hand a parser a document the customer
// does not have. The configuration lists references "unwrapped and
// duplicated for each significant traversal step" and says nothing about
// which of them is unknown, so the sentence names what the expression
// references, with the implied steps dropped, never which reference is the
// cause. The configuration's resource addresses are module-local and free
// of instance keys, which was recorded rather than read from the page; if
// a future format keyed them, the lookup would find nothing and the
// sentence would say the configuration does not describe the instance,
// never invent a reference. Deferral of a data document is keyed on its
// resource_changes entry marking json unknown, not on action_reason,
// which the format calls display hints that may change. An object listed
// as deposed is read like a current one and named by its key in the
// evidence. A resource type the table does not map but whose name belongs
// to a trust-bearing family is listed as unread and named on every grant,
// so that a customer sees "not read" rather than nothing; a type outside
// the families is passed over without a word.
//
// Two facts about the providers bear on the table. The azuread provider's
// schema at main (v3.9.0, 2026-06-18) makes subject Required and has no
// expression argument, so a flexible credential cannot be stated in
// Terraform and the reader never meets one; azurerm_federated_identity_credential,
// the managed identity's credential, has the same three members under
// audience, issuer and subject. The name and state of a Google provider
// are computed, unknown in every create plan, and identifying rather than
// admission-bearing: an unknown one is left out of the built document and
// the GCP parser's own doubts apply, the default audience underivable and
// the pool of a nameless provider undecided. A name is never derived from
// id or from project and the pool id, since id carries the project ID
// where the name carries its number and the derived default audience would
// be one no token has. Before apply every provider of a pool is nameless,
// so a member is met with every provider whose workload_identity_pool_id
// is the member's pool id, with the parser's doubt stated on each; a
// member of a pool the document holds no provider of, or one that is not a
// pool principal at all, states a grant that admits everything, declared,
// because what it admits is decided elsewhere and a member that vanished
// would be silence; a binding that names no member states one grant that
// admits nothing, exactly, the one emptiness a document proves, and so
// does a role whose policy the AWS parser projects no statement from, an
// empty Statement list or none, with the parser's own sentence beside the
// reader's; the parser's facts about a document as a whole ride on every
// grant of it, since the grant is the only thing this reader hands on. A
// credential whose target is created in the same plan and cannot be
// resolved to one instance keeps its own address, which may split one
// target into several, a fan-out that does not exist, rather than merge
// two targets into one, a fan-out that would be missed. The managed
// identity's kind, userAssignedIdentity, is spelt after Resource
// Manager's resource type ahead of any collector spelling it, and the
// service account's, serviceAccount, as the GCP parser's tests spell it,
// where the join's tests spell it service-account; one of the two must
// move before the join reads these grants.
//
// Departures from the binding decisions of the Pass 1, each for a reason
// stated. Grants takes the AWS claim vocabulary as a parameter, because
// the package imports no registry and the AWS parser needs one. The
// evidence Params name the attributes read under "attributes", a list,
// rather than one "field", because a provider is read from seven, and
// name the member of the plan they were read from under "from". The
// target of a credential or a binding is the application, managed
// identity or service account it names, not the resource's own address,
// because the join compares targets by struct equality and two
// credentials of one application on two addresses would be a fan-out that
// does not exist; the attribute's value, when the document states it, is
// in Params under the attribute's name. Grant.Source is what the cloud
// parser set it to, the statement's own bytes for an AWS policy, rather
// than the whole attribute value: the parser quotes the statement a grant
// came from, and the whole value is the record's Bytes, so nothing is
// lost and the per-statement quote is kept.
//
// The package is pure: no IO, no clock, no randomness, no regexp and no
// reflection beyond encoding/json, enforced by test/arch. It is total over
// arbitrary bytes, refusing only what is not a plan or a state document at
// all: not one JSON object, a raw terraform.tfstate file, which carries
// every sensitive value in clear and is never read, an unsupported major
// version, or the other reader's document.
package terraform
