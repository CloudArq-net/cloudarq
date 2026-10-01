// Package registry is the one seam through which the engine reads the
// published issuer census, github.com/CloudArq-net/issuers.
//
// It exists so that CloudArq depends on the same artefact it asks everyone
// else to depend on, and so that the engine speaks its own types: an
// IssuerRef in, claim keys and the classifier's Facts out. The census is
// embedded in the module at build time and parsed once; no call here
// reaches the network, which is the standing rule that the registry is data
// and never a live fetch, and the purity walk covers this package and the
// module beneath it.
//
// Facts reads the census's tenancy sub-package alone, which is what the
// WebAssembly engine can afford to link; Lookup and its neighbours read the
// census whole. Every lookup folds a host by ASCII rules and no others: an
// issuer holding a character outside ASCII is none of the census's.
//
// Two answers come in pairs. AudienceIsBoundary and SubjectsAreRecyclable
// return a known flag beside the answer, and known == false is never read
// as a boundary or as a safe subject: nobody surveyed it, which is the same
// discipline as Unknown in the lattice, applied at an API boundary. Lookup's
// false means the same: not surveyed, never safe. Facts carries the same
// discipline in the classifier's own values, where the zero of each is the
// cautious one.
//
// The census has a version. When it changes, the module is tagged and
// go.mod is bumped in a commit of its own; that is the cost of the import
// and it is the right cost. go.mod never replaces it: an unreleased census
// is read through a go.work that git ignores.
package registry
