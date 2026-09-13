// Package registry is the one seam through which the engine reads the
// published issuer census, github.com/CloudArq-net/issuers.
//
// It exists so that CloudArq depends on the same artefact it asks everyone
// else to depend on, and so that the engine speaks its own types: an
// IssuerRef in, claim keys out. The census is embedded in the module at
// build time and parsed once; no call here reaches the network, which is
// the standing rule that the registry is data and never a live fetch, and
// the purity walk covers this package and the module beneath it.
//
// Two answers come in pairs. AudienceIsBoundary and SubjectsAreRecyclable
// return a known flag beside the answer, and known == false is never read
// as a boundary or as a safe subject: nobody surveyed it, which is the same
// discipline as Unknown in the lattice, applied at an API boundary. Lookup's
// false means the same: not surveyed, never safe.
//
// The census has a version. When it changes, the module is tagged and
// go.mod is bumped in a commit of its own; that is the cost of the import
// and it is the right cost.
package registry
