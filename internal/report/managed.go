package report

import (
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// A role AWS made for one of its services sits in the account like any
// other, and its answer is the same as any role's with that trust:
// the service, acting for whoever can make it act, which is not read. What
// the findings add is what the role is. It is said beside the answer and
// never in it, so it cannot move where a grant lands: who can make the
// service act is set where the engine does not read, in the account's
// identity policies and, for a service its AWS Organization gives trusted
// access, by the Organization's management account and delegated
// administrators, and saying whose role it is answers nothing about who
// gets in.

// Managed is what the findings say of a role AWS made and manages for one
// of its services: who made it, for which service, and in words, what it
// is and why who gets in through it is still not known.
type Managed struct {
	// By is who made the role. Values: aws.
	By       string
	Service  string
	Sentence string
	Caption  string
}

// serviceLinkedPath begins the path of every role AWS makes for a service.
// IAM keeps it for them: CreateRole at a path beginning
// "/aws-service-role" is refused with "Paths beginning with
// '/aws-service-role' are reserved for AWS Service Linked Roles" (IAM's
// answer to a test account, 3 October 2026), and a service-linked role's
// trust policy is one only its service can change (UpdateAssumeRolePolicy's
// UnmodifiableEntity).
const serviceLinkedPath = "/aws-service-role/"

// managedBy says what a role is when AWS made it for a service: its path is
// exactly serviceLinkedPath and one segment, the service, and its trust
// admits that service and nobody else. A bundle is a file, and a path in
// one is a claim, so the claim is held to the trust the role carries: a
// role on that path whose trust admits anyone beside the service is not
// explained, and neither is one whose path is not known.
func managedBy(path *string, document []byte) *Managed {
	if path == nil {
		return nil
	}
	service, ok := strings.CutPrefix(*path, serviceLinkedPath)
	if !ok {
		return nil
	}
	service, ok = strings.CutSuffix(service, "/")
	if !ok || service == "" || strings.Contains(service, "/") || !admitsOnly(document, service) {
		return nil
	}
	sentence, caption := managedWords(service)
	return &Managed{By: "aws", Service: service, Sentence: sentence, Caption: caption}
}

// admitsOnly reports whether every grant of a trust policy that may admit
// is the service's, and one does. A Deny admits nobody; an effect the
// parser could not read may be an Allow, so it must be the service's too.
// A policy the engine does not read proves nothing, so it is not
// explained.
//
// The service is the path's segment as written, and the parser keeps a
// service's issuer in lower case, so a segment in another case matches no
// grant: AWS writes both in lower case, and a role that does not is not
// explained.
func admitsOnly(document []byte, service string) bool {
	r, err := readPolicy(document)
	if err != nil {
		return false
	}
	issuer := trust.IssuerRef(aws.ServiceIssuerPrefix + service)
	admits := false
	for _, g := range r.grants {
		switch {
		case g.Effect == trust.Deny:
		case g.Issuer != issuer:
			return false
		case g.Effect == trust.Allow:
			admits = true
		}
	}
	return admits
}

// managed writes a role's managed member: null for a role nothing is said
// of.
func (e *encoder) managed(m *Managed) {
	e.key("managed")
	if m == nil {
		e.null()
		return
	}
	saved := e.begin()
	e.str("by", m.By)
	e.str("service", m.Service)
	e.str("sentence", m.Sentence)
	e.str("caption", m.Caption)
	e.end(saved)
}
