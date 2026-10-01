package aws

import "slices"

// Intermediary is an AWS service that AWS documents as assuming a role for
// identities outside IAM and passing them its session, or acting with the
// session for them. Who those identities are is set in a resource of the
// service's own, a trust anchor, a role alias, an activation, an
// association or a user, which a trust policy does not carry: a role such
// a service can assume is a door, and the policy names only the door.
//
// A service this table does not list is not thereby AWS's own. Nobody
// surveyed it, so what is said of it is what is true of every service:
// who can make it act, or receives its session, is not read.
type Intermediary struct {
	// Service is the service principal, ASCII lower case.
	Service string
	// ActsFor is who the service assumes a role for, in the few words a row
	// of the rings has room for after "for".
	ActsFor string
	// ActsForInFull is who it assumes a role for and what it does with the
	// session, as a grant's note says it after "can assume a role for": can,
	// since whether the service's resource names a role is not in the
	// policy. Each clause is written from Sentences and claims no more.
	ActsForInFull string
	// Sentences are AWS's own, which the reading rests on.
	Sentences []Citation
	// OtherUses are AWS's sentences on the service assuming roles for other
	// purposes too, for whoever names a role to it. Where there are any,
	// whom ActsFor names is one use among others, so no sentence may name
	// it alone, and who can make the service act stays what is not read.
	OtherUses []Citation
}

// HasOtherUses reports whether the row records AWS's sentences on the
// service assuming roles for more than the use it names.
func (i Intermediary) HasOtherUses() bool { return len(i.OtherUses) > 0 }

// Citations are every sentence of AWS's the row rests on: those for the use
// it names, then those for its other uses.
func (i Intermediary) Citations() []Citation {
	return append(slices.Clone(i.Sentences), i.OtherUses...)
}

// Citation is one sentence AWS wrote, verbatim, the page it is on, and the
// date it was read.
type Citation struct {
	Quote  string
	Source string
	Read   string
}

// intermediaries is the table, one row per service, the sentences of each in
// the order its reading follows them. The sentences reach the reader as
// the answer's citations, so a sentence that needs a noun the answer never
// prints is not chosen where AWS says the same in another. It is a Go
// literal, as the parser's other grammar facts are, so that nothing is
// decoded, and nothing can fail to load, inside the WebAssembly engine. No
// row says where its service's callers run: none of the sentences quoted
// confines them to a place, and EKS Pod Identity serves pods on EKS Hybrid
// Nodes, on premises, as well as on Amazon EC2. Transfer Family acts with
// the session and hands it to no one, so its row never says it passes the
// session on.
var intermediaries = []Intermediary{
	{
		Service:       "rolesanywhere.amazonaws.com",
		ActsFor:       "workloads holding a certificate",
		ActsForInFull: "workloads that hold a certificate a trust anchor in the account accepts, and pass them its session",
		Sentences: []Citation{
			{Quote: "To use IAM Roles Anywhere, your workloads must use X.509 certificates issued by your certificate authority (CA).", Source: "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html", Read: "2026-09-27"},
			{Quote: "Certificates issued by any trust anchor in the account can be used to assume any target role in that same account, unless you specify conditions in the role's trust policy.", Source: "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html", Read: "2026-09-27"},
			{Quote: "Temporary credentials for IAM roles are issued to IAM Roles Anywhere clients via the API method CreateSession.", Source: "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html", Read: "2026-09-27"},
			{Quote: "After validating the signature, IAM Roles Anywhere checks that the certificate was issued by a certificate authority configured as a trust anchor in the account using algorithms defined by public key infrastructure X.509 (PKIX) standards.", Source: "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html", Read: "2026-09-27"},
		},
	},
	{
		Service:       "credentials.iot.amazonaws.com",
		ActsFor:       "devices holding a certificate",
		ActsForInFull: "devices that present an X.509 certificate AWS IoT accepts, and pass them its session",
		Sentences: []Citation{
			{Quote: "AWS IoT Core has a credentials provider that allows you to use the built-in X.509 certificate as the unique device identity to authenticate AWS requests.", Source: "https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html", Read: "2026-09-27"},
			{Quote: "Configure the IAM role that the credentials provider assumes on behalf of your device.", Source: "https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html", Read: "2026-09-27"},
			{Quote: "The requested service invokes IAM to validate the signature and authorize the request against access policies attached to the IAM role that you created for the credentials provider.", Source: "https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html", Read: "2026-09-27"},
		},
	},
	{
		Service:       "ssm.amazonaws.com",
		ActsFor:       "hybrid-activated machines",
		ActsForInFull: "machines registered by a hybrid activation, and pass them its session",
		Sentences: []Citation{
			{Quote: "Non-EC2 (Amazon Elastic Compute Cloud) machines in a hybrid and multicloud environment require an AWS Identity and Access Management (IAM) service role to communicate with the AWS Systems Manager service.", Source: "https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html", Read: "2026-09-27"},
			{Quote: `On a non-EC2 machine, SSM Agent normally gets the needed permissions from the shared credentials file, located at /root/.aws/credentials (Linux and macOS) or %USERPROFILE%\.aws\credentials (Windows Server).`, Source: "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html", Read: "2026-09-27"},
			{Quote: "The needed permissions are added to this file during the hybrid activation process.", Source: "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html", Read: "2026-09-27"},
			{Quote: "Systems Manager supports on-premises servers, edge devices, and virtual machines running in other cloud environments, including Microsoft Azure.", Source: "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-hybrid-multicloud.html", Read: "2026-09-27"},
		},
		OtherUses: []Citation{
			{Quote: "When you register a task with a maintenance window, you specify a service role to run the actual task operations. This is the role that the service assumes when it runs tasks on your behalf.", Source: "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-perm-console.html", Read: "2026-09-27"},
			{Quote: "Using this role, or the Amazon Resource Name (ARN) of an AWS Identity and Access Management (IAM) role, in runbooks allows Automation to perform actions in your environment, such as launch new instances and perform actions on your behalf.", Source: "https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-setup-iam.html", Read: "2026-09-27"},
		},
	},
	{
		Service:       "pods.eks.amazonaws.com",
		ActsFor:       "pods of EKS clusters",
		ActsForInFull: "the pods of an EKS cluster in the account whose service account is associated with it, and pass them its session",
		Sentences: []Citation{
			{Quote: "EKS Pod Identity uses AssumeRole to assume the IAM role before passing the temporary credentials to your pods.", Source: "https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html", Read: "2026-09-27"},
			{Quote: "Each EKS Pod Identity association maps a role to a service account in a namespace in the specified cluster.", Source: "https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html", Read: "2026-09-27"},
			{Quote: "If you have the same application in multiple clusters, you can make identical associations in each cluster without modifying the trust policy of the role.", Source: "https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html", Read: "2026-09-27"},
			{Quote: "Each Kubernetes service account in a cluster can be associated with one IAM role from the same AWS account as the cluster.", Source: "https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html", Read: "2026-09-27"},
		},
	},
	{
		Service:       "transfer.amazonaws.com",
		ActsFor:       "Transfer Family users",
		ActsForInFull: "the users of a Transfer Family server, and act with its session for them",
		Sentences: []Citation{
			{Quote: "User role – Allows service-managed users to access the necessary Transfer Family resources. AWS Transfer Family assumes this role in the context of a Transfer Family user ARN.", Source: "https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html", Read: "2026-09-27"},
			{Quote: "When your user sends an authentication request to your server by using a client, your server first confirms that the user has access to the associated SSH private key.", Source: "https://docs.aws.amazon.com/transfer/latest/userguide/create-user.html", Read: "2026-09-27"},
		},
		OtherUses: []Citation{
			{Quote: "Invocation role – For use with Amazon API Gateway as the server's custom identity provider. Transfer Family assumes this role in the context of a Transfer Family server ARN.", Source: "https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html", Read: "2026-09-27"},
			{Quote: "Logging role – Used to log entries into Amazon CloudWatch. Transfer Family uses this role to log success and failure details along with information about file transfers. Transfer Family assumes this role in the context of a Transfer Family server ARN.", Source: "https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html", Read: "2026-09-27"},
			{Quote: "Execution role – Allows a Transfer Family user to call and launch workflows. Transfer Family assumes this role in the context of a Transfer Family workflow ARN.", Source: "https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html", Read: "2026-09-27"},
		},
	},
}

// Intermediaries is the whole table, in its order, for whoever composes
// words from its rows and must hold every row's to the room a sentence has.
func Intermediaries() []Intermediary { return slices.Clone(intermediaries) }

// IntermediaryOf is the row of the service a Service principal names, found
// the way the principal's issuer is: ASCII lower case, since a service
// principal is a DNS name. A spelling no row holds, another partition's
// suffix among them, finds none, and the service reads with the words true
// of every service.
func IntermediaryOf(service string) (Intermediary, bool) {
	service = fold(service)
	for _, i := range intermediaries {
		if i.Service == service {
			return i, true
		}
	}
	return Intermediary{}, false
}
