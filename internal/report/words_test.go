package report

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/issuers/tenancy"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The budgets of the answer's shortest words: the headline, the five ring
// labels, the labels of the lines beside them, the question and a row's
// sentence are what a reader sees before anything else, so each is held to
// a count of words that reads at a glance.
const (
	headlineBudget   = 14
	ringLabelBudget  = 5
	lineLabelBudget  = 2
	questionBudget   = 4
	rowBudget        = 16
	emptyRingsBudget = 12
)

func words(s string) int { return len(strings.Fields(s)) }

// platformNames is every platform a sentence can name: each census entry's,
// as platformName reads it for an issuer the entry matches, with the names
// the registry gives that issuer, and AWS. Each is at most two words, which
// is what the budgets below are counted with.
func platformNames(t *testing.T) []string {
	t.Helper()
	names := []string{platformName(aws.AWSPrincipalIssuer, registry.Names{})}
	for _, e := range tenancy.All() {
		issuer := instanceOf(e)
		_, census := registry.Facts(issuer)
		if census.Entry != e.Name {
			t.Fatalf("%s: its instance %q reaches %q", e.Name, issuer, census.Entry)
		}
		names = append(names, platformName(issuer, census))
	}
	longest := ""
	for _, n := range names {
		if words(n) > 2 {
			t.Errorf("the platform %q is %d words; a ring's label has room for two", n, words(n))
		}
		if words(n) > words(longest) || words(n) == words(longest) && len(n) > len(longest) {
			longest = n
		}
	}
	if len(names) < 25 || words(longest) != 2 {
		t.Fatalf("%d platforms, the longest %q; the budgets would be counted with too little", len(names), longest)
	}
	return names
}

// instanceOf is an issuer the census entry matches: its issuer with every
// placeholder filled, by a GUID where the census records the tenant as one.
func instanceOf(e tenancy.Issuer) trust.IssuerRef {
	fill := "p"
	if e.TenantSyntax == "guid" {
		fill = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0"
	}
	issuer := e.Issuer
	for strings.Contains(issuer, "<") {
		open := strings.Index(issuer, "<")
		issuer = issuer[:open] + fill + issuer[open+strings.Index(issuer[open:], ">")+1:]
	}
	if !strings.HasPrefix(issuer, "https://") {
		issuer = "https://" + issuer
	}
	return trust.IssuerRef(issuer)
}

// grantAt is a placed grant at one place, its populations of the given
// bases, each naming the owners given.
func grantAt(number int, issuer trust.IssuerRef, platform string, place ring.Place, state ring.State, owners []ring.Owner, bases ...ring.Basis) placed {
	p := ring.Placement{Outcome: ring.Placed, Places: []ring.Place{place}, State: state, Owners: owners}
	for i, b := range bases {
		p.Populations = append(p.Populations, ring.Population{Term: i, Place: place, State: state, Basis: b, Owners: owners})
	}
	return placed{number: number, issuer: issuer, platform: platform, placement: p}
}

// budgetRows is every row the words compose, filled with the longest
// values: every basis alone and mixed, one, two and several platforms,
// owners and providers and services, in both states, populations a grant
// lets in for certain beside ones it does not, owners of every kind
// together, and every ring empty. Each row is made the way the answer
// makes it, by rowOf, so its state is the one its populations give it.
func budgetRows(t *testing.T) []row {
	t.Helper()
	var longestPlatform string
	for _, n := range platformNames(t) {
		if words(n) > words(longestPlatform) || words(n) == words(longestPlatform) && len(n) > len(longestPlatform) {
			longestPlatform = n
		}
	}
	const issuer = trust.IssuerRef("https://a-long-issuer-host.example.com/with/a/tenant/path")
	repository := ring.Owner{Issuer: issuer, Namespace: ring.NamespaceGitHub, Scope: ring.ScopeRepository, Kind: ring.KindName, Value: "a-long-owner/a-long-repository"}
	enterprise := ring.Owner{Issuer: issuer, Namespace: ring.NamespaceGitHub, Scope: ring.ScopeEnterprise, Kind: ring.KindID, Value: "4200000000"}
	named := func(declared bool) []ring.Owner {
		r, e := repository, enterprise
		r.Declared, e.Declared = declared, declared
		return []ring.Owner{r, e}
	}
	provider := func(name string) ring.Owner {
		return ring.Owner{Issuer: "arn:aws:iam::123456789012:saml-provider/" + trust.IssuerRef(name), Namespace: ring.NamespaceSAML, Scope: ring.ScopeProvider, Value: "arn:aws:iam::123456789012:saml-provider/" + name, Declared: true}
	}
	service := func(name string) trust.IssuerRef { return trust.IssuerRef(aws.ServiceIssuerPrefix + name) }
	var rows []row
	for _, state := range []ring.State{ring.StateExact, ring.StateUnknown} {
		at := func(place ring.Place, grants ...placed) row { return rowOf(place, grants) }
		for _, b := range []ring.Basis{ring.IssuerNotSurveyed, ring.TokensWithoutAccount, ring.AccountNotVerified, ring.AnyIssuer, ring.PrincipalNotModelled} {
			rows = append(rows, at(ring.Anyone, grantAt(1, issuer, longestPlatform, ring.Anyone, state, nil, b)))
		}
		rows = append(rows,
			at(ring.Anyone, grantAt(1, issuer, longestPlatform, ring.Anyone, state, nil, ring.IssuerNotSurveyed, ring.AnyIssuer)),
			at(ring.Anyone, grantAt(10, issuer, longestPlatform, ring.Anyone, state, nil, ring.IssuerNotSurveyed), grantAt(11, "https://another.example.com", longestPlatform, ring.Anyone, state, nil, ring.IssuerNotSurveyed)),
			at(ring.Anyone, grantAt(10, issuer, longestPlatform, ring.Anyone, state, nil, ring.IssuerNotSurveyed), grantAt(11, "https://another.example.com", longestPlatform, ring.Anyone, state, nil, ring.AccountNotVerified), grantAt(12, issuer, longestPlatform, ring.Anyone, state, nil, ring.PrincipalNotModelled)))
		for _, b := range []ring.Basis{ring.Unpinned, ring.OpenTenant, ring.TenancyNotRecorded, ring.UnreadConstraint, ring.MembershipNotVerified} {
			rows = append(rows, at(ring.Platform, grantAt(1, issuer, longestPlatform, ring.Platform, state, nil, b)))
		}
		rows = append(rows,
			at(ring.Platform, grantAt(1, issuer, longestPlatform, ring.Platform, state, nil, ring.Unpinned, ring.UnreadConstraint)),
			at(ring.Platform, grantAt(10, issuer, longestPlatform, ring.Platform, state, nil, ring.Unpinned), grantAt(11, issuer, longestPlatform, ring.Platform, state, nil, ring.UnreadConstraint)),
			at(ring.Platform, grantAt(1, issuer, longestPlatform, ring.Platform, state, nil, ring.Unpinned), grantAt(2, issuer, "HCP Terraform", ring.Platform, state, nil, ring.Unpinned)),
			at(ring.Platform, grantAt(1, issuer, longestPlatform, ring.Platform, state, nil, ring.Unpinned), grantAt(2, issuer, "HCP Terraform", ring.Platform, state, nil, ring.Unpinned), grantAt(3, issuer, "AWS", ring.Platform, state, nil, ring.Unpinned)))
		for _, declared := range []bool{false, true} {
			place := map[bool]ring.Place{false: ring.Outsider, true: ring.Yours}[declared]
			owners := named(declared)
			rows = append(rows,
				at(place, grantAt(1, issuer, longestPlatform, place, state, owners[:1], ring.Pinned)),
				at(place, grantAt(1, issuer, longestPlatform, place, state, owners, ring.Pinned)),
				at(place, grantAt(1, issuer, longestPlatform, place, state, owners, ring.Pinned), grantAt(2, issuer, longestPlatform, place, state, []ring.Owner{func() ring.Owner { o := repository; o.Value += "-2"; o.Declared = declared; return o }()}, ring.Pinned)))
		}
		rows = append(rows,
			at(ring.People, grantAt(1, "arn:aws:iam::123456789012:saml-provider/AVeryLongProviderName", "", ring.People, state, []ring.Owner{provider("AVeryLongProviderName")}, ring.SAMLProvider)),
			at(ring.People, grantAt(1, "p1", "", ring.People, state, []ring.Owner{provider("One")}, ring.SAMLProvider), grantAt(2, "p2", "", ring.People, state, []ring.Owner{provider("Two")}, ring.SAMLProvider)))
	}
	rows = append(rows, mixedRows(t, issuer, longestPlatform, repository, enterprise)...)
	unknownRow := func(place ring.Place, grants ...placed) row {
		return row{place: place, state: ring.StateUnknown, grants: grants}
	}
	rows = append(rows,
		unknownRow(ring.SAML, grantAt(1, "", "", ring.SAML, ring.StateUnknown, nil, ring.AccountSAMLProviders)),
		unknownRow(ring.SAML, grantAt(1, "arn:aws:iam::123456789012:saml-provider/AVeryLongProviderName", "", ring.SAML, ring.StateUnknown, []ring.Owner{provider("AVeryLongProviderName")}, ring.SAMLProvider)),
		unknownRow(ring.SAML, grantAt(1, "p1", "", ring.SAML, ring.StateUnknown, []ring.Owner{provider("One")}, ring.SAMLProvider), grantAt(2, "p2", "", ring.SAML, ring.StateUnknown, []ring.Owner{provider("Two")}, ring.SAMLProvider)),
		unknownRow(ring.Service, grantAt(1, "", "", ring.Service, ring.StateUnknown, nil, ring.AnyService)),
		unknownRow(ring.Service, grantAt(1, service("a-very-long-service-name.amazonaws.com"), "", ring.Service, ring.StateUnknown, nil, ring.ServicePrincipal)),
		unknownRow(ring.Service, grantAt(1, service("one.amazonaws.com"), "", ring.Service, ring.StateUnknown, nil, ring.ServicePrincipal), grantAt(2, service("two.amazonaws.com"), "", ring.Service, ring.StateUnknown, nil, ring.ServicePrincipal)))
	// a service that assumes a role for identities outside IAM names whom
	// it acts for, and every row of the table must fit
	for _, i := range aws.Intermediaries() {
		rows = append(rows, unknownRow(ring.Service, grantAt(1, service(i.Service), "", ring.Service, ring.StateUnknown, nil, ring.ServiceIntermediary)))
	}
	// a grant of two terms, one pinned and one open, lands at the platform
	// and is worded by its term there: the reader of another dialect than
	// AWS's gives a grant several terms, where AWS's gives one
	twoTerms := grantAt(1, issuer, longestPlatform, ring.Platform, ring.StateExact, nil, ring.Unpinned)
	twoTerms.placement.Populations = append(twoTerms.placement.Populations, ring.Population{Term: 1, Place: ring.Outsider, State: ring.StateExact, Basis: ring.Pinned, Owners: named(false)[:1]})
	rows = append(rows, row{place: ring.Platform, state: ring.StateExact, grants: []placed{twoTerms}})
	if s := plain(rowWords(rows[len(rows)-1])); s != "Anyone on "+longestPlatform+" can assume this role; no condition confines its tokens to one owner." {
		t.Errorf("a grant of a pinned and an open term is worded %q", s)
	}
	for place := ring.Anyone; place <= ring.People; place++ {
		rows = append(rows, row{place: place, state: ring.StateExact})
	}
	return rows
}

// mixedRows are the rows whose populations differ: every split of up to
// six platforms, and of up to five owners of every kind, into those a grant
// lets in for certain and those it does not, and an Anyone row whose
// certain reason and unknown one differ. The owners are the longest a
// sentence names: a declared and an undeclared owner by name, and a
// repository and an enterprise, which cannot be declared and take two
// words each.
func mixedRows(t *testing.T, issuer trust.IssuerRef, longestPlatform string, repository, enterprise ring.Owner) []row {
	t.Helper()
	var rows []row
	stateOf := func(i, sure int) ring.State {
		if i < sure {
			return ring.StateExact
		}
		return ring.StateUnknown
	}
	for n := 1; n <= 6; n++ {
		for sure := 0; sure <= n; sure++ {
			var grants []placed
			for i := range n {
				platform := "Platform " + string(rune('A'+i))
				grants = append(grants, grantAt(i+1, trust.IssuerRef("https://p"+strconv.Itoa(i)+".example.com"), platform, ring.Platform, stateOf(i, sure), nil, ring.Unpinned))
			}
			rows = append(rows, rowOf(ring.Platform, grants))
		}
	}
	// the kinds of owner: 0 undeclared, 1 a repository, 2 an enterprise, 3
	// declared, each spelled apart by its position
	kinds := func(kind, i int) ring.Owner {
		o := ring.Owner{Issuer: issuer, Namespace: ring.NamespaceGitHub, Scope: ring.ScopeOwner, Kind: ring.KindName, Value: "a-long-owner-name-" + strconv.Itoa(i)}
		switch kind {
		case 1:
			o = repository
			o.Value += "-" + strconv.Itoa(i)
		case 2:
			o = enterprise
			o.Value += strconv.Itoa(i)
		case 3:
			o.Declared = true
		}
		return o
	}
	examined := 0
	for n := 1; n <= 5; n++ {
		combinations := 1
		for range n {
			combinations *= 4
		}
		for c := range combinations {
			var owners []ring.Owner
			undeclared := false
			for i, code := 0, c; i < n; i, code = i+1, code/4 {
				owners = append(owners, kinds(code%4, i))
				undeclared = undeclared || code%4 != 3
			}
			for sure := 0; sure <= n; sure++ {
				var outside, yours []placed
				for i, o := range owners {
					outside = append(outside, grantAt(i+1, issuer, longestPlatform, ring.Outsider, stateOf(i, sure), []ring.Owner{o}, ring.Pinned))
					declared := o
					declared.Declared = true
					yours = append(yours, grantAt(i+1, issuer, longestPlatform, ring.Yours, stateOf(i, sure), []ring.Owner{declared}, ring.Pinned))
				}
				// an outsider's population always names an owner nobody
				// declared, or it would be the user's own
				if undeclared {
					rows = append(rows, rowOf(ring.Outsider, outside))
				}
				rows = append(rows, rowOf(ring.Yours, yours))
				examined++
			}
		}
	}
	if examined < 1000 {
		t.Fatalf("%d owner mixes built; the budgets would be held over too few", examined)
	}
	rows = append(rows, rowOf(ring.Anyone, []placed{
		grantAt(1, issuer, longestPlatform, ring.Anyone, ring.StateExact, nil, ring.TokensWithoutAccount),
		grantAt(2, "https://another.example.com", longestPlatform, ring.Anyone, ring.StateUnknown, nil, ring.IssuerNotSurveyed),
	}))
	return rows
}

// TestTheWordBudgets holds every template to its budget, filled with the
// longest platform name the census gives and the longest owners, providers
// and services a sentence can name, in every state and with every line
// beside the rings: the headline with its clause, a ring's label, a line's
// label, a row's sentence, and the sentence for an empty set of rings.
func TestTheWordBudgets(t *testing.T) {
	rows := budgetRows(t)
	questions := 0
	byPlace := map[ring.Place][]row{}
	for _, r := range rows {
		byPlace[r.place] = append(byPlace[r.place], r)
		budget := ringLabelBudget
		if !r.place.Ring() {
			budget = lineLabelBudget
		}
		if l := label(r); words(l) > budget {
			t.Errorf("%s: the label %q is %d words, over %d", r.place, l, words(l), budget)
		}
		if s := plain(rowWords(r)); words(s) > rowBudget || s == "" || strings.Contains(" "+strings.ToLower(s)+" ", " only ") {
			t.Errorf("%s %s: the sentence %q is %d words, over %d, or says only", r.place, r.state, s, words(s), rowBudget)
		}
		for _, o := range r.questions() {
			questions++
			if q := plain(questionWords(o)); words(q) > questionBudget {
				t.Errorf("%s: the question %q is %d words, over %d", r.place, q, words(q), questionBudget)
			}
		}
	}
	// the headline: every outermost ring reached, with every set of lines
	// beside it; every set of lines alone; every ring of the user's own
	// whose place is not established; and nothing at all
	lineSets := [][]row{nil}
	for _, saml := range byPlace[ring.SAML] {
		lineSets = append(lineSets, []row{saml})
		for _, service := range byPlace[ring.Service] {
			lineSets = append(lineSets, []row{saml, service})
		}
	}
	for _, service := range byPlace[ring.Service] {
		lineSets = append(lineSets, []row{service})
	}
	empty := func() []row {
		out := make([]row, 0, 5)
		for place := ring.Anyone; place <= ring.People; place++ {
			out = append(out, row{place: place, state: ring.StateExact})
		}
		return out
	}
	headlines := 0
	check := func(rings, lines []row) string {
		h := plain(headline(rings, lines))
		budget := headlineBudget
		if h == "Nothing outside your company can assume this role." {
			budget = emptyRingsBudget
		}
		if words(h) > budget || strings.Contains(" "+strings.ToLower(h)+" ", " only ") {
			t.Errorf("the headline %q is %d words, over %d, or says only", h, words(h), budget)
		}
		// every line beside the rings is named: by its class beside a ring,
		// by its own population when it is the headline's whole subject
		for _, l := range lines {
			class := map[ring.Place]string{ring.SAML: "SAML", ring.Service: "cloud service"}[l.place]
			if !strings.Contains(h, class) && !strings.HasPrefix(h, rowWords(l)[0].Text) {
				t.Errorf("the headline %q omits the line %s", h, l.place)
			}
		}
		headlines++
		return h
	}
	for _, lines := range lineSets {
		for _, place := range []ring.Place{ring.Anyone, ring.Platform, ring.Outsider} {
			for _, r := range byPlace[place] {
				if len(r.grants) == 0 {
					continue
				}
				rings := empty()
				rings[place] = r
				check(rings, lines)
			}
		}
		check(empty(), lines)
	}
	for _, place := range []ring.Place{ring.Yours, ring.People} {
		for _, r := range byPlace[place] {
			rings := empty()
			rings[place] = r
			check(rings, nil)
		}
	}
	if h := check(empty(), nil); h != "Nothing outside your company can assume this role." {
		t.Errorf("no ring and no line reached: %q", h)
	}
	if h := plain(noStatementWords()); words(h) > headlineBudget {
		t.Errorf("the headline of a document with no statement %q is %d words, over %d", h, words(h), headlineBudget)
	}
	for place := ring.Anyone; place <= ring.Service; place++ {
		reached := 0
		for _, r := range byPlace[place] {
			if len(r.grants) > 0 {
				reached++
			}
		}
		if reached == 0 {
			t.Errorf("no row at %s holds a grant; its sentences went uncounted", place)
		}
	}
	if headlines < 150 || questions < 100 {
		t.Fatalf("%d headlines and %d questions counted; the budgets were held over too little", headlines, questions)
	}
	t.Logf("%d rows, %d headlines and %d questions within their budgets", len(rows), headlines, questions)
}

// TestAServiceGrantActsForWhoeverCanMakeItAct: an unconstrained grant to a
// service admits the service, acting for whoever can make it act, which is
// who a service's grant lets in: no service issues a token, so no sentence
// says the grant admits every identity a service issues one to. The phrase
// is marked beyond on an Allow, as every unconstrained identity is, since
// nothing read bounds who can make the service act; a Deny's is not marked,
// and a statement whose effect could not be read says it may admit. Its
// caption says who can make the service act is not read, never that the set
// is known exactly or that no construct went unevaluated: who can make the
// service act is the construct nobody evaluated. The sweep asks every trust
// policy of testdata's policies, grants and rings, and counts what it asked.
func TestAServiceGrantActsForWhoeverCanMakeItAct(t *testing.T) {
	read := func(path string) []byte {
		raw, err := os.ReadFile(filepath.Join(testdata, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	one := func(effect, service string) []byte {
		return policyOf(`{"Sid":"OneService","Effect":"` + effect + `","Principal":{"Service":"` + service + `"},"Action":"sts:AssumeRole"}`)
	}
	const (
		notRead = "Who can make the service act, or receives its session, is not read: who gets in through it is not known."
		aDeny   = "A Deny subtracts from what the Allow statements admit; it admits nobody by itself."
	)
	cases := []struct {
		name, sid string
		doc       []byte
		want      string
		mark      string
		caption   string
	}{
		{"policy 11", "ServicePrincipal", read("policies/11-principal-shapes.json"), "This role admits ec2.amazonaws.com, acting for whoever can make it act: no condition constrains this statement.", "beyond", notRead},
		{"policy 22", "DenyTheCognitoService", read("policies/22-service-and-federated-share-a-host.json"), "This role refuses cognito-identity.amazonaws.com, acting for whoever can make it act: no condition constrains this statement.", "", aDeny},
		{"ring 21", "ServiceAssumes", read("rings/21-service-without-source-account/aws.json"), "This role admits sns.amazonaws.com, acting for whoever can make it act: no condition constrains this statement.", "beyond", notRead},
		{"a service the table lists", "OneService", one("Allow", "RolesAnywhere.amazonaws.com"), "This role admits rolesanywhere.amazonaws.com, acting for whoever can make it act: no condition constrains this statement.", "beyond", notRead},
		{"an effect not read", "OneService", one("Maybe", "sns.amazonaws.com"), "This statement, whose effect could not be read, may admit sns.amazonaws.com, acting for whoever can make it act: no condition constrains this statement.", "", notRead},
	}
	for _, c := range cases {
		a := AnswerOf(c.doc)
		i := slices.IndexFunc(a.Grants, func(g Grant) bool { return g.Sid == c.sid })
		if i < 0 {
			t.Fatalf("%s: no grant of %s", c.name, c.sid)
		}
		g := a.Grants[i]
		if g.Sentence != c.want || len(g.Spans) != 3 || g.Spans[1].Mark != c.mark {
			t.Errorf("%s: %q, the phrase marked %q; want %q, marked %q", c.name, g.Sentence, g.Spans[min(1, len(g.Spans)-1)].Mark, c.want, c.mark)
		}
		if g.Caption != c.caption {
			t.Errorf("%s: captioned %q, want %q", c.name, g.Caption, c.caption)
		}
	}
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		docs[name], _ = ringsCase(t, name)
	}
	examined := 0
	for name, doc := range docs {
		for _, g := range AnswerOf(doc).Grants {
			if !strings.HasPrefix(g.Issuer, aws.ServiceIssuerPrefix) {
				continue
			}
			examined++
			unconstrained := g.Top && g.Exact && !g.Empty
			if strings.Contains(g.Sentence, "issues a token") || unconstrained && !strings.Contains(g.Sentence, ", acting for whoever can make it act: ") {
				t.Errorf("%s: grant %d on %s says %q", name, g.Number, g.Issuer, g.Sentence)
			}
			if strings.Contains(g.Caption, "known exactly") || strings.Contains(g.Caption, "no construct went unevaluated") {
				t.Errorf("%s: grant %d on %s says %q and is captioned %q", name, g.Number, g.Issuer, g.Sentence, g.Caption)
			}
		}
	}
	// the policies and grants hold two service grants and the rings cases
	// sixteen; fewer than that and the sweep has lost its inputs
	if examined < 18 {
		t.Fatalf("%d service grants examined; the sweep held over too little", examined)
	}
	t.Logf("%d service grants examined", examined)
}

// TestTheRefusalsAreWorded: every reason a declared line is refused has
// words of its own, and a reason this version does not know says so.
func TestTheRefusalsAreWorded(t *testing.T) {
	seen := map[string]bool{}
	for r := ring.NotUTF8; r <= ring.NotAnIssuerURL; r++ {
		w := refusalWords(r)
		if w == "" || seen[w] || strings.Contains(w, "does not know") {
			t.Errorf("%s is worded %q", r, w)
		}
		seen[w] = true
	}
	if w := refusalWords(ring.Reason(99)); w != "not read, for a reason this version does not know: reason(99)" {
		t.Errorf("an unknown reason is worded %q", w)
	}
}

// TestTheHeadlineCountsWhatTheLabelCounts: when the platform ring is the
// outermost reached, the headline and the ring's label on the same first
// screen count the same platforms. A ring holding platforms a grant lets in
// for certain beside platforms it does not is headed by a range, from the
// certain ones, of which "can" is said, to the label's count, whose excess
// is marked unknown; any other platform ring is headed by its label.
func TestTheHeadlineCountsWhatTheLabelCounts(t *testing.T) {
	empty := func() []row {
		out := make([]row, 0, 5)
		for place := ring.Anyone; place <= ring.People; place++ {
			out = append(out, row{place: place, state: ring.StateExact})
		}
		return out
	}
	mixed := 0
	for _, r := range budgetRows(t) {
		if r.place != ring.Platform || len(r.grants) == 0 {
			continue
		}
		rings := empty()
		rings[ring.Platform] = r
		h := headline(rings, nil)
		sure := map[string]bool{}
		all := map[string]bool{}
		for _, p := range r.populations() {
			all[p.grant.platform] = true
			sure[p.grant.platform] = sure[p.grant.platform] || p.State == ring.StateExact
		}
		certain := 0
		for _, s := range sure {
			if s {
				certain++
			}
		}
		l := label(r)
		if certain == 0 || certain == len(all) {
			if !strings.HasPrefix(plain(h), l+" ") {
				t.Errorf("%d platforms, %d of them certain: the headline %q is not headed by the label %q", len(all), certain, plain(h), l)
			}
			continue
		}
		mixed++
		upper := "-" + strconv.Itoa(len(all))
		if l != "Anyone on "+strconv.Itoa(len(all))+" platforms" || !strings.HasPrefix(plain(h), "Anyone on "+strconv.Itoa(certain)+upper+" platforms can assume this role") {
			t.Errorf("%d platforms, %d of them certain: the headline %q does not count what the label %q counts", len(all), certain, plain(h), l)
			continue
		}
		if i := slices.IndexFunc(h, func(s Span) bool { return s.Text == upper }); i < 0 || h[i].Mark != "unknown" {
			t.Errorf("%d platforms, %d of them certain: the uncertain count is not marked unknown in %+v", len(all), certain, h)
		}
	}
	if mixed < 10 {
		t.Fatalf("%d platform rings mixed certain and uncertain platforms; the headline was held over too few", mixed)
	}
}

// TestALineIsNamedOnceForHeadlineAndRow: when a line beside the rings is
// the whole of what the headline names, the headline names its population
// in exactly the words the line's own row leads with, for every population
// a line can hold: the face of "*", one provider or service, and several.
func TestALineIsNamedOnceForHeadlineAndRow(t *testing.T) {
	empty := make([]row, 0, 5)
	for place := ring.Anyone; place <= ring.People; place++ {
		empty = append(empty, row{place: place, state: ring.StateExact})
	}
	compared := 0
	for _, r := range budgetRows(t) {
		if r.place.Ring() {
			continue
		}
		h, own := headline(empty, []row{r}), rowWords(r)
		if h[0].Text != own[0].Text || h[0].Mark != own[0].Mark {
			t.Errorf("%s: the headline names %+v, the row %+v", r.place, h[0], own[0])
		}
		compared++
	}
	if compared < 6 {
		t.Fatalf("%d lines compared; every population a line can hold was not", compared)
	}
}
