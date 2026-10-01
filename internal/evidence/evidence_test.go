package evidence

import (
	"testing"
	"time"
)

func TestDigestIgnoresFetchedAt(t *testing.T) {
	body := []byte(`{"Role":{"RoleName":"deploy"}}`)
	a := New("iam:GetRole", `{"RoleName":"deploy"}`, StatusOK, body, time.Unix(0, 0))
	b := New("iam:GetRole", `{"RoleName":"deploy"}`, StatusOK, body, time.Unix(1<<31, 0))
	if a.SHA256 != b.SHA256 {
		t.Fatalf("digest must not depend on FetchedAt: %s != %s", a.SHA256, b.SHA256)
	}
}

func TestDeniedIsNotConclusive(t *testing.T) {
	for _, s := range []Status{StatusDenied, StatusThrottled, StatusUnsupported} {
		if s.Conclusive() {
			t.Fatalf("%s must not be conclusive: a refused call is not an empty result", s)
		}
	}
	if !StatusOK.Conclusive() || !StatusNotConfigured.Conclusive() {
		t.Fatal("ok and not_configured are conclusive")
	}
}
