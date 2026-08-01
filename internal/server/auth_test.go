package server

import (
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
)

func TestPrincipalSubjectKeyCanonicalizesGroupsAndExtra(t *testing.T) {
	t.Parallel()

	left := &Principal{
		Username: "alice", UID: "uid-1",
		Groups: []string{"system:authenticated", "team-readers"},
		Extra: map[string]authenticationv1.ExtraValue{
			"scopes": {"read", "cluster"},
			"tenant": {"one"},
		},
	}
	right := &Principal{
		Username: "alice", UID: "uid-1",
		Groups: []string{"team-readers", "system:authenticated"},
		Extra: map[string]authenticationv1.ExtraValue{
			"tenant": {"one"},
			"scopes": {"cluster", "read"},
		},
	}
	if left.SubjectKey() != right.SubjectKey() {
		t.Fatalf("subject key changed with group/extra ordering: %q != %q", left.SubjectKey(), right.SubjectKey())
	}

	right.Extra["tenant"] = authenticationv1.ExtraValue{"two"}
	if left.SubjectKey() == right.SubjectKey() {
		t.Fatal("subject key did not change when TokenReview Extra value changed")
	}
}
