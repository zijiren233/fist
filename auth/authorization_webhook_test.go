package auth

import (
	"strings"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestEvaluateAuthorizationReview(t *testing.T) {
	cfg := &AuthorizationWebhookConfig{
		Users: []AuthorizationUserPolicy{
			{
				Usernames: []string{"alice", "bob"},
				ProtectedResources: []AuthorizationResourceRule{
					{
						APIGroups:  []string{""},
						Resources:  []string{"secrets"},
						Verbs:      []string{"get", "list", "watch", "create", "update", "patch", "delete"},
						Scope:      authzScopeNamespaced,
						Namespaces: []string{"dev", "prod"},
					},
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"clusterroles"},
						Verbs:     []string{"get", "list"},
						Scope:     authzScopeCluster,
					},
				},
				Whitelist: []AuthorizationResourceRule{
					{
						APIGroups:  []string{""},
						Resources:  []string{"secrets"},
						Verbs:      []string{"get", "list"},
						Scope:      authzScopeNamespaced,
						Namespaces: []string{"dev"},
					},
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"clusterroles"},
						Verbs:     []string{"get"},
						Scope:     authzScopeCluster,
					},
				},
			},
		},
	}
	normalizeAuthorizationConfig(cfg)

	tests := []struct {
		name      string
		review    authorizationReview
		allowed   bool
		denied    bool
		reasonHas string
	}{
		{
			name: "user not configured returns no opinion",
			review: authorizationReview{
				User: "charlie",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
					Namespace: "dev",
				},
			},
			reasonHas: "not configured",
		},
		{
			name: "protected namespaced resource allowed by whitelist",
			review: authorizationReview{
				User: "alice",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
					Namespace: "dev",
				},
			},
			allowed:   true,
			reasonHas: "whitelist",
		},
		{
			name: "second configured username in same policy is also allowed by whitelist",
			review: authorizationReview{
				User: "bob",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
					Namespace: "dev",
				},
			},
			allowed:   true,
			reasonHas: "whitelist",
		},
		{
			name: "protected namespaced resource denied outside whitelist namespace",
			review: authorizationReview{
				User: "alice",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
					Namespace: "prod",
				},
			},
			denied:    true,
			reasonHas: "blocked",
		},
		{
			name: "protected cluster resource denied when verb not whitelisted",
			review: authorizationReview{
				User: "alice",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "list",
					Group:    "rbac.authorization.k8s.io",
					Resource: "clusterroles",
				},
			},
			denied:    true,
			reasonHas: "blocked",
		},
		{
			name: "protected cluster resource allowed by whitelist",
			review: authorizationReview{
				User: "alice",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "get",
					Group:    "rbac.authorization.k8s.io",
					Resource: "clusterroles",
				},
			},
			allowed:   true,
			reasonHas: "whitelist",
		},
		{
			name: "non protected resource returns no opinion",
			review: authorizationReview{
				User: "alice",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "get",
					Group:     "",
					Resource:  "configmaps",
					Namespace: "dev",
				},
			},
			reasonHas: "not managed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := evaluateAuthorizationReview(cfg, tt.review)
			if status.Allowed != tt.allowed {
				t.Fatalf("allowed = %v, want %v", status.Allowed, tt.allowed)
			}
			if status.Denied != tt.denied {
				t.Fatalf("denied = %v, want %v", status.Denied, tt.denied)
			}
			if tt.reasonHas != "" && !contains(status.Reason, tt.reasonHas) {
				t.Fatalf("reason = %q, want substring %q", status.Reason, tt.reasonHas)
			}
		})
	}
}

func TestEvaluateAuthorizationReviewLegacyUsernameStillWorks(t *testing.T) {
	cfg := &AuthorizationWebhookConfig{
		Users: []AuthorizationUserPolicy{
			{
				Username: "legacy-user",
				ProtectedResources: []AuthorizationResourceRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"get"},
					},
				},
			},
		},
	}
	normalizeAuthorizationConfig(cfg)

	status := evaluateAuthorizationReview(cfg, authorizationReview{
		User: "legacy-user",
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Verb:      "get",
			Group:     "",
			Resource:  "secrets",
			Namespace: "default",
		},
	})

	if !status.Denied {
		t.Fatalf("denied = %v, want true", status.Denied)
	}
	if !contains(status.Reason, "blocked") {
		t.Fatalf("reason = %q, want blocked", status.Reason)
	}
}

func TestMergeUserPoliciesAcrossEntriesAndAliases(t *testing.T) {
	cfg := &AuthorizationWebhookConfig{
		Users: []AuthorizationUserPolicy{
			{
				Usernames: []string{"alice", "bob"},
				ProtectedResources: []AuthorizationResourceRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"get"},
					},
				},
			},
			{
				Username: "bob",
				Whitelist: []AuthorizationResourceRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"get"},
					},
				},
			},
		},
	}
	normalizeAuthorizationConfig(cfg)

	status := evaluateAuthorizationReview(cfg, authorizationReview{
		User: "bob",
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Verb:      "get",
			Group:     "",
			Resource:  "secrets",
			Namespace: "default",
		},
	})

	if !status.Allowed {
		t.Fatalf("allowed = %v, want true", status.Allowed)
	}
	if !contains(status.Reason, "whitelist") {
		t.Fatalf("reason = %q, want whitelist", status.Reason)
	}
}

func TestMatchesAuthorizationRuleSubresource(t *testing.T) {
	rule := AuthorizationResourceRule{
		APIGroups:    []string{""},
		Resources:    []string{"pods"},
		Subresources: []string{"log"},
		Verbs:        []string{"get"},
		Scope:        authzScopeNamespaced,
	}
	normalizeAuthorizationConfig(&AuthorizationWebhookConfig{
		Users: []AuthorizationUserPolicy{{Username: "alice", ProtectedResources: []AuthorizationResourceRule{rule}}},
	})

	if !matchesAuthorizationRule(rule, &authorizationv1.ResourceAttributes{
		Verb:        "get",
		Group:       "",
		Resource:    "pods",
		Subresource: "log",
		Namespace:   "default",
	}) {
		t.Fatal("expected pods/log request to match")
	}

	if matchesAuthorizationRule(rule, &authorizationv1.ResourceAttributes{
		Verb:      "get",
		Group:     "",
		Resource:  "pods",
		Namespace: "default",
	}) {
		t.Fatal("expected pods primary resource request not to match subresource rule")
	}
}

func TestNormalizeAuthorizationConfigUsernames(t *testing.T) {
	cfg := &AuthorizationWebhookConfig{
		Users: []AuthorizationUserPolicy{
			{
				Username:  " alice ",
				Usernames: []string{"bob", "alice", " bob ", ""},
				ProtectedResources: []AuthorizationResourceRule{
					{
						Resources: []string{" secrets "},
						Verbs:     []string{" GET "},
					},
				},
			},
			{
				Usernames: []string{" ", ""},
			},
		},
	}

	normalizeAuthorizationConfig(cfg)

	if len(cfg.Users) != 1 {
		t.Fatalf("users len = %d, want 1", len(cfg.Users))
	}
	if len(cfg.Users[0].Usernames) != 2 {
		t.Fatalf("usernames len = %d, want 2", len(cfg.Users[0].Usernames))
	}
	if cfg.Users[0].Usernames[0] != "alice" || cfg.Users[0].Usernames[1] != "bob" {
		t.Fatalf("usernames = %#v, want [alice bob]", cfg.Users[0].Usernames)
	}
	if cfg.Users[0].Username != "" {
		t.Fatalf("username = %q, want empty for multi-username policy", cfg.Users[0].Username)
	}
	if cfg.Users[0].ProtectedResources[0].Resources[0] != "secrets" {
		t.Fatalf("resource = %q, want secrets", cfg.Users[0].ProtectedResources[0].Resources[0])
	}
	if cfg.Users[0].ProtectedResources[0].Verbs[0] != "get" {
		t.Fatalf("verb = %q, want get", cfg.Users[0].ProtectedResources[0].Verbs[0])
	}
}

func contains(value, expected string) bool {
	return strings.Contains(value, expected)
}
