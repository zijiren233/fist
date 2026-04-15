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
				Username: "alice",
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
				User: "bob",
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

func contains(value, expected string) bool {
	return strings.Contains(value, expected)
}
