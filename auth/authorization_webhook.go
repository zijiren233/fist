package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/emicklei/go-restful"
	"github.com/wonderivan/logger"
	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type authorizationReview struct {
	User               string
	ResourceAttributes *authorizationv1.ResourceAttributes
}

func handleSubjectAccessReview(request *restful.Request, response *restful.Response) {
	body, err := ioutil.ReadAll(request.Request.Body)
	if err != nil {
		writeAuthorizationWebhookError(response, http.StatusBadRequest, fmt.Errorf("read subjectaccessreview failed: %v", err))
		return
	}

	typeMeta := metav1.TypeMeta{}
	if len(body) != 0 {
		if err := json.Unmarshal(body, &typeMeta); err != nil {
			writeAuthorizationWebhookError(response, http.StatusBadRequest, fmt.Errorf("decode subjectaccessreview type failed: %v", err))
			return
		}
	}

	if typeMeta.Kind != "" && typeMeta.Kind != "SubjectAccessReview" {
		writeAuthorizationWebhookError(response, http.StatusBadRequest, fmt.Errorf("unsupported kind %q", typeMeta.Kind))
		return
	}

	cfg, cfgErr := authzConfigStore.Load()

	switch typeMeta.APIVersion {
	case "", authorizationv1.SchemeGroupVersion.String():
		review := &authorizationv1.SubjectAccessReview{}
		if err := json.Unmarshal(body, review); err != nil {
			writeAuthorizationWebhookError(response, http.StatusBadRequest, fmt.Errorf("decode v1 subjectaccessreview failed: %v", err))
			return
		}
		status := evaluateAuthorizationReview(cfg, authorizationReview{
			User:               review.Spec.User,
			ResourceAttributes: review.Spec.ResourceAttributes,
		})
		if cfgErr != nil {
			status.EvaluationError = cfgErr.Error()
		}
		writeAuthorizationV1Response(response, review.TypeMeta, status)
	case authorizationv1beta1.SchemeGroupVersion.String():
		review := &authorizationv1beta1.SubjectAccessReview{}
		if err := json.Unmarshal(body, review); err != nil {
			writeAuthorizationWebhookError(response, http.StatusBadRequest, fmt.Errorf("decode v1beta1 subjectaccessreview failed: %v", err))
			return
		}
		v1Review := authorizationReview{User: review.Spec.User}
		if review.Spec.ResourceAttributes != nil {
			v1Review.ResourceAttributes = &authorizationv1.ResourceAttributes{
				Namespace:   review.Spec.ResourceAttributes.Namespace,
				Verb:        review.Spec.ResourceAttributes.Verb,
				Group:       review.Spec.ResourceAttributes.Group,
				Version:     review.Spec.ResourceAttributes.Version,
				Resource:    review.Spec.ResourceAttributes.Resource,
				Subresource: review.Spec.ResourceAttributes.Subresource,
				Name:        review.Spec.ResourceAttributes.Name,
			}
		}
		status := evaluateAuthorizationReview(cfg, v1Review)
		if cfgErr != nil {
			status.EvaluationError = cfgErr.Error()
		}
		writeAuthorizationV1Beta1Response(response, review.TypeMeta, status)
	default:
		writeAuthorizationWebhookError(response, http.StatusBadRequest, fmt.Errorf("unsupported apiVersion %q", typeMeta.APIVersion))
	}
}

func writeAuthorizationWebhookError(response *restful.Response, code int, err error) {
	logger.Error(err)
	_ = response.WriteErrorString(code, err.Error())
}

func writeAuthorizationV1Response(response *restful.Response, typeMeta metav1.TypeMeta, status authorizationv1.SubjectAccessReviewStatus) {
	if typeMeta.APIVersion == "" {
		typeMeta.APIVersion = authorizationv1.SchemeGroupVersion.String()
	}
	if typeMeta.Kind == "" {
		typeMeta.Kind = "SubjectAccessReview"
	}
	response.AddHeader("Content-Type", "application/json")
	_ = response.WriteEntity(&authorizationv1.SubjectAccessReview{
		TypeMeta: typeMeta,
		Status:   status,
	})
}

func writeAuthorizationV1Beta1Response(response *restful.Response, typeMeta metav1.TypeMeta, status authorizationv1.SubjectAccessReviewStatus) {
	if typeMeta.APIVersion == "" {
		typeMeta.APIVersion = authorizationv1beta1.SchemeGroupVersion.String()
	}
	if typeMeta.Kind == "" {
		typeMeta.Kind = "SubjectAccessReview"
	}
	response.AddHeader("Content-Type", "application/json")
	_ = response.WriteEntity(&authorizationv1beta1.SubjectAccessReview{
		TypeMeta: typeMeta,
		Status: authorizationv1beta1.SubjectAccessReviewStatus{
			Allowed:         status.Allowed,
			Denied:          status.Denied,
			Reason:          status.Reason,
			EvaluationError: status.EvaluationError,
		},
	})
}

func evaluateAuthorizationReview(cfg *AuthorizationWebhookConfig, review authorizationReview) authorizationv1.SubjectAccessReviewStatus {
	if review.ResourceAttributes == nil {
		return noOpinionStatus("secondary authorization skipped non-resource request")
	}

	attr := normalizedResourceAttributes(review.ResourceAttributes)
	policy := mergeUserPolicies(cfg, strings.TrimSpace(review.User))
	if policy == nil {
		return noOpinionStatus("secondary authorization not configured for this user")
	}

	if !matchesAnyAuthorizationRule(policy.ProtectedResources, attr) {
		return noOpinionStatus("request not managed by secondary authorization")
	}

	if matchesAnyAuthorizationRule(policy.Whitelist, attr) {
		status := authorizationv1.SubjectAccessReviewStatus{
			Allowed: true,
			Reason:  "allowed by fist secondary authorization whitelist",
		}
		logger.Info("secondary authorization allowed user %q on %s", review.User, describeResourceAttributes(attr))
		return status
	}

	status := authorizationv1.SubjectAccessReviewStatus{
		Denied: true,
		Reason: fmt.Sprintf("blocked by fist secondary authorization policy: %s", describeResourceAttributes(attr)),
	}
	logger.Warn("secondary authorization denied user %q on %s", review.User, describeResourceAttributes(attr))
	return status
}

func mergeUserPolicies(cfg *AuthorizationWebhookConfig, username string) *AuthorizationUserPolicy {
	if cfg == nil || username == "" {
		return nil
	}

	merged := &AuthorizationUserPolicy{Username: username}
	for _, user := range cfg.Users {
		if user.Username != username {
			continue
		}
		merged.ProtectedResources = append(merged.ProtectedResources, user.ProtectedResources...)
		merged.Whitelist = append(merged.Whitelist, user.Whitelist...)
	}

	if len(merged.ProtectedResources) == 0 && len(merged.Whitelist) == 0 {
		return nil
	}
	return merged
}

func normalizedResourceAttributes(attr *authorizationv1.ResourceAttributes) *authorizationv1.ResourceAttributes {
	if attr == nil {
		return nil
	}
	return &authorizationv1.ResourceAttributes{
		Namespace:   strings.TrimSpace(attr.Namespace),
		Verb:        strings.ToLower(strings.TrimSpace(attr.Verb)),
		Group:       strings.ToLower(strings.TrimSpace(attr.Group)),
		Version:     strings.TrimSpace(attr.Version),
		Resource:    strings.ToLower(strings.TrimSpace(attr.Resource)),
		Subresource: strings.ToLower(strings.TrimSpace(attr.Subresource)),
		Name:        strings.TrimSpace(attr.Name),
	}
}

func matchesAnyAuthorizationRule(rules []AuthorizationResourceRule, attr *authorizationv1.ResourceAttributes) bool {
	for _, rule := range rules {
		if matchesAuthorizationRule(rule, attr) {
			return true
		}
	}
	return false
}

func matchesAuthorizationRule(rule AuthorizationResourceRule, attr *authorizationv1.ResourceAttributes) bool {
	if attr == nil {
		return false
	}
	if !matchesRuleScope(rule.Scope, attr.Namespace) {
		return false
	}
	if !matchesWildcardList(rule.Verbs, attr.Verb, true) {
		return false
	}
	if !matchesWildcardList(rule.APIGroups, attr.Group, true) {
		return false
	}
	if !matchesNamespaceRule(rule.Namespaces, attr.Namespace) {
		return false
	}
	if !matchesRuleResource(rule, attr.Resource, attr.Subresource) {
		return false
	}
	if !matchesResourceNameRule(rule.ResourceNames, attr.Name) {
		return false
	}
	return true
}

func matchesRuleScope(scope, namespace string) bool {
	switch normalizeScope(scope) {
	case authzScopeCluster:
		return namespace == ""
	case authzScopeNamespaced:
		return namespace != ""
	default:
		return true
	}
}

func matchesNamespaceRule(allowedNamespaces []string, namespace string) bool {
	if len(allowedNamespaces) == 0 {
		return true
	}
	if namespace == "" {
		return false
	}
	return matchesWildcardList(allowedNamespaces, namespace, false)
}

func matchesResourceNameRule(allowedNames []string, name string) bool {
	if len(allowedNames) == 0 {
		return true
	}
	if name == "" {
		return containsWildcard(allowedNames)
	}
	return matchesWildcardList(allowedNames, name, false)
}

func matchesRuleResource(rule AuthorizationResourceRule, resource, subresource string) bool {
	for _, pattern := range rule.Resources {
		resourcePattern, subresourcePattern, hasSubresource := splitResourcePattern(pattern)
		if !matchesPattern(resourcePattern, resource) {
			continue
		}
		if hasSubresource {
			if matchesPattern(subresourcePattern, subresource) {
				return true
			}
			continue
		}
		if len(rule.Subresources) != 0 {
			if matchesSubresourceRule(rule.Subresources, subresource) {
				return true
			}
			continue
		}
		if subresource == "" {
			return true
		}
	}
	return false
}

func matchesSubresourceRule(allowedSubresources []string, subresource string) bool {
	if len(allowedSubresources) == 0 {
		return subresource == ""
	}
	if subresource == "" {
		return containsWildcard(allowedSubresources) || containsExact(allowedSubresources, "")
	}
	return matchesWildcardList(allowedSubresources, subresource, false)
}

func matchesWildcardList(patterns []string, actual string, emptyMatchesAll bool) bool {
	if len(patterns) == 0 {
		return emptyMatchesAll
	}
	for _, pattern := range patterns {
		if matchesPattern(pattern, actual) {
			return true
		}
	}
	return false
}

func matchesPattern(pattern, actual string) bool {
	if pattern == "*" {
		return true
	}
	return pattern == actual
}

func splitResourcePattern(pattern string) (string, string, bool) {
	if !strings.Contains(pattern, "/") {
		return pattern, "", false
	}
	parts := strings.SplitN(pattern, "/", 2)
	return parts[0], parts[1], true
}

func containsWildcard(values []string) bool {
	return containsExact(values, "*")
}

func containsExact(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func noOpinionStatus(reason string) authorizationv1.SubjectAccessReviewStatus {
	return authorizationv1.SubjectAccessReviewStatus{
		Allowed: false,
		Denied:  false,
		Reason:  reason,
	}
}

func describeResourceAttributes(attr *authorizationv1.ResourceAttributes) string {
	if attr == nil {
		return "empty request"
	}
	resource := attr.Resource
	if attr.Subresource != "" {
		resource = resource + "/" + attr.Subresource
	}
	if attr.Namespace == "" {
		return fmt.Sprintf("verb=%s group=%q resource=%s", attr.Verb, attr.Group, resource)
	}
	if attr.Name == "" {
		return fmt.Sprintf("verb=%s group=%q resource=%s namespace=%s", attr.Verb, attr.Group, resource, attr.Namespace)
	}
	return fmt.Sprintf("verb=%s group=%q resource=%s namespace=%s name=%s", attr.Verb, attr.Group, resource, attr.Namespace, attr.Name)
}
