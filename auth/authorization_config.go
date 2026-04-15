package auth

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wonderivan/logger"
	"sigs.k8s.io/yaml"
)

const (
	authzScopeAll        = "all"
	authzScopeCluster    = "cluster"
	authzScopeNamespaced = "namespaced"
)

var (
	// AuthorizationConfigPath is the mounted config file used by the authorization webhook.
	AuthorizationConfigPath string
	// AuthorizationCacheTTL controls how long the webhook keeps the parsed policy in memory.
	AuthorizationCacheTTL time.Duration
)

type AuthorizationWebhookConfig struct {
	APIVersion string                    `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string                    `json:"kind,omitempty" yaml:"kind,omitempty"`
	Users      []AuthorizationUserPolicy `json:"users,omitempty" yaml:"users,omitempty"`
}

type AuthorizationUserPolicy struct {
	Username           string                      `json:"username,omitempty" yaml:"username,omitempty"`
	ProtectedResources []AuthorizationResourceRule `json:"protectedResources,omitempty" yaml:"protectedResources,omitempty"`
	Whitelist          []AuthorizationResourceRule `json:"whitelist,omitempty" yaml:"whitelist,omitempty"`
}

type AuthorizationResourceRule struct {
	APIGroups     []string `json:"apiGroups,omitempty" yaml:"apiGroups,omitempty"`
	Resources     []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	Subresources  []string `json:"subresources,omitempty" yaml:"subresources,omitempty"`
	Verbs         []string `json:"verbs,omitempty" yaml:"verbs,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	ResourceNames []string `json:"resourceNames,omitempty" yaml:"resourceNames,omitempty"`
	Scope         string   `json:"scope,omitempty" yaml:"scope,omitempty"`
}

type authorizationConfigStore struct {
	lock       sync.RWMutex
	config     *AuthorizationWebhookConfig
	lastLoadAt time.Time
	lastErr    error
}

var authzConfigStore = &authorizationConfigStore{}

func (s *authorizationConfigStore) Load() (*AuthorizationWebhookConfig, error) {
	s.lock.RLock()
	if s.config != nil && s.cacheFresh() {
		cfg := s.config
		err := s.lastErr
		s.lock.RUnlock()
		return cfg, err
	}
	s.lock.RUnlock()

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.config != nil && s.cacheFresh() {
		return s.config, s.lastErr
	}

	cfg, err := loadAuthorizationConfig(AuthorizationConfigPath)
	s.lastLoadAt = time.Now()
	if err != nil {
		s.lastErr = err
		if s.config != nil {
			logger.Warn("authorization webhook reload failed, keep last valid config: %v", err)
			return s.config, err
		}
		s.config = &AuthorizationWebhookConfig{}
		return s.config, err
	}

	s.config = cfg
	s.lastErr = nil
	return s.config, nil
}

func (s *authorizationConfigStore) cacheFresh() bool {
	if AuthorizationCacheTTL <= 0 {
		return false
	}
	return time.Since(s.lastLoadAt) < AuthorizationCacheTTL
}

func loadAuthorizationConfig(path string) (*AuthorizationWebhookConfig, error) {
	if strings.TrimSpace(path) == "" {
		return &AuthorizationWebhookConfig{}, nil
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AuthorizationWebhookConfig{}, nil
		}
		return nil, err
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return &AuthorizationWebhookConfig{}, nil
	}

	cfg := &AuthorizationWebhookConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse authorization config %q failed: %v", path, err)
	}

	normalizeAuthorizationConfig(cfg)
	return cfg, nil
}

func normalizeAuthorizationConfig(cfg *AuthorizationWebhookConfig) {
	cfg.APIVersion = trimOrDefault(cfg.APIVersion, "fist.sealyun.com/v1alpha1")
	cfg.Kind = trimOrDefault(cfg.Kind, "AuthorizationWebhookConfig")

	normalizedUsers := make([]AuthorizationUserPolicy, 0, len(cfg.Users))
	for _, user := range cfg.Users {
		user.Username = strings.TrimSpace(user.Username)
		if user.Username == "" {
			continue
		}
		user.ProtectedResources = normalizeAuthorizationRules(user.ProtectedResources)
		user.Whitelist = normalizeAuthorizationRules(user.Whitelist)
		normalizedUsers = append(normalizedUsers, user)
	}
	cfg.Users = normalizedUsers
}

func normalizeAuthorizationRules(rules []AuthorizationResourceRule) []AuthorizationResourceRule {
	normalizedRules := make([]AuthorizationResourceRule, 0, len(rules))
	for _, rule := range rules {
		rule.Scope = normalizeScope(rule.Scope)
		rule.APIGroups = normalizeLowerList(rule.APIGroups)
		rule.Resources = normalizeLowerList(rule.Resources)
		rule.Subresources = normalizeLowerList(rule.Subresources)
		rule.Verbs = normalizeLowerList(rule.Verbs)
		rule.Namespaces = normalizeList(rule.Namespaces)
		rule.ResourceNames = normalizeList(rule.ResourceNames)
		if len(rule.Resources) == 0 {
			continue
		}
		normalizedRules = append(normalizedRules, rule)
	}
	return normalizedRules
}

func normalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", "*", authzScopeAll:
		return authzScopeAll
	case authzScopeCluster:
		return authzScopeCluster
	case authzScopeNamespaced, "namespace":
		return authzScopeNamespaced
	default:
		return strings.ToLower(strings.TrimSpace(scope))
	}
}

func normalizeLowerList(values []string) []string {
	normalized := normalizeList(values)
	for i := range normalized {
		normalized[i] = strings.ToLower(normalized[i])
	}
	return normalized
}

func normalizeList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	return normalized
}

func trimOrDefault(value, defaultValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}
	return value
}
