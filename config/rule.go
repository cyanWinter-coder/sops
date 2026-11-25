package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ruleKind describes how a creation rule matches file paths.
type ruleKind int

const (
	// regexRule is the legacy rule type, matched with path_regex.
	regexRule ruleKind = iota
	// prefixRule matches by directory prefix (the "path" field).
	prefixRule
	// catchAllRule has neither path nor path_regex and matches every file.
	catchAllRule
)

// compiledCreationRule is a creation rule validated and precompiled at load
// time. Index is the zero-based position of the rule in the config file,
// used to point users at the offending rule in error messages.
type compiledCreationRule struct {
	index      int
	kind       ruleKind
	path       string // normalized prefix, without a trailing separator
	regex      *regexp.Regexp
	extensions []string // normalized to lower case, each including the leading dot
	rule       creationRule
}

// RuleMatch describes the creation rule that matched a file path.
type RuleMatch struct {
	// Index is the zero-based position of the rule in creation_rules.
	Index int
	// Path is the rule's "path" prefix, or "" for regex/catch-all rules.
	Path string
	// PathRegex is the rule's "path_regex", or "" for prefix rules.
	PathRegex string
	// Extensions is the rule's file extension constraint (empty means any).
	Extensions []string
}

// matchable reports whether the rule applies to filePath. filePath must be
// relative to the config file directory and cleaned.
func (r *compiledCreationRule) matchable(filePath string) bool {
	if !r.extensionMatches(filePath) {
		return false
	}
	switch r.kind {
	case prefixRule:
		return hasPathPrefix(filePath, r.path)
	case regexRule:
		return r.regex.MatchString(filePath)
	case catchAllRule:
		return true
	default:
		return false
	}
}

// extensionMatches enforces the rule's extension constraint. A rule without
// an extension constraint matches every file.
func (r *compiledCreationRule) extensionMatches(filePath string) bool {
	if len(r.extensions) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return false
	}
	for _, allowed := range r.extensions {
		if ext == allowed {
			return true
		}
	}
	return false
}

// hasPathPrefix reports whether filePath is located inside the directory
// prefix, matching on path segments so that prefix "foo/bar" does not match
// "foo/barbaz". An empty prefix matches everything (the config root).
func hasPathPrefix(filePath, prefix string) bool {
	if prefix == "" || prefix == "." {
		return true
	}
	if filePath == prefix {
		return true
	}
	return strings.HasPrefix(filePath, prefix+string(filepath.Separator))
}

// moreSpecificThan implements the stable tie-break between two prefix rules
// that both match: the longer (more specific) prefix wins, and on equal
// length the earlier declaration wins.
func (r *compiledCreationRule) moreSpecificThan(other *compiledCreationRule) bool {
	if len(r.path) != len(other.path) {
		return len(r.path) > len(other.path)
	}
	return r.index < other.index
}

// compileCreationRules validates every creation rule up front: path_regex is
// compiled, path and extensions are normalized, and key references are parsed
// so that a broken rule fails at load time with its position, instead of at
// first use.
func compileCreationRules(rules []creationRule, kmsEncryptionContext map[string]*string) ([]*compiledCreationRule, error) {
	compiled := make([]*compiledCreationRule, 0, len(rules))
	var errs []error
	for i := range rules {
		r := &rules[i]
		cr := &compiledCreationRule{index: i, rule: *r}

		normalizedPath := normalizeRulePath(r.Path)
		exts, err := normalizeExtensions(r.Extensions)
		if err != nil {
			errs = append(errs, fmt.Errorf("creation_rules[%d]: %w", i, err))
		}
		cr.path = normalizedPath
		cr.extensions = exts

		switch {
		case r.Path != "" && r.PathRegex != "":
			errs = append(errs, fmt.Errorf("creation_rules[%d]: path and path_regex are mutually exclusive", i))
			continue
		case r.Path != "":
			cr.kind = prefixRule
		case r.PathRegex != "":
			cr.kind = regexRule
			reg, err := regexp.Compile(r.PathRegex)
			if err != nil {
				errs = append(errs, fmt.Errorf("creation_rules[%d]: can not compile path_regex %q: %w", i, r.PathRegex, err))
				continue
			}
			cr.regex = reg
		default:
			cr.kind = catchAllRule
		}

		if err := validateRuleKeys(r, kmsEncryptionContext); err != nil {
			errs = append(errs, fmt.Errorf("creation_rules[%d]: %w", i, err))
			continue
		}

		compiled = append(compiled, cr)
	}
	if len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	return compiled, nil
}

// normalizeRulePath cleans a path prefix and forces slash separators so that
// rules and file paths compare identically on every platform.
func normalizeRulePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(filepath.Clean(p))
	p = strings.TrimPrefix(p, "./")
	return strings.TrimSuffix(p, "/")
}

// normalizeExtensions normalizes the extension constraint to lower-case
// extensions including the leading dot, accepting values with or without it.
func normalizeExtensions(exts []string) ([]string, error) {
	if len(exts) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(exts))
	seen := make(map[string]bool)
	for _, ext := range exts {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			return nil, fmt.Errorf("extensions must not contain empty values")
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		ext = strings.ToLower(ext)
		if !seen[ext] {
			seen[ext] = true
			normalized = append(normalized, ext)
		}
	}
	return normalized, nil
}

// validateRuleKeys parses every key reference in a rule without contacting
// any backend. Rules without any key references remain legal (for example
// suffix-only rules and rules with empty key groups).
func validateRuleKeys(r *creationRule, kmsEncryptionContext map[string]*string) error {
	if _, err := getKeyGroupsFromCreationRule(r, kmsEncryptionContext); err != nil {
		return err
	}
	return nil
}

// matchCreationRule selects the rule that applies to filePath.
//
// Prefix rules (the "path" field) take precedence over legacy path_regex
// rules. Among matching prefix rules the most specific one wins: longest
// prefix first, then declaration order. Only when no prefix rule matches are
// path_regex rules evaluated, preserving their historical first-match
// semantics, followed by the catch-all rule.
func matchCreationRule(rules []*compiledCreationRule, filePath string) (*compiledCreationRule, error) {
	var prefixMatch *compiledCreationRule
	var regexMatch *compiledCreationRule
	var catchAll *compiledCreationRule

	for _, r := range rules {
		if !r.matchable(filePath) {
			continue
		}
		switch r.kind {
		case prefixRule:
			if prefixMatch == nil || r.moreSpecificThan(prefixMatch) {
				prefixMatch = r
			}
		case regexRule:
			if regexMatch == nil {
				regexMatch = r
			}
		case catchAllRule:
			if catchAll == nil {
				catchAll = r
			}
		}
	}

	switch {
	case prefixMatch != nil:
		return prefixMatch, nil
	case regexMatch != nil:
		return regexMatch, nil
	case catchAll != nil:
		return catchAll, nil
	default:
		return nil, fmt.Errorf("error loading config: no matching creation rules found for %q", filePath)
	}
}

// joinErrors combines validation errors so all problems in the config file
// are reported in one pass, each prefixed with its rule position.
func joinErrors(errs []error) error {
	messages := make([]string, len(errs))
	for i, err := range errs {
		messages[i] = err.Error()
	}
	return fmt.Errorf("error loading config: %s", strings.Join(messages, "; "))
}
