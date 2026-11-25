package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempConfig writes contents into a fresh temp dir as .sops.yaml and
// returns its absolute path.
func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, ".sops.yaml")
	require.NoError(t, os.WriteFile(confPath, []byte(contents), 0o600))
	return confPath
}

// futureTime returns a timestamp strictly after "now", used to force cache
// invalidation regardless of filesystem timestamp granularity.
func futureTime() time.Time {
	return time.Now().Add(time.Hour)
}

// prefixConfig exercises directory prefixes of varying specificity. Two
// rules share the same prefix length to make the declaration-order tie-break
// deterministic.
var prefixConfig = []byte(`
creation_rules:
  - path: services/payments
    kms: arn:aws:kms:us-east-1:1:key/payments
  - path: services
    kms: arn:aws:kms:us-east-1:1:key/services
  - path: services/payments-v2
    kms: arn:aws:kms:us-east-1:1:key/payments-v2
  - path: ""
    kms: arn:aws:kms:us-east-1:1:key/root
`)

func TestPrefixRuleMostSpecificWins(t *testing.T) {
	confPath := writeTempConfig(t, string(prefixConfig))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)

	cases := map[string]string{
		"services/payments/secret.yaml":    "arn:aws:kms:us-east-1:1:key/payments",
		"services/payments/nested/a.yaml":  "arn:aws:kms:us-east-1:1:key/payments",
		"services/payments-v2/secret.yaml": "arn:aws:kms:us-east-1:1:key/payments-v2",
		"services/auth/secret.yaml":        "arn:aws:kms:us-east-1:1:key/services",
		"services/secret.yaml":             "arn:aws:kms:us-east-1:1:key/services",
		"top-level.yaml":                   "arn:aws:kms:us-east-1:1:key/root",
		// Segment boundary: services/payments-other must not match the
		// services/payments prefix.
		"services/payments-other/x.yaml": "arn:aws:kms:us-east-1:1:key/services",
	}
	for file, expectedKey := range cases {
		match, err := loaded.MatchRule(filepath.Join(filepath.Dir(confPath), file))
		require.NoError(t, err, file)
		conf, err := loaded.ConfigForFile(filepath.Join(filepath.Dir(confPath), file), nil)
		require.NoError(t, err, file)
		assert.Equal(t, expectedKey, conf.KeyGroups[0][0].ToString(), file)
		assert.GreaterOrEqual(t, match.Index, 0)
	}
}

func TestPrefixTieBreakByDeclarationOrder(t *testing.T) {
	// When two prefix rules have equal length and both match, the rule
	// declared first must win deterministically.
	cfg := []byte(`
creation_rules:
  - path: a/b
    kms: arn:aws:kms:us-east-1:1:key/first
  - path: a/b
    kms: arn:aws:kms:us-east-1:1:key/second
`)
	confPath := writeTempConfig(t, string(cfg))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)

	conf, err := loaded.ConfigForFile(filepath.Join(filepath.Dir(confPath), "a/b/f.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/first", conf.KeyGroups[0][0].ToString())
}

func TestPrefixRulesTakePrecedenceOverRegex(t *testing.T) {
	cfg := []byte(`
creation_rules:
  - path_regex: ".*payments.*"
    kms: arn:aws:kms:us-east-1:1:key/regex
  - path: services/payments
    kms: arn:aws:kms:us-east-1:1:key/prefix
`)
	confPath := writeTempConfig(t, string(cfg))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)

	conf, err := loaded.ConfigForFile(filepath.Join(filepath.Dir(confPath), "services/payments/x.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/prefix", conf.KeyGroups[0][0].ToString())

	// A path only the regex matches still falls through to legacy behavior.
	conf, err = loaded.ConfigForFile(filepath.Join(filepath.Dir(confPath), "other/payments/x.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/regex", conf.KeyGroups[0][0].ToString())
}

func TestMatchRuleIsQueryableAndStableAcrossMoves(t *testing.T) {
	confPath := writeTempConfig(t, string(prefixConfig))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)

	oldPath := filepath.Join(filepath.Dir(confPath), "services/payments/secret.yaml")
	match, err := loaded.MatchRule(oldPath)
	require.NoError(t, err)
	assert.Equal(t, 0, match.Index)
	assert.Equal(t, "services/payments", match.Path)

	// Moving the file to another directory re-selects the rule from the new
	// path; no state from the old lookup survives.
	newPath := filepath.Join(filepath.Dir(confPath), "services/auth/secret.yaml")
	match, err = loaded.MatchRule(newPath)
	require.NoError(t, err)
	assert.Equal(t, 1, match.Index)
	assert.Equal(t, "services", match.Path)
}

func TestExtensionConstraint(t *testing.T) {
	cfg := []byte(`
creation_rules:
  - path: services/payments
    extensions: ["yaml", "yml"]
    kms: arn:aws:kms:us-east-1:1:key/yaml-only
  - path: services/payments
    kms: arn:aws:kms:us-east-1:1:key/anything
  - path_regex: ".*\\.json$"
    kms: arn:aws:kms:us-east-1:1:key/json-regex
`)
	confPath := writeTempConfig(t, string(cfg))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)
	base := filepath.Dir(confPath)

	cases := map[string]string{
		"services/payments/a.yaml": "arn:aws:kms:us-east-1:1:key/yaml-only",
		"services/payments/a.YML":  "arn:aws:kms:us-east-1:1:key/yaml-only",
		"services/payments/a.txt":  "arn:aws:kms:us-east-1:1:key/anything",
		"services/payments/a.json": "arn:aws:kms:us-east-1:1:key/anything",
		"elsewhere/a.json":         "arn:aws:kms:us-east-1:1:key/json-regex",
	}
	for file, expectedKey := range cases {
		conf, err := loaded.ConfigForFile(filepath.Join(base, file), nil)
		require.NoError(t, err, file)
		assert.Equal(t, expectedKey, conf.KeyGroups[0][0].ToString(), file)
	}

	// A rule constrained to an extension must not match extensionless files.
	onlyYaml := []byte(`
creation_rules:
  - path: ""
    extensions: [".yaml"]
    kms: arn:aws:kms:us-east-1:1:key/only-yaml
`)
	confPath2 := writeTempConfig(t, string(onlyYaml))
	loaded2, err := LoadConfig(confPath2)
	require.NoError(t, err)
	_, err = loaded2.ConfigForFile(filepath.Join(filepath.Dir(confPath2), "noext"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching creation rules found")
}

func TestNoMatchingRuleReturnsExplicitError(t *testing.T) {
	cfg := []byte(`
creation_rules:
  - path: services/payments
    extensions: [".yaml"]
    kms: arn:aws:kms:us-east-1:1:key/payments
`)
	confPath := writeTempConfig(t, string(cfg))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)

	_, err = loaded.MatchRule(filepath.Join(filepath.Dir(confPath), "services/auth/x.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching creation rules found")
	assert.Contains(t, err.Error(), "services/auth/x.json")
}

func TestLoadRejectsMissingAndMalformedKeyReferences(t *testing.T) {
	t.Run("malformed age recipient points at rule position", func(t *testing.T) {
		cfg := []byte(`
creation_rules:
  - path: good
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - path: bad
    age: not-an-age-recipient
`)
		_, err := LoadConfig(writeTempConfig(t, string(cfg)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_rules[1]")
	})

	t.Run("malformed vault URI points at rule position", func(t *testing.T) {
		cfg := []byte(`
creation_rules:
  - path: ""
    hc_vault_transit_uri: "no-scheme-here"
`)
		_, err := LoadConfig(writeTempConfig(t, string(cfg)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_rules[0]")
	})

	t.Run("invalid key field type points at rule position", func(t *testing.T) {
		cfg := []byte(`
creation_rules:
  - path: ""
    age:
      - 123
`)
		_, err := LoadConfig(writeTempConfig(t, string(cfg)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_rules[0]")
	})

	t.Run("malformed hckms key id points at rule position", func(t *testing.T) {
		cfg := []byte(`
creation_rules:
  - path: ""
    hckms:
      - "missing-colon-and-uuid"
`)
		_, err := LoadConfig(writeTempConfig(t, string(cfg)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_rules[0]")
	})

	t.Run("path and path_regex together are rejected", func(t *testing.T) {
		cfg := []byte(`
creation_rules:
  - path: services
    path_regex: "services/.*"
    kms: arn:aws:kms:us-east-1:1:key/x
`)
		_, err := LoadConfig(writeTempConfig(t, string(cfg)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_rules[0]")
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("empty extension value is rejected", func(t *testing.T) {
		cfg := []byte(`
creation_rules:
  - path: ""
    extensions: [""]
    kms: arn:aws:kms:us-east-1:1:key/x
`)
		_, err := LoadConfig(writeTempConfig(t, string(cfg)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_rules[0]")
	})
}

func TestKeylessRulesRemainValid(t *testing.T) {
	// Suffix-only rules and empty key groups are legitimate.
	cfg := []byte(`
creation_rules:
  - path: ""
    unencrypted_suffix: _unencrypted
  - path: no-keys
    key_groups: []
`)
	loaded, err := LoadConfig(writeTempConfig(t, string(cfg)))
	require.NoError(t, err)
	assert.Len(t, loaded.conf.compiledRules, 2)
}

func TestCacheReloadsOnChangeWithoutStaleRules(t *testing.T) {
	first := []byte(`
creation_rules:
  - path: services
    kms: arn:aws:kms:us-east-1:1:key/old
`)
	confPath := writeTempConfig(t, string(first))
	base := filepath.Dir(confPath)

	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)
	conf, err := loaded.ConfigForFile(filepath.Join(base, "services/x.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/old", conf.KeyGroups[0][0].ToString())

	// Second LoadConfig before any change is served from the cache.
	loadedAgain, err := LoadConfig(confPath)
	require.NoError(t, err)
	assert.Same(t, loaded.conf, loadedAgain.conf)

	// Replace the rule set. The new prefix no longer covers services/.
	second := []byte(`
creation_rules:
  - path: database
    kms: arn:aws:kms:us-east-1:1:key/new
`)
	require.NoError(t, os.WriteFile(confPath, []byte(second), 0o600))
	// Bump mtime explicitly in case the filesystem timestamp granularity is
	// coarse; size already differs here, but keep both realistic.
	require.NoError(t, os.Chtimes(confPath, futureTime(), futureTime()))

	reloaded, err := LoadConfig(confPath)
	require.NoError(t, err)
	assert.NotSame(t, loaded.conf, reloaded.conf)

	_, err = reloaded.ConfigForFile(filepath.Join(base, "services/x.yaml"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching creation rules found")

	conf, err = reloaded.ConfigForFile(filepath.Join(base, "database/x.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/new", conf.KeyGroups[0][0].ToString())
}

func TestFailedReloadDropsStaleEntry(t *testing.T) {
	good := []byte(`
creation_rules:
  - path: services
    kms: arn:aws:kms:us-east-1:1:key/good
`)
	confPath := writeTempConfig(t, string(good))
	_, err := LoadConfig(confPath)
	require.NoError(t, err)

	// Overwrite with syntactically valid YAML but an invalid key reference.
	bad := []byte(`
creation_rules:
  - path: services
    age: not-an-age-recipient
`)
	require.NoError(t, os.WriteFile(confPath, []byte(bad), 0o600))
	require.NoError(t, os.Chtimes(confPath, futureTime(), futureTime()))

	_, err = LoadConfig(confPath)
	require.Error(t, err)

	abs, err := filepath.Abs(confPath)
	require.NoError(t, err)
	configCache.RLock()
	_, cached := configCache.entries[abs]
	configCache.RUnlock()
	assert.False(t, cached, "stale entry must be removed on failed reload")

	// Repair the file: the next load succeeds without manual invalidation.
	require.NoError(t, os.WriteFile(confPath, good, 0o600))
	require.NoError(t, os.Chtimes(confPath, futureTime(), futureTime()))
	loaded, err := LoadConfig(confPath)
	require.NoError(t, err)
	assert.Len(t, loaded.conf.compiledRules, 1)
}

func TestInvalidateAndReloadHelpers(t *testing.T) {
	cfg := []byte(`
creation_rules:
  - path: services
    kms: arn:aws:kms:us-east-1:1:key/a
`)
	confPath := writeTempConfig(t, string(cfg))
	first, err := LoadConfig(confPath)
	require.NoError(t, err)

	InvalidateConfig(confPath)
	second, err := LoadConfig(confPath)
	require.NoError(t, err)
	assert.NotSame(t, first.conf, second.conf)

	InvalidateAllConfigs()
	abs, err := filepath.Abs(confPath)
	require.NoError(t, err)
	configCache.RLock()
	_, cached := configCache.entries[abs]
	configCache.RUnlock()
	assert.False(t, cached)
}

func TestConcurrentConfigAccess(t *testing.T) {
	cfg := []byte(`
creation_rules:
  - path: services
    kms: arn:aws:kms:us-east-1:1:key/a
`)
	confPath := writeTempConfig(t, string(cfg))
	target := filepath.Join(filepath.Dir(confPath), "services/x.yaml")

	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					loaded, err := LoadConfig(confPath)
					if !assert.NoError(t, err) {
						return
					}
					if _, err := loaded.MatchRule(target); !assert.NoError(t, err) {
						return
					}
					if _, err := loaded.ConfigForFile(target, nil); !assert.NoError(t, err) {
						return
					}
				}
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(done)
	wg.Wait()
}

func TestLegacyConfigFileRemainsCompatible(t *testing.T) {
	// A config using only path_regex keeps first-match semantics and works
	// through the same public entry points.
	cfg := []byte(`
creation_rules:
  - path_regex: "stage/dev/feature-.*"
    kms: arn:aws:kms:us-east-1:1:key/dev-feature
  - path_regex: "stage/dev/.*"
    kms: arn:aws:kms:us-east-1:1:key/dev
  - path_regex: ""
    kms: arn:aws:kms:us-east-1:1:key/default
`)
	confPath := writeTempConfig(t, string(cfg))
	conf, err := LoadCreationRuleForFile(confPath, filepath.Join(filepath.Dir(confPath), "stage/dev/feature-x.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/dev-feature", conf.KeyGroups[0][0].ToString())

	conf, err = LoadCreationRuleForFile(confPath, filepath.Join(filepath.Dir(confPath), "stage/prod/x.yaml"), nil)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/default", conf.KeyGroups[0][0].ToString())
}
