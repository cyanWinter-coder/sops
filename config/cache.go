package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// cachedConfig pairs a validated config file with the file identity (mod
// time and size) it was loaded from. A replaced config file never reuses an
// old entry.
type cachedConfig struct {
	modTime time.Time
	size    int64
	conf    *configFile
}

var configCache = struct {
	sync.RWMutex
	entries map[string]*cachedConfig
}{
	entries: make(map[string]*cachedConfig),
}

// LoadedConfig is a validated, cached view of a SOPS config file. It is safe
// for concurrent use. Obtain one with LoadConfig, and use MatchRule to query
// which creation rule applies to a file path.
type LoadedConfig struct {
	path string
	conf *configFile
}

// Path returns the absolute path of the loaded config file.
func (l *LoadedConfig) Path() string {
	return l.path
}

// MatchRule returns the creation rule that would be selected for filePath,
// without building master keys. Moving a file to a new directory and calling
// MatchRule again therefore re-runs selection against the new path.
func (l *LoadedConfig) MatchRule(filePath string) (RuleMatch, error) {
	rel, err := relativeFilePath(l.path, filePath)
	if err != nil {
		return RuleMatch{}, err
	}
	if len(l.conf.compiledRules) == 0 {
		return RuleMatch{}, fmt.Errorf("error loading config: config file %q contains no creation rules", l.path)
	}
	r, err := matchCreationRule(l.conf.compiledRules, rel)
	if err != nil {
		return RuleMatch{}, err
	}
	return RuleMatch{
		Index:      r.index,
		Path:       r.rule.Path,
		PathRegex:  r.rule.PathRegex,
		Extensions: append([]string(nil), r.extensions...),
	}, nil
}

// ConfigForFile builds the encryption Config (key groups and suffix/regex
// settings) for filePath from the creation rule selected for that path.
func (l *LoadedConfig) ConfigForFile(filePath string, kmsEncryptionContext map[string]*string) (*Config, error) {
	rel, err := relativeFilePath(l.path, filePath)
	if err != nil {
		return nil, err
	}
	r, err := matchCreationRule(l.conf.compiledRules, rel)
	if err != nil {
		return nil, err
	}
	return configFromRule(&r.rule, kmsEncryptionContext)
}

// relativeFilePath renders filePath relative to the directory of the config
// file, matching the historical behavior of parseCreationRuleForFile.
func relativeFilePath(confPath, filePath string) (string, error) {
	configDir, err := filepath.Abs(filepath.Dir(confPath))
	if err != nil {
		return "", err
	}
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		// Fall back to the raw path when it cannot be made absolute, so
		// callers passing already-relative paths keep working.
		absFile = filePath
	}
	rel := absFile
	if configDir != "/" {
		rel = trimPrefix(absFile, configDir)
	}
	return filepath.ToSlash(rel), nil
}

func trimPrefix(filePath, configDir string) string {
	prefix := configDir + string(filepath.Separator)
	if len(filePath) >= len(prefix) && filePath[:len(prefix)] == prefix {
		return filePath[len(prefix):]
	}
	return filePath
}

// LoadConfig loads and validates the config file at confPath, serving
// repeated calls from a cache. When the file changes (different modification
// time or size) it is reloaded and validated from scratch, and the cached
// entry is replaced atomically: a failed reload removes the old entry, so
// stale rules can never be served.
func LoadConfig(confPath string) (*LoadedConfig, error) {
	abs, err := filepath.Abs(confPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(abs)
	if err != nil {
		invalidateConfigPath(abs)
		return nil, fmt.Errorf("could not read config file: %s", err)
	}

	configCache.RLock()
	entry, ok := configCache.entries[abs]
	configCache.RUnlock()
	if ok && entry.modTime.Equal(info.ModTime()) && entry.size == info.Size() {
		return &LoadedConfig{path: abs, conf: entry.conf}, nil
	}

	conf, err := readAndCompileConfig(abs)
	if err != nil {
		// Do not keep the previous entry around: a broken or replaced
		// config file must not leave stale rules in effect.
		invalidateConfigPath(abs)
		return nil, err
	}

	configCache.Lock()
	configCache.entries[abs] = &cachedConfig{
		modTime: info.ModTime(),
		size:    info.Size(),
		conf:    conf,
	}
	configCache.Unlock()

	return &LoadedConfig{path: abs, conf: conf}, nil
}

// ReloadConfig forces a fresh load of confPath, bypassing the cache. It is
// useful after an explicit config change when the file identity is unchanged.
func ReloadConfig(confPath string) (*LoadedConfig, error) {
	abs, err := filepath.Abs(confPath)
	if err != nil {
		return nil, err
	}
	invalidateConfigPath(abs)
	return LoadConfig(abs)
}

// InvalidateConfig drops the cached config file at confPath, if any.
func InvalidateConfig(confPath string) {
	abs, err := filepath.Abs(confPath)
	if err != nil {
		return
	}
	invalidateConfigPath(abs)
}

// InvalidateAllConfigs drops every cached config file.
func InvalidateAllConfigs() {
	configCache.Lock()
	configCache.entries = make(map[string]*cachedConfig)
	configCache.Unlock()
}

func invalidateConfigPath(abs string) {
	configCache.Lock()
	delete(configCache.entries, abs)
	configCache.Unlock()
}

// readAndCompileConfig reads, parses and validates a config file.
func readAndCompileConfig(confPath string) (*configFile, error) {
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %s", err)
	}
	conf := &configFile{}
	conf.Stores = *NewStoresConfig()
	if err := conf.load(confBytes); err != nil {
		return nil, fmt.Errorf("error loading config: %s", err)
	}
	if err := conf.compile(); err != nil {
		return nil, err
	}
	return conf, nil
}
