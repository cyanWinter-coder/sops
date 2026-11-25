package audit

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	// empty import as per https://godoc.org/github.com/lib/pq
	_ "github.com/lib/pq"

	"github.com/getsops/sops/v3/logging"
	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("AUDIT")
	confBytes, err := os.ReadFile(configFile)
	if err != nil {
		log.WithField("error", err).Debugf("Error reading config")
		return
	}
	var conf config
	if err := yaml.Unmarshal(confBytes, &conf); err != nil {
		log.WithField("error", err).Panicf("Error unmarshalling config")
	}
	// If we are running test, then don't create auditors.
	// This is pretty hacky, but doing it The Right Way would require
	// restructuring SOPS to use dependency injection instead of just using
	// globals everywhere.
	if flag.Lookup("test.v") != nil {
		return
	}

	redactor := NewRedactorFromConfig(RedactionConfig{
		SensitiveFields:     conf.SensitiveFields,
		SafeFields:          conf.SafeFields,
		RedactUnknownFields: conf.RedactUnknownFields,
	})
	bufferSize := conf.Buffer.Size
	if bufferSize <= 0 {
		bufferSize = DefaultBufferCapacity
	}

	for _, pgConf := range conf.Backends.Postgres {
		auditDb, err := NewPostgresAuditor(pgConf.ConnStr)
		if err != nil {
			// Audit availability must not take down decryption. The pool is
			// still wrapped below; SaveAuditEvent retries until the remote
			// database recovers or the bounded buffer fills.
			log.WithField("error", err).Warn("Audit database ping failed; events will be buffered")
		}
		if auditDb == nil {
			continue
		}
		auditDb.Redactor = redactor
		if conf.RetentionDays > 0 {
			auditDb.Retention = time.Duration(conf.RetentionDays) * 24 * time.Hour
		}
		buffered := NewBufferedAuditor(auditDb, bufferSize, WithRedactor(redactor))
		Register(buffered)
	}
}

// TODO: Make platform agnostic
const configFile = "/etc/sops/audit.yaml"

type config struct {
	// SensitiveFields extends or overrides field classification. Unknown
	// fields are sensitive unless RedactUnknownFields is explicitly false.
	SensitiveFields     []string `yaml:"sensitive_fields"`
	SafeFields          []string `yaml:"safe_fields"`
	RedactUnknownFields *bool    `yaml:"redact_unknown_fields"`
	Buffer              struct {
		Size int `yaml:"size"`
	} `yaml:"buffer"`
	RetentionDays int `yaml:"retention_days"`

	Backends struct {
		Postgres []struct {
			ConnStr string `yaml:"connection_string"`
		} `yaml:"postgres"`
	} `yaml:"backends"`
}

var (
	auditors  []Auditor
	auditorMu sync.RWMutex
)

// SubmitEvent handles an event for all auditors. Registered asynchronous
// auditors are expected to return quickly; the global call itself never
// retries or performs database I/O.
func SubmitEvent(event interface{}) {
	auditorMu.RLock()
	registered := make([]Auditor, len(auditors))
	copy(registered, auditors)
	auditorMu.RUnlock()

	for _, auditor := range registered {
		auditor.Handle(event)
	}
}

// Register registers a new Auditor in the global auditor list. The signature
// is unchanged for compatibility with existing SOPS integrations.
func Register(auditor Auditor) {
	if auditor == nil {
		return
	}
	auditorMu.Lock()
	defer auditorMu.Unlock()
	auditors = append(auditors, auditor)
}

// ResetAuditorsForTest removes globally registered auditors. Production code
// should not call it; it exists because the package-level registry is global.
func ResetAuditorsForTest() {
	auditorMu.Lock()
	defer auditorMu.Unlock()
	auditors = nil
}

// Auditor is notified when noteworthy events happen,
// for example when a file is encrypted or decrypted.
type Auditor interface {
	// Handle() takes an audit event and attempts to persists it;
	// how it is persisted and how errors are handled is up to the
	// implementation of this interface.
	Handle(event interface{})
}

// DecryptEvent contains fields relevant to a decryption event. The added
// fields are optional so existing composite literals remain valid.
type DecryptEvent struct {
	ID         string
	File       string
	Timestamp  time.Time
	KeyGroupID string
	Result     string
	Username   string
	Details    map[string]any
	Fields     map[string]any
}

// EncryptEvent contains fields relevant to an encryption event.
type EncryptEvent struct {
	ID         string
	File       string
	Timestamp  time.Time
	KeyGroupID string
	Result     string
	Username   string
	Details    map[string]any
	Fields     map[string]any
}

// RotateEvent contains fields relevant to a key rotation event.
type RotateEvent struct {
	ID         string
	File       string
	Timestamp  time.Time
	KeyGroupID string
	Result     string
	Username   string
	Details    map[string]any
	Fields     map[string]any
}

// PostgresAuditor is a Postgres SQL DB implementation of the Auditor interface.
// It persists safe, redacted events to the audit_event table. Temporary
// database errors are returned from SaveAuditEvent so the bounded buffer can
// retry; Handle logs them instead of terminating the SOPS process.
type PostgresAuditor struct {
	DB        *sql.DB
	Redactor  *Redactor
	Retention time.Duration
}

// NewPostgresAuditor is the constructor for a new PostgresAuditor struct
// initialized with the given db connection string.
func NewPostgresAuditor(connStr string) (*PostgresAuditor, error) {
	db, err := sql.Open("postgres", connStr)
	pg := &PostgresAuditor{DB: db, Redactor: DefaultRedactor()}
	if err != nil {
		return pg, err
	}
	var result int
	err = pg.DB.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		return pg, fmt.Errorf("Pinging audit database failed: %s", err)
	} else if result != 1 {
		return pg, fmt.Errorf("Database malfunction: SELECT 1 should return 1, but returned %d", result)
	}
	return pg, nil
}
