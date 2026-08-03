package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const transactionJournalVersion = 1

var ErrRecoveryRequired = errors.New("recrypt transaction recovery required")

type commitPhase string

const (
	phasePrepared commitPhase = "prepared"
	phaseBackedUp commitPhase = "backed_up"
	phaseReplaced commitPhase = "replaced"
)

type commitHook func(commitPhase) error

type transactionJournal struct {
	Version        int         `json:"version"`
	Destination    string      `json:"destination"`
	Stage          string      `json:"stage"`
	Backup         string      `json:"backup,omitempty"`
	HadDestination bool        `json:"hadDestination"`
	Phase          commitPhase `json:"phase"`
}

// RecoverFile resolves an interrupted durable replacement for destination.
// A transaction before phaseReplaced is rolled back. A transaction at or
// after phaseReplaced is completed. This makes the persisted journal phase
// the explicit commit point rather than relying on rename timing.
func RecoverFile(destination string) error {
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	journalPath := journalPathFor(absolute)
	journal, err := readJournal(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read recovery journal: %w", err)
	}
	if err := validateJournal(journal, absolute); err != nil {
		return fmt.Errorf("unsafe recovery journal: %w", err)
	}

	directory := filepath.Dir(absolute)
	stagePath := filepath.Join(directory, journal.Stage)
	backupPath := ""
	if journal.Backup != "" {
		backupPath = filepath.Join(directory, journal.Backup)
	}

	switch journal.Phase {
	case phasePrepared, phaseBackedUp:
		if journal.HadDestination {
			if fileExists(backupPath) {
				if err := removeIfExists(absolute); err != nil {
					return fmt.Errorf("remove uncommitted destination: %w", err)
				}
				if err := os.Rename(backupPath, absolute); err != nil {
					return fmt.Errorf("restore previous destination: %w", err)
				}
			} else if !fileExists(absolute) {
				return fmt.Errorf("%w: previous destination and backup are both missing", ErrRecoveryRequired)
			}
		} else {
			if err := removeIfExists(absolute); err != nil {
				return fmt.Errorf("remove uncommitted destination: %w", err)
			}
		}
		if err := removeIfExists(stagePath); err != nil {
			return fmt.Errorf("remove staged file: %w", err)
		}
		if backupPath != "" {
			if err := removeIfExists(backupPath); err != nil {
				return fmt.Errorf("remove stale backup: %w", err)
			}
		}
	case phaseReplaced:
		if !fileExists(absolute) {
			if journal.HadDestination && fileExists(backupPath) {
				if err := os.Rename(backupPath, absolute); err != nil {
					return fmt.Errorf("restore destination after incomplete commit: %w", err)
				}
			} else {
				return fmt.Errorf("%w: committed destination is missing", ErrRecoveryRequired)
			}
		}
		if err := removeIfExists(stagePath); err != nil {
			return fmt.Errorf("remove stale stage: %w", err)
		}
		if backupPath != "" {
			if err := removeIfExists(backupPath); err != nil {
				return fmt.Errorf("remove committed backup: %w", err)
			}
		}
	default:
		return fmt.Errorf("unknown transaction phase %q", journal.Phase)
	}

	if err := removeIfExists(journalPath); err != nil {
		return fmt.Errorf("remove recovery journal: %w", err)
	}
	return syncDirectory(directory)
}

func durableReplace(destination string, mode os.FileMode, write func(*os.File) error, hook commitHook) (err error) {
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	if err := RecoverFile(absolute); err != nil {
		return err
	}

	stage, err := os.OpenFile(
		filepath.Join(directory, "."+filepath.Base(absolute)+".stage-"+newID("txn")),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		mode,
	)
	if err != nil {
		return err
	}
	stagePath := stage.Name()
	journalCreated := false
	defer func() {
		if !journalCreated {
			_ = stage.Close()
			_ = os.Remove(stagePath)
		}
	}()

	if err := write(stage); err != nil {
		_ = stage.Close()
		return err
	}
	if err := stage.Sync(); err != nil {
		_ = stage.Close()
		return err
	}
	if err := stage.Close(); err != nil {
		return err
	}
	if err := os.Chmod(stagePath, mode); err != nil {
		return err
	}

	_, statErr := os.Stat(absolute)
	hadDestination := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	backupName := ""
	if hadDestination {
		backupName = "." + filepath.Base(absolute) + ".backup-" + newID("txn")
	}
	journal := transactionJournal{
		Version:        transactionJournalVersion,
		Destination:    absolute,
		Stage:          filepath.Base(stagePath),
		Backup:         backupName,
		HadDestination: hadDestination,
		Phase:          phasePrepared,
	}
	journalPath := journalPathFor(absolute)
	if err := createJournal(journalPath, journal); err != nil {
		return err
	}
	journalCreated = true
	if err := syncDirectory(directory); err != nil {
		return err
	}
	if hook != nil {
		if err := hook(phasePrepared); err != nil {
			return err
		}
	}

	backupPath := ""
	if hadDestination {
		backupPath = filepath.Join(directory, backupName)
		if err := os.Rename(absolute, backupPath); err != nil {
			return rollbackTransaction(absolute, fmt.Errorf("backup destination: %w", err))
		}
		if err := syncDirectory(directory); err != nil {
			return rollbackTransaction(absolute, err)
		}
	}
	journal.Phase = phaseBackedUp
	if err := replaceJournal(journalPath, journal); err != nil {
		return rollbackTransaction(absolute, err)
	}
	if hook != nil {
		if err := hook(phaseBackedUp); err != nil {
			return err
		}
	}

	if err := os.Rename(stagePath, absolute); err != nil {
		return rollbackTransaction(absolute, fmt.Errorf("replace destination: %w", err))
	}
	if err := syncDirectory(directory); err != nil {
		return rollbackTransaction(absolute, err)
	}
	journal.Phase = phaseReplaced
	if err := replaceJournal(journalPath, journal); err != nil {
		return rollbackTransaction(absolute, err)
	}
	if hook != nil {
		if err := hook(phaseReplaced); err != nil {
			return err
		}
	}

	if backupPath != "" {
		if err := removeIfExists(backupPath); err != nil {
			return err
		}
	}
	if err := removeIfExists(journalPath); err != nil {
		return err
	}
	journalCreated = false
	return syncDirectory(directory)
}

func rollbackTransaction(destination string, cause error) error {
	if err := RecoverFile(destination); err != nil {
		return fmt.Errorf("%v; rollback failed: %w", cause, err)
	}
	return cause
}

func journalPathFor(destination string) string {
	return destination + ".pqm-journal"
}

func createJournal(path string, journal transactionJournal) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrRecoveryRequired
		}
		return err
	}
	if err := encodeAndSyncJournal(file, journal); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func replaceJournal(path string, journal transactionJournal) error {
	directory := filepath.Dir(path)
	temporary, err := os.OpenFile(
		filepath.Join(directory, "."+filepath.Base(path)+".tmp-"+newID("journal")),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := encodeAndSyncJournal(temporary, journal); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func encodeAndSyncJournal(file *os.File, journal transactionJournal) error {
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(journal); err != nil {
		return err
	}
	return file.Sync()
}

func readJournal(path string) (transactionJournal, error) {
	file, err := os.Open(path)
	if err != nil {
		return transactionJournal{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var journal transactionJournal
	if err := decoder.Decode(&journal); err != nil {
		return transactionJournal{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return transactionJournal{}, err
	}
	return journal, nil
}

func validateJournal(journal transactionJournal, destination string) error {
	if journal.Version != transactionJournalVersion {
		return fmt.Errorf("unsupported journal version %d", journal.Version)
	}
	if filepath.Clean(journal.Destination) != filepath.Clean(destination) {
		return errors.New("journal destination mismatch")
	}
	if !safeTransactionName(journal.Stage) {
		return errors.New("invalid stage name")
	}
	if journal.HadDestination {
		if !safeTransactionName(journal.Backup) {
			return errors.New("invalid backup name")
		}
	} else if journal.Backup != "" {
		return errors.New("unexpected backup name")
	}
	return nil
}

func safeTransactionName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.ContainsRune(name, os.PathSeparator)
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func removeIfExists(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
