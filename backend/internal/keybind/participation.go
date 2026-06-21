package keybind

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// ParticipationStore tracks which users have already claimed a key in the
// current natural month. State lives in plain text files under
// <dataDir>/keybind/<YYYYMM>.bind-keys.users (one user_id per line).
//
// The file-per-month layout makes month rollover free: when the next month
// arrives the new filename is missing, so every user is automatically
// eligible again. Past months are kept as audit trail.
//
// Cross-process safety uses fcntl flock(LOCK_EX); within a single process
// we additionally take sync.Mutex to avoid pointless syscalls when the
// same instance handles concurrent commits.
type ParticipationStore struct {
	dir string
	mu  sync.Mutex
}

// NewParticipationStore returns a store rooted at <dataDir>/keybind.
// The directory is created lazily on the first write.
func NewParticipationStore(dataDir string) *ParticipationStore {
	return &ParticipationStore{dir: filepath.Join(dataDir, "keybind")}
}

// CurrentMonthKey formats the current server-local month as "YYYYMM".
func (p *ParticipationStore) CurrentMonthKey() string {
	return time.Now().Format("200601")
}

// NextResetUnixMs returns the epoch millis of the next natural month's
// 1st day, 00:00 in the server's local timezone. Used by the UI to render
// a countdown.
func (p *ParticipationStore) NextResetUnixMs() int64 {
	now := time.Now()
	next := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
	return next.UnixMilli()
}

// HasParticipated reports whether userID has bound a key during the
// current month. Returns (false, nil) when the month file does not exist.
func (p *ParticipationStore) HasParticipated(_ context.Context, userID int64) (bool, error) {
	if userID <= 0 {
		return false, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	path := p.currentPath()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("open participation file: %v", err))
	}
	defer func() { _ = f.Close() }()

	if err := lockShared(f); err != nil {
		return false, infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("lock participation file: %v", err))
	}
	defer func() { _ = unlock(f) }()

	target := strconv.FormatInt(userID, 10)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == target {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("read participation file: %v", err))
	}
	return false, nil
}

// MarkParticipated appends userID to the current month's file. Idempotent:
// if the user is already recorded the call is a no-op.
func (p *ParticipationStore) MarkParticipated(_ context.Context, userID int64) error {
	if userID <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("mkdir participation dir: %v", err))
	}

	path := p.currentPath()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("open participation file: %v", err))
	}
	defer func() { _ = f.Close() }()

	if err := lockExclusive(f); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("lock participation file: %v", err))
	}
	defer func() { _ = unlock(f) }()

	target := strconv.FormatInt(userID, 10)
	if _, err := f.Seek(0, 0); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("seek participation file: %v", err))
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == target {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("read participation file: %v", err))
	}

	if _, err := f.Seek(0, 2); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("seek end participation file: %v", err))
	}
	if _, err := f.WriteString(target + "\n"); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("write participation file: %v", err))
	}
	if err := f.Sync(); err != nil {
		return infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", fmt.Sprintf("sync participation file: %v", err))
	}
	return nil
}

func (p *ParticipationStore) currentPath() string {
	return filepath.Join(p.dir, p.CurrentMonthKey()+".bind-keys.users")
}
