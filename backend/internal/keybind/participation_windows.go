//go:build windows

package keybind

import "os"

// Windows stub: the in-process sync.Mutex in ParticipationStore provides
// adequate serialization. Production runs on Linux; the Windows path is
// only here so contributors can build/test on Windows.
func lockExclusive(_ *os.File) error { return nil }
func lockShared(_ *os.File) error    { return nil }
func unlock(_ *os.File) error        { return nil }
