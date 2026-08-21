package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/platform"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func OpenDatabase(dbPath string, pids []uint32) (*sql.DB, error) {
	cleanPath := dbPath
	if i := strings.IndexByte(dbPath, '?'); i >= 0 {
		cleanPath = dbPath[:i]
	}

	hasWAL := false
	if wal, err := os.Stat(cleanPath + "-wal"); err == nil && wal.Size() > 0 {
		hasWAL = true
	}

	if !hasWAL {
		uri := fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", dbPath)
		if db, err := sql.Open("sqlite3", uri); err == nil {
			if err := db.Ping(); err == nil {
				logf("opened %s via immutable snapshot", dbPath)
				return db, nil
			}
			db.Close()
		}
	}

	if snapshot, cloneErr := cloneSnapshot(cleanPath, pids); cloneErr == nil {
		logf("opened %s via cloned snapshot (%d bytes)", dbPath, len(snapshot))
		return OpenDatabaseFromBytes(snapshot)
	} else {
		logf("clone failed for %s: %v; falling back to direct read", dbPath, cloneErr)
	}

	data, err := platform.ReadLockedFile(cleanPath, pids)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dbPath, err)
	}
	logf("opened %s via injected ReadLockedFile (%d bytes)", dbPath, len(data))
	return OpenDatabaseFromBytes(data)
}

func cloneSnapshot(dbPath string, pids []uint32) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "kematian_db_*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	clonePath := filepath.Join(tmp, filepath.Base(dbPath))

	mainData, err := platform.ReadLockedFile(dbPath, pids)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(clonePath, mainData, 0600); err != nil {
		return nil, err
	}

	for _, suffix := range []string{"-wal", "-journal"} {
		src := dbPath + suffix
		if info, err := os.Stat(src); err == nil && info.Size() > 0 {
			if data, err := platform.ReadLockedFile(src, pids); err == nil {
				if err := os.WriteFile(clonePath+suffix, data, 0600); err != nil {
					return nil, err
				}
			}
		}
	}

	d, err := sql.Open("sqlite3", clonePath)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if _, err := d.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		d.Close()
		return nil, err
	}
	d.Close()

	return os.ReadFile(clonePath)
}

func OpenDatabaseFromBytes(data []byte) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	conn, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		return nil, err
	}

	err = conn.Raw(func(driverConn interface{}) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("not a sqlite3 connection")
		}
		return sqliteConn.Deserialize(data, "main")
	})
	conn.Close()

	if err != nil {
		db.Close()
		return nil, fmt.Errorf("deserialize: %w", err)
	}
	return db, nil
}
