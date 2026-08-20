package db

import (
	"context"
	"database/sql"
	"fmt"

	"recovery/recovery/platform"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func OpenDatabase(dbPath string, pids []uint32) (*sql.DB, error) {
	uri := fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", dbPath)
	if db, err := sql.Open("sqlite3", uri); err == nil {
		if err := db.Ping(); err == nil {
			return db, nil
		}
		db.Close()
	}

	data, err := platform.ReadLockedFile(dbPath, pids)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dbPath, err)
	}

	return OpenDatabaseFromBytes(data)
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
