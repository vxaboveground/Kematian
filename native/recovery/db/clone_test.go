package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestOpenDatabaseReadsLiveWAL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Cookies")

	live, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	live.SetMaxOpenConns(1)
	defer live.Close()
	if _, err := live.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Exec("CREATE TABLE cookies (host_key TEXT, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Exec("INSERT INTO cookies VALUES ('example.com', 'secret')"); err != nil {
		t.Fatal(err)
	}

	d, err := OpenDatabase(dbPath, nil)
	if err != nil {
		t.Fatalf("OpenDatabase: %v", err)
	}
	defer d.Close()

	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM cookies").Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 cookie row, got %d", n)
	}
}
