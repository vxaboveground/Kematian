package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/browser"
	"recovery/recovery/types"
)

var knownWalletExtensions = map[string]string{
	"bhghoamapcdpbohphigoooaddinpkbai": "Authenticator",
	"fhbohimaelbohpjbbldcngcnapndodjp": "Binance",
	"fihkakfobkmkjojpchpfgcmhfjnmnfpi": "Bitapp",
	"aodkkagnadcbobfpggfnjeongemjbjca": "BoltX",
	"aeachknmefphepccionboohckonoeemg": "Coin98",
	"hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase",
	"agoakfejjabomempkjlepdflaleeobhb": "Core",
	"pnlfjmlcjdjgkddecgincndfgegkecke": "Crocobit",
	"blnieiiffboillknjnepogjhkgnoapac": "Equal",
	"cgeeodpfagjceefieflmdfphplkenlfk": "Ever",
	"aholpfdialjgjfhomihkjbmgjidlcdno": "ExodusWeb3",
	"ebfidpplhabeedpnhjnobghokpiioolj": "Fewcha",
	"cjmkndjhnagcfbpiemnkdpomccnjblmj": "Finnie",
	"hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
	"nanjmdknhkinifnkgdcggcfnhdaammmj": "Guild",
	"fnnegphlobjdpkhecapkijjdkgcjhkib": "Harmony",
	"flpiciilemghbmfalicajoolhkkenfel": "Iconex",
	"cjelfplplebdjjenllpjcblmjkfcffne": "Jaxx Liberty",
	"jblndlipeogpafnldhgmapagcccfchpi": "Kaikas",
	"pdadjkfkgcafgbceimcpbkalnfnepbnk": "KardiaChain",
	"dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
	"kpfopkelmapcoipemfendmdcghnegimn": "Liquality",
	"nlbmnnijcnlegkjjpcfjclmcfggfefdm": "MEWCX",
	"dngmlblcodfobpdpecaadgfbcggfjfnm": "MaiarDEFI",
	"efbglgofoippbgcjepnhiblaibcnclgk": "Martian",
	"afbcbjpbpfadlkmhmclhkeeodmamcflc": "Math",
	"nkbihfbeogaeaoehlefnkodbefgpgknn": "Metamask",
	"ejbalbakoplchlghecdalmeeeajnimhm": "Metamask",
	"fcckkdbjnoikooededlapcalpionmalo": "Mobox",
	"lpfcbjknijpeeillifnkikgncikgfhdo": "Nami",
	"jbdaocneiiinmjbjlgalhcelgbejmnid": "Nifty",
	"fhilaheimglignddkjgofkcbgekhenbh": "Oxygen",
	"mgffkfbidihjpoaomajlbgchddlicgpn": "PaliWallet",
	"ejjladinnckdgjemekebdpeokbikhfci": "Petra",
	"bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
	"phkbamefinggmakgklpkljjmgibohnba": "Pontem",
	"fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin",
	"lgmpcpglpngdoalbgeoldeajfclnhafa": "Safepal",
	"nkddgncdjgjfcddamfgcmfnlhccnimig": "Saturn",
	"pocmplpaccanhmnllbbkpgfliimjljgo": "Slope",
	"bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
	"fhmfendgdocmcbmfikdcogofphimnkno": "Sollet",
	"mfhbebgoclkghebffdldpobeajmbecfk": "Starcoin",
	"cmndjbecilbocjfkibfbifhngkdmjgog": "Swash",
	"ookjlbkiijinhpmnjffcofjonbfbgaoc": "TempleTezos",
	"aiifbnbfobpmeekipheeijimdpnlpgpp": "TerraStation",
	"mfgccjchihfkkindfppnaooecgfneiii": "Tokenpocket",
	"nphplpgoakhhjchkkhmiggakijnkhfnd": "Ton",
	"ibnejdfjmmkpcnlpebklmnkoeoihofec": "Tron",
	"egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
	"amkmjjmmflddogmhpjloimipbofnfjih": "Wombat",
	"hmeobnfnfcmdkdcmlblgagmfpfboieaf": "XDEFI",
	"eigblbgjknlfbajkfhopmcojidlgcehm": "XMR.PT",
	"bocpokimicclpaiekenaeelehdjllofo": "XinPay",
	"ffnbelfdoeiohenkjibnmadjiehjhajb": "Yoroi",
	"kncchdigobghenbbaddojjnnaogfppfj": "iWallet",
}

func ScanExtensions() []types.ExtensionResult {
	var results []types.ExtensionResult
	for _, cfg := range browser.Browsers {
		if cfg.IsFirefox {
			continue
		}
		profiles := browser.FindProfileDirs(cfg)
		for _, profile := range profiles {
			extDir := filepath.Join(profile.Path, "Extensions")
			entries, err := os.ReadDir(extDir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				extID := e.Name()
				// Skip internal Chromium marker dirs
				if strings.HasPrefix(extID, "_") {
					continue
				}
				extIDDir := filepath.Join(extDir, extID)
				versionDirs, err := os.ReadDir(extIDDir)
				if err != nil {
					continue
				}
				for _, vd := range versionDirs {
					if !vd.IsDir() {
						continue
					}
					versionPath := filepath.Join(extIDDir, vd.Name())
					name, version := readManifestBasics(filepath.Join(versionPath, "manifest.json"))
					category := ""
					if walletName, ok := knownWalletExtensions[extID]; ok {
						category = "wallet"
						if name == "" {
							name = walletName
						}
					}
					results = append(results, types.ExtensionResult{
						ExtID:    extID,
						Name:     name,
						Version:  version,
						Browser:  cfg.Name,
						Profile:  profile.Name,
						Path:     versionPath,
						Category: category,
					})
					break // first version directory only
				}
			}
		}
	}
	return results
}

type manifestBasics struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func readManifestBasics(path string) (name, version string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var m manifestBasics
	if err := json.Unmarshal(data, &m); err != nil {
		return "", ""
	}
	if strings.HasPrefix(m.Name, "__MSG_") {
		m.Name = ""
	}
	return m.Name, m.Version
}
