// Generates the icon block in kematian.js from maintained icon packages.
// Run with: bun gen-icons.mjs
// Sources:
//   - simple-icons   (brand/app logos)  -> ICONS
//   - lucide-static  (stroke UI icons)  -> TAB_ICONS
//   - icons.fallback.json               -> brands removed from simple-icons
// Overlord ships exactly one .js file per plugin, so the icons are inlined
// into kematian.js between the __KEMATIAN_ICONS_BEGIN__/__END__ markers.
import {
  siGooglechrome, siBrave, siVivaldi, siArc, siOpera, siOperagx,
  siFirefox, siLibrewolf, siSteam, siBattledotnet, siEpicgames,
  siRiotgames, siUbisoft, siDiscord, siTelegram, siNordvpn,
  siWireguard, siOpenvpn, siGooglecloud, siDocker, siKubernetes,
} from "simple-icons";
import * as lucide from "lucide-static";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fallback = JSON.parse(readFileSync(join(here, "icons.fallback.json"), "utf8"));

const brand = (icon) => ({ color: "#" + icon.hex.toLowerCase(), path: icon.path });

// Ordered: browsers first (matching BROWSERS), then the rest.
// A string value means "look this key up in icons.fallback.json".
const BRANDS = [
  ["Chrome", siGooglechrome],
  ["Edge", "Edge"],
  ["Brave", siBrave],
  ["Firefox", siFirefox],
  ["Opera", siOpera],
  ["Opera GX", siOperagx],
  ["Vivaldi", siVivaldi],
  ["Arc", siArc],
  ["LibreWolf", siLibrewolf],
  ["Steam", siSteam],
  ["Battle.net", siBattledotnet],
  ["Epic", siEpicgames],
  ["Riot", siRiotgames],
  ["Uplay", siUbisoft],
  ["Discord", siDiscord],
  ["Telegram", siTelegram],
  ["NordVPN", siNordvpn],
  ["WireGuard", siWireguard],
  ["OpenVPN", siOpenvpn],
  ["aws", "aws"],
  ["gcp", siGooglecloud],
  ["azure", "azure"],
  ["docker", siDocker],
  ["kubernetes", siKubernetes],
];

const ICONS = {};
for (const [name, src] of BRANDS) {
  ICONS[name] = typeof src === "string" ? fallback[src] : brand(src);
}

const stroke = (inner) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;

const lucideInner = (name) => {
  const svg = lucide[name];
  if (!svg) throw new Error("lucide-static: missing icon " + name);
  return svg
    .replace(/^\s*<svg[^>]*>/, "")
    .replace(/<\/svg>\s*$/, "")
    .replace(/\s+/g, " ")
    .replace(/\s\/>/g, "/>")
    .trim();
};

const TABS = [
  ["passwords", "Lock"],
  ["cookies", "Cookie"],
  ["autofill", "FormInput"],
  ["history", "History"],
  ["bookmarks", "Bookmark"],
  ["cards", "CreditCard"],
  ["files", "Files"],
  ["extensions", "Puzzle"],
  ["wallets", "Wallet"],
  ["keys", "KeyRound"],
  ["seeds", "Sprout"],
  ["apps", "LayoutGrid"],
  ["gaming", "Gamepad2"],
  ["vpn", "Shield"],
];

const TAB_ICONS = {};
for (const [id, name] of TABS) {
  TAB_ICONS[id] = stroke(lucideInner(name));
}

function buildIconBlock() {
  const out = [];
  out.push("// __KEMATIAN_ICONS_BEGIN__");
  out.push("  const ICONS = {");
  for (const [name] of BRANDS) {
    const { color, path } = ICONS[name];
    out.push(`    ${JSON.stringify(name)}: { color: ${JSON.stringify(color)}, path: ${JSON.stringify(path)} },`);
  }
  out.push("  };");
  out.push("");
  out.push("  const TAB_ICONS = {");
  for (const [id] of TABS) {
    out.push(`    ${JSON.stringify(id)}: \`${TAB_ICONS[id]}\`,`);
  }
  out.push("  };");
  out.push("  // __KEMATIAN_ICONS_END__");
  return out.join("\n");
}

const kematianPath = join(here, "kematian.js");
const src = readFileSync(kematianPath, "utf8");
const markerRe = /\/\/ __KEMATIAN_ICONS_BEGIN__[\s\S]*?\/\/ __KEMATIAN_ICONS_END__/;
if (!markerRe.test(src)) {
  throw new Error("kematian.js is missing the __KEMATIAN_ICONS_BEGIN__/__END__ markers");
}
writeFileSync(kematianPath, src.replace(markerRe, buildIconBlock()));
console.log(`gen-icons: inlined ${Object.keys(ICONS).length} brands, ${Object.keys(TAB_ICONS).length} tabs into kematian.js`);
