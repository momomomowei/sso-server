import 'dotenv/config';
import express from 'express';
import Provider from 'oidc-provider';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { generateKeyPair, exportJWK } from 'jose';

const issuer = env('ISSUER', 'http://localhost:7080');
const port = Number(env('PORT', '7080'));
const allowedDomains = envDomains();
const clientId = env('CLIENT_ID', 'kiro');
const clientSecret = env('CLIENT_SECRET', randomDevSecret());
const redirectUris = envList('REDIRECT_URIS', ['http://localhost:3000/callback']);
const postLogoutRedirectUris = envList('POST_LOGOUT_REDIRECT_URIS', []);
const cookieKeys = envList('COOKIE_KEYS', [randomDevSecret(), randomDevSecret()]);
const dataDir = env('DATA_DIR', path.join(process.cwd(), 'data'));
const jwksPath = env('JWKS_PATH', path.join(dataDir, 'jwks.json'));

class FileAdapter {
  static filePath;
  static store = {};
  static loaded = false;
  static writeQueue = Promise.resolve();

  static configure(filePath) {
    FileAdapter.filePath = filePath;
  }

  constructor(name) {
    this.name = name;
  }

  async upsert(id, payload, expiresIn) {
    await FileAdapter.load();
    FileAdapter.cleanup();

    FileAdapter.store[this.name] ||= {};
    FileAdapter.store[this.name][id] = {
      payload,
      expiresAt: expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null,
    };

    await FileAdapter.save();
  }

  async find(id) {
    await FileAdapter.load();
    const entry = FileAdapter.store[this.name]?.[id];
    if (!entry) return undefined;

    if (entry.expiresAt && entry.expiresAt <= Math.floor(Date.now() / 1000)) {
      await this.destroy(id);
      return undefined;
    }

    return entry.payload;
  }

  async findByUserCode(userCode) {
    return this.findBy('userCode', userCode);
  }

  async findByUid(uid) {
    return this.findBy('uid', uid);
  }

  async findBy(field, value) {
    await FileAdapter.load();
    const entries = Object.values(FileAdapter.store[this.name] || {});
    const entry = entries.find((item) => item.payload?.[field] === value);
    if (!entry) return undefined;
    if (entry.expiresAt && entry.expiresAt <= Math.floor(Date.now() / 1000)) return undefined;
    return entry.payload;
  }

  async destroy(id) {
    await FileAdapter.load();
    if (FileAdapter.store[this.name]) {
      delete FileAdapter.store[this.name][id];
      await FileAdapter.save();
    }
  }

  async revokeByGrantId(grantId) {
    await FileAdapter.load();
    let changed = false;

    for (const collection of Object.values(FileAdapter.store)) {
      for (const [id, entry] of Object.entries(collection)) {
        if (entry.payload?.grantId === grantId) {
          delete collection[id];
          changed = true;
        }
      }
    }

    if (changed) await FileAdapter.save();
  }

  async consume(id) {
    await FileAdapter.load();
    const entry = FileAdapter.store[this.name]?.[id];
    if (entry) {
      entry.payload.consumed = Math.floor(Date.now() / 1000);
      await FileAdapter.save();
    }
  }

  static async load() {
    if (FileAdapter.loaded) return;
    await fs.mkdir(path.dirname(FileAdapter.filePath), { recursive: true });

    try {
      const raw = await fs.readFile(FileAdapter.filePath, 'utf8');
      FileAdapter.store = JSON.parse(raw);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      FileAdapter.store = {};
    }

    FileAdapter.loaded = true;
  }

  static async save() {
    FileAdapter.writeQueue = FileAdapter.writeQueue.then(async () => {
      await fs.mkdir(path.dirname(FileAdapter.filePath), { recursive: true });
      await fs.writeFile(FileAdapter.filePath, `${JSON.stringify(FileAdapter.store, null, 2)}\n`, { mode: 0o600 });
    });
    return FileAdapter.writeQueue;
  }

  static cleanup() {
    const now = Math.floor(Date.now() / 1000);
    for (const collection of Object.values(FileAdapter.store)) {
      for (const [id, entry] of Object.entries(collection)) {
        if (entry.expiresAt && entry.expiresAt <= now) delete collection[id];
      }
    }
  }
}

const users = new Map();
const jwks = await loadOrCreateJwks(jwksPath);

const oidc = new Provider(issuer, {
  adapter: FileAdapter,
  jwks,
  clients: [
    {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: redirectUris,
      post_logout_redirect_uris: postLogoutRedirectUris,
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'client_secret_basic',
    },
  ],
  cookies: {
    keys: cookieKeys,
  },
  pkce: {
    required: false,
  },
  claims: {
    openid: ['sub'],
    email: ['email', 'email_verified'],
    profile: ['preferred_username', 'name', 'given_name', 'family_name'],
  },
  features: {
    devInteractions: { enabled: false },
    revocation: { enabled: true },
  },
  findAccount: async (_ctx, id) => {
    const email = users.get(id) || id;
    return {
      accountId: id,
      claims: async () => ({
        sub: id,
        email,
        email_verified: true,
        preferred_username: email,
        name: email,
        given_name: email.split('@')[0],
        family_name: 'User',
      }),
    };
  },
  interactions: {
    url(_ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
  },
});
oidc.proxy = true;

FileAdapter.configure(path.join(dataDir, 'oidc-store.json'));

const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: false }));

app.get('/', (_req, res) => {
  res.type('html').send(page('SSO服务器运行成功', `
    <section class="panel">
      <h1>SSO服务器运行成功</h1>
    </section>
  `));
});

app.get('/interaction/:uid', async (req, res, next) => {
  try {
    const details = await oidc.interactionDetails(req, res);
    const clientName = details.params.client_id || 'OIDC Client';
    res.type('html').send(page('Sign in', `
      <section class="panel">
        <h1>Sign in</h1>
        <p class="muted">Continue to <strong>${escapeHtml(clientName)}</strong></p>
        <form method="post" action="/interaction/${encodeURIComponent(req.params.uid)}/login">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" placeholder="name@${escapeHtml(allowedDomains[0])}" autocomplete="email" autofocus required>
          <button type="submit">Continue</button>
        </form>
        <p class="hint">Only configured email domains are accepted.</p>
      </section>
    `));
  } catch (error) {
    next(error);
  }
});

app.post('/interaction/:uid/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!isAllowedEmail(email)) {
      res.status(400).type('html').send(page('Invalid email', `
        <section class="panel">
          <h1>Invalid email</h1>
          <p class="error">Only configured email domains can sign in.</p>
          <p><a href="/interaction/${encodeURIComponent(req.params.uid)}">Try again</a></p>
        </section>
      `));
      return;
    }

    const accountId = accountIdForEmail(email);
    users.set(accountId, email);
    const details = await oidc.interactionDetails(req, res);
    const grant = new oidc.Grant({
      accountId,
      clientId: details.params.client_id,
    });
    grant.addOIDCScope('openid profile email');
    const grantId = await grant.save();

    await oidc.interactionFinished(req, res, {
      login: {
        accountId,
        remember: true,
        ts: Math.floor(Date.now() / 1000),
      },
      consent: {
        grantId,
      },
    }, { mergeWithLastSubmission: false });
  } catch (error) {
    next(error);
  }
});

app.use(oidc.callback());

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(error.statusCode || 500).type('html').send(page('SSO error', `
    <section class="panel">
      <h1>SSO error</h1>
      <p class="error">${escapeHtml(error.message || 'Unexpected error')}</p>
    </section>
  `));
});

app.listen(port, () => {
  console.log(`Domain SSO listening on ${issuer}`);
  console.log(`Allowed email domains: ${allowedDomains.map((domain) => `@${domain}`).join(', ')}`);
  console.log(`Client ID: ${clientId}`);
  console.log(`Redirect URIs: ${redirectUris.join(', ')}`);
});

function env(name, fallback) {
  return process.env[name] && process.env[name].trim() ? process.env[name].trim() : fallback;
}

function envList(name, fallback) {
  const value = process.env[name];
  if (!value || !value.trim()) return fallback;
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function normalizeDomain(domain) {
  return domain.trim().toLowerCase().replace(/^@/, '');
}

function envDomains() {
  const configured = process.env.ALLOWED_EMAIL_DOMAINS || process.env.ALLOWED_EMAIL_DOMAIN || 'smartatomic.singles';
  const domains = configured
    .split(',')
    .map(normalizeDomain)
    .filter(Boolean);

  return [...new Set(domains)];
}

function isAllowedEmail(email) {
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return false;
  return allowedDomains.some((domain) => email.endsWith(`@${domain}`));
}

function accountIdForEmail(email) {
  return crypto.createHash('sha256').update(email).digest('hex');
}

function randomDevSecret() {
  return crypto.randomBytes(32).toString('hex');
}

async function loadOrCreateJwks(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.keys) && parsed.keys.length > 0) return parsed;
    throw new Error('JWKS file has no keys');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const key = await exportJWK(privateKey);
  key.kid = crypto.randomUUID();
  key.use = 'sig';
  key.alg = 'RS256';

  const generated = { keys: [key] };
  await fs.writeFile(filePath, `${JSON.stringify(generated, null, 2)}\n`, { mode: 0o600 });
  return generated;
}


function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #18202a;
      --muted: #657080;
      --line: #d9dee7;
      --brand: #155eef;
      --brand-dark: #0f48b8;
      --error: #ba1a1a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .panel {
      width: min(440px, 100%);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 28px;
      box-shadow: 0 18px 40px rgba(20, 29, 40, 0.08);
    }
    h1 {
      margin: 0 0 10px;
      font-size: 26px;
      line-height: 1.2;
      letter-spacing: 0;
    }
    p { line-height: 1.55; }
    .muted, .hint { color: var(--muted); }
    .hint { font-size: 14px; margin-bottom: 0; }
    .error { color: var(--error); }
    label {
      display: block;
      margin: 24px 0 8px;
      font-weight: 650;
    }
    input {
      width: 100%;
      height: 44px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 12px;
      font: inherit;
    }
    input:focus {
      outline: 3px solid rgba(21, 94, 239, 0.18);
      border-color: var(--brand);
    }
    button {
      width: 100%;
      height: 44px;
      margin-top: 16px;
      border: 0;
      border-radius: 6px;
      background: var(--brand);
      color: #fff;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--brand-dark); }
    code {
      padding: 2px 5px;
      border-radius: 4px;
      background: #eef1f6;
      overflow-wrap: anywhere;
    }
    a { color: var(--brand); }
    dl { margin: 20px 0 0; }
    dl div {
      padding: 12px 0;
      border-top: 1px solid var(--line);
    }
    dt {
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 4px;
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
  </style>
</head>
<body>
  ${body}
</body>
</html>`;
}
