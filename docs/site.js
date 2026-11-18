// Shared helpers and the site shell. No framework: the pages read JSON that
// `mcpobs export` wrote and render it. Everything here is a function of that
// data, so a disputed number is answered by re-running the export.
const n = x => (x ?? 0).toLocaleString('en-US');
const pct = (a, b) => b ? (100 * a / b).toFixed(1) + '%' : '—';
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const BRAND = 'Surfacelog';
const REPO = 'https://github.com/yassinht/mcp-transparency-log';
// Where the data lives, so badge URLs handed to shields.io are absolute.
const SITE = new URL('.', location.href).href;

// Same slug the Go side computes: 16 hex chars of SHA-256 over the endpoint.
async function slugOf(endpoint) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return [...new Uint8Array(buf)].slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}
const shard = (dir, slug, suffix = '.json') => `data/${dir}/${slug.slice(0, 2)}/${slug}${suffix}`;
const pageHref = slug => `server.html?s=${slug}`;

function daysBetween(a, b) {
  const d = (Date.parse(b + 'T00:00:00Z') - Date.parse(a + 'T00:00:00Z')) / 86400000;
  return Number.isFinite(d) ? Math.round(d) : 0;
}
const nights = d => d === 1 ? '1 night' : `${n(d)} nights`;

async function getJSON(path) {
  const r = await fetch(path, {cache: 'no-cache'});
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

// Dates of the last k census days, newest first; the change files are named by them.
function lastDates(census, k) {
  return census.slice(-k).map(c => c.date).reverse();
}

function badgeURL(slug, suffix = '.json') {
  return 'https://img.shields.io/endpoint?url=' + encodeURIComponent(SITE + shard('badge', slug, suffix));
}

function copyable(text) {
  return `<pre class="copy" title="click to copy" tabindex="0">${esc(text)}</pre>`;
}
document.addEventListener('click', e => {
  const pre = e.target.closest('pre.copy');
  if (!pre || !navigator.clipboard) return;
  navigator.clipboard.writeText(pre.textContent).then(() => {
    pre.classList.add('copied');
    setTimeout(() => pre.classList.remove('copied'), 900);
  });
});

// Take a pasted URL or name to the right place.
function goLookup(value) {
  const v = (value || '').trim();
  if (!v) return;
  if (/^https?:\/\//i.test(v)) location.href = 'server.html?e=' + encodeURIComponent(v);
  else location.href = 'servers.html?q=' + encodeURIComponent(v);
}

// ---------- shell: one header and one footer for every page ----------
const NAV = [
  ['servers.html', 'Servers'], ['lock.html', 'Lock & CI'], ['scan.html', 'Scan'],
  ['verify.html', 'Verify'], ['plans.html', 'Pricing'], ['index.html#about', 'About'], [REPO, 'GitHub'],
];
function mountShell() {
  if (!document.querySelector('link[href*="fonts.googleapis.com/css2?family=Inter"]')) {
    const l = document.createElement('link'); l.rel = 'stylesheet';
    l.href = 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap';
    document.head.appendChild(l);
  }
  const here = location.pathname.split('/').pop() || 'index.html';
  const header = document.createElement('header');
  header.className = 'site';
  header.innerHTML = `<div class="site-in">
    <a class="brand" href="./"><i></i><span>${BRAND}<small>operator of the MCP Transparency Log</small></span></a>
    <nav>${NAV.map(([h, t]) => `<a href="${h}"${h === here ? ' class="on"' : ''}>${t}</a>`).join('')}</nav>
    <a class="btn p s" href="servers.html">Look up a server</a>
  </div>`;
  const legacyNav = document.querySelector('.wrap > nav');
  if (legacyNav) legacyNav.remove();
  document.body.prepend(header);

  if (!document.querySelector('footer.site')) {
    const f = document.createElement('footer');
    f.className = 'site';
    f.innerHTML = `<div class="site-in">
      <div><div class="brand" style="margin-bottom:10px"><i></i>${BRAND}</div>Independent nightly record of what public MCP servers actually serve, and the tools that act on it. Signed, append-only, recomputable. Built in Tunisia, delivered with experteam.tn.</div>
      <div><b>Product</b><a href="servers.html">Servers</a><a href="lock.html">Lock &amp; CI</a><a href="scan.html">Rule scan</a><a href="verify.html">Verify</a></div>
      <div><b>Solutions</b><a href="plans.html">Audit</a><a href="plans.html">Evidence packs</a><a href="${REPO}/blob/main/ROADMAP.md">Roadmap</a></div>
      <div><b>Company</b><a href="index.html#about">About</a><a href="plans.html">Pricing</a><a href="index.html#contact">Contact</a><a href="${REPO}/blob/main/SECURITY.md">Security</a></div>
      <div><b>Open</b><a href="${REPO}">GitHub</a><a href="${REPO}/tree/main/heads">Signed heads</a><a href="${REPO}/tree/main/docs/data/leaves">Leaf hashes</a><a href="${REPO}/blob/main/docs/spec/surface-hash.md">Hash spec</a><a href="${REPO}#related-work">Related work</a></div>
      <div class="fine"><span>© 2026 Yassine Houta · code Apache-2.0</span><span id="foot-head">MCP Transparency Log · since 2026-08-30</span></div>
    </div>`;
    document.body.appendChild(f);
  }
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountShell);
else mountShell();
