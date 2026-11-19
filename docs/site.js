// Shared helpers for the static pages. No framework: the pages read JSON that
// `mcpobs export` wrote and render it. Everything here is a function of that
// data, so a disputed number is answered by re-running the export.
const n = x => (x ?? 0).toLocaleString('en-US');
const pct = (a, b) => b ? (100 * a / b).toFixed(1) + '%' : '—';
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

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
