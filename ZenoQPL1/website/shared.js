// Shared configuration and utilities for all Zeno sub-pages.
const RPC_URL = window.ZENO_RPC || window.location.origin;

async function rpcCall(method, params = []) {
  const resp = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params })
  });
  const data = await resp.json();
  if (data.error) throw new Error(data.error.message);
  return data.result;
}

function shortHash(h, n = 8) {
  if (!h) return '';
  const s = h.startsWith('0x') ? h : '0x' + h;
  return s.slice(0, n + 2) + '...' + s.slice(-n);
}

function timeAgo(ms) {
  const secs = Math.floor((Date.now() - ms) / 1000);
  if (secs < 60) return secs + 's ago';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
  return Math.floor(secs / 86400) + 'd ago';
}

function hexToNum(hex) {
  if (!hex) return 0;
  return parseInt(hex.replace('0x', ''), 16) || 0;
}

function formatNum(n) {
  return n.toLocaleString();
}
