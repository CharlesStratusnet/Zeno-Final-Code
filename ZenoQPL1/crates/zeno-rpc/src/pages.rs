//! HTML page templates for the block explorer, staking, faucet, and governance UIs.

/// Shared CSS for all pages.
pub const SHARED_CSS: &str = r#"
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0f;color:#e0e0e0;line-height:1.6}
a{color:#818cf8;text-decoration:none}a:hover{text-decoration:underline;color:#a5b4fc}
.container{max-width:1200px;margin:0 auto;padding:1.5rem}
nav{background:#111118;border-bottom:1px solid #1e1e2e;padding:.8rem 0;position:sticky;top:0;z-index:100}
nav .container{display:flex;align-items:center;gap:2rem}
nav .logo{font-size:1.3rem;font-weight:800;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
nav .links{display:flex;gap:1.5rem;font-size:.9rem}
nav .links a{color:#888}nav .links a:hover{color:#fff;text-decoration:none}
nav .links a.active{color:#818cf8}
.hero{text-align:center;padding:2rem 0 1rem}
.hero h1{font-size:1.8rem;margin-bottom:.3rem;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:#666;font-size:.9rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.8rem;margin:1.5rem 0}
.stat{background:#13131d;border:1px solid #1e1e2e;border-radius:10px;padding:1.2rem}
.stat h3{color:#666;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.3rem}
.stat .val{font-size:1.4rem;font-weight:700;color:#fff}
.card{background:#13131d;border:1px solid #1e1e2e;border-radius:10px;padding:1.5rem;margin-bottom:1rem}
.card h2{font-size:1rem;color:#888;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:#666;font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;padding:.6rem .8rem;border-bottom:1px solid #1e1e2e}
td{padding:.6rem .8rem;border-bottom:1px solid #111118;font-size:.85rem}
tr:hover{background:#16161f}
.mono{font-family:'SF Mono',Monaco,'Cascadia Code',monospace;font-size:.8rem}
.hash{color:#818cf8;cursor:pointer}.hash:hover{color:#a5b4fc}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:600}
.badge-success{background:#064e3b;color:#34d399}
.badge-warning{background:#78350f;color:#fbbf24}
.badge-danger{background:#7f1d1d;color:#f87171}
.badge-info{background:#1e1b4b;color:#818cf8}
.truncate{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:bottom}
.search-box{display:flex;gap:.5rem;margin:1rem 0}
.search-box input{flex:1;background:#1a1a26;border:1px solid #2a2a3a;border-radius:8px;padding:.7rem 1rem;color:#e0e0e0;font-size:.9rem;outline:none}
.search-box input:focus{border-color:#6366f1}
.search-box button{background:#6366f1;color:#fff;border:none;border-radius:8px;padding:.7rem 1.5rem;cursor:pointer;font-weight:600}
.search-box button:hover{background:#4f46e5}
.btn{background:#6366f1;color:#fff;border:none;border-radius:8px;padding:.6rem 1.2rem;cursor:pointer;font-weight:600;font-size:.85rem}
.btn:hover{background:#4f46e5}.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-outline{background:transparent;border:1px solid #6366f1;color:#818cf8}
.btn-outline:hover{background:#6366f120}
.btn-danger{background:#dc2626}.btn-danger:hover{background:#b91c1c}
.form-group{margin-bottom:1rem}
.form-group label{display:block;color:#888;font-size:.8rem;margin-bottom:.3rem}
.form-group input,.form-group select{width:100%;background:#1a1a26;border:1px solid #2a2a3a;border-radius:8px;padding:.6rem .8rem;color:#e0e0e0;font-size:.85rem;outline:none}
.form-group input:focus,.form-group select:focus{border-color:#6366f1}
.alert{padding:1rem;border-radius:8px;margin:1rem 0;font-size:.85rem}
.alert-success{background:#064e3b;border:1px solid #065f46;color:#34d399}
.alert-error{background:#7f1d1d;border:1px solid #991b1b;color:#f87171}
.detail-row{display:flex;border-bottom:1px solid #1e1e2e;padding:.7rem 0}
.detail-label{width:200px;color:#666;font-size:.85rem;flex-shrink:0}
.detail-value{flex:1;font-size:.85rem;word-break:break-all}
footer{text-align:center;padding:2rem 0;color:#444;font-size:.75rem;border-top:1px solid #1e1e2e;margin-top:2rem}
.pq-badge{display:inline-flex;align-items:center;gap:.3rem;background:linear-gradient(135deg,#6366f120,#8b5cf620);border:1px solid #6366f140;border-radius:6px;padding:.2rem .6rem;font-size:.7rem;color:#a5b4fc}
@media(max-width:768px){.stats{grid-template-columns:1fr 1fr}.truncate{max-width:100px}.detail-row{flex-direction:column}.detail-label{width:auto;margin-bottom:.2rem}}
"#;

/// Navigation bar HTML.
pub fn nav(active: &str) -> String {
    let link = |href: &str, label: &str, key: &str| -> String {
        let class = if active == key { " class=\"active\"" } else { "" };
        format!("<a href=\"{href}\"{class}>{label}</a>")
    };
    format!(
        r#"<nav><div class="container"><span class="logo">Zeno PQ Chain</span><div class="links">{}{}{}{}<span class="pq-badge">Post-Quantum Secured</span></div></div></nav>"#,
        link("/explorer", "Explorer", "explorer"),
        link("/staking", "Staking", "staking"),
        link("/governance", "Governance", "governance"),
        link("/faucet", "Faucet", "faucet"),
    )
}

/// Page wrapper.
pub fn page(title: &str, active: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} — Zeno PQ Chain</title><style>{css}</style></head><body>{nav}<div class="container">{body}</div><footer>Zeno PQ Chain — Post-Quantum Blockchain &middot; Chain ID 424242 &middot; ML-DSA Secured</footer></body></html>"#,
        title = title,
        css = SHARED_CSS,
        nav = nav(active),
        body = body,
    )
}

/// Explorer home page.
pub fn explorer_page(
    height: u64,
    chain_id: u64,
    peers: usize,
    ticker: &str,
    blocks: &[(u64, String, u64, usize, String)], // (height, hash, timestamp, tx_count, proposer)
) -> String {
    let mut block_rows = String::new();
    for (h, hash, ts, txs, proposer) in blocks {
        block_rows.push_str(&format!(
            r#"<tr><td><a href="/explorer/block/{h}" class="hash">#{h}</a></td><td class="mono"><a href="/explorer/block/{h}" class="hash"><span class="truncate">{hash}</span></a></td><td>{txs}</td><td class="mono"><span class="truncate">{proposer}</span></td><td>{ts}</td></tr>"#,
        ));
    }
    if block_rows.is_empty() {
        block_rows = "<tr><td colspan=\"5\" style=\"text-align:center;color:#666;padding:2rem\">No blocks yet — chain is starting...</td></tr>".to_string();
    }
    let body = format!(
        r#"
<div class="hero"><h1>Zeno PQ Chain Explorer</h1><p>Post-Quantum Blockchain with EVM Compatibility</p></div>
<div class="search-box"><input type="text" id="searchInput" placeholder="Search by block height, tx hash, or address..." onkeydown="if(event.key==='Enter')doSearch()"><button onclick="doSearch()">Search</button></div>
<div class="stats">
  <div class="stat"><h3>Block Height</h3><div class="val">{height}</div></div>
  <div class="stat"><h3>Chain ID</h3><div class="val">{chain_id}</div></div>
  <div class="stat"><h3>Peers</h3><div class="val">{peers}</div></div>
  <div class="stat"><h3>Ticker</h3><div class="val">{ticker}</div></div>
</div>
<div class="card"><h2>Recent Blocks</h2><table><thead><tr><th>Height</th><th>Hash</th><th>Txs</th><th>Proposer</th><th>Time</th></tr></thead><tbody>{block_rows}</tbody></table></div>
<div class="card" style="margin-top:1rem"><h2>Add to MetaMask</h2><table><tr><td style="color:#888;width:200px">Network Name</td><td>Zeno PQ Chain</td></tr><tr><td style="color:#888">RPC URL</td><td id="rpcUrl"></td></tr><tr><td style="color:#888">Chain ID</td><td>{chain_id}</td></tr><tr><td style="color:#888">Currency Symbol</td><td>{ticker}</td></tr><tr><td style="color:#888">Block Explorer</td><td id="explorerUrl"></td></tr></table></div>
<script>
document.getElementById('rpcUrl').textContent=window.location.origin;
document.getElementById('explorerUrl').textContent=window.location.origin+'/explorer';
function doSearch(){{var q=document.getElementById('searchInput').value.trim();if(!q)return;if(/^\d+$/.test(q)){{window.location='/explorer/block/'+q}}else if(q.length>=64){{window.location='/explorer/tx/'+q}}else if(q.length>=40){{window.location='/explorer/address/'+q}}else{{alert('Enter a block number, tx hash, or address')}}}}
</script>"#,
    );
    page("Explorer", "explorer", &body)
}

/// Block detail page.
pub fn block_page(
    height: u64,
    hash: &str,
    parent_hash: &str,
    state_root: &str,
    tx_root: &str,
    receipt_root: &str,
    proposer: &str,
    timestamp: u64,
    tx_count: usize,
    txs: &[(String, String, String, u128, u128)], // (hash, from, to, amount, fee)
) -> String {
    let mut tx_rows = String::new();
    for (hash, from, to, amount, fee) in txs {
        tx_rows.push_str(&format!(
            r#"<tr><td class="mono"><a href="/explorer/tx/{hash}" class="hash"><span class="truncate">{hash}</span></a></td><td class="mono"><a href="/explorer/address/{from}" class="hash"><span class="truncate">{from}</span></a></td><td class="mono"><a href="/explorer/address/{to}" class="hash"><span class="truncate">{to}</span></a></td><td>{amount}</td><td>{fee}</td></tr>"#,
        ));
    }
    if tx_rows.is_empty() {
        tx_rows = "<tr><td colspan=\"5\" style=\"text-align:center;color:#666;padding:1rem\">No transactions in this block</td></tr>".to_string();
    }
    let time_str = format_timestamp(timestamp);
    let body = format!(
        r#"
<div class="hero"><h1>Block #{height}</h1><p>Finalized block details</p></div>
<div class="card"><h2>Block Overview</h2>
<div class="detail-row"><div class="detail-label">Block Height</div><div class="detail-value">{height}</div></div>
<div class="detail-row"><div class="detail-label">Timestamp</div><div class="detail-value">{time_str}</div></div>
<div class="detail-row"><div class="detail-label">Block Hash</div><div class="detail-value mono">{hash}</div></div>
<div class="detail-row"><div class="detail-label">Parent Hash</div><div class="detail-value mono"><a href="/explorer/block/{prev}" class="hash">{parent_hash}</a></div></div>
<div class="detail-row"><div class="detail-label">Proposer</div><div class="detail-value mono"><a href="/explorer/address/{proposer}" class="hash">{proposer}</a></div></div>
<div class="detail-row"><div class="detail-label">Transactions</div><div class="detail-value">{tx_count}</div></div>
<div class="detail-row"><div class="detail-label">State Root</div><div class="detail-value mono">{state_root}</div></div>
<div class="detail-row"><div class="detail-label">Tx Root</div><div class="detail-value mono">{tx_root}</div></div>
<div class="detail-row"><div class="detail-label">Receipt Root</div><div class="detail-value mono">{receipt_root}</div></div>
</div>
<div class="card"><h2>Transactions</h2><table><thead><tr><th>Hash</th><th>From</th><th>To</th><th>Amount</th><th>Fee</th></tr></thead><tbody>{tx_rows}</tbody></table></div>"#,
        prev = height.saturating_sub(1),
    );
    page(&format!("Block #{height}"), "explorer", &body)
}

/// Transaction detail page.
pub fn tx_page(
    hash: &str,
    height: u64,
    from: &str,
    to: &str,
    amount: u128,
    fee: u128,
    nonce: u64,
    status: &str,
) -> String {
    let badge = if status == "Success" {
        "<span class=\"badge badge-success\">Success</span>"
    } else {
        "<span class=\"badge badge-danger\">Failed</span>"
    };
    let body = format!(
        r#"
<div class="hero"><h1>Transaction Details</h1><p>Transaction information</p></div>
<div class="card"><h2>Overview</h2>
<div class="detail-row"><div class="detail-label">Transaction Hash</div><div class="detail-value mono">{hash}</div></div>
<div class="detail-row"><div class="detail-label">Status</div><div class="detail-value">{badge}</div></div>
<div class="detail-row"><div class="detail-label">Block</div><div class="detail-value"><a href="/explorer/block/{height}" class="hash">#{height}</a></div></div>
<div class="detail-row"><div class="detail-label">From</div><div class="detail-value mono"><a href="/explorer/address/{from}" class="hash">{from}</a></div></div>
<div class="detail-row"><div class="detail-label">To</div><div class="detail-value mono"><a href="/explorer/address/{to}" class="hash">{to}</a></div></div>
<div class="detail-row"><div class="detail-label">Value</div><div class="detail-value">{amount} ZPQ</div></div>
<div class="detail-row"><div class="detail-label">Fee</div><div class="detail-value">{fee} ZPQ</div></div>
<div class="detail-row"><div class="detail-label">Nonce</div><div class="detail-value">{nonce}</div></div>
</div>"#,
    );
    page("Transaction", "explorer", &body)
}

/// Address page.
pub fn address_page(address: &str, balance: u128, nonce: u64) -> String {
    let body = format!(
        r#"
<div class="hero"><h1>Address</h1><p>Account details</p></div>
<div class="card"><h2>Overview</h2>
<div class="detail-row"><div class="detail-label">Address</div><div class="detail-value mono">{address}</div></div>
<div class="detail-row"><div class="detail-label">Balance</div><div class="detail-value">{balance} ZPQ</div></div>
<div class="detail-row"><div class="detail-label">Nonce</div><div class="detail-value">{nonce}</div></div>
</div>"#,
    );
    page("Address", "explorer", &body)
}

/// Staking page.
pub fn staking_page(
    epoch: u64,
    treasury: u128,
    validators: &[(String, u128, u128, u16, String)], // (address, self_bond, total_stake, commission_bps, status)
) -> String {
    let mut rows = String::new();
    for (addr, self_bond, total_stake, commission, status) in validators {
        let badge = match status.as_str() {
            "Active" => "<span class=\"badge badge-success\">Active</span>",
            "Jailed" => "<span class=\"badge badge-danger\">Jailed</span>",
            _ => "<span class=\"badge badge-warning\">Inactive</span>",
        };
        rows.push_str(&format!(
            r#"<tr><td class="mono"><a href="/explorer/address/{addr}" class="hash"><span class="truncate">{addr}</span></a></td><td>{self_bond}</td><td>{total_stake}</td><td>{commission_pct:.1}%</td><td>{badge}</td></tr>"#,
            commission_pct = *commission as f64 / 100.0,
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"5\" style=\"text-align:center;color:#666;padding:2rem\">No validators registered</td></tr>".to_string();
    }
    let body = format!(
        r#"
<div class="hero"><h1>Staking</h1><p>Validator staking and delegation</p></div>
<div class="stats">
  <div class="stat"><h3>Current Epoch</h3><div class="val">{epoch}</div></div>
  <div class="stat"><h3>Treasury</h3><div class="val">{treasury} ZPQ</div></div>
  <div class="stat"><h3>Validators</h3><div class="val">{count}</div></div>
</div>
<div class="card"><h2>Validators</h2><table><thead><tr><th>Address</th><th>Self Bond</th><th>Total Stake</th><th>Commission</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="card"><h2>Delegate Stake</h2><p style="color:#666;margin-bottom:1rem;font-size:.85rem">Delegate ZPQ to a validator to earn rewards and secure the network.</p>
<div class="form-group"><label>Validator Address</label><input type="text" id="delValidator" placeholder="Validator address..."></div>
<div class="form-group"><label>Amount (ZPQ)</label><input type="number" id="delAmount" placeholder="1000"></div>
<button class="btn" onclick="alert('Delegation requires an ML-DSA signed transaction. Use the CLI: zeno-cli wallet build-tx')">Delegate</button>
</div>"#,
        count = validators.len(),
    );
    page("Staking", "staking", &body)
}

/// Governance page.
pub fn governance_page(
    next_id: u64,
    economics_treasury_bps: u16,
    economics_epoch_length: u64,
    economics_min_bond: u128,
    pending: &[(u64, u64, String)], // (id, activation_epoch, description)
) -> String {
    let mut rows = String::new();
    for (id, epoch, desc) in pending {
        rows.push_str(&format!(
            r#"<tr><td>#{id}</td><td>{desc}</td><td>{epoch}</td><td><span class="badge badge-warning">Pending</span></td></tr>"#,
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"4\" style=\"text-align:center;color:#666;padding:2rem\">No pending proposals</td></tr>".to_string();
    }
    let body = format!(
        r#"
<div class="hero"><h1>Governance</h1><p>Protocol parameter management</p></div>
<div class="stats">
  <div class="stat"><h3>Next Proposal ID</h3><div class="val">{next_id}</div></div>
  <div class="stat"><h3>Treasury Share</h3><div class="val">{treasury_pct:.1}%</div></div>
  <div class="stat"><h3>Epoch Length</h3><div class="val">{economics_epoch_length} blocks</div></div>
  <div class="stat"><h3>Min Self Bond</h3><div class="val">{economics_min_bond} ZPQ</div></div>
</div>
<div class="card"><h2>Active Parameters</h2>
<div class="detail-row"><div class="detail-label">Treasury Share</div><div class="detail-value">{treasury_pct:.1}%</div></div>
<div class="detail-row"><div class="detail-label">Epoch Length</div><div class="detail-value">{economics_epoch_length} blocks</div></div>
<div class="detail-row"><div class="detail-label">Min Self Bond</div><div class="detail-value">{economics_min_bond} ZPQ</div></div>
<div class="detail-row"><div class="detail-label">Downtime Slash</div><div class="detail-value">1%</div></div>
<div class="detail-row"><div class="detail-label">Double Sign Slash</div><div class="detail-value">5%</div></div>
</div>
<div class="card"><h2>Pending Proposals</h2><table><thead><tr><th>ID</th><th>Description</th><th>Activation Epoch</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>"#,
        treasury_pct = economics_treasury_bps as f64 / 100.0,
    );
    page("Governance", "governance", &body)
}

/// Faucet page.
pub fn faucet_page() -> String {
    let body = r#"
<div class="hero"><h1>Faucet</h1><p>Get free ZPQ testnet tokens</p></div>
<div class="card" style="max-width:600px;margin:2rem auto">
<h2>Request Tokens</h2>
<p style="color:#666;margin-bottom:1.5rem;font-size:.85rem">Enter your wallet address to receive 1,000,000 ZPQ. Supports both MetaMask (0x...) and native Zeno addresses.</p>
<div class="form-group"><label>Wallet Address</label><input type="text" id="faucetAddr" placeholder="0x... or native address"></div>
<div class="form-group"><label>Amount</label><input type="number" id="faucetAmount" value="1000000" min="1" max="10000000"></div>
<button class="btn" id="faucetBtn" onclick="requestFaucet()" style="width:100%;padding:.8rem">Request ZPQ</button>
<div id="faucetResult" style="margin-top:1rem"></div>
</div>
<script>
async function requestFaucet(){
  var btn=document.getElementById('faucetBtn');
  var addr=document.getElementById('faucetAddr').value.trim();
  var amount=parseInt(document.getElementById('faucetAmount').value)||1000000;
  var result=document.getElementById('faucetResult');
  if(!addr){result.innerHTML='<div class="alert alert-error">Please enter an address</div>';return}
  btn.disabled=true;btn.textContent='Sending...';
  try{
    var resp=await fetch('/',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method:'faucet_send',params:[addr,amount]})});
    var data=await resp.json();
    if(data.error){result.innerHTML='<div class="alert alert-error">'+data.error.message+'</div>'}
    else{result.innerHTML='<div class="alert alert-success">Sent '+amount+' ZPQ to '+addr+'! It will appear in your wallet within a few seconds.</div>'}
  }catch(e){result.innerHTML='<div class="alert alert-error">'+e.message+'</div>'}
  btn.disabled=false;btn.textContent='Request ZPQ';
}
</script>"#;
    page("Faucet", "faucet", body)
}

fn format_timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let mins_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(secs);
    if mins_ago < 60 {
        format!("{mins_ago}s ago")
    } else if mins_ago < 3600 {
        format!("{}m ago", mins_ago / 60)
    } else {
        format!("{}h ago", mins_ago / 3600)
    }
}
