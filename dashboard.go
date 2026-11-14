package main

// dashboard.go — the human-facing HTML page for the dnsscale API.
//
// It is rendered from the same endpoint table that generates the JSON index and
// the discovery document, so the page cannot drift from the API. The page shows
// the service's attributes (provider, domain, tailnet, poll interval, filters),
// its functions (every operation with a worked example) and its actions (a
// button that triggers a batch reconciliation immediately).

import (
	"html"
	"strings"
)

// renderDashboard builds the HTML dashboard.
func renderDashboard(baseURL string) string {
	var b strings.Builder

	b.WriteString(dashboardHead)
	b.WriteString(`
<div class="container">

<h1>DNSScale</h1>
<p>Automatically manages DNS records for Tailscale nodes. This page describes the
service, its configuration and every operation it exposes.</p>

<p><strong>Base URL:</strong> <code>` + html.EscapeString(baseURL) + `</code></p>
<p><strong>Machine-readable:</strong>
<a href="/api">/api</a> &middot;
<a href="/api/v1/endpoints">/api/v1/endpoints</a> &middot;
<a href="/.well-known/dnsscale">/.well-known/dnsscale</a></p>

<h2>Status</h2>
<div class="card">
<div id="status"><p>Loading status&hellip;</p></div>
<button id="syncBtn" onclick="triggerSync()">Sync Now</button>
<p class="muted">Sync Now runs the same reconciliation pass the poll runs &mdash;
it adds, updates and removes DNS records for every authorized Tailscale node.</p>
</div>

<h2>Nodes</h2>
<div class="card">
<div id="nodes"><p>Loading nodes&hellip;</p></div>
</div>

<h2>Attributes</h2>
<div class="card">
<table>
<tr><th>Attribute</th><th>Value</th></tr>
`)
	for _, row := range dashboardAttributes() {
		b.WriteString("<tr><td>" + html.EscapeString(row[0]) + "</td><td><code>" +
			html.EscapeString(row[1]) + "</code></td></tr>\n")
	}
	b.WriteString(`</table>
</div>

<h2>Functions</h2>
`)

	for _, e := range endpoints {
		methodClass := "get"
		if e.Method == "POST" {
			methodClass = "post"
		}
		b.WriteString(`<div class="card">
<div class="endpoint"><span class="method ` + methodClass + `">` + e.Method +
			`</span><span class="path">` + html.EscapeString(e.Path) + `</span></div>
<p>` + html.EscapeString(e.Description) + `</p>
`)
		if len(e.Params) > 0 {
			b.WriteString(`<div class="params">`)
			for name, desc := range e.Params {
				b.WriteString(`<span class="param">` + html.EscapeString(name) + " " +
					html.EscapeString(desc) + `</span>`)
			}
			b.WriteString(`</div>`)
		}
		if e.Example != "" {
			b.WriteString(`<pre>` + html.EscapeString(e.Example) + `</pre>`)
		}
		b.WriteString(`</div>
`)
	}

	b.WriteString(`
<h2>Quick Start</h2>
<div class="card">
<p><strong>Check health:</strong></p>
<pre>curl -s ` + html.EscapeString(baseURL) + `/health</pre>
<p><strong>Trigger a batch sync now:</strong></p>
<pre>curl -s -X POST ` + html.EscapeString(baseURL) + `/api/v1/sync</pre>
<p><strong>List the current nodes:</strong></p>
<pre>curl -s ` + html.EscapeString(baseURL) + `/api/v1/nodes</pre>
</div>

<h2>Discovery</h2>
<div class="card">
<p>For automated clients (agents, scripts, programmatic access):</p>
<ul>
<li><a href="/api">/api</a> &mdash; JSON API index with version, endpoints, doc links</li>
<li><a href="/api/v1/endpoints">/api/v1/endpoints</a> &mdash; complete operation listing (HATEOAS)</li>
<li><a href="/.well-known/dnsscale">/.well-known/dnsscale</a> &mdash; RFC 5785 service metadata</li>
<li>Every response carries <code>Link</code> headers (RFC 8631): <code>service-doc</code>, <code>service-desc</code>, <code>status</code></li>
<li>Errors and empty results carry <code>next_steps</code> naming the next call to make</li>
</ul>
</div>

<p class="footer">
Service: <code>dnsscale</code> &nbsp;|&nbsp; Version: <code>` + serviceVersion + `</code>
&nbsp;|&nbsp; <a href="https://github.com/e-hollebone/dnsscale-webhook">Upstream</a>
&nbsp;|&nbsp; <a href="README.md">README</a> &middot; <a href="design.md">design</a>
</p>

</div>
<script>
function fmtUptime(s){
  if(s==null) return 'n/a';
  s=Math.max(0,Math.floor(s));
  var d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
  var p=[];
  if(d) p.push(d+'d');
  if(h) p.push(h+'h');
  if(m) p.push(m+'m');
  if(!p.length) p.push('0m');
  return p.join(' ');
}

function loadStatus(){
  fetch('/api/v1/status').then(function(x){return x.json()}).then(function(d){
    var el=document.getElementById('status');
    var tags = (d.required_tags && d.required_tags.length) ? d.required_tags.join(', ') : '(none - sync everything)';
    var last = d.sync.last_sync_at ? new Date(d.sync.last_sync_at).toLocaleString() : 'never';
    var h = '';
    h += '<p><strong>DNS provider:</strong> ' + d.dns_provider + ' &nbsp;|&nbsp; <strong>Domain:</strong> ' + d.dns_domain + '</p>';
    h += '<p><strong>Poll interval:</strong> ' + d.poll_interval + ' &nbsp;|&nbsp; <strong>Workers:</strong> ' + d.workers + '</p>';
    h += '<p><strong>Tag filter:</strong> ' + tags + '</p>';
    h += '<p><strong>Syncs completed:</strong> ' + d.sync.sync_count + ' &nbsp;|&nbsp; <strong>Last sync:</strong> ' + last + '</p>';
    h += '<p><strong>Uptime:</strong> ' + d.sync.uptime + ' &nbsp;|&nbsp; <strong>Nodes known:</strong> ' + d.nodes.count + '</p>';
    h += '<p><strong>Webhook:</strong> ' + (d.webhook_enabled ? 'enabled' : 'disabled') + '</p>';
    el.innerHTML = h;
  }).catch(function(){
    document.getElementById('status').innerHTML = '<p class="status-bad">Failed to load status.</p>';
  });
}

function loadNodes(){
  fetch('/api/v1/nodes').then(function(x){return x.json()}).then(function(d){
    var el=document.getElementById('nodes');
    if(!d.nodes || !d.nodes.length){
      el.innerHTML = '<p class="muted">No nodes known yet.</p>';
      return;
    }
    var h = '<table><tr><th>Name</th><th>Addresses</th><th>Tags</th><th>Online</th></tr>';
    d.nodes.forEach(function(n){
      var tags = (n.Tags && n.Tags.length) ? n.Tags.join(', ') : '';
      h += '<tr><td>' + (n.Name||'') + '</td><td>' + (n.Addresses||[]).join(', ') + '</td><td>' + tags + '</td><td>' + (n.Online ? 'yes' : 'no') + '</td></tr>';
    });
    h += '</table>';
    el.innerHTML = h;
  }).catch(function(){
    document.getElementById('nodes').innerHTML = '<p class="status-bad">Failed to load nodes.</p>';
  });
}

function triggerSync(){
  var btn=document.getElementById('syncBtn');
  btn.disabled=true;
  btn.textContent='Syncing...';
  fetch('/api/v1/sync',{method:'POST'}).then(function(x){return x.json()}).then(function(d){
    btn.textContent='Sync Now';
    btn.disabled=false;
    loadStatus();
  }).catch(function(){
    btn.textContent='Sync Now';
    btn.disabled=false;
  });
}

loadStatus();
loadNodes();
setInterval(loadStatus, 10000);
setInterval(loadNodes, 30000);
</script>
</body>
</html>
`)

	return b.String()
}

// dashboardAttributes lists the static attributes shown on the page.
func dashboardAttributes() [][2]string {
	return [][2]string{
		{"Service", "dnsscale"},
		{"Version", serviceVersion},
		{"Source", "github.com/e-hollebone/dnsscale-webhook"},
		{"DNS providers", "cloudflare, route53, pihole"},
		{"Record types", "A, AAAA, TXT (ownership)"},
		{"Poll model", "constant daemon; change detected -> reconcile immediately"},
		{"Webhook", "Tailscale events -> HMAC-verified fast-path sync"},
		{"Discovery", "RFC 8631 Link headers, RFC 5785 /.well-known/dnsscale, HATEOAS"},
	}
}

// dashboardHead is the HTML head and stylesheet, shared by the dashboard.
const dashboardHead = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DNSScale — API Documentation</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--accent:#38bdf8;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--success:#22c55e;--warn:#f59e0b;--err:#ef4444}
body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--text);line-height:1.6}
.container{max-width:900px;margin:0 auto;padding:2rem 1rem}
h1{font-size:1.8rem;border-bottom:2px solid var(--accent);padding-bottom:0.5rem}
h2{font-size:1.3rem;color:var(--accent);margin-top:2rem}
code{background:#0f172a;border:1px solid var(--border);padding:2px 6px;border-radius:4px;font-size:0.9rem}
pre{background:#0f172a;border:1px solid var(--border);border-radius:6px;padding:1rem;overflow-x:auto;font-size:0.85rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin:1rem 0}
.endpoint{display:flex;align-items:center;gap:0.75rem;margin:0.5rem 0}
.method{font-weight:bold;padding:2px 8px;border-radius:4px;font-size:0.8rem;min-width:50px;text-align:center}
.get{background:#166534;color:#86efac}
.post{background:#1e40af;color:#93c5fd}
.path{font-family:monospace;font-size:0.95rem}
.params{font-size:0.85rem;color:var(--muted);margin:0.25rem 0 0.25rem 1.5rem}
.param{display:inline-block;background:#0f172a;padding:1px 5px;border-radius:3px;margin:2px;font-family:monospace;font-size:0.8rem}
a{color:var(--accent);text-decoration:none;text-decoration:underline}
.muted{color:var(--muted);font-size:0.85rem}
.status-bad{color:var(--err)}
table{width:100%;border-collapse:collapse;font-size:0.9rem}
th,td{text-align:left;padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)}
th{color:var(--accent);font-weight:600}
button{padding:10px 24px;border-radius:6px;border:0;background:var(--accent);color:var(--bg);font-weight:bold;cursor:pointer;margin-top:0.5rem}
button:disabled{opacity:0.6;cursor:default}
.footer{margin-top:2rem;font-size:0.85rem;color:var(--muted);border-top:1px solid var(--border);padding-top:1rem}
</style>
</head>
<body>
`
