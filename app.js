const $ = id => document.getElementById(id);
const esc = s => s.replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const split = s => s.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
const cleanDomain = s => s.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'');
const validDomain = d => /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(d);
const validEmail = e => /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(e);

function record(title, name, value, type='TXT'){
  const id = 'r' + Math.random().toString(36).slice(2);
  return `<div class="rec"><div class="t"><span>${esc(title)}</span><button class="copy" data-copy="${id}">Copy</button></div>
  <pre id="${id}">${esc(value)}</pre></div>`;
}
function dnsBlock(host, value){
  return record('Host / Name', '', host) + record('Type: TXT — Value', '', value);
}
document.addEventListener('click', e => {
  const b = e.target.closest('.copy'); if(!b) return;
  const txt = $(b.dataset.copy).textContent;
  navigator.clipboard.writeText(txt).then(()=>{ const o=b.textContent; b.textContent='Copied!'; setTimeout(()=>b.textContent=o,1200); });
});

// Tabs
document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tabs button').forEach(x => x.classList.toggle('active', x===b));
  document.querySelectorAll('section').forEach(s => s.classList.toggle('active', s.id===b.dataset.tab));
});

/* ---------- SPF ---------- */
const PROVIDERS = [
  ['Google Workspace','_spf.google.com'],
  ['Microsoft 365','spf.protection.outlook.com'],
  ['Zoho Mail','zoho.com'],
  ['SendGrid','sendgrid.net'],
  ['Mailgun','mailgun.org'],
  ['Amazon SES','amazonses.com'],
  ['Mailchimp / Mandrill','servers.mcsv.net'],
  ['Postmark','spf.mtasv.net'],
  ['Brevo (Sendinblue)','spf.brevo.com'],
  ['SparkPost','sparkpostmail.com'],
];
$('spf-providers').innerHTML = PROVIDERS.map(([n,d],i)=>`<label><input type="checkbox" data-inc="${d}"> ${n}</label>`).join('');

function buildSpf(){
  const domain = cleanDomain($('spf-domain').value);
  const parts = ['v=spf1'];
  let lookups = 0;
  const msgs = [];
  if($('spf-mx').checked){ parts.push('mx'); lookups++; }
  if($('spf-a').checked){ parts.push('a'); lookups++; }
  split($('spf-ips').value).forEach(ip => {
    const v6 = ip.includes(':');
    const ok = v6 ? /^[0-9a-f:.]+(\/\d{1,3})?$/i.test(ip) : /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(ip);
    if(!ok){ msgs.push(`<span class="warn">Skipped invalid IP: ${esc(ip)}</span>`); return; }
    parts.push((v6?'ip6:':'ip4:') + ip);
  });
  const incs = [...document.querySelectorAll('#spf-providers input:checked')].map(i=>i.dataset.inc)
    .concat(split($('spf-inc').value).map(cleanDomain).filter(validDomain));
  [...new Set(incs)].forEach(d => { parts.push('include:'+d); lookups++; });
  parts.push($('spf-all').value);
  const value = parts.join(' ');

  let h = '';
  if(!domain || !validDomain(domain)) h += `<p class="note warn">Enter a valid domain to show the DNS host.</p>`;
  h += dnsBlock('@  ('+(domain||'yourdomain.com')+')', value);
  h += `<p class="note ${lookups>10?'warn':'ok'}">DNS lookups used by this record (excluding nested includes): ${lookups} / 10 max.</p>`;
  if(parts.includes('+all')) h += `<p class="note warn">+all lets anyone send as your domain.</p>`;
  h += `<p class="note">Only one SPF record is allowed per domain — merge with any existing <code>v=spf1</code> record.</p>`;
  h += msgs.map(m=>`<p class="note">${m}</p>`).join('');
  $('spf-out').innerHTML = h;
}
['spf-domain','spf-mx','spf-a','spf-ips','spf-inc','spf-all'].forEach(i=>$(i).addEventListener('input',buildSpf));
$('spf-providers').addEventListener('change',buildSpf);
buildSpf();

/* ---------- DMARC ---------- */
function buildDmarc(){
  const domain = cleanDomain($('dm-domain').value);
  const p = $('dm-p').value, sp = $('dm-sp').value;
  let pct = parseInt($('dm-pct').value,10);
  const warns = [];
  if(isNaN(pct) || pct<1 || pct>100){ if($('dm-pct').value.trim()!=='') warns.push('pct must be 1–100; using 100.'); pct = 100; }
  const parts = ['v=DMARC1', 'p='+p];
  if(sp) parts.push('sp='+sp);
  if(pct!==100) parts.push('pct='+pct);
  const mk = (id, tag) => {
    const list = split($(id).value);
    const bad = list.filter(e=>!validEmail(e.replace(/^mailto:/,'')));
    if(bad.length) warns.push('Invalid email: '+bad.join(', '));
    const good = list.filter(e=>!bad.includes(e)).map(e=>'mailto:'+e.replace(/^mailto:/,''));
    if(good.length) parts.push(tag+'='+good.join(','));
    return good.length;
  };
  const hasRua = mk('dm-rua','rua');
  const hasRuf = mk('dm-ruf','ruf');
  if($('dm-adkim').value==='s') parts.push('adkim=s');
  if($('dm-aspf').value==='s') parts.push('aspf=s');
  if(hasRuf && $('dm-fo').value!=='0') parts.push('fo='+$('dm-fo').value);
  const value = parts.join('; ');

  let h = dnsBlock('_dmarc  ('+'_dmarc.'+(domain||'yourdomain.com')+')', value);
  if(!domain || !validDomain(domain)) warns.unshift('Enter a valid domain to show the DNS host.');
  if(!hasRua) warns.push('No rua address: you will not receive aggregate reports.');
  if(p==='none') h += `<p class="note">p=none is monitoring only. Move to quarantine/reject once reports show legitimate mail passes.</p>`;
  h += `<p class="note">Requires SPF and/or DKIM to pass <em>and align</em> with the From domain.</p>`;
  h += warns.map(w=>`<p class="note warn">${esc(w)}</p>`).join('');
  $('dm-out').innerHTML = h;
}
['dm-domain','dm-p','dm-sp','dm-pct','dm-fo','dm-adkim','dm-aspf','dm-rua','dm-ruf'].forEach(i=>$(i).addEventListener('input',buildDmarc));
buildDmarc();

/* ---------- DKIM ---------- */
const b64 = buf => { let s=''; new Uint8Array(buf).forEach(b=>s+=String.fromCharCode(b)); return btoa(s); };
const pem = (b, label) => `-----BEGIN ${label}-----\n${b.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;

$('dkim-go').onclick = async () => {
  const domain = cleanDomain($('dkim-domain').value);
  const sel = $('dkim-selector').value.trim().toLowerCase();
  const out = $('dkim-out');
  out.hidden = false;
  if(!validDomain(domain)){ out.innerHTML = '<p class="note warn">Enter a valid domain.</p>'; return; }
  if(!/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(sel)){ out.innerHTML = '<p class="note warn">Selector may only contain letters, numbers, dots, hyphens, underscores.</p>'; return; }
  if(!window.crypto || !crypto.subtle){ out.innerHTML = '<p class="note warn">WebCrypto unavailable. Open this page via http://localhost or https.</p>'; return; }
  const btn = $('dkim-go'); btn.disabled = true; btn.textContent = 'Generating…';
  try{
    const bits = parseInt($('dkim-bits').value,10);
    const kp = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:bits,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
    const pub = b64(await crypto.subtle.exportKey('spki',kp.publicKey));
    const priv = pem(b64(await crypto.subtle.exportKey('pkcs8',kp.privateKey)),'PRIVATE KEY');
    const value = `v=DKIM1; k=rsa; p=${pub}`;
    const chunks = value.match(/.{1,255}/g).map(c=>`"${c}"`).join(' ');
    const host = `${sel}._domainkey`;
    out.innerHTML =
      record('Host / Name', '', host) +
      record('Type: TXT — Value (single string)', '', value) +
      (value.length>255 ? record('Value split into 255-char strings (for BIND / zone files)', '', chunks) : '') +
      record('Private key (PKCS#8) — keep secret, install on your mail server', '', priv) +
      `<div class="actions"><button class="btn" id="dl-priv">Download private key</button></div>
       <p class="note">Full DNS name: <code>${esc(host)}.${esc(domain)}</code></p>
       <p class="note warn">Never share or publish the private key. Most providers (Google, Microsoft, SendGrid…) generate DKIM keys for you — use this generator only for self-hosted mail servers.</p>
       <p class="note">Some servers (OpenDKIM, Exim) need RSA format (<code>BEGIN RSA PRIVATE KEY</code>); convert with: <code>openssl rsa -in key.pem -out rsa.pem -traditional</code></p>`;
    $('dl-priv').onclick = () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([priv],{type:'text/plain'}));
      a.download = `${sel}.${domain}.private.pem`; a.click();
    };
  }catch(err){
    out.innerHTML = `<p class="note warn">Key generation failed: ${esc(String(err))}</p>`;
  }finally{
    btn.disabled = false; btn.textContent = 'Generate key pair';
  }
};

/* ---------- VERIFY (DNS-over-HTTPS) ---------- */
const DOH = [
  n => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=TXT`,
  n => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=TXT`,
];
async function txtLookup(name){
  let lastErr;
  for(const u of DOH){
    try{
      const r = await fetch(u(name), {headers:{accept:'application/dns-json'}});
      if(!r.ok) throw new Error('HTTP '+r.status);
      const j = await r.json();
      if(j.Status === 3) return [];            // NXDOMAIN
      if(j.Status !== 0) throw new Error('DNS status '+j.Status);
      // TXT data is returned quoted; multiple strings are joined
      return (j.Answer||[]).filter(a=>a.type===16)
        .map(a => a.data.replace(/"\s+"/g,'').replace(/^"|"$/g,''));
    }catch(e){ lastErr = e; }
  }
  throw lastErr;
}
function result(title, status, items, found){
  const label = {pass:'PASS',fail:'NOT FOUND',warn:'WARNING'}[status];
  return `<div class="res"><h3>${esc(title)} <span class="badge ${status}">${label}</span></h3>
    <ul>${items.map(i=>`<li>${i}</li>`).join('')}</ul>
    ${found ? `<pre>${esc(found)}</pre>` : ''}</div>`;
}
const tags = rec => Object.fromEntries(rec.split(';').map(p=>p.trim()).filter(Boolean)
  .map(p=>{const i=p.indexOf('=');return i<0?[p,'']:[p.slice(0,i).trim(),p.slice(i+1).trim()]}));

async function verifySpf(d){
  const recs = (await txtLookup(d)).filter(r=>/^v=spf1(\s|$)/i.test(r));
  if(!recs.length) return result('SPF','fail',['No <code>v=spf1</code> TXT record at '+esc(d)+'.']);
  const r = recs[0], items = [];
  let status = 'pass';
  if(recs.length>1){ status='fail'; items.push('Multiple SPF records found — only one is allowed (causes permerror).'); }
  const all = r.match(/\s([-~?+]?all)\s*$/i);
  if(!all){ if(status==='pass') status='warn'; items.push('No <code>all</code> mechanism at the end.'); }
  else if(all[1]==='+all'){ if(status==='pass') status='warn'; items.push('<code>+all</code> allows anyone to send as your domain.'); }
  else items.push('Ends with <code>'+esc(all[1])+'</code>.');
  const n = (r.match(/\s[-~?+]?(include:|a(:|\/|\s|$)|mx(:|\/|\s|$)|ptr|exists:)|\sredirect=/gi)||[]).length;
  items.push(`Approx. DNS lookups (top level): ${n} / 10.`);
  if(n>10){ status='fail'; items.push('Exceeds 10 DNS lookups.'); }
  return result('SPF',status,items,r);
}
async function verifyDmarc(d){
  const recs = (await txtLookup('_dmarc.'+d)).filter(r=>/^v=DMARC1/i.test(r));
  if(!recs.length) return result('DMARC','fail',['No <code>v=DMARC1</code> TXT record at <code>_dmarc.'+esc(d)+'</code>.']);
  const r = recs[0], t = tags(r), items = [];
  let status = 'pass';
  if(recs.length>1){ status='fail'; items.push('Multiple DMARC records found.'); }
  if(!['none','quarantine','reject'].includes(t.p)){ status='fail'; items.push('Missing or invalid <code>p</code> tag.'); }
  else{
    items.push('Policy: <code>p='+esc(t.p)+'</code>'+(t.sp?', subdomains: <code>sp='+esc(t.sp)+'</code>':''));
    if(t.p==='none'){ if(status==='pass') status='warn'; items.push('Monitoring only — consider quarantine/reject once reports look clean.'); }
  }
  if(t.rua) items.push('Aggregate reports sent to '+esc(t.rua)); else { if(status==='pass') status='warn'; items.push('No <code>rua</code> — you will not receive reports.'); }
  if(t.pct && t.pct!=='100') items.push('Applied to '+esc(t.pct)+'% of mail.');
  return result('DMARC',status,items,r);
}
async function verifyDkim(d, sel){
  const name = `${sel}._domainkey.${d}`;
  const recs = await txtLookup(name);
  if(!recs.length) return result('DKIM','fail',['No TXT record at <code>'+esc(name)+'</code>. Check the selector name.']);
  const r = recs[0], t = tags(r), items = [];
  let status = 'pass';
  if(!t.p){ status='fail'; items.push('Public key (<code>p</code>) is empty — this key has been revoked.'); }
  else{
    let bits = null;
    try{ // RSA SPKI length -> approximate key size
      const len = atob(t.p.replace(/\s/g,'')).length;
      bits = len>500?4096:len>250?2048:len>150?1024:null;
      items.push('Public key found'+(bits?` (~${bits}-bit RSA)`:'')+'.');
      if(bits===1024){ status='warn'; items.push('1024-bit keys are weak; prefer 2048-bit.'); }
    }catch(e){ status='fail'; items.push('Public key is not valid base64.'); }
  }
  if(t.v && t.v.toUpperCase()!=='DKIM1'){ status='fail'; items.push('Unexpected version <code>v='+esc(t.v)+'</code>.'); }
  if(t.t && t.t.includes('y')){ if(status==='pass') status='warn'; items.push('Testing mode (<code>t=y</code>) is set.'); }
  return result('DKIM',status,items,r);
}

const COMMON_SELECTORS = ['default','google','selector1','selector2','k1','k2','s1','s2','mail','dkim','smtp','mandrill','mxvault','zoho','sendgrid','amazonses','mailgun','krs'];
async function autoDkim(d){
  const found = [];
  await Promise.all(COMMON_SELECTORS.map(async s => {
    try{ if((await txtLookup(`${s}._domainkey.${d}`)).length) found.push(s); }catch(e){}
  }));
  if(!found.length) return result('DKIM','warn',['No DKIM record found for common selectors ('+COMMON_SELECTORS.map(esc).join(', ')+'). Enter your selector above to check a specific one.']);
  found.sort((x,y)=>COMMON_SELECTORS.indexOf(x)-COMMON_SELECTORS.indexOf(y));
  return verifyDkim(d, found[0])
    .then(h => h.replace('<ul>', `<ul><li>Auto-detected selector: <code>${esc(found[0])}</code>${found.length>1?' (also found: '+found.slice(1).map(esc).join(', ')+')':''}.</li>`));
}

$('v-go').onclick = async () => {
  const d = cleanDomain($('v-domain').value);
  const sel = $('v-selector').value.trim().toLowerCase();
  const out = $('v-out'); out.hidden = false;
  if(!validDomain(d)){ out.innerHTML = '<p class="note warn">Enter a valid domain.</p>'; return; }
  const btn = $('v-go'); btn.disabled = true; btn.textContent = 'Checking…';
  out.innerHTML = '<p class="note">Querying DNS…</p>';
  const safe = async (title, fn) => { try{ return await fn(); }catch(e){ return result(title,'warn',['Lookup failed: '+esc(String(e.message||e))+'. Check your connection or try again.']); } };
  const html = await Promise.all([
    safe('SPF', ()=>verifySpf(d)),
    safe('DKIM', ()=>sel ? verifyDkim(d,sel) : autoDkim(d)),
    safe('DMARC', ()=>verifyDmarc(d)),
  ]);
  out.innerHTML = html.join('');
  btn.disabled = false; btn.textContent = 'Verify records';
};

// Prefill verify fields from the other tabs
document.querySelector('[data-tab="verify"]').addEventListener('click', () => {
  if(!$('v-domain').value) $('v-domain').value = $('dkim-domain').value || $('spf-domain').value || $('dm-domain').value;
  // only prefill the selector once a DKIM key has actually been generated
  if(!$('v-selector').value && !$('dkim-out').hidden) $('v-selector').value = $('dkim-selector').value;
});
