
// FiShield Feature Extractor — mirrors Python extract_features()
const SUSPICIOUS_TLDS = new Set([
  '.tk','.ml','.ga','.cf','.gq','.xyz','.top','.club',
  '.online','.site','.icu','.buzz','.fun','.uno','.rest'
]);
const BRAND_KEYWORDS = [
  'paypal','apple','google','microsoft','amazon','facebook',
  'instagram','netflix','bank','secure','login','signin',
  'account','verify','update','confirm','ebay','chase',
  'wellsfargo','citibank','irs','gov','support','helpdesk'
];

function entropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((acc, n) => {
    const p = n / s.length;
    return acc + p * Math.log2(p);
  }, 0);
}

function extractFeatures(url) {
  let parsed;
  try { parsed = new URL(url.includes('://') ? url : 'http://' + url); }
  catch { parsed = new URL('http://unknown'); }

  const hostname = parsed.hostname || '';
  const path     = parsed.pathname || '';
  const query    = parsed.search  || '';
  const full     = url.toLowerCase();
  const domain   = hostname.replace(/^www\./, '').toLowerCase();
  const parts    = domain.split('.');
  const tld      = parts.length > 1 ? '.' + parts[parts.length - 1] : '';

  const f1  = Math.min(url.length, 300) / 300;
  const f2  = Math.min(hostname.length, 100) / 100;
  const f3  = Math.min(path.length, 200) / 200;
  const f4  = (url.split('-').length - 1) / Math.max(url.length, 1);
  const f5  = (url.split('.').length - 1) / Math.max(url.length, 1);
  const f6  = url.includes('@') ? 1 : 0;
  const f7  = (url.split('//').length - 1) > 1 ? 1 : 0;
  const f8  = (hostname.replace(/[^0-9]/g,'').length) / Math.max(hostname.length, 1);
  const f9  = (url.match(/[!#$%^&*()=+\[\]{};'\\:"|,<>?]/g)||[]).length / Math.max(url.length,1);
  const f10 = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;
  const f11 = parts.length > 4 ? 1 : 0;
  const f12 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0;
  const brandHits = BRAND_KEYWORDS.filter(k => full.includes(k)).length;
  const f13 = Math.min(brandHits, 5) / 5;
  const f14 = (domain.includes('secure') || domain.includes('login') || domain.includes('verify')) ? 1 : 0;
  const f15 = (url.match(/%[0-9a-fA-F]{2}/g)||[]).length / Math.max(url.length,1);
  const f16 = Math.min(entropy(domain), 5) / 5;
  const f17 = query.length > 50 ? 1 : 0;
  const f18 = (query.split('=').length - 1) > 3 ? 1 : 0;
  const f19 = parsed.protocol === 'https:' ? 1 : 0;
  const f20 = (hostname.split('-').length - 1) > 2 ? 1 : 0;

  return [f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20];
}
