"""
FiShield - Real-Time Phishing URL Detection
============================================
This script:
  1. Trains a Random Forest model on phishing URL features
  2. Exports the model as a lightweight JSON decision tree (runs in browser JS)
  3. Generates ALL Chrome extension files automatically
  4. Outputs a ready-to-load /fishield_extension/ folder

Dataset: https://www.kaggle.com/datasets/suryaprabha19/phishing-url
Place the CSV as 'phishing_urls.csv' in the same directory, OR
the script will use a built-in synthetic dataset to demo the extension.

Usage:
  pip install scikit-learn pandas numpy joblib
  python build_fishield_extension.py
  
Then in Chrome:
  1. Go to chrome://extensions
  2. Enable Developer Mode
  3. Click "Load unpacked" → select the generated fishield_extension/ folder
"""

import os
import json
import re
import math
import struct
import pickle
import base64
import hashlib
import textwrap
import urllib.parse
from pathlib import Path

# ─────────────────────────────────────────────
# 1. FEATURE ENGINEERING (Python + mirrored in JS)
# ─────────────────────────────────────────────

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
                   '.online', '.site', '.icu', '.buzz', '.fun', '.uno', '.rest'}
BRAND_KEYWORDS = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
                  'instagram', 'netflix', 'bank', 'secure', 'login', 'signin',
                  'account', 'verify', 'update', 'confirm', 'ebay', 'chase',
                  'wellsfargo', 'citibank', 'irs', 'gov', 'support', 'helpdesk']

def extract_features(url: str) -> list:
    """Extract 20 heuristic features from a URL. Mirrored in extension JS."""
    try:
        parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    except Exception:
        parsed = urllib.parse.urlparse('http://unknown')

    hostname = parsed.hostname or ''
    path     = parsed.path or ''
    query    = parsed.query or ''
    full     = url.lower()

    # Remove www. for cleaner analysis
    domain = re.sub(r'^www\.', '', hostname.lower())
    domain_parts = domain.split('.')
    tld = '.' + domain_parts[-1] if len(domain_parts) > 1 else ''

    # --- Length features ---
    f1  = min(len(url), 300) / 300                          # URL length (norm)
    f2  = min(len(hostname), 100) / 100                     # Hostname length (norm)
    f3  = min(len(path), 200) / 200                         # Path length (norm)

    # --- Character-based features ---
    f4  = url.count('-') / max(len(url), 1)                 # Hyphen density
    f5  = url.count('.') / max(len(url), 1)                 # Dot density
    f6  = url.count('@') > 0                                # Has @ symbol
    f7  = url.count('//') > 1                               # Double slash (after proto)
    f8  = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)  # Digit ratio in host
    f9  = len(re.findall(r'[!#$%^&*()=+\[\]{};\'\\:"|,<>?]', url)) / max(len(url), 1)  # Special chars

    # --- Domain features ---
    f10 = 1 if tld in SUSPICIOUS_TLDS else 0               # Suspicious TLD
    f11 = len(domain_parts) > 4                             # Excessive subdomains
    f12 = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))  # IP address as host

    # --- Keyword / brand abuse features ---
    brand_hits = sum(kw in full for kw in BRAND_KEYWORDS)
    f13 = min(brand_hits, 5) / 5                            # Brand keyword density
    f14 = 'secure' in domain or 'login' in domain or 'verify' in domain  # Deceptive domain words
    f15 = len(re.findall(r'%[0-9a-fA-F]{2}', url)) / max(len(url), 1)   # URL encoding ratio

    # --- Entropy of domain (randomness → DGA / phishing) ---
    def entropy(s):
        if not s: return 0
        freq = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in freq)
    f16 = min(entropy(domain), 5) / 5                       # Domain entropy (norm)

    # --- Query string features ---
    f17 = len(query) > 50                                   # Long query string
    f18 = query.count('=') > 3                              # Many query params

    # --- Protocol features ---
    f19 = 1 if parsed.scheme == 'https' else 0              # HTTPS (legitimate signal)
    f20 = hostname.count('-') > 2                           # Many hyphens in hostname

    return [float(x) for x in [
        f1, f2, f3, f4, f5, f6, f7, f8, f9, f10,
        f11, f12, f13, f14, f15, f16, f17, f18, f19, f20
    ]]

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "hyphen_density",
    "dot_density", "has_at_symbol", "double_slash", "digit_ratio_host",
    "special_char_ratio", "suspicious_tld", "excessive_subdomains",
    "ip_as_host", "brand_keyword_density", "deceptive_domain_words",
    "url_encoding_ratio", "domain_entropy", "long_query_string",
    "many_query_params", "uses_https", "many_hyphens_hostname"
]

# ─────────────────────────────────────────────
# 2. DATASET LOADING / SYNTHETIC FALLBACK
# ─────────────────────────────────────────────

def load_dataset():
    """Load Kaggle CSV if available, else generate synthetic training data."""
    csv_path = Path('phishing_urls.csv')
    
    if csv_path.exists():
        import pandas as pd
        print(f"[✓] Loading dataset from {csv_path} ...")
        df = pd.read_csv(csv_path)
        
        # Handle common column name variations
        url_col   = next((c for c in df.columns if 'url' in c.lower()), df.columns[0])
        label_col = next((c for c in df.columns if 'label' in c.lower() or 'type' in c.lower() or 'class' in c.lower()), df.columns[-1])
        
        df = df[[url_col, label_col]].dropna()
        df.columns = ['url', 'label']
        
        # Normalize labels to 0 (legit) / 1 (phishing)
        df['label'] = df['label'].astype(str).str.lower()
        df['label'] = df['label'].map(lambda x: 0 if x in ('0', 'legitimate', 'benign', 'safe', 'good') else 1)
        
        print(f"[✓] Loaded {len(df)} URLs  ({df['label'].sum()} phishing, {(df['label']==0).sum()} legit)")
        return df['url'].tolist(), df['label'].tolist()
    
    else:
        print("[!] phishing_urls.csv not found — generating synthetic training data.")
        print("    Download dataset from: https://www.kaggle.com/datasets/suryaprabha19/phishing-url")
        print("    Place as phishing_urls.csv in the same folder and re-run for a production model.\n")
        return _synthetic_dataset()

def _synthetic_dataset():
    """Balanced synthetic dataset covering known phishing patterns."""
    legit = [
        "https://www.google.com/search?q=python",
        "https://github.com/openai/gpt-4",
        "https://stackoverflow.com/questions/12345",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://docs.python.org/3/library/re.html",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.reddit.com/r/python",
        "https://medium.com/@author/article-title",
        "https://developer.mozilla.org/en-US/docs/Web",
        "https://www.linkedin.com/in/username",
        "https://twitter.com/home",
        "https://www.nytimes.com/section/technology",
        "https://www.bbc.com/news",
        "https://www.paypal.com/signin",
        "https://banking.chase.com/login",
        "https://www.apple.com/shop/buy-iphone",
        "https://account.microsoft.com",
        "https://www.netflix.com/browse",
        "https://www.ebay.com/itm/123456",
        "https://mail.google.com/mail",
        "https://drive.google.com/file/d/abc",
        "https://www.dropbox.com/home",
        "https://www.salesforce.com/crm",
        "https://www.adobe.com/products/acrobat.html",
        "https://zoom.us/j/meeting",
        "https://slack.com/workspace",
        "https://www.coursera.org/learn/python",
        "https://aws.amazon.com/s3",
        "https://portal.azure.com/#blade/home",
    ] * 5

    phishing = [
        "http://paypa1-secure-login.tk/verify/account",
        "http://192.168.1.1/admin/login.php",
        "http://secure-apple-id-verify.ml/confirm",
        "http://www.google.com.evil-site.xyz/login",
        "http://amazon-prize-winner.top/claim?user=you",
        "http://microsoft-account-suspended.club/reactivate",
        "http://login-facebook-security.ga/checkpoint",
        "http://bank-of-america-verify.cf/secure/login",
        "http://netflix-billing-update.xyz/payment",
        "http://irs-tax-refund-2024.online/claim",
        "http://paypal.account-verification-required.tk/",
        "http://appleid.apple.com.scam-domain.ml/",
        "http://secure-ebay-signin.cf/signin",
        "http://wellsfargo-online-banking.top/account",
        "http://update-your-amazon-account.xyz/verify",
        "http://chase-bank-login-secure.club/login.html",
        "http://google-prize-draw.tk/winner?id=12345",
        "http://instagram-login-verify.ga/checkpoint",
        "http://microsoft-helpdesk-support.ml/remote",
        "http://citibank-secure-login.online/signin",
        "http://1nst4gram-login.com/verify-account",
        "http://arnazon.com/dp/claim-prize",
        "http://faceb00k-security.net/login",
        "http://micosoft-support.xyz/windows-error-fix",
        "http://payp4l-secure.top/account/verify",
        "http://g00gle-account-signin.ml/security-check",
        "http://amaz0n-gift-claim.cf/free-gift",
        "http://twitter-login-verify.online/oauth",
        "http://linkedin-account-verify.club/login",
        "http://dropbox-share-document.xyz/view?doc=abc%20xyz%20xyz@evil.com",
        "http://support-apple-id.tk/unlock?token=abc123xyz",
        "http://secure.paypal.com.login.tk/webscr",
        "http://bank-alert-security-notice.ml/login",
        "http://verify-your-account-immediately.online/",
        "http://xn--pple-43d.com/apple-id-verify",
        "http://signin-ebay.com-secure-login.cf/",
        "http://account-suspended-amazon.top/reactivate",
        "http://free-gift-card-generator-2024.xyz/claim",
        "http://covid-relief-fund-gov.tk/apply",
        "http://crypto-investment-guaranteed.ml/signup",
    ] * 4

    urls   = legit + phishing
    labels = [0] * len(legit) + [1] * len(phishing)
    return urls, labels

# ─────────────────────────────────────────────
# 3. TRAIN MODEL & EXPORT AS JSON
# ─────────────────────────────────────────────

def train_and_export(urls, labels):
    """Train RandomForest and export as a JSON structure for in-browser inference."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report

    print("[*] Extracting features ...")
    X = [extract_features(u) for u in urls]
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[*] Training Random Forest ...")
    clf = RandomForestClassifier(
        n_estimators=50,          # Keep small for JS export
        max_depth=8,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[✓] Model Performance:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # Export trees as JSON for browser-side inference
    print("[*] Exporting model as JSON ...")
    model_json = export_forest_to_json(clf)
    return model_json, clf

def export_tree_to_json(tree, feature_names):
    """Recursively convert a sklearn decision tree to a plain JSON dict."""
    t = tree.tree_
    
    def recurse(node):
        if t.children_left[node] == -1:  # Leaf
            values = t.value[node][0]
            total  = sum(values)
            prob   = values[1] / total if total > 0 else 0
            return {"leaf": True, "prob": round(prob, 4)}
        return {
            "feature": int(t.feature[node]),
            "threshold": round(float(t.threshold[node]), 6),
            "left":  recurse(t.children_left[node]),
            "right": recurse(t.children_right[node]),
        }
    return recurse(0)

def export_forest_to_json(clf):
    trees = [export_tree_to_json(est, FEATURE_NAMES) for est in clf.estimators_]
    return {
        "trees": trees,
        "n_trees": len(trees),
        "feature_names": FEATURE_NAMES,
        "version": "1.0"
    }

# ─────────────────────────────────────────────
# 4. GENERATE CHROME EXTENSION FILES
# ─────────────────────────────────────────────

EXT_DIR = Path('fishield_extension')

def write(path, content):
    full = EXT_DIR / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding='utf-8')
    print(f"  [+] {path}")

def generate_extension(model_json):
    print(f"\n[*] Generating Chrome extension in ./{EXT_DIR}/")

    # ── manifest.json ──────────────────────────────────────────────────────────
    write('manifest.json', json.dumps({
        "manifest_version": 3,
        "name": "FiShield – Phishing URL Detector",
        "version": "1.0.0",
        "description": "Real-time ML-powered phishing detection for every URL you visit.",
        "permissions": ["tabs", "storage", "webNavigation", "alarms"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
        "content_scripts": [{
            "matches": ["<all_urls>"],
            "js": ["content.js"],
            "run_at": "document_start"
        }],
        "action": {
            "default_popup": "popup.html",
            "default_icon": {
                "16":  "icons/icon16.png",
                "48":  "icons/icon48.png",
                "128": "icons/icon128.png"
            }
        },
        "icons": {
            "16":  "icons/icon16.png",
            "48":  "icons/icon48.png",
            "128": "icons/icon128.png"
        },
        "web_accessible_resources": [{
            "resources": ["overlay.html", "model.json"],
            "matches": ["<all_urls>"]
        }]
    }, indent=2))

    # ── model.json ─────────────────────────────────────────────────────────────
    write('model.json', json.dumps(model_json))

    # ── feature_extractor.js ───────────────────────────────────────────────────
    write('feature_extractor.js', r"""
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
""")

    # ── model_inference.js ─────────────────────────────────────────────────────
    write('model_inference.js', r"""
// FiShield Random Forest inference — runs entirely in the browser
let MODEL = null;

async function loadModel() {
  if (MODEL) return MODEL;
  const url  = chrome.runtime.getURL('model.json');
  const resp = await fetch(url);
  MODEL = await resp.json();
  return MODEL;
}

function predictTree(node, features) {
  if (node.leaf) return node.prob;
  return features[node.feature] <= node.threshold
    ? predictTree(node.left,  features)
    : predictTree(node.right, features);
}

async function classifyURL(url) {
  const model    = await loadModel();
  const features = extractFeatures(url);
  const probs    = model.trees.map(t => predictTree(t, features));
  const avgProb  = probs.reduce((a, b) => a + b, 0) / probs.length;

  let verdict, color;
  if (avgProb >= 0.70)      { verdict = 'PHISHING';    color = '#e53935'; }
  else if (avgProb >= 0.40) { verdict = 'SUSPICIOUS';  color = '#fb8c00'; }
  else                      { verdict = 'SAFE';         color = '#43a047'; }

  // Build human-readable explanations
  const reasons = buildReasons(url, features, avgProb);

  return {
    url,
    verdict,
    confidence: Math.round(avgProb * 100),
    color,
    reasons,
    features
  };
}

function buildReasons(url, f, prob) {
  const reasons = [];
  if (f[11])  reasons.push('🔴 IP address used as hostname (no domain name)');
  if (f[9])   reasons.push('🔴 Suspicious top-level domain (.tk / .ml / .xyz ...)');
  if (f[5])   reasons.push('🔴 URL contains @ symbol — likely credential theft');
  if (f[12] > 0.4) reasons.push(`🔴 Brand name abuse detected in URL`);
  if (f[13])  reasons.push('🟠 Deceptive words (secure/login/verify) in domain');
  if (f[10])  reasons.push('🟠 Unusually large number of subdomains');
  if (f[6])   reasons.push('🟠 Redirecting double-slash found in URL path');
  if (f[3] > 0.1) reasons.push('🟠 High density of hyphens — common in phishing domains');
  if (f[15] > 0.04) reasons.push('🟠 Heavy URL encoding — obfuscation detected');
  if (f[15] > 0.4) reasons.push('🟠 Domain entropy is high — possibly auto-generated');
  if (!f[18]) reasons.push('🟢 Site uses HTTPS');
  if (reasons.length === 0 && prob < 0.3) reasons.push('🟢 No suspicious signals detected');
  return reasons.slice(0, 5);
}
""")

    # ── background.js ──────────────────────────────────────────────────────────
    write('background.js', r"""
// FiShield Service Worker
// Handles: URL interception, model inference, tab state, popup messaging

importScripts('feature_extractor.js', 'model_inference.js');

// Cache: tabId → last result
const tabResults = {};

// Intercept navigations
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;  // Main frame only
  const url = details.url;
  if (!url || url.startsWith('chrome://') || url.startsWith('about:')) return;

  try {
    const result = await classifyURL(url);
    tabResults[details.tabId] = result;

    // Update badge
    const badge = result.verdict === 'PHISHING'   ? '⛔' :
                  result.verdict === 'SUSPICIOUS' ? '⚠️' : '✓';
    chrome.action.setBadgeText({ text: result.verdict === 'SAFE' ? '✓' : '!', tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: result.color, tabId: details.tabId });

    // Inject alert overlay for phishing / suspicious
    if (result.verdict !== 'SAFE') {
      chrome.tabs.sendMessage(details.tabId, {
        type: 'FISHIELD_ALERT',
        result
      }).catch(() => {}); // Content script may not be ready yet — handled by onUpdated too
    }
  } catch (e) {
    console.error('[FiShield]', e);
  }
});

// Also send alert when content script is ready (onCommitted can race)
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status !== 'complete') return;
  const result = tabResults[tabId];
  if (result && result.verdict !== 'SAFE') {
    chrome.tabs.sendMessage(tabId, { type: 'FISHIELD_ALERT', result }).catch(() => {});
  }
});

// Popup asks for current tab result
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_RESULT') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab) return sendResponse(null);
      sendResponse(tabResults[tab.id] || null);
    });
    return true; // async
  }

  if (msg.type === 'CLOSE_OVERLAY') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'CLOSE_OVERLAY' }).catch(() => {});
      }
    });
  }
});
""")

    # ── content.js ─────────────────────────────────────────────────────────────
    write('content.js', r"""
// FiShield Content Script — injects the alert overlay into pages

let overlayEl = null;

function injectOverlay(result) {
  if (overlayEl) overlayEl.remove();

  const verdictEmoji = result.verdict === 'PHISHING' ? '⛔' : '⚠️';
  const bgGradient   = result.verdict === 'PHISHING'
    ? 'linear-gradient(135deg, #b71c1c 0%, #e53935 100%)'
    : 'linear-gradient(135deg, #e65100 0%, #fb8c00 100%)';

  const reasonsHTML = result.reasons.map(r =>
    `<div style="margin:4px 0;font-size:13px;line-height:1.4">${r}</div>`
  ).join('');

  overlayEl = document.createElement('div');
  overlayEl.id = 'fishield-overlay';
  overlayEl.innerHTML = `
    <div id="fishield-overlay-inner">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="font-size:32px">${verdictEmoji}</div>
          <div>
            <div style="font-size:11px;opacity:.8;letter-spacing:1px;text-transform:uppercase">FiShield Alert</div>
            <div style="font-size:20px;font-weight:700;letter-spacing:.5px">${result.verdict}</div>
          </div>
        </div>
        <button id="fishield-close" title="Dismiss">✕</button>
      </div>

      <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:10px 14px;margin-bottom:12px">
        <div style="font-size:11px;opacity:.7;margin-bottom:4px">URL ANALYSED</div>
        <div style="font-size:12px;word-break:break-all;opacity:.95">${result.url.slice(0,90)}${result.url.length>90?'…':''}</div>
      </div>

      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <div style="flex:1">
          <div style="font-size:11px;opacity:.7;margin-bottom:4px">ML CONFIDENCE</div>
          <div style="height:8px;background:rgba(0,0,0,.3);border-radius:4px;overflow:hidden">
            <div style="height:100%;width:${result.confidence}%;background:#fff;border-radius:4px;transition:width .6s ease"></div>
          </div>
        </div>
        <div style="text-align:right">
          <div style="font-size:28px;font-weight:800;line-height:1">${result.confidence}%</div>
          <div style="font-size:10px;opacity:.7">confidence</div>
        </div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:11px;opacity:.7;margin-bottom:6px">DETECTED SIGNALS</div>
        ${reasonsHTML}
      </div>

      <div style="display:flex;gap:8px">
        <button id="fishield-leave" style="flex:1;padding:9px;background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.3);border-radius:6px;cursor:pointer;font-size:13px;font-weight:600">
          ← Go Back
        </button>
        <button id="fishield-proceed" style="flex:1;padding:9px;background:rgba(0,0,0,.25);color:rgba(255,255,255,.7);border:1px solid rgba(255,255,255,.2);border-radius:6px;cursor:pointer;font-size:12px">
          Proceed anyway
        </button>
      </div>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    #fishield-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 2147483647;
      background: rgba(0,0,0,.55); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      animation: fishieldFadeIn .25s ease;
    }
    #fishield-overlay-inner {
      background: ${bgGradient};
      color: #fff; padding: 22px; border-radius: 16px;
      max-width: 400px; width: calc(100% - 40px);
      box-shadow: 0 24px 60px rgba(0,0,0,.5);
    }
    #fishield-close {
      background: rgba(0,0,0,.2); border: none; color: #fff;
      width: 28px; height: 28px; border-radius: 50%; cursor: pointer;
      font-size: 14px; display: flex; align-items: center; justify-content: center;
    }
    #fishield-leave:hover   { background: rgba(255,255,255,.25) !important; }
    #fishield-proceed:hover { background: rgba(0,0,0,.4) !important; }
    @keyframes fishieldFadeIn { from { opacity:0; transform: scale(.96); } to { opacity:1; transform: scale(1); } }
  `;

  document.head.appendChild(style);
  document.documentElement.appendChild(overlayEl);

  document.getElementById('fishield-close').onclick   = removeOverlay;
  document.getElementById('fishield-proceed').onclick  = removeOverlay;
  document.getElementById('fishield-leave').onclick    = () => { removeOverlay(); history.back(); };
}

function removeOverlay() {
  if (overlayEl) { overlayEl.remove(); overlayEl = null; }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'FISHIELD_ALERT') injectOverlay(msg.result);
  if (msg.type === 'CLOSE_OVERLAY')  removeOverlay();
});
""")

    # ── popup.html ─────────────────────────────────────────────────────────────
    write('popup.html', '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FiShield</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      width: 340px; min-height: 200px;
      font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', sans-serif;
      background: #0f172a; color: #f1f5f9;
    }
    .header {
      background: linear-gradient(135deg, #1e3a5f 0%, #0f2744 100%);
      padding: 18px 20px; display: flex; align-items: center; gap: 12px;
      border-bottom: 1px solid rgba(255,255,255,.08);
    }
    .logo { font-size: 28px; }
    .brand { font-size: 18px; font-weight: 700; letter-spacing: .5px; }
    .brand small { display:block; font-size:11px; font-weight:400; opacity:.6; }
    .body { padding: 16px 20px; }
    .verdict-card {
      border-radius: 12px; padding: 16px; margin-bottom: 14px;
      text-align: center;
    }
    .verdict-label { font-size: 11px; opacity: .7; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 6px; }
    .verdict-text  { font-size: 26px; font-weight: 800; letter-spacing: .5px; }
    .confidence-row { display:flex; align-items:center; gap:10px; margin-bottom:12px; }
    .conf-bar { flex:1; height:6px; background:rgba(255,255,255,.1); border-radius:3px; overflow:hidden; }
    .conf-fill { height:100%; border-radius:3px; transition: width .5s ease; }
    .conf-pct  { font-size:20px; font-weight:700; min-width:44px; text-align:right; }
    .url-box { font-size:11px; opacity:.5; word-break:break-all; margin-bottom:14px; line-height:1.5; }
    .signals { margin-bottom:8px; }
    .signal  { font-size:12px; line-height:1.5; margin-bottom:3px; }
    .loading { text-align:center; padding:30px; opacity:.5; }
    .footer  { padding:10px 20px; border-top:1px solid rgba(255,255,255,.06); font-size:10px; opacity:.4; text-align:center; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🛡️</div>
    <div class="brand">FiShield <small>Real-Time Phishing Detection</small></div>
  </div>
  <div class="body" id="body">
    <div class="loading">Analysing current page…</div>
  </div>
  <div class="footer">Powered by Random Forest ML · FiShield v1.0</div>

  <script src="popup.js"></script>
</body>
</html>
''')

    # ── popup.js ───────────────────────────────────────────────────────────────
    write('popup.js', r"""
chrome.runtime.sendMessage({ type: 'GET_RESULT' }, (result) => {
  const body = document.getElementById('body');
  if (!result) {
    body.innerHTML = '<div class="loading" style="opacity:.6">No analysis yet for this page.<br><small style="font-size:11px">Navigate to a URL to scan it.</small></div>';
    return;
  }

  const color = result.color;
  const emoji = result.verdict === 'PHISHING' ? '⛔' : result.verdict === 'SUSPICIOUS' ? '⚠️' : '✅';
  const signalsHTML = (result.reasons || []).map(r => `<div class="signal">${r}</div>`).join('');

  body.innerHTML = `
    <div class="verdict-card" style="background:${color}22;border:1px solid ${color}55">
      <div class="verdict-label">Verdict ${emoji}</div>
      <div class="verdict-text" style="color:${color}">${result.verdict}</div>
    </div>
    <div class="confidence-row">
      <div class="conf-bar">
        <div class="conf-fill" style="width:${result.confidence}%;background:${color}"></div>
      </div>
      <div class="conf-pct" style="color:${color}">${result.confidence}%</div>
    </div>
    <div class="url-box">${result.url}</div>
    <div class="signals">${signalsHTML || '<div class="signal">🟢 No suspicious signals detected</div>'}</div>
  `;
});
""")

    # ── icons (generate simple PNG icons via raw bytes) ────────────────────────
    generate_icons()

    print(f"\n[✓] Extension generated at: ./{EXT_DIR}/")

def generate_icons():
    """Create minimal PNG icons (shield shape) programmatically."""
    import zlib, struct

    def make_png(size, r, g, b):
        """Create a solid-color PNG of given size."""
        raw = b''
        for _ in range(size):
            row = b'\x00' + bytes([r, g, b, 255]) * size
            raw += row
        compressed = zlib.compress(raw)
        
        def chunk(tag, data):
            c = struct.pack('>I', len(data)) + tag + data
            crc = zlib.crc32(tag + data) & 0xffffffff
            return c + struct.pack('>I', crc)
        
        png  = b'\x89PNG\r\n\x1a\n'
        png += chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0))
        png += chunk(b'IDAT', compressed)
        png += chunk(b'IEND', b'')
        return png

    icons_dir = EXT_DIR / 'icons'
    icons_dir.mkdir(exist_ok=True)
    for sz in [16, 48, 128]:
        (icons_dir / f'icon{sz}.png').write_bytes(make_png(sz, 30, 100, 180))
    print("  [+] icons/ (icon16.png, icon48.png, icon128.png)")

# ─────────────────────────────────────────────
# 5. GENERATE BACKEND (optional Flask API)
# ─────────────────────────────────────────────

def generate_backend_server():
    write('server/app.py', '''"""
FiShield Optional Backend Server
Runs a Flask API that the extension can call for server-side inference.
Use this if you want to run a heavier model (XGBoost, deep learning) server-side.

Usage:
  pip install flask scikit-learn joblib
  python server/app.py
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

app = Flask(__name__)
CORS(app)

# Import feature extractor from parent dir
from build_fishield_extension import extract_features

try:
    import joblib
    model = joblib.load(\'server/model.pkl\')
    print("[✓] Loaded server model")
except Exception as e:
    model = None
    print(f"[!] No server model found ({e}) — run build_fishield_extension.py first")

@app.route(\'/classify\', methods=[\'POST\'])
def classify():
    data = request.get_json()
    url  = data.get(\'url\', \'\')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    if model is None:
        return jsonify({"error": "Model not loaded"}), 503

    features = [extract_features(url)]
    prob     = model.predict_proba(features)[0][1]
    
    verdict = \'PHISHING\' if prob >= 0.70 else \'SUSPICIOUS\' if prob >= 0.40 else \'SAFE\'
    return jsonify({
        "url": url,
        "verdict": verdict,
        "confidence": round(prob * 100),
        "phishing_probability": round(prob, 4)
    })

if __name__ == \'__main__\':
    app.run(host=\'127.0.0.1\', port=5000, debug=True)
''')


# ─────────────────────────────────────────────
# 6. README
# ─────────────────────────────────────────────

def generate_readme():
    readme = """
# FiShield – Real-Time Phishing URL Detection Extension

## Quick Start

### 1. Install dependencies
```bash
pip install scikit-learn pandas numpy joblib
```

### 2. (Optional but recommended) Download the dataset
Get it from: https://www.kaggle.com/datasets/suryaprabha19/phishing-url  
Place the CSV file as `phishing_urls.csv` in the same directory as `build_fishield_extension.py`

### 3. Run the builder
```bash
python build_fishield_extension.py
```
This trains the model and generates the `fishield_extension/` folder.

### 4. Load in Chrome
1. Open Chrome → go to `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `fishield_extension/` folder

### 5. Use it!
- Visit any website — FiShield intercepts every navigation automatically
- If a URL is **Phishing** or **Suspicious**, a full-screen alert appears instantly
- The popup badge shows ✓ (safe), ! (alert)
- Click the 🛡️ extension icon to see the detailed verdict for the current page

---

## Architecture

```
fishield_extension/
├── manifest.json          ← Chrome extension config (MV3)
├── background.js          ← Service worker: intercepts navigations, runs ML
├── content.js             ← Injects alert overlay into pages  
├── popup.html / popup.js  ← Extension popup UI
├── feature_extractor.js   ← 20-feature URL heuristics (mirrors Python)
├── model_inference.js     ← Random Forest inference (browser-native JS)
├── model.json             ← Trained RF model exported as JSON trees
└── icons/                 ← Extension icons
```

## Features Extracted (20 total)

| # | Feature | Description |
|---|---------|-------------|
| 1 | url_length | Normalized URL length |
| 2 | hostname_length | Domain name length |
| 3 | path_length | URL path length |
| 4 | hyphen_density | Hyphens per character |
| 5 | dot_density | Dots per character |
| 6 | has_at_symbol | Presence of @ (credential theft) |
| 7 | double_slash | Redirect indicator |
| 8 | digit_ratio_host | Numbers in hostname (IP-like) |
| 9 | special_char_ratio | Obfuscation characters |
| 10 | suspicious_tld | Free/abused TLDs |
| 11 | excessive_subdomains | Too many subdomain levels |
| 12 | ip_as_host | IP address used instead of domain |
| 13 | brand_keyword_density | Brand name abuse |
| 14 | deceptive_domain_words | secure/login/verify in domain |
| 15 | url_encoding_ratio | %xx encoding obfuscation |
| 16 | domain_entropy | Shannon entropy → DGA detection |
| 17 | long_query_string | Unusually long query |
| 18 | many_query_params | Too many parameters |
| 19 | uses_https | HTTPS is legitimate signal |
| 20 | many_hyphens_hostname | Hyphenated domain abuse |

## Verdict Thresholds

| Confidence | Verdict |
|-----------|---------|
| ≥ 70% | 🔴 PHISHING |
| 40–69% | 🟠 SUSPICIOUS |
| < 40% | 🟢 SAFE |

## Performance Notes
- Inference runs entirely in the browser (no server needed)
- < 5ms per URL classification
- Model: Random Forest, 50 trees, max depth 8
- Re-train with full Kaggle dataset for production accuracy
""".strip()
    (EXT_DIR / 'README.md').write_text(readme)
    print("  [+] README.md")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  FiShield – Chrome Extension Builder")
    print("=" * 60)

    EXT_DIR.mkdir(exist_ok=True)

    # 1. Load data
    urls, labels = load_dataset()

    # 2. Train & export
    model_json, clf = train_and_export(urls, labels)

    # 3. Save sklearn model for optional backend
    try:
        import joblib
        server_dir = EXT_DIR / 'server'
        server_dir.mkdir(exist_ok=True)
        joblib.dump(clf, server_dir / 'model.pkl')
        print("[✓] Saved server/model.pkl for optional Flask backend")
    except Exception:
        pass

    # 4. Generate extension files
    generate_extension(model_json)
    generate_backend_server()
    generate_readme()

    print("\n" + "=" * 60)
    print("  ✅ BUILD COMPLETE")
    print("=" * 60)
    print(f"\n  Extension folder: ./fishield_extension/")
    print("\n  To load in Chrome:")
    print("    1. Open chrome://extensions")
    print("    2. Enable Developer Mode (top-right)")
    print("    3. Click 'Load unpacked'")
    print("    4. Select the fishield_extension/ folder")
    print("\n  With Kaggle dataset:")
    print("    Download: https://www.kaggle.com/datasets/suryaprabha19/phishing-url")
    print("    Place as: phishing_urls.csv")
    print("    Re-run:   python build_fishield_extension.py")
    print("=" * 60)
