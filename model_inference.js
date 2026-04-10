
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
