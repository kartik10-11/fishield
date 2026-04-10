
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
