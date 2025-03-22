// Background script for Muninn extension

// Store settings and current scan status
let settings = {
    enablePhishingDetection: true,
    enableXssDetection: true,
    enableCsrfDetection: true,
    enableEducationMode: true,
    automaticScan: true,
    notifyOnHighRisk: true,
    apiEndpoint: 'http://localhost:5000/api'
  };
  
  // Load settings from storage
  chrome.storage.sync.get('settings', (data) => {
    if (data.settings) {
      settings = {...settings, ...data.settings};
    } else {
      // Save default settings if none exist
      chrome.storage.sync.set({ settings });
    }
  });
  
  // Track current tab's scan results
  let currentScanResults = {};
  
  // Listen for messages from content script or popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getSettings') {
      sendResponse({ settings });
    }
    else if (message.action === 'saveSettings') {
      settings = {...settings, ...message.settings};
      chrome.storage.sync.set({ settings });
      sendResponse({ success: true });
    }
    else if (message.action === 'scanPage') {
      scanCurrentPage(sender.tab?.id, message.url, message.html)
        .then(results => {
          currentScanResults = results;
          sendResponse({ success: true, results });
        })
        .catch(error => {
          console.error('Scan error:', error);
          sendResponse({ success: false, error: error.message });
        });
      return true; // Keep the message channel open for the async response
    }
    else if (message.action === 'getScanResults') {
      sendResponse({ results: currentScanResults });
    }
  });
  
  // Listen for tab updates to trigger automatic scanning
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only scan when the page has completed loading
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
      if (settings.automaticScan) {
        // Notify the content script to prepare for scanning
        chrome.tabs.sendMessage(tabId, { action: 'prepareForScan' });
      }
    }
  });
  
  // Function to scan the current page
  async function scanCurrentPage(tabId, url, html) {
    if (!url || !html) {
      throw new Error('Missing URL or HTML content');
    }
    
    try {
      // Send request to Flask backend
      const response = await fetch(`${settings.apiEndpoint}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, html })
      });
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`);
      }
      
      const results = await response.json();
      
      // Update badge based on risk level
      updateBadge(tabId, results.risk_score);
      
      // Send notification for high-risk sites
      if (settings.notifyOnHighRisk && results.risk_score >= 70) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: chrome.runtime.getURL('static/images/icon-128.png'),
          title: 'High Risk Website Detected',
          message: `Muninn has detected security risks on ${url}. Click to see details.`,
          priority: 2
        });
      }
      
      return results;
    } catch (error) {
      console.error('Error scanning page:', error);
      throw error;
    }
  }
  
  // Update the extension badge based on risk score
  function updateBadge(tabId, riskScore) {
    let color, text;
    
    if (riskScore >= 70) {
      color = '#ff006e'; // Danger
      text = 'HIGH';
    } else if (riskScore >= 30) {
      color = '#fb5607'; // Warning
      text = 'MED';
    } else {
      color = '#38b000'; // Safe
      text = 'OK';
    }
    
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    chrome.action.setBadgeText({ text: text, tabId: tabId });
  }
  
  // Listen for installation or update
  chrome.runtime.onInstalled.addListener(() => {
    // Create context menu items
    chrome.contextMenus.create({
      id: 'scanPage',
      title: 'Scan this page with Muninn',
      contexts: ['page']
    });
    
    chrome.contextMenus.create({
      id: 'learnMore',
      title: 'Learn about web security',
      contexts: ['page']
    });
  });
  
  // Handle context menu clicks
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'scanPage') {
      chrome.tabs.sendMessage(tab.id, { action: 'prepareForScan' });
    } else if (info.menuItemId === 'learnMore') {
      chrome.tabs.create({ url: chrome.runtime.getURL('templates/education.html') });
    }
  });