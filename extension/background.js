// Store for active tabs that have been scanned
const scannedTabs = new Map();

// Listen for installation
chrome.runtime.onInstalled.addListener(function() {
    console.log("Muninn extension installed");
    
    // Initialize default settings
    chrome.storage.sync.get(['scanMode', 'notificationsEnabled', 'educationMode'], function(result) {
        if (result.scanMode === undefined) {
            chrome.storage.sync.set({scanMode: 'manual'});
        }
        
        if (result.notificationsEnabled === undefined) {
            chrome.storage.sync.set({notificationsEnabled: true});
        }
        
        if (result.educationMode === undefined) {
            chrome.storage.sync.set({educationMode: true});
        }
    });
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "showNotification" && request.title && request.message) {
        // Check if notifications are enabled
        chrome.storage.sync.get(['notificationsEnabled'], function(result) {
            if (result.notificationsEnabled) {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'images/icon-128.png',
                    title: request.title,
                    message: request.message
                });
            }
        });
    }
    
    else if (request.action === "showEducation" && request.threatType) {
        // Check if education mode is enabled
        chrome.storage.sync.get(['educationMode'], function(result) {
            if (result.educationMode) {
                // Fetch education content
                fetch(`http://localhost:5000/api/educate/${request.threatType}`)
                    .then(response => response.json())
                    .then(data => {
                        // Create a new tab with the education content
                        chrome.tabs.create({
                            url: `education.html?type=${request.threatType}`
                        }, function(tab) {
                            // Store the education data for the new tab
                            chrome.storage.local.set({
                                [`education_${tab.id}`]: data
                            });
                        });
                    })
                    .catch(error => {
                        console.error('Error fetching education content:', error);
                    });
            }
        });
    }
    
    else if (request.action === "scanCompleted") {
        const tabId = sender.tab.id;
        const result = request.result;
        
        // Store result for this tab
        scannedTabs.set(tabId, result);
        
        // Update badge if high risk
        if (result.risk_score > 70) {
            chrome.action.setBadgeText({text: "⚠️", tabId: tabId});
            chrome.action.setBadgeBackgroundColor({color: "#FF0000", tabId: tabId});
        } else if (result.risk_score > 30) {
            chrome.action.setBadgeText({text: "!", tabId: tabId});
            chrome.action.setBadgeBackgroundColor({color: "#FFA500", tabId: tabId});
        } else {
            chrome.action.setBadgeText({text: "✓", tabId: tabId});
            chrome.action.setBadgeBackgroundColor({color: "#00FF00", tabId: tabId});
        }
    }
    
    // Return true to indicate async response
    return true;
});

// Handle tab updates for automatic scanning
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    // Only proceed if the tab has completed loading and has an HTTP/HTTPS URL
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Check if automatic scanning is enabled
        chrome.storage.sync.get(['scanMode'], function(result) {
            if (result.scanMode === 'automatic') {
                // Send message to content script to perform automatic scan
                chrome.tabs.sendMessage(tabId, {action: "autoScan"});
            }
        });
    }
});

// Handle tab removal to clean up stored data
chrome.tabs.onRemoved.addListener(function(tabId) {
    // Remove stored scan result for this tab
    if (scannedTabs.has(tabId)) {
        scannedTabs.delete(tabId);
    }
    
    // Remove any education data for this tab
    chrome.storage.local.remove(`education_${tabId}`);
});