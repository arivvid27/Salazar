// Flag to track if we've already scanned this page
let hasScanned = false;

// Listen for messages from the popup or background script
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    // If the popup is requesting the page content
    if (request.action === "getPageContent") {
        sendResponse({
            html: document.documentElement.outerHTML
        });
    }
    
    // If background script is requesting an automatic scan
    else if (request.action === "autoScan" && !hasScanned) {
        hasScanned = true;
        
        // Send the page content to the backend for scanning
        fetch('http://localhost:5000/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: window.location.href,
                html: document.documentElement.outerHTML
            })
        })
        .then(response => response.json())
        .then(data => {
            // Store the result in local storage
            chrome.storage.local.set({[window.location.href]: data});
            
            // Notify the background script of the scan result
            chrome.runtime.sendMessage({
                action: "scanCompleted",
                result: data
            });
            
            // If high risk and education mode is enabled, show warning
            if (data.risk_score > 70) {
                chrome.storage.sync.get(['educationMode'], function(result) {
                    if (result.educationMode) {
                        showPageWarning(data);
                    }
                });
            }
        })
        .catch(error => {
            console.error('Error during automatic scan:', error);
        });
    }
    
    // Return true to indicate async response
    return true;
});

// Function to show a warning overlay on high-risk pages
function showPageWarning(data) {
    // Create warning overlay container
    const overlay = document.createElement('div');
    overlay.id = 'muninn-warning-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.85);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    `;
    
    // Create warning content
    const warningBox = document.createElement('div');
    warningBox.style.cssText = `
        width: 600px;
        max-width: 90%;
        background-color: #fff;
        border-radius: 8px;
        padding: 24px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    `;
    
    // Add warning content
    let warningContent = `
        <div style="text-align: center; margin-bottom: 24px;">
            <img src="${chrome.runtime.getURL('images/icon-48.png')}" alt="Muninn Logo" style="height: 48px;">
            <h2 style="color: #e74c3c; margin: 12px 0; font-size: 24px;">Security Warning</h2>
            <p style="color: #333; font-size: 16px;">Muninn has detected high-risk security issues on this website:</p>
        </div>
        <div style="margin-bottom: 20px;">
    `;
    
    // Add threat details
    if (data.phishing && data.phishing.risk_level === 'high') {
        warningContent += `
            <div style="margin-bottom: 16px;">
                <h3 style="color: #e74c3c; font-size: 18px;">Phishing Risk</h3>
                <ul style="margin-top: 8px; color: #333;">
                    ${data.phishing.risk_factors.slice(0, 3).map(factor => `<li>${factor}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    if (data.safe_browsing && data.safe_browsing.threats && data.safe_browsing.threats.length > 0) {
        warningContent += `
            <div style="margin-bottom: 16px;">
                <h3 style="color: #e74c3c; font-size: 18px;">Malware Risk</h3>
                <p>This site has been flagged by Google Safe Browsing.</p>
            </div>
        `;
    }
    
    // Add actions
    warningContent += `
        </div>
        <div style="display: flex; justify-content: space-between; margin-top: 24px;">
            <button id="muninn-leave-btn" style="
                padding: 12px 24px;
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                font-weight: bold;
            ">Leave This Site</button>
            <button id="muninn-proceed-btn" style="
                padding: 12px 24px;
                background-color: #f1f1f1;
                color: #333;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
            ">Proceed Anyway</button>
        </div>
    `;
    
    warningBox.innerHTML = warningContent;
    overlay.appendChild(warningBox);
    document.body.appendChild(overlay);
    
    // Add event listeners
    document.getElementById('muninn-leave-btn').addEventListener('click', function() {
        window.location.href = "about:blank";
    });
    
    document.getElementById('muninn-proceed-btn').addEventListener('click', function() {
        document.body.removeChild(overlay);
    });
}

// Check if there are any forms on the page that might need protection
function checkForVulnerableForms() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        // Check if the form has a password field or appears to be collecting sensitive data
        const hasPasswordField = form.querySelector('input[type="password"]') !== null;
        const hasEmailField = form.querySelector('input[type="email"], input[name*="email"], input[placeholder*="email"]') !== null;
        const hasCreditCardField = form.querySelector('input[name*="card"], input[placeholder*="card"]') !== null;
        
        if (hasPasswordField || hasEmailField || hasCreditCardField) {
            // Check if the form is submitting over HTTPS
            const formAction = form.getAttribute('action') || '';
            const isSecureSubmission = formAction.startsWith('https://') || 
                                     (formAction.startsWith('/') && window.location.protocol === 'https:');
            
            // If not submitting securely, add a warning
            if (!isSecureSubmission && window.location.protocol !== 'https:') {
                addFormWarning(form, 'This form is not submitting over a secure connection.');
            }
            
            // Check for CSRF token
            const hasCSRFToken = Array.from(form.elements).some(element => 
                element.name && element.name.toLowerCase().includes('csrf') || 
                element.name && element.name.toLowerCase().includes('token')
            );
            
            if (!hasCSRFToken && form.method && form.method.toLowerCase() === 'post') {
                addFormWarning(form, 'This form may not be protected against CSRF attacks.');
            }
        }
    });
}

// Add a warning banner to vulnerable forms
function addFormWarning(form, message) {
    const warningBanner = document.createElement('div');
    warningBanner.className = 'muninn-form-warning';
    warningBanner.style.cssText = `
        background-color: #fff3cd;
        color: #856404;
        padding: 10px 15px;
        margin-bottom: 12px;
        border-left: 4px solid #ffc107;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-size: 14px;
        display: flex;
        align-items: center;
        border-radius: 4px;
    `;
    
    // Add warning icon
    warningBanner.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 10px;">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span>${message}</span>
    `;
    
    // Insert the warning banner before the form
    form.parentNode.insertBefore(warningBanner, form);
}

// Run form checks when the page loads
window.addEventListener('load', function() {
    // Check if education mode is enabled
    chrome.storage.sync.get(['educationMode'], function(result) {
        if (result.educationMode) {
            checkForVulnerableForms();
        }
    });
});