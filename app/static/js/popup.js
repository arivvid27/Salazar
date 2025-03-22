document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.getElementById('scan-button');
    const settingsButton = document.getElementById('settings-button');
    const scanMessage = document.getElementById('scan-message');
    const scanIcon = document.getElementById('scan-icon');
    const riskIndicator = document.getElementById('risk-indicator');
    const resultContainer = document.getElementById('scan-result');
    const threatDetails = document.getElementById('threat-details');
    const loadingSpinner = document.getElementById('loading-spinner');
    
    // Hide results initially
    resultContainer.style.display = 'none';
    
    // Check if we're in a tab that can be scanned
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTab = tabs[0];
        const url = currentTab.url;
        
        // Check if URL is scannable (not chrome:// or other special URLs)
        if (!url.startsWith('http')) {
            scanButton.disabled = true;
            scanMessage.textContent = 'Cannot scan this page';
            scanMessage.classList.add('error');
            return;
        }
        
        // Check if we already have scan results for this URL
        chrome.storage.local.get([url], function(result) {
            if (result[url]) {
                displayResults(result[url]);
            }
        });
    });
    
    // Scan button click handler
    scanButton.addEventListener('click', function() {
        // Show loading spinner
        scanButton.disabled = true;
        scanMessage.textContent = 'Scanning...';
        scanIcon.classList.add('scanning');
        loadingSpinner.style.display = 'block';
        resultContainer.style.display = 'none';
        
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const currentTab = tabs[0];
            
            // Send message to content script to get the page HTML
            chrome.tabs.sendMessage(currentTab.id, {action: "getPageContent"}, function(response) {
                if (chrome.runtime.lastError) {
                    // Content script might not be loaded yet
                    console.error(chrome.runtime.lastError);
                    scanMessage.textContent = 'Error: Could not analyze page';
                    scanMessage.classList.add('error');
                    scanButton.disabled = false;
                    scanIcon.classList.remove('scanning');
                    loadingSpinner.style.display = 'none';
                    return;
                }
                
                const pageContent = response.html;
                const pageUrl = currentTab.url;
                
                // Send to backend for analysis
                fetch('http://localhost:5000/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        url: pageUrl,
                        html: pageContent
                    })
                })
                .then(response => response.json())
                .then(data => {
                    // Save results to storage
                    chrome.storage.local.set({[pageUrl]: data});
                    
                    // Display results
                    displayResults(data);
                    
                    // Enable scan button again
                    scanButton.disabled = false;
                    scanIcon.classList.remove('scanning');
                    loadingSpinner.style.display = 'none';
                    
                    // Show notification if high risk
                    if (data.risk_score > 70) {
                        chrome.runtime.sendMessage({
                            action: "showNotification",
                            title: "High Risk Detected!",
                            message: "This website may pose security risks. See Muninn for details."
                        });
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    scanMessage.textContent = 'Error during scan';
                    scanMessage.classList.add('error');
                    scanButton.disabled = false;
                    scanIcon.classList.remove('scanning');
                    loadingSpinner.style.display = 'none';
                });
            });
        });
    });
    
    // Settings button click handler
    settingsButton.addEventListener('click', function() {
        chrome.runtime.openOptionsPage();
    });
    
    // Learn more links
    document.addEventListener('click', function(e) {
        if (e.target && e.target.classList.contains('learn-more')) {
            const threatType = e.target.dataset.threat;
            
            // Send message to open education panel
            chrome.runtime.sendMessage({
                action: "showEducation",
                threatType: threatType
            });
        }
    });
    
    // Function to display scan results
    function displayResults(data) {
        resultContainer.style.display = 'block';
        
        // Update risk indicator
        const riskScore = data.risk_score;
        riskIndicator.style.width = `${riskScore}%`;
        
        if (riskScore < 30) {
            riskIndicator.className = 'risk-indicator low';
            scanMessage.textContent = 'Low Risk';
            scanMessage.className = 'scan-message safe';
        } else if (riskScore < 70) {
            riskIndicator.className = 'risk-indicator medium';
            scanMessage.textContent = 'Medium Risk';
            scanMessage.className = 'scan-message warning';
        } else {
            riskIndicator.className = 'risk-indicator high';
            scanMessage.textContent = 'High Risk!';
            scanMessage.className = 'scan-message danger';
        }
        
        // Clear previous threat details
        threatDetails.innerHTML = '';
        
        // Add phishing details if applicable
        if (data.phishing && data.phishing.risk_level !== 'low') {
            const phishingSection = createThreatSection(
                'Phishing',
                data.phishing.risk_level,
                data.phishing.risk_factors,
                data.phishing.recommendations
            );
            threatDetails.appendChild(phishingSection);
        }
        
        // Add XSS details if applicable
        if (data.xss && data.xss.vulnerable) {
            const xssSection = createThreatSection(
                'Cross-Site Scripting (XSS)',
                'high',
                data.xss.risk_factors,
                data.xss.recommendations
            );
            threatDetails.appendChild(xssSection);
        }
        
        // Add CSRF details if applicable
        if (data.csrf && data.csrf.vulnerable) {
            const csrfSection = createThreatSection(
                'Cross-Site Request Forgery (CSRF)',
                'medium',
                data.csrf.risk_factors,
                data.csrf.recommendations
            );
            threatDetails.appendChild(csrfSection);
        }
        
        // Add Safe Browsing API results if applicable
        if (data.safe_browsing && data.safe_browsing.threats && data.safe_browsing.threats.length > 0) {
            const threats = data.safe_browsing.threats.map(threat => `Google Safe Browsing detected: ${threat.type}`);
            
            const safeBrowsingSection = createThreatSection(
                'Google Safe Browsing',
                'high',
                threats,
                data.safe_browsing.recommendations || []
            );
            threatDetails.appendChild(safeBrowsingSection);
        }
        
        // If no threats were found
        if (threatDetails.children.length === 0) {
            const noThreatsElement = document.createElement('div');
            noThreatsElement.className = 'no-threats';
            noThreatsElement.innerHTML = `
                <div class="icon-safe"></div>
                <p>No significant threats detected!</p>
                <p class="note">Remember to always stay vigilant when sharing personal information online.</p>
            `;
            threatDetails.appendChild(noThreatsElement);
        }
    }
    
    // Helper function to create threat section
    function createThreatSection(title, level, factors, recommendations) {
        const section = document.createElement('div');
        section.className = `threat-section ${level}`;
        
        const threatType = title.toLowerCase().replace(/\s/g, '-').replace(/[()]/g, '');
        
        let factorsHtml = '';
        if (factors && factors.length > 0) {
            factorsHtml = `
                <ul class="risk-factors">
                    ${factors.map(factor => `<li>${factor}</li>`).join('')}
                </ul>
            `;
        }
        
        let recommendationsHtml = '';
        if (recommendations && recommendations.length > 0) {
            recommendationsHtml = `
                <div class="recommendations">
                    <h4>Recommendations:</h4>
                    <ul>
                        ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        section.innerHTML = `
            <div class="threat-header">
                <h3>${title}</h3>
                <span class="risk-badge ${level}">${level.toUpperCase()}</span>
            </div>
            ${factorsHtml}
            ${recommendationsHtml}
            <a href="#" class="learn-more" data-threat="${threatType}">Learn more about ${title}</a>
        `;
        
        return section;
    }
});