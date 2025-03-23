document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scan-form');
    const submitButton = document.getElementById('submit-scan');
    const loadingIndicator = document.getElementById('loading-indicator');
    
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            if (submitButton && loadingIndicator) {
                submitButton.disabled = true;
                submitButton.style.display = 'none';
                loadingIndicator.style.display = 'flex';
            }
            
        });
    }
    
    const toggleButtons = document.querySelectorAll('.vuln-header, .ai-header');
    if (toggleButtons) {
        toggleButtons.forEach(function(button) {
            button.addEventListener('click', function() {
                const details = this.nextElementSibling;
                const icon = this.querySelector('.toggle-icon');
                
                if (details.style.display === 'block') {
                    details.style.display = 'none';
                    icon.textContent = '+';
                } else {
                    details.style.display = 'block';
                    icon.textContent = '-';
                }
            });
        });
    }
    
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    if (accordionHeaders) {
        accordionHeaders.forEach(function(header) {
            header.addEventListener('click', function() {
                const content = this.nextElementSibling;
                const icon = this.querySelector('.toggle-icon');
                
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                    icon.textContent = '+';
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                    icon.textContent = '-';
                }
            });
        });
    }
    
    const urlInput = document.getElementById('url');
    const urlError = document.getElementById('url-error');
    
    if (urlInput && urlError) {
        urlInput.addEventListener('input', function() {
            const url = this.value.trim();
            
            if (!url) {
                urlError.textContent = '';
                submitButton.disabled = true;
                return;
            }
            
            try {
                new URL(url);
                
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    throw new Error('URL must start with http:// or https://');
                }
                
                urlError.textContent = '';
                submitButton.disabled = false;
            } catch (e) {
                urlError.textContent = 'Please enter a valid URL (include http:// or https://)';
                submitButton.disabled = true;
            }
        });
    }
});

function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(function() {
        const originalText = buttonElement.textContent;
        buttonElement.textContent = 'Copied!';
        
        setTimeout(function() {
            buttonElement.textContent = originalText;
        }, 2000);
    }).catch(function(err) {
        console.error('Failed to copy: ', err);
        alert('Failed to copy text. Please try again.');
    });
}

