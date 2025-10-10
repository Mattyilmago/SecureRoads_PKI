// ============================================
// API TESTER FUNCTIONS WITH MODAL FORMS
// ============================================

// Global storage for last certificate
let lastEnrollmentCertificate = null;
let lastEnrollmentData = null;

function addApiLog(message, type = 'info') {
    const resultsDiv = document.getElementById('apiTestResults');
    const timestamp = new Date().toLocaleTimeString();
    const logLine = document.createElement('div');
    logLine.style.cssText = `
        margin-bottom: 8px;
        padding: 8px;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        ${type === 'error' ? 'color: #ef4444; background: rgba(239, 68, 68, 0.1);' : ''}
        ${type === 'success' ? 'color: #10b981; background: rgba(16, 185, 129, 0.1);' : ''}
        ${type === 'info' ? 'color: #60a5fa;' : ''}
        ${type === 'warning' ? 'color: #f59e0b; background: rgba(245, 158, 11, 0.1);' : ''}
    `;
    logLine.textContent = `[${timestamp}] ${message}`;
    resultsDiv.appendChild(logLine);
    resultsDiv.scrollTop = resultsDiv.scrollHeight;
}

function clearApiLogs() {
    const resultsDiv = document.getElementById('apiTestResults');
    resultsDiv.innerHTML = '';
}

// ============================================
// MODAL FORM SYSTEM (from old dashboard)
// ============================================

function showRequestForm(title, fields, onSubmit, options = {}) {
    // Remove existing modal if any
    const existingModal = document.getElementById('requestFormModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Build form HTML
    let formHTML = '';
    fields.forEach(field => {
        const fieldId = `field_${field.name}`;
        
        if (field.type === 'textarea') {
            formHTML += `
                <div style="margin-bottom: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                        <label style="display: block; color: #333; font-weight: 600;">${field.label}:</label>
                        <div style="display: flex; gap: 5px;">
                            ${field.useLast ? `
                                <button type="button" onclick="useLastCertificate('${fieldId}')" 
                                        style="padding: 4px 10px; background: #10b981; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">
                                    📋 Use Last Certificate
                                </button>
                            ` : ''}
                        </div>
                    </div>
                    <textarea id="${fieldId}" name="${field.name}" placeholder="${field.placeholder || ''}" ${field.required ? 'required' : ''} style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 0.9em; min-height: 120px;">${field.value || ''}</textarea>
                </div>
            `;
        } else if (field.type === 'checkbox') {
            formHTML += `
                <div style="margin-bottom: 15px;">
                    <label style="display: flex; align-items: center; color: #333; font-weight: 600; cursor: pointer;">
                        <input id="${fieldId}" type="checkbox" name="${field.name}" ${field.value ? 'checked' : ''} ${field.required ? 'required' : ''} style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                        <span>${field.label}</span>
                    </label>
                </div>
            `;
        } else {
            formHTML += `
                <div style="margin-bottom: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                        <label style="display: block; color: #333; font-weight: 600;">${field.label}:</label>
                        ${field.random ? `
                            <button type="button" onclick="randomizeField('${fieldId}', '${field.name}')" 
                                    style="padding: 4px 10px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">
                                🎲 Random
                            </button>
                        ` : ''}
                    </div>
                    <input id="${fieldId}" type="${field.type}" name="${field.name}" value="${field.value || ''}" placeholder="${field.placeholder || ''}" min="${field.min || ''}" max="${field.max || ''}" ${field.required ? 'required' : ''} style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1em;">
                </div>
            `;
        }
    });
    
    // Create modal
    const modal = document.createElement('div');
    modal.id = 'requestFormModal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 10000;
        overflow-y: auto;
    `;
    
    modal.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 15px; max-width: 600px; width: 90%; max-height: 90vh; overflow-y: auto; box-shadow: 0 10px 40px rgba(0,0,0,0.3); margin: 20px;">
            <h2 style="color: #667eea; margin-bottom: 20px;">🧪 ${title}</h2>
            <form id="apiTestForm">
                ${formHTML}
                <div style="display: flex; gap: 10px; margin-top: 25px;">
                    <button type="submit" style="flex: 2; padding: 12px; background: #10b981; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 1em;">
                        ▶️ Send Request
                    </button>
                    <button type="button" onclick="closeRequestForm()" style="flex: 1; padding: 12px; background: #6b7280; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 1em;">
                        ✕ Cancel
                    </button>
                </div>
            </form>
            <div style="margin-top: 15px; padding: 10px; background: #f0f9ff; border-left: 3px solid #3b82f6; border-radius: 4px; font-size: 0.85em; color: #1e40af;">
                <strong>ℹ️ Tip:</strong> Fill all required fields to test the API endpoint
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Handle form submission
    const form = document.getElementById('apiTestForm');
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const formData = {};
        fields.forEach(field => {
            const input = form.elements[field.name];
            if (field.type === 'checkbox') {
                formData[field.name] = input.checked;
            } else {
                formData[field.name] = input.value;
            }
        });
        
        // Close modal and execute callback
        closeRequestForm();
        onSubmit(formData);
    });
    
    // Close on background click
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            closeRequestForm();
        }
    });
}

function closeRequestForm() {
    const modal = document.getElementById('requestFormModal');
    if (modal) {
        modal.remove();
    }
}

// Generate a real ECDSA P-256 public key using Web Crypto API
async function generateRealPublicKey() {
    try {
        // Generate ECDSA key pair with P-256 curve
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            true,
            ["sign", "verify"]
        );
        
        // Export public key to SPKI format
        const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        
        // Convert to PEM format
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
        const pemPublicKey = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
        
        return pemPublicKey;
    } catch (error) {
        console.error("Error generating key:", error);
        return "-----BEGIN PUBLIC KEY-----\nMOCK_KEY_DATA_FOR_TESTING\n-----END PUBLIC KEY-----";
    }
}

// ============================================
// API REQUEST FUNCTION
// ============================================

async function makeApiRequest(method, endpoint, body = null) {
    clearApiLogs();
    
    let baseUrl;
    
    // Smart entity selection based on endpoint type
    if (endpoint.includes('/enrollment/')) {
        // Use selected EA
        const selectedEA = document.getElementById('selectedEA');
        if (!selectedEA || !selectedEA.value) {
            addApiLog('❌ No EA selected! Please select an Enrollment Authority first.', 'error');
            return;
        }
        baseUrl = `http://localhost:${selectedEA.value}`;
        addApiLog(`📝 Using Enrollment Authority: Port ${selectedEA.value}`, 'info');
        
    } else if (endpoint.includes('/authorization/')) {
        // Use selected AA
        const selectedAA = document.getElementById('selectedAA');
        if (!selectedAA || !selectedAA.value) {
            addApiLog('❌ No AA selected! Please select an Authorization Authority first.', 'error');
            return;
        }
        baseUrl = `http://localhost:${selectedAA.value}`;
        addApiLog(`🎫 Using Authorization Authority: Port ${selectedAA.value}`, 'info');
        
    } else {
        // Fallback to old apiBaseUrl if exists (for backward compatibility)
        const oldInput = document.getElementById('apiBaseUrl');
        if (oldInput && oldInput.value) {
            baseUrl = oldInput.value;
        } else {
            // Default to first EA if available
            const selectedEA = document.getElementById('selectedEA');
            if (selectedEA && selectedEA.value) {
                baseUrl = `http://localhost:${selectedEA.value}`;
                addApiLog(`ℹ️ Using default EA: Port ${selectedEA.value}`, 'info');
            } else {
                addApiLog('❌ No entity selected!', 'error');
                return;
            }
        }
    }
    
    const url = `${baseUrl}${endpoint}`;
    
    addApiLog(`${method} ${endpoint}`, 'info');
    addApiLog(`Target URL: ${url}`, 'info');
    
    try {
        console.log('🔍 Making API Request:', {url, method, body});
        
        const options = {
            method: method,
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (body) {
            options.body = JSON.stringify(body);
            addApiLog(`Request Body: ${JSON.stringify(body, null, 2)}`, 'info');
        }
        
        console.log('📤 Fetch options:', options);
        
        const startTime = Date.now();
        
        // Add timeout to fetch
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout
        options.signal = controller.signal;
        
        const response = await fetch(url, options);
        clearTimeout(timeoutId);
        
        const endTime = Date.now();
        
        console.log('📥 Response received:', response);
        
        addApiLog(`Response Time: ${endTime - startTime}ms`, 'success');
        addApiLog(`Status: ${response.status} ${response.statusText}`, 
                  response.ok ? 'success' : 'error');
        
        const contentType = response.headers.get('content-type');
        addApiLog(`Content-Type: ${contentType || 'N/A'}`, 'info');
        
        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();
            addApiLog(`Response Data:`, 'success');
            addApiLog(JSON.stringify(data, null, 2), 'success');
            
            // Save enrollment certificate if present
            if (endpoint.includes('/enrollment/request/simple') && data.success && data.certificate) {
                lastEnrollmentCertificate = data.certificate;
                lastEnrollmentData = {
                    its_id: body.its_id,
                    certificate: data.certificate,
                    certificate_info: data.certificate_info
                };
                addApiLog('💾 Certificate saved! Use "Use Last Certificate" in Authorization Request', 'success');
            }
            
            return data;
        } else if (contentType && contentType.includes('application/pkix-crl')) {
            const blob = await response.blob();
            addApiLog(`CRL Downloaded: ${blob.size} bytes`, 'success');
        } else {
            const text = await response.text();
            addApiLog(`Response: ${text.substring(0, 500)}${text.length > 500 ? '...' : ''}`, 'success');
        }
        
    } catch (error) {
        if (error.name === 'AbortError') {
            addApiLog(`❌ Request timeout after 10 seconds`, 'error');
            addApiLog(`Check if server is running on ${url}`, 'error');
        } else if (error.message.includes('Failed to fetch')) {
            addApiLog(`❌ Connection failed: ${error.message}`, 'error');
            addApiLog(`Possible causes:`, 'warning');
            addApiLog(`  - Server not running on ${url}`, 'warning');
            addApiLog(`  - CORS policy blocking the request`, 'warning');
            addApiLog(`  - Network/firewall issue`, 'warning');
            addApiLog(`Try: Check if server is running with netstat -ano | Select-String "${url.match(/:(\d+)/)?.[1]}"`, 'info');
        } else {
            addApiLog(`❌ Error: ${error.message}`, 'error');
            console.error('Full error:', error);
        }
    }
}

// ============================================
// API TEST FUNCTIONS
// ============================================

// System APIs
async function testHealthCheck() {
    await makeApiRequest('GET', '/health');
}

async function testRootEndpoint() {
    await makeApiRequest('GET', '/');
}

async function testGetMetrics() {
    await makeApiRequest('GET', '/api/monitoring/metrics');
}

// CRL APIs
async function testGetFullCRL() {
    await makeApiRequest('GET', '/api/crl/full');
}

async function testGetDeltaCRL() {
    await makeApiRequest('GET', '/api/crl/delta');
}

// Trust List APIs
async function testGetFullCTL() {
    const baseUrl = document.getElementById('apiBaseUrl').value;
    
    // CTL is typically on port 5050 (TLM)
    document.getElementById('apiBaseUrl').value = 'http://localhost:5050';
    
    await makeApiRequest('GET', '/api/trust-list/full');
    
    // Restore original URL
    document.getElementById('apiBaseUrl').value = baseUrl;
}

async function testGetDeltaCTL() {
    const baseUrl = document.getElementById('apiBaseUrl').value;
    
    // CTL is typically on port 5050 (TLM)
    document.getElementById('apiBaseUrl').value = 'http://localhost:5050';
    
    await makeApiRequest('GET', '/api/trust-list/delta');
    
    // Restore original URL
    document.getElementById('apiBaseUrl').value = baseUrl;
}

// Enrollment APIs - ETSI COMPLIANT (requires ASN.1 OER)
async function testEnrollmentRequest() {
    clearApiLogs();
    addApiLog('⚠️ POST /api/enrollment/request is ETSI TS 102941 compliant', 'warning');
    addApiLog('This endpoint requires ASN.1 OER encoded binary data', 'warning');
    addApiLog('', 'info');
    addApiLog('🔧 ETSI-Compliant Testing:', 'info');
    addApiLog('Use the provided Python scripts for proper ETSI testing:', 'info');
    addApiLog('', 'info');
    addApiLog('1. Test with ITS Station simulation:', 'success');
    addApiLog('   python examples/api_client_example.py --test enrollment', 'success');
    addApiLog('', 'info');
    addApiLog('2. Interactive PKI tester (complete workflow):', 'success');
    addApiLog('   python examples/interactive_pki_tester.py', 'success');
    addApiLog('', 'info');
    addApiLog('3. Quick test script:', 'success');
    addApiLog('   python examples/quick_test.py', 'success');
    addApiLog('', 'info');
    addApiLog('ℹ️ For JSON testing (non-ETSI), use:', 'info');
    addApiLog('   POST /api/enrollment/request/simple', 'info');
}

async function testEnrollmentValidation() {
    clearApiLogs();
    addApiLog('⚠️ POST /api/enrollment/validation requires mTLS authentication', 'warning');
    addApiLog('This endpoint is used for AA→EA communication', 'warning');
    addApiLog('Requires valid client certificate from an Authorization Authority', 'info');
    addApiLog('', 'info');
    addApiLog('🔒 mTLS Configuration Required:', 'info');
    addApiLog('1. Generate AA certificate with proper client auth extension', 'info');
    addApiLog('2. Configure TLS client certificate in HTTP client', 'info');
    addApiLog('3. Use mutual TLS (mTLS) enabled connection', 'info');
    addApiLog('', 'info');
    addApiLog('❌ Cannot be tested from browser without certificate setup', 'error');
}

// Authorization APIs - ETSI COMPLIANT (requires ASN.1 OER)
async function testAuthorizationRequest() {
    clearApiLogs();
    addApiLog('⚠️ POST /api/authorization/request is ETSI TS 102941 compliant', 'warning');
    addApiLog('This endpoint requires ASN.1 OER encoded binary data', 'warning');
    addApiLog('', 'info');
    addApiLog('📋 Required Components:', 'info');
    addApiLog('1. Valid Enrollment Certificate (EC) from EA', 'info');
    addApiLog('2. Signed Authorization Request with EC private key', 'info');
    addApiLog('3. ASN.1 OER encoding of EtsiTs102941Data-SignedEncrypted', 'info');
    addApiLog('4. HMAC key for unlinkable authorization', 'info');
    addApiLog('', 'info');
    addApiLog('🔧 ETSI-Compliant Testing:', 'info');
    addApiLog('Use the provided Python scripts:', 'success');
    addApiLog('', 'info');
    addApiLog('1. Full workflow test:', 'success');
    addApiLog('   python examples/interactive_pki_tester.py', 'success');
    addApiLog('', 'info');
    addApiLog('2. Authorization-specific test:', 'success');
    addApiLog('   python examples/api_client_example.py --test authorization', 'success');
}

async function testButterflyRequest() {
    clearApiLogs();
    addApiLog('⚠️ POST /api/authorization/butterfly-request is ETSI TS 102941 compliant', 'warning');
    addApiLog('This endpoint uses Butterfly Key Expansion for privacy', 'warning');
    addApiLog('', 'info');
    addApiLog('🦋 Butterfly Key Expansion:', 'info');
    addApiLog('Generates 20 unlinkable Authorization Tickets in one request', 'info');
    addApiLog('Uses HMAC-based key derivation for privacy preservation', 'info');
    addApiLog('', 'info');
    addApiLog('📋 Required Components:', 'info');
    addApiLog('1. Valid Enrollment Certificate (EC)', 'info');
    addApiLog('2. Master HMAC key for key expansion', 'info');
    addApiLog('3. ASN.1 OER encoded butterfly request', 'info');
    addApiLog('', 'info');
    addApiLog('🔧 ETSI-Compliant Testing:', 'info');
    addApiLog('Use the butterfly test script:', 'success');
    addApiLog('', 'info');
    addApiLog('1. Butterfly authorization test:', 'success');
    addApiLog('   python tests/test_butterfly_authorization.py', 'success');
    addApiLog('', 'info');
    addApiLog('2. Interactive tester (includes butterfly):', 'success');
    addApiLog('   python examples/interactive_pki_tester.py', 'success');
}

// ============================================
// SIMPLIFIED JSON API TEST FUNCTIONS (FOR DASHBOARD TESTING)
// ============================================

async function testSimpleEnrollmentRequest() {
    showRequestForm('Enrollment Request (Simplified JSON)', [
        { name: 'its_id', label: 'ITS Station ID', type: 'text', value: 'VEHICLE_001', required: true, placeholder: 'e.g. VEHICLE_001', random: true },
        { name: 'generate_key', label: 'Generate new EC key pair automatically', type: 'checkbox', value: true },
        { name: 'country', label: 'Country Code', type: 'text', value: 'IT', required: true, placeholder: 'e.g. IT, DE, FR' },
        { name: 'organization', label: 'Organization', type: 'text', value: 'SecureRoad', required: true },
        { name: 'validity_days', label: 'Validity (days)', type: 'number', value: '365', min: '1', max: '730', required: true }
    ], async (formData) => {
        clearApiLogs();
        addApiLog('📝 Starting Simplified Enrollment Request...', 'info');
        addApiLog(`ITS ID: ${formData.its_id}`, 'info');
        
        let publicKey;
        
        // Generate key if requested
        if (formData.generate_key) {
            addApiLog('🔑 Generating EC P-256 key pair...', 'info');
            try {
                publicKey = await generateRealPublicKey();
                addApiLog('✅ Key pair generated successfully', 'success');
            } catch (error) {
                addApiLog(`❌ Key generation failed: ${error.message}`, 'error');
                return;
            }
        } else {
            publicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMockPOKEpPCM=\n-----END PUBLIC KEY-----";
            addApiLog('ℹ️ Using sample public key', 'info');
        }
        
        const requestBody = {
            its_id: formData.its_id,
            public_key: publicKey,
            requested_attributes: {
                country: formData.country,
                organization: formData.organization,
                validity_days: parseInt(formData.validity_days)
            }
        };
        
        addApiLog('📤 Sending enrollment request to EA...', 'info');
        await makeApiRequest('POST', '/api/enrollment/request/simple', requestBody);
    }, {
        randomize: (field) => {
            if (field.name === 'its_id') {
                const randomNum = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
                return `VEHICLE_${randomNum}`;
            }
            return field.value;
        }
    });
}

async function testSimpleAuthorizationRequest() {
    showRequestForm('Authorization Request (Simplified JSON)', [
        { name: 'its_id', label: 'ITS Station ID', type: 'text', value: 'VEHICLE_001', required: true, random: true },
        { name: 'enrollment_cert', label: 'Enrollment Certificate (PEM)', type: 'textarea', value: '', required: true, placeholder: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----', useLast: true },
        { name: 'public_key', label: 'Public Key for AT (PEM)', type: 'textarea', value: '', required: false, placeholder: 'Leave empty to auto-generate' },
        { name: 'permissions', label: 'Requested Permissions (comma-separated)', type: 'text', value: 'cam,denm', required: true, placeholder: 'cam,denm,spatem' },
        { name: 'validity_days', label: 'Validity (days)', type: 'number', value: '7', min: '1', max: '30', required: true }
    ], async (formData) => {
        clearApiLogs();
        addApiLog('🎫 Starting Simplified Authorization Request...', 'info');
        addApiLog(`ITS ID: ${formData.its_id}`, 'info');
        
        // Validate EC
        if (!formData.enrollment_cert || !formData.enrollment_cert.includes('BEGIN CERTIFICATE')) {
            addApiLog('❌ Invalid Enrollment Certificate format', 'error');
            addApiLog('Please paste a valid PEM certificate from enrollment', 'error');
            return;
        }
        
        let publicKey;
        
        // Generate key if not provided
        if (!formData.public_key || formData.public_key.trim() === '') {
            addApiLog('🔑 Generating new key pair for AT...', 'info');
            try {
                publicKey = await generateRealPublicKey();
                addApiLog('✅ Key pair generated successfully', 'success');
            } catch (error) {
                addApiLog(`❌ Key generation failed: ${error.message}`, 'error');
                return;
            }
        } else {
            publicKey = formData.public_key;
            addApiLog('ℹ️ Using provided public key', 'info');
        }
        
        // Parse permissions
        const permissions = formData.permissions.split(',').map(p => p.trim().toLowerCase());
        
        const requestBody = {
            its_id: formData.its_id,
            enrollment_certificate: formData.enrollment_cert,
            public_key: publicKey,
            requested_permissions: permissions,
            validity_days: parseInt(formData.validity_days)
        };
        
        addApiLog('📤 Sending authorization request to AA...', 'info');
        addApiLog(`Requested permissions: ${permissions.join(', ')}`, 'info');
        
        await makeApiRequest('POST', '/api/authorization/request/simple', requestBody);
    });
}

async function testSimpleButterflyRequest() {
    showRequestForm('Butterfly Authorization Request (Simplified JSON)', [
        { name: 'its_id', label: 'ITS Station ID', type: 'text', value: 'VEHICLE_001', required: true, random: true },
        { name: 'enrollment_cert', label: 'Enrollment Certificate (PEM)', type: 'textarea', value: '', required: true, placeholder: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----', useLast: true },
        { name: 'num_tickets', label: 'Number of Tickets', type: 'number', value: '20', min: '1', max: '100', required: true },
        { name: 'validity_days', label: 'Validity (days)', type: 'number', value: '7', min: '1', max: '30', required: true }
    ], async (formData) => {
        clearApiLogs();
        addApiLog('🦋 Starting Butterfly Authorization Request...', 'info');
        addApiLog(`ITS ID: ${formData.its_id}`, 'info');
        addApiLog(`Requesting ${formData.num_tickets} tickets`, 'info');
        
        // Validate EC
        if (!formData.enrollment_cert || !formData.enrollment_cert.includes('BEGIN CERTIFICATE')) {
            addApiLog('❌ Invalid Enrollment Certificate format', 'error');
            return;
        }
        
        // Generate multiple public keys
        const numTickets = parseInt(formData.num_tickets);
        addApiLog(`🔑 Generating ${numTickets} key pairs...`, 'info');
        
        const publicKeys = [];
        try {
            for (let i = 0; i < numTickets; i++) {
                const pk = await generateRealPublicKey();
                publicKeys.push(pk);
                if ((i + 1) % 5 === 0) {
                    addApiLog(`  Generated ${i + 1}/${numTickets} keys...`, 'info');
                }
            }
            addApiLog('✅ All key pairs generated successfully', 'success');
        } catch (error) {
            addApiLog(`❌ Key generation failed: ${error.message}`, 'error');
            return;
        }
        
        const requestBody = {
            its_id: formData.its_id,
            enrollment_certificate: formData.enrollment_cert,
            public_keys: publicKeys,
            num_tickets: numTickets,
            validity_days: parseInt(formData.validity_days)
        };
        
        addApiLog('📤 Sending butterfly request to AA...', 'info');
        addApiLog('⏳ This may take a moment...', 'info');
        
        await makeApiRequest('POST', '/api/authorization/butterfly-request/simple', requestBody);
    });
}

// ============================================
// HELPER FUNCTIONS FOR RANDOM AND USE LAST
// ============================================

function randomizeField(fieldId, fieldName) {
    const field = document.getElementById(fieldId);
    if (!field) return;
    
    if (fieldName === 'its_id') {
        const randomNum = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        field.value = `VEHICLE_${randomNum}`;
    }
}

function useLastCertificate(fieldId) {
    const field = document.getElementById(fieldId);
    if (!field || !lastEnrollmentCertificate) {
        alert('❌ No certificate available. Run Enrollment Request first!');
        return;
    }
    
    // Convert escaped newlines to actual newlines
    const certPem = lastEnrollmentCertificate.replace(/\\n/g, '\n');
    field.value = certPem;
    
    // Also fill ITS ID if available
    if (lastEnrollmentData && lastEnrollmentData.its_id) {
        const itsIdField = document.getElementById('field_its_id');
        if (itsIdField) {
            itsIdField.value = lastEnrollmentData.its_id;
        }
    }
    
    alert(`✅ Certificate from ${lastEnrollmentData?.its_id || 'previous enrollment'} loaded!`);
}
