// Global state variables
let token = null;
let userRole = null; // Store the user's role ('doctor', 'receptionist', etc.)
let currentUsername = null; // Store logged-in username

// --- Helper Functions ---

/**
 * Sets text content and CSS class for a message element.
 * Clears message if text is empty. Hides/shows element.
 * @param {string} elementId - The ID of the message paragraph element.
 * @param {string} message - The message text to display.
 * @param {'success' | 'error' | 'info' | 'warning'} type - The type of message.
 */
function showMessage(elementId, message, type = 'info') {
    const msgElement = document.getElementById(elementId);
    if (msgElement) {
        if (message) {
            // Basic sanitization (replace < >) to prevent accidental HTML injection if message comes from unexpected source
            // For AI messages specifically, we use innerHTML later after processing.
            // msgElement.textContent = message; // Use textContent for general messages
            msgElement.innerHTML = message; // Allow basic HTML for now, ensure server sanitizes properly if needed
            msgElement.style.display = 'block'; // Show element using block
            let className = ''; // Define class based on type
            switch (type) {
                case 'success': className = 'success-message'; break;
                case 'error':   className = 'error-message';   break;
                case 'info':    className = 'info-message';    break;
                case 'warning': className = 'warning-message'; break;
                default: className = '';
            }
            msgElement.className = ''; // Clear existing possibly conflicting classes first
            // Ensure base message class is always present if needed for styling empty state
            // msgElement.classList.add('message-base-class');
            if (className) { msgElement.classList.add(className); }
        } else { // Clear message
            msgElement.textContent = '';
            msgElement.className = ''; // Clear classes
            msgElement.style.display = 'none'; // Hide element when empty
        }
    } else {
        // Only warn if it's not a dynamically created results message ID or temp report msg
        if (!elementId.endsWith('-results-msg') && !elementId.startsWith('temp-view-report-msg-')) {
             console.warn(`Message element with ID "${elementId}" not found.`);
        }
    }
}

/** Clears message content and class. */
function clearMessage(elementId) { showMessage(elementId, '', 'info'); } // Use default type or specific for clearing

/** General purpose API fetch function. */
async function fetchApi(endpoint, method = 'GET', body = null, isFormData = false, expectBlob = false) {
    const headers = {};
    if (token) {
        headers['x-access-token'] = token;
    }
    // Add cache control to prevent IE/Edge caching issues with GET requests
    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
    headers['Pragma'] = 'no-cache';
    headers['Expires'] = '0';

    const options = {
        method: method,
        headers: headers,
        // cache: 'no-store' // Already handled by headers above
    };
    if (body) {
        if (isFormData) {
            // Content-Type is set automatically by the browser for FormData
            options.body = body;
        } else {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
    }

    console.debug(`Fetching API: ${method} ${endpoint}`);

    try {
        const response = await fetch(endpoint, options);

        // Handle Blob response separately
        if (expectBlob && response.ok) {
            console.debug(`Received Blob for ${endpoint}`);
            const blob = await response.blob();
            return { ok: true, status: response.status, data: blob, headers: response.headers };
        }

        // Handle JSON or Text response
        const contentType = response.headers.get("content-type");
        let responseData = { message: `Request failed with status ${response.status}` }; // Default error data

        try {
            const text = await response.text(); // Always get text first
            if (contentType?.includes("application/json")) {
                responseData = JSON.parse(text || '{}'); // Parse text as JSON
            } else {
                // If not JSON, use the text, but still package it similarly
                responseData = { message: text || response.statusText };
                console.debug(`Non-JSON response received for ${endpoint}: ${text.substring(0, 100)}...`);
            }
        } catch (parseError) {
             console.error(`Error parsing response from ${endpoint}: ${parseError}. Raw text: ${await response.text()}`);
             // Keep the default error data or try to use raw text if needed
             // responseData = { message: `Error parsing response: ${await response.text()}` };
        }


        if (!response.ok) {
            console.error(`API Error (${response.status}) calling ${method} ${endpoint}:`, responseData);
             // Check for specific auth errors to potentially trigger logout
             if (response.status === 401) {
                 // More specific message based on common JWT errors
                 const msg = responseData.message || '';
                 let logoutMsg = 'Authentication failed. Please log in again.';
                 if (msg.includes('expired')) { logoutMsg = 'Session expired. Please log in again.'; }
                 else if (msg.includes('Invalid token')) { logoutMsg = 'Invalid session token. Please log in again.'; }
                 else if (msg.includes('missing')) { logoutMsg = 'Authentication token missing. Please log in again.'; }
                 else if (msg.includes('User not found')) { logoutMsg = 'User associated with token not found. Please log in again.'; }

                 console.warn(`Authentication error (${response.status}), logging out. Message: ${msg}`);
                 showMessage('login-message', logoutMsg, 'error');
                 logout(); // Force logout on any 401
             } else if (response.status === 403) {
                 console.warn(`Authorization error (${response.status}): Access denied. Message: ${responseData.message}`);
                 // Show message on dashboard if possible, or login if dashboard isn't visible
                 const dashMsg = document.getElementById('dashboard-message');
                 if (dashMsg && document.getElementById('dashboard')?.style.display !== 'none') {
                     showMessage('dashboard-message', `Access Denied: ${responseData.message || 'You do not have permission for this action.'}`, 'error');
                 } else {
                     showMessage('login-message', `Access Denied: ${responseData.message || 'Permission required.'}`, 'error');
                 }
             }
        } else {
             console.debug(`API Success (${response.status}) for ${method} ${endpoint}`);
        }
        // Always return a consistent structure
        return { ok: response.ok, status: response.status, data: responseData };

    } catch (error) {
        console.error(`Network or Fetch Error for ${method} ${endpoint}:`, error);
        const dashboardElement = document.getElementById('dashboard');
        // Try showing error on dashboard if visible, otherwise on login form
        if (dashboardElement && dashboardElement.style.display !== 'none') {
             showMessage('dashboard-message', `Network error: ${error.message || 'Could not connect to the server.'}`, 'error');
        } else {
            showMessage('login-message', `Network error: ${error.message || 'Unable to reach the server.'}`, 'error');
        }
        // Return a consistent error structure
        return { ok: false, status: 0, data: { message: `Network error: ${error.message || 'Server is unreachable.'}` } };
    }
}


// --- Load Roles Function ---
async function loadRoles() {
    const roleSelect = document.getElementById('role');
    if (!roleSelect) { console.error("Role select element not found."); return; }
    roleSelect.disabled = true; // Disable while loading
    try {
        const response = await fetchApi('/roles'); // Public endpoint
        if (!response.ok) throw new Error(response.data.message || `HTTP error! status: ${response.status}`);

        const data = response.data;
        roleSelect.innerHTML = ''; // Clear existing "Loading..."
        // Add a placeholder/default option
        const placeholder = document.createElement('option');
        placeholder.value = "";
        placeholder.textContent = "-- Select Role --";
        placeholder.disabled = true;
        placeholder.selected = true;
        roleSelect.appendChild(placeholder);

        if (data.roles && Array.isArray(data.roles) && data.roles.length > 0) {
            data.roles.forEach(role => {
                const option = document.createElement('option');
                option.value = role;
                // Capitalize first letter for display
                option.textContent = role.charAt(0).toUpperCase() + role.slice(1);
                roleSelect.appendChild(option);
            });
            roleSelect.disabled = false; // Re-enable after successful load
        } else {
            roleSelect.innerHTML = '<option value="">No roles available</option>';
            // Keep disabled if no roles found
        }
    } catch (error) {
        console.error('Error loading roles:', error);
        roleSelect.innerHTML = '<option value="">Error loading roles</option>';
        showMessage('login-message', `Could not load user roles. ${error.message}`, 'error');
        // Keep disabled on error
    }
}

// --- Authentication ---
async function login() {
    const roleInput = document.getElementById('role');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginButton = document.querySelector('#login-form button'); // Get the button

    const role = roleInput.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value; // No trim on password

    // Clear previous messages
    clearMessage('login-message');

    // Basic frontend validation
    if (!role) { return showMessage('login-message', 'Please select a role.', 'warning'); }
    if (!username) { usernameInput.focus(); return showMessage('login-message', 'Username is required.', 'warning'); }
    if (!password) { passwordInput.focus(); return showMessage('login-message', 'Password is required.', 'warning'); }

    // Disable form elements during login attempt
    roleInput.disabled = true; usernameInput.disabled = true; passwordInput.disabled = true; loginButton.disabled = true;
    showMessage('login-message', 'Logging in, please wait...', 'info');

    const response = await fetchApi('/login', 'POST', { role, username, password });

    if (response.ok && response.data.token) {
        token = response.data.token;
        userRole = response.data.role;
        currentUsername = response.data.username;
        // Store in localStorage for session persistence
        localStorage.setItem('authToken', token);
        localStorage.setItem('userRole', userRole);
        localStorage.setItem('username', currentUsername);

        document.getElementById('login-form').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        clearMessage('login-message'); // Clear "Logging in..." message
        passwordInput.value = ''; // Clear password field after successful login attempt
        await loadDashboardContent(); // Load dashboard content AFTER setting state and hiding login

    } else {
        // Show error message from API response or a generic one
        showMessage('login-message', response.data.message || 'Login failed. Please check credentials and role.', 'error');
        token = null; userRole = null; currentUsername = null;
        localStorage.clear(); // Clear any potentially stale session data
        passwordInput.value = ''; // Clear password field on failure
        passwordInput.focus(); // Focus password field for re-entry
        // Re-enable form elements on failure
        roleInput.disabled = false; usernameInput.disabled = false; passwordInput.disabled = false; loginButton.disabled = false;
    }
}

async function checkSessionAndLoad() {
    token = localStorage.getItem('authToken');
    userRole = localStorage.getItem('userRole');
    currentUsername = localStorage.getItem('username');

    if (token && userRole && currentUsername) {
        console.log("Session token found in localStorage. Verifying...");
        // Verify token with backend (e.g., call a protected /dashboard or /verify endpoint)
        const verifyResponse = await fetchApi('/dashboard'); // This endpoint now verifies token

        if (verifyResponse.ok) {
            console.log("Session verified successfully.");
            // Token is valid, show dashboard
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            await loadDashboardContent(); // Load content now that session is verified
        } else {
             // fetchApi handles 401 logout automatically now
             // If verification failed (e.g., token expired, invalid), fetchApi should have logged out.
             console.log("Session verification failed. Assuming fetchApi handled logout.");
             // Ensure UI is in logged-out state just in case
             if (document.getElementById('login-form').style.display === 'none') {
                 logout(); // Explicitly ensure clean state if verification failed
             }
        }
    } else {
        // No token found, ensure user is logged out
        console.log("No session token found in localStorage. Login required.");
        document.getElementById('login-form').style.display = 'block';
        document.getElementById('dashboard').style.display = 'none';
        logout(); // Ensure clean state
    }
}

/** Loads content and sets up UI after login/session verification */
async function loadDashboardContent() {
    if (!currentUsername || !userRole) {
        console.error("Cannot load dashboard content without username and role.");
        logout(); // Force logout if state is inconsistent
        return;
    }
    showMessage('dashboard-message', `Welcome back, ${currentUsername}! (Role: ${userRole})`, 'success');
    // Update elements showing username
    document.querySelectorAll('.logged-in-username').forEach(el => el.textContent = currentUsername);
    setupRoleSpecificUI();
    // Potentially pre-load some data based on role, e.g., fetchAllUsers for superadmin
    if (userRole === 'superadmin') {
        await fetchAllUsers(); // Fetch users immediately for admin
    }
}

function setupRoleSpecificUI() {
    console.log(`Setting up UI for role: ${userRole}`);
    // Hide all role-specific action divs first
    document.querySelectorAll('#dashboard > div[id$="-actions"]').forEach(section => {
        section.style.display = 'none';
    });

    // Show the div corresponding to the current user's role
    const roleActionId = `${userRole}-actions`;
    const roleElement = document.getElementById(roleActionId);

    if (roleElement) {
        roleElement.style.display = 'block';
        console.log(`Displayed UI section: ${roleActionId}`);

        // Special handling for AI sections within the role's div
        const aiSection = roleElement.querySelector('.ai-assistant-section');
        if(aiSection) {
            // Check if the specific role should have AI enabled (e.g., doctor, superadmin)
             if (['doctor', 'superadmin'].includes(userRole)) {
                aiSection.style.display = 'block';
                console.log("AI Assistant section enabled for this role.");
                initializeAiChat(userRole); // Initialize AI chat with role-specific greeting
             } else {
                 aiSection.style.display = 'none'; // Ensure it's hidden for other roles
             }
        } else {
             // console.log("No AI Assistant section found within this role's UI.");
        }

        // Reset forms specific to this role when switching or logging in
        switch (userRole) {
            case 'receptionist': clearReceptionistForms(); break;
            case 'doctor': clearDoctorForms(); break;
            case 'labtechnician': clearLabtechForms(); break;
            case 'pharmacist': clearPharmacistForms(); break;
            case 'superadmin': clearSuperadminDisplay(); break; // Clears user list, AI handled above
        }

    } else {
        console.warn(`UI container for role "${userRole}" with ID "${roleActionId}" not found.`);
        showMessage('dashboard-message', `Error: Could not load UI components for the '${userRole}' role.`, 'error');
    }
}

function logout() {
    console.log("Logging out user...");
    token = null; userRole = null; currentUsername = null;
    localStorage.clear(); // Clear all stored session data

    // Reset UI to logged-out state
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';

    // Clear messages
    clearMessage('dashboard-message');
    clearMessage('login-message'); // Clear any previous login errors

    // Reset login form fields
    const usernameInput = document.getElementById('username'); if(usernameInput) usernameInput.value = '';
    const passwordInput = document.getElementById('password'); if(passwordInput) passwordInput.value = '';
    const roleSelect = document.getElementById('role'); if(roleSelect) roleSelect.value = ''; // Reset role dropdown

    // Re-enable login form fields if they were disabled
    if(roleSelect) roleSelect.disabled = false;
    if(usernameInput) usernameInput.disabled = false;
    if(passwordInput) passwordInput.disabled = false;
    const loginButton = document.querySelector('#login-form button');
    if(loginButton) loginButton.disabled = false;


    // Clear all dynamic content and forms within the dashboard sections
    clearAllFormsAndDisplays();

    console.log("User logged out.");
    // Optionally, redirect to login page or refresh
    // window.location.reload();
}

// --- Patient Search & Selection ---
async function searchPatient(searchInputId, resultsDivId, selectCallbackName) {
    const queryInput = document.getElementById(searchInputId);
    const query = queryInput.value.trim();
    const resultsDiv = document.getElementById(resultsDivId);
    resultsDiv.innerHTML = ''; // Clear previous results
    const msgId = resultsDivId + '-msg'; // Message ID associated with this search
    clearMessage(msgId); // Clear previous search messages

    if (!query || query.length < 2) { // Require at least 2 characters to search
        return showMessage(msgId, 'Please enter at least 2 characters to search.', 'warning');
    }
    showMessage(msgId, 'Searching for patients...', 'info');

    try {
        const response = await fetchApi(`/patients/search?q=${encodeURIComponent(query)}`);
        clearMessage(msgId); // Clear "Searching..." message

        if (response.ok && response.data.patients) {
            if (response.data.patients.length > 0) {
                let listHtml = '<ul class="search-results-list">';
                response.data.patients.forEach(p => {
                    const name = p.name || 'N/A';
                    const identifier = p.patient_identifier || 'N/A';
                    const dob = p.dob ? ` (DOB: ${p.dob})` : '';
                    const displayName = `${name} (${identifier})${dob}`;
                    // Escape single quotes and backslashes for the onclick handler string
                    const escapedDisplayName = displayName.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
                    // Pass patient ID and the formatted display name to the callback
                    listHtml += `<li>
                                   <span>${displayName}</span>
                                   <button onclick="${selectCallbackName}(${p.id}, '${escapedDisplayName}')" class="select-patient-btn">Select</button>
                                 </li>`;
                });
                resultsDiv.innerHTML = listHtml + '</ul>';
            } else {
                showMessage(msgId, 'No patients found matching your query.', 'info');
                 resultsDiv.innerHTML = ''; // Ensure results div is empty if nothing found
            }
        } else {
            // Show error from API or a generic message
            showMessage(msgId, `Search Error: ${response.data.message || 'Failed to fetch patient data.'}`, 'error');
        }
    } catch (error) {
         // Catch network errors from fetchApi itself
         console.error("Error during patient search:", error);
         showMessage(msgId, `Network error during search: ${error.message}`, 'error');
    } finally {
         // Optional: Re-enable search button if it was disabled
    }
}

// --- Role Specific Functions (Clear forms, Select patient, Actions) ---

// Receptionist
function clearReceptionistForms() {
    ['new-patient-id', 'new-patient-name', 'new-patient-dob', 'new-patient-contact'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    clearMessage('receptionist-create-patient-msg');

    ['visit-search-patient', 'visit-patient-id', 'visit-reason'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    clearMessage('receptionist-record-visit-msg');
    clearMessage('visit-search-results-msg');
    document.getElementById('visit-search-results').innerHTML = '';
    document.getElementById('visit-selected-patient-name').textContent = 'None Selected';
    const recordBtn = document.getElementById('record-visit-btn'); if(recordBtn) recordBtn.disabled = true;
}
async function createPatient() {
    const identifier = document.getElementById('new-patient-id').value.trim();
    const name = document.getElementById('new-patient-name').value.trim();
    const dob = document.getElementById('new-patient-dob').value; // YYYY-MM-DD format
    const contact = document.getElementById('new-patient-contact').value.trim();
    const msgId = 'receptionist-create-patient-msg';
    const createBtn = document.querySelector('#receptionist-actions .action-section:nth-child(1) button'); // More specific button selection

    clearMessage(msgId);
    if (!identifier) { document.getElementById('new-patient-id').focus(); return showMessage(msgId, 'Patient ID is required.', 'warning'); }
    if (!name) { document.getElementById('new-patient-name').focus(); return showMessage(msgId, 'Patient Name is required.', 'warning'); }
    // Basic date format check (doesn't validate day/month ranges)
    if (dob && !/^\d{4}-\d{2}-\d{2}$/.test(dob)) { document.getElementById('new-patient-dob').focus(); return showMessage(msgId, 'Invalid Date of Birth format. Use YYYY-MM-DD.', 'warning'); }

    if(createBtn) createBtn.disabled = true;
    showMessage(msgId, 'Creating patient record...', 'info');
    const response = await fetchApi('/patients', 'POST', {
        patient_identifier: identifier,
        name: name,
        dob: dob || null, // Send null if empty
        contact_info: contact
    });
    if (response.ok) {
        showMessage(msgId, `Success: ${response.data.message || 'Patient created.'}`, 'success');
        // Clear only the create form on success
        ['new-patient-id', 'new-patient-name', 'new-patient-dob', 'new-patient-contact'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    } else {
        showMessage(msgId, `Error: ${response.data.message || 'Failed to create patient.'}`, 'error');
    }
    if(createBtn) createBtn.disabled = false;
}
function selectPatientForVisit(patientId, patientName) {
    document.getElementById('visit-patient-id').value = patientId;
    document.getElementById('visit-selected-patient-name').textContent = patientName || 'Error: Name missing';
    const recordBtn = document.getElementById('record-visit-btn'); if(recordBtn) recordBtn.disabled = false;
    // Clear search results and message after selection
    document.getElementById('visit-search-results').innerHTML = '';
    clearMessage('visit-search-results-msg');
    // Clear any previous visit recording message
    clearMessage('receptionist-record-visit-msg');
    // Focus on reason field
    document.getElementById('visit-reason').focus();
}
async function recordVisit() {
    const patientId = document.getElementById('visit-patient-id').value;
    const reason = document.getElementById('visit-reason').value.trim();
    const msgId = 'receptionist-record-visit-msg';
    const btn = document.getElementById('record-visit-btn');

    if (!patientId) { return showMessage(msgId, 'No patient selected. Please search and select a patient first.', 'error'); }

    btn.disabled = true;
    showMessage(msgId, 'Recording visit...', 'info');
    const response = await fetchApi('/visits', 'POST', {
        patient_id: parseInt(patientId), // Ensure it's an integer
        reason: reason
    });

    if (response.ok) {
        showMessage(msgId, `Success: ${response.data.message || 'Visit recorded.'}`, 'success');
        // Clear the visit part of the form on success
        document.getElementById('visit-search-patient').value = '';
        document.getElementById('visit-patient-id').value = '';
        document.getElementById('visit-reason').value = '';
        document.getElementById('visit-selected-patient-name').textContent = 'None Selected';
        btn.disabled = true; // Disable button again after successful record
        document.getElementById('visit-search-results').innerHTML = ''; // Clear results again
    } else {
        showMessage(msgId, `Error: ${response.data.message || 'Failed to record visit.'}`, 'error');
        btn.disabled = false; // Re-enable button on failure
    }
}

// Doctor
function clearDoctorForms() {
     ['history-search-patient', 'history-patient-id'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
     document.getElementById('history-search-results').innerHTML = '';
     document.getElementById('history-selected-patient-name').textContent = 'None Selected';
     document.getElementById('patient-history-display').innerHTML = '<p class="info-message">Search for and select a patient to view their history or write a prescription.</p>';
     clearMessage('history-search-results-msg');
     const historyBtn = document.getElementById('view-history-btn'); if(historyBtn) historyBtn.disabled = true;

     ['prescription-medication', 'prescription-dosage', 'prescription-instructions'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
     clearMessage('doctor-prescription-msg');
     const prescBtn = document.getElementById('create-prescription-btn'); if(prescBtn) prescBtn.disabled = true;

     // Also clear and reset the AI chat
     initializeAiChat('doctor');
     const aiQueryInput = document.getElementById('doctor-ai-query'); if(aiQueryInput) aiQueryInput.value = '';

}
function selectPatientForHistory(patientId, patientName) {
    document.getElementById('history-patient-id').value = patientId;
    document.getElementById('history-selected-patient-name').textContent = patientName || 'Error: Name missing';
    // Enable buttons
    const historyBtn = document.getElementById('view-history-btn'); if(historyBtn) historyBtn.disabled = false;
    const prescBtn = document.getElementById('create-prescription-btn'); if(prescBtn) prescBtn.disabled = false;
    // Clear search results and message
    document.getElementById('history-search-results').innerHTML = '';
    clearMessage('history-search-results-msg');
    // Update history display placeholder
    document.getElementById('patient-history-display').innerHTML = `<p class="info-message">Selected: ${patientName}. Click "View Full History" or write a prescription below.</p>`;
    // Clear any previous prescription message
    clearMessage('doctor-prescription-msg');
}
async function viewPatientHistory() {
    const patientId = document.getElementById('history-patient-id').value;
    const displayDiv = document.getElementById('patient-history-display');
    const btn = document.getElementById('view-history-btn');

    if (!patientId) { return displayDiv.innerHTML = '<p class="error-message">No patient selected. Please search and select one first.</p>'; }

    btn.disabled = true;
    displayDiv.innerHTML = '<p class="info-message">Loading patient history...</p>';

    const response = await fetchApi(`/patients/${patientId}/history`);

    if (response.ok && response.data && response.data.patient) {
        const h = response.data; // Full history object
        const patientName = h.patient.name || 'N/A';
        const patientIdentifier = h.patient.patient_identifier || 'N/A';
        let html = `<h4>History for: ${patientName} (${patientIdentifier})</h4>
                    <p><strong>DOB:</strong> ${h.patient.dob || 'N/A'} | <strong>Contact:</strong> ${h.patient.contact_info || 'N/A'}</p>`;

        // Format Visits
        html += '<h5>Visits</h5>';
        if (h.visits?.length) {
            html += '<ul class="history-list">';
            h.visits.forEach(v => {
                const visitDate = v.visit_datetime ? new Date(v.visit_datetime).toLocaleString() : 'N/A';
                // Attempt to get recorder username if available from eager loading
                const recorderName = v.recorded_by ? v.recorded_by.username : `User ID ${v.recorded_by_id}`; // Fallback to ID
                html += `<li><strong>${visitDate}:</strong> ${v.reason || 'No reason recorded.'}
                         <small>(Visit ID: ${v.id}, Recorded by: ${recorderName})</small></li>`;
            });
            html += '</ul>';
        } else { html += '<p>No visits recorded in the database.</p>'; }

        // Format Prescriptions
        html += '<h5>Prescriptions</h5>';
        if (h.prescriptions?.length) {
            html += '<ul class="history-list">';
            h.prescriptions.forEach(p => {
                const prescDate = p.created_at ? new Date(p.created_at).toLocaleDateString() : 'N/A';
                const doctorName = p.doctor ? p.doctor.username : `Dr. ID ${p.doctor_id}`; // Fallback to ID
                html += `<li><strong>${prescDate} - Dr. ${doctorName}:</strong><br>
                           <strong>Medication:</strong> ${p.medication || 'N/A'}<br>
                           <strong>Dosage:</strong> ${p.dosage || 'N/A'}<br>
                           <strong>Instructions:</strong> ${p.instructions || 'N/A'}
                           <small>(Prescription ID: ${p.id}, Associated Visit ID: ${p.visit_id || 'N/A'})</small></li>`;
            });
            html += '</ul>';
        } else { html += '<p>No prescriptions found in the database.</p>'; }

        // Format Reports
        html += '<h5>Reports</h5>';
        if (h.reports?.length) {
            html += '<ul class="history-list">';
            h.reports.forEach((r, index) => {
                const reportDate = r.uploaded_at ? new Date(r.uploaded_at).toLocaleDateString() : 'N/A';
                const techName = r.lab_technician ? r.lab_technician.username : `Tech ID ${r.lab_technician_id}`; // Fallback to ID
                // Generate a unique ID for the temporary message span for this specific report link
                const tempMsgId = `temp-view-report-msg-${r.id}-${index}`;
                const reportLink = r.file_url
                    ? `<a href="#" onclick="viewReport('${r.file_url}', '${tempMsgId}'); return false;" class="report-link" title="View PDF Report (opens new tab)">View Report (PDF)</a> <span id="${tempMsgId}" class="temp-message"></span>`
                    : '(File link not available)';
                html += `<li><strong>${reportDate} - ${r.report_type || 'N/A'}:</strong> ${reportLink}
                           <small>(Report ID: ${r.id}, Uploaded by: ${techName}, Associated Visit ID: ${r.visit_id || 'N/A'})</small>
                         </li>`;
            });
            html += '</ul>';
        } else { html += '<p>No reports found in the database.</p>'; }

        displayDiv.innerHTML = html;
    } else {
        // Handle error case
        displayDiv.innerHTML = `<p class="error-message">Error loading history: ${response.data.message || 'Failed to fetch patient data.'}</p>`;
    }
    // Re-enable the button regardless of success or failure
    btn.disabled = false;
}
async function createPrescription() {
    const patientId = document.getElementById('history-patient-id').value;
    const medication = document.getElementById('prescription-medication').value.trim();
    const dosage = document.getElementById('prescription-dosage').value.trim();
    const instructions = document.getElementById('prescription-instructions').value.trim();
    const msgId = 'doctor-prescription-msg';
    const btn = document.getElementById('create-prescription-btn');

    clearMessage(msgId);
    if (!patientId) { return showMessage(msgId, 'No patient selected. Please select a patient first.', 'error'); }
    if (!medication) { document.getElementById('prescription-medication').focus(); return showMessage(msgId, 'Medication name/details are required.', 'warning'); }
    // Dosage and instructions are optional based on DB schema

    btn.disabled = true;
    showMessage(msgId, 'Creating prescription...', 'info');

    const response = await fetchApi('/prescriptions', 'POST', {
        patient_id: parseInt(patientId), // Ensure integer
        medication: medication,
        dosage: dosage,
        instructions: instructions
    });

    if (response.ok) {
        showMessage(msgId, `Success: ${response.data.message || 'Prescription created.'}`, 'success');
        // Clear prescription form fields only
        document.getElementById('prescription-medication').value = '';
        document.getElementById('prescription-dosage').value = '';
        document.getElementById('prescription-instructions').value = '';
        // Refresh the history view to show the new prescription
        await viewPatientHistory(); // Assumes patient selection hasn't changed
    } else {
        showMessage(msgId, `Error: ${response.data.message || 'Failed to create prescription.'}`, 'error');
    }
    // Re-enable button only if a patient is still selected
    if (document.getElementById('history-patient-id').value) {
        btn.disabled = false;
    }
}

// Lab Technician
function clearLabtechForms(){
    ['report-search-patient', 'report-patient-id'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    document.getElementById('report-search-results').innerHTML = '';
    document.getElementById('report-selected-patient-name').textContent = 'None Selected';
    clearMessage('report-search-results-msg');
    clearMessage('labtech-selection-msg'); // Message related to patient selection itself
    clearMessage('labtech-upload-msg'); // General message for upload status

    // Clear file inputs and 'Other' type input
    ['scan-report-file', 'blood-test-file', 'other-report-file', 'other-report-type'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });

    // Hide the upload options section and disable buttons
    const uploadOptions = document.getElementById('labtech-upload-options');
    if(uploadOptions) uploadOptions.style.display = 'none';
    document.querySelectorAll('.labtech-upload-btn').forEach(btn => btn.disabled = true);
}
function selectPatientForReport(patientId, patientName) {
    document.getElementById('report-patient-id').value = patientId;
    document.getElementById('report-selected-patient-name').textContent = patientName || 'Error: Name missing';
    // Clear search results and message
    document.getElementById('report-search-results').innerHTML = '';
    clearMessage('report-search-results-msg');
    clearMessage('labtech-selection-msg'); // Clear selection status message
    clearMessage('labtech-upload-msg'); // Clear any previous upload message

    // Show the upload options section and enable buttons
    const uploadOptions = document.getElementById('labtech-upload-options');
    if(uploadOptions) uploadOptions.style.display = 'block';
    document.querySelectorAll('.labtech-upload-btn').forEach(btn => btn.disabled = false);
}
async function uploadReport(reportType, fileInputId) {
    // Find the button that was clicked to trigger this upload
    const clickedButton = event?.target;

    const patientId = document.getElementById('report-patient-id').value;
    const fileInput = document.getElementById(fileInputId);
    const msgId = 'labtech-upload-msg'; // Use one message area for all uploads
    let finalReportType = reportType; // Default report type

    clearMessage(msgId); // Clear previous upload messages

    // Special handling for 'Other' report type
    if (fileInputId === 'other-report-file') { // Check based on input ID for robustness
        const otherTypeInput = document.getElementById('other-report-type');
        finalReportType = otherTypeInput ? otherTypeInput.value.trim() : '';
        if (!finalReportType) {
            otherTypeInput?.focus();
            return showMessage(msgId, 'Please specify the document type for "Other".', 'warning');
        }
    }

     // Validations
     if (!patientId) { return showMessage(msgId, 'No patient selected. Please search and select a patient first.', 'error'); }
     if (!fileInput || fileInput.files.length === 0) { return showMessage(msgId, `Please select a PDF file for "${finalReportType}".`, 'warning'); }
     const file = fileInput.files[0];
     // Check file type (allow only PDF as per requirement)
     if (!file.type || file.type !== 'application/pdf') { fileInput.value = ''; /* Clear invalid file selection */ return showMessage(msgId, 'Invalid file type. Only PDF files (.pdf) are allowed.', 'error'); }
     // Check file size (e.g., 10MB limit)
     const maxSizeMB = 10;
     if (file.size > maxSizeMB * 1024 * 1024) { fileInput.value = ''; return showMessage(msgId, `File is too large. Maximum size is ${maxSizeMB}MB.`, 'error'); }


     // Disable the specific button clicked (and maybe others briefly)
     if (clickedButton && clickedButton.tagName === 'BUTTON') clickedButton.disabled = true;
     // Optionally disable all upload buttons during any upload
     // document.querySelectorAll('.labtech-upload-btn').forEach(btn => btn.disabled = true);

     showMessage(msgId, `Uploading "${finalReportType}" report for patient...`, 'info');
     const formData = new FormData();
     formData.append('patient_id', patientId);
     formData.append('report_type', finalReportType);
     formData.append('report_file', file, file.name); // Include filename in FormData

     const response = await fetchApi('/reports', 'POST', formData, true); // Send as FormData

     if (response.ok) {
        showMessage(msgId, `Success: ${response.data.message || `Report '${finalReportType}' uploaded.`}`, 'success');
        // Clear the specific file input and 'Other' type if applicable
        fileInput.value = '';
        if (fileInputId === 'other-report-file') {
            const otherTypeInput = document.getElementById('other-report-type');
            if (otherTypeInput) otherTypeInput.value = '';
        }
     } else {
        showMessage(msgId, `Upload Error: ${response.data.message || `Failed to upload '${finalReportType}'.`}`, 'error');
     }

     // Re-enable the button(s) after completion, only if a patient is still selected
     if (document.getElementById('report-patient-id').value) {
          if (clickedButton && clickedButton.tagName === 'BUTTON') clickedButton.disabled = false;
         // If all buttons were disabled, re-enable them
         // document.querySelectorAll('.labtech-upload-btn').forEach(btn => btn.disabled = false);
     } else {
         // If patient selection was somehow cleared, keep buttons disabled
         document.querySelectorAll('.labtech-upload-btn').forEach(btn => btn.disabled = true);
         if (document.getElementById('labtech-upload-options')) {
             document.getElementById('labtech-upload-options').style.display = 'none';
         }
     }
}

// Pharmacist
function clearPharmacistForms() {
    ['pharma-search-patient', 'pharma-patient-id'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    document.getElementById('pharma-search-results').innerHTML = '';
    document.getElementById('pharma-selected-patient-name').textContent = 'None Selected';
    document.getElementById('pharmacist-prescription-display').innerHTML = '<p class="info-message">Search for and select a patient to view their prescriptions.</p>';
    clearMessage('pharma-search-results-msg');
    clearMessage('pharmacist-view-msg');
    const viewBtn = document.getElementById('view-prescriptions-btn'); if(viewBtn) viewBtn.disabled = true;
}
function selectPatientForPrescriptions(patientId, patientName) {
    document.getElementById('pharma-patient-id').value = patientId;
    document.getElementById('pharma-selected-patient-name').textContent = patientName || 'Error: Name missing';
    const viewBtn = document.getElementById('view-prescriptions-btn'); if(viewBtn) viewBtn.disabled = false;
    // Clear search results and message
    document.getElementById('pharma-search-results').innerHTML = '';
    clearMessage('pharma-search-results-msg');
    // Update display placeholder and clear previous view message
    document.getElementById('pharmacist-prescription-display').innerHTML = `<p class="info-message">Selected: ${patientName}. Click "View Prescriptions".</p>`;
    clearMessage('pharmacist-view-msg');
}
async function viewPatientPrescriptions() {
    const patientId = document.getElementById('pharma-patient-id').value;
    const displayDiv = document.getElementById('pharmacist-prescription-display');
    const btn = document.getElementById('view-prescriptions-btn');
    const msgId = 'pharmacist-view-msg'; // Message specifically for the view action

    clearMessage(msgId);
    if (!patientId) { return showMessage(msgId, 'No patient selected. Please search and select one first.', 'error'); }

    btn.disabled = true;
    // Show loading message directly in the display area
    displayDiv.innerHTML = '<p class="info-message">Loading prescriptions...</p>';

    const response = await fetchApi(`/patients/${patientId}/prescriptions`);

    // Clear loading message before showing results or error
    displayDiv.innerHTML = '';

    if (response.ok && response.data && response.data.patient) {
        const r = response.data; // Response includes patient and prescriptions array
        const patientName = r.patient.name || 'N/A';
        const patientIdentifier = r.patient.patient_identifier || 'N/A';
        let html = `<h4>Prescriptions for: ${patientName} (${patientIdentifier})</h4>`;

        if (r.prescriptions?.length) {
            html += '<ul class="history-list">'; // Reuse history list styling
            r.prescriptions.forEach(p => {
                 const prescDate = p.created_at ? new Date(p.created_at).toLocaleDateString() : 'N/A';
                 const doctorName = p.doctor ? p.doctor.username : `Dr. ID ${p.doctor_id}`; // Fallback to ID
                 html += `<li><strong>${prescDate} - Dr. ${doctorName}:</strong><br>
                            <strong>Medication:</strong> ${p.medication || 'N/A'}<br>
                            <strong>Dosage:</strong> ${p.dosage || 'N/A'}<br>
                            <strong>Instructions:</strong> ${p.instructions || 'N/A'}
                            <small>(Prescription ID: ${p.id}, Associated Visit ID: ${p.visit_id || 'N/A'})</small></li>`;
            });
            html += '</ul>';
        } else {
            html += '<p>No prescriptions found for this patient in the database.</p>';
        }
        displayDiv.innerHTML = html;
    } else {
        // Show error message from API or a generic one
        const errorMsg = response.data.message || 'Failed to load prescriptions.';
        showMessage(msgId, `Error: ${errorMsg}`, 'error'); // Show error in the dedicated message area
        displayDiv.innerHTML = `<p class="error-message">Could not load prescriptions. ${errorMsg}</p>`; // Also show in display area
    }
    // Re-enable button if a patient is still selected
    if (document.getElementById('pharma-patient-id').value) {
        btn.disabled = false;
    }
}

// Superadmin
function clearSuperadminDisplay() {
    const displayDiv = document.getElementById('all-users-display');
    if(displayDiv) displayDiv.innerHTML = '<p class="info-message">Click "View All System Users" to load the list.</p>'; // Reset placeholder

    // Reset AI chat for superadmin
    initializeAiChat('superadmin');
    const aiQueryInput = document.getElementById('superadmin-ai-query'); if(aiQueryInput) aiQueryInput.value = '';
}
async function fetchAllUsers() {
    const displayDiv = document.getElementById('all-users-display');
    const btn = document.querySelector('#superadmin-actions .action-section button'); // Find the button
    if(!displayDiv) { console.error("User display div not found."); return; }

    if(btn) btn.disabled = true;
    displayDiv.innerHTML = '<p class="info-message">Loading system users...</p>';

    const response = await fetchApi('/users'); // Endpoint requires superadmin role

    if (response.ok && response.data.users) {
        if (response.data.users.length > 0) {
            let html = '<h5>System Users:</h5><ul class="user-list">';
            response.data.users.forEach(u => {
                 html += `<li><strong>${u.username || 'N/A'}</strong> (Role: ${u.role || 'N/A'}, ID: ${u.id || 'N/A'})</li>`;
            });
            html += '</ul>';
            displayDiv.innerHTML = html;
        } else {
            displayDiv.innerHTML = '<p class="info-message">No users found in the system.</p>';
        }
    } else {
        // Handle error - fetchApi might have already logged out if it was 401/403
        displayDiv.innerHTML = `<p class="error-message">Error fetching users: ${response.data.message || 'Failed to load user list.'}</p>`;
    }
    if(btn) btn.disabled = false; // Re-enable button
}


// --- AI Assistant Functions ---

/** Initializes or clears the AI chat display with a role-specific greeting */
function initializeAiChat(rolePrefix) {
    const display = document.getElementById(`${rolePrefix}-ai-chat-display`);
    const statusEl = document.getElementById(`${rolePrefix}-ai-status`);
    const queryInput = document.getElementById(`${rolePrefix}-ai-query`);

    if (!display) { console.warn(`AI chat display not found for role: ${rolePrefix}`); return; }

    const username = currentUsername || 'User'; // Use logged-in username or fallback
    let greeting = `Hello ${username}! How can I assist you today?`; // Default greeting

    // Role-specific greetings mentioning capabilities
    if (rolePrefix === 'doctor') {
        greeting = `Hi Dr. ${username}! Ask about specific patient history (DB), overall visit counts/graphs (Excel log), or recent general visits (Excel log). For example: "Show history for MRN123", "How many visits today?", "Graph visits last 7 days".`;
    } else if (rolePrefix === 'superadmin') {
        greeting = `Hello Admin ${username}! You can query patient details (DB), aggregate visit counts/graphs (Excel log), or recent general visits (Excel log). Try "Find patient Jane Doe", "Visit count this month", "Show recent visits".`;
    }

    // Set initial greeting message
    display.innerHTML = `<div class="chat-message ai-message"><span>${greeting}</span></div>`;

    // Clear status and input field
    if(statusEl) statusEl.textContent = '';
    if(queryInput) {
        queryInput.value = '';
        queryInput.disabled = false; // Ensure input is enabled
        // Enable send button too
        const sendButton = queryInput.closest('.ai-chat-input')?.querySelector('button');
        if(sendButton) sendButton.disabled = false;
    }
}

/**
 * Adds a message to the AI chat display. Handles text, URLs, and image URLs.
 * @param {string} rolePrefix - 'doctor' or 'superadmin' to find the correct display.
 * @param {string} text - The message text from the user or AI.
 * @param {'user' | 'ai' | 'thinking' | 'error'} type - The type of message.
 */
function addAiChatMessage(rolePrefix, text, type) {
    const display = document.getElementById(`${rolePrefix}-ai-chat-display`);
    if (!display) { console.error(`Chat display element not found: ${rolePrefix}-ai-chat-display`); return; }

    const messageContainer = document.createElement('div');
    messageContainer.classList.add('chat-message'); // Base class for all messages

    const messageSpan = document.createElement('span'); // Content holder

    if (type === 'user') {
        messageContainer.classList.add('user-message');
        messageSpan.textContent = text; // User input is plain text
    } else { // AI messages ('ai', 'thinking', 'error')
        messageContainer.classList.add('ai-message');
        if (type === 'thinking') {
            messageContainer.classList.add('ai-thinking');
            messageSpan.innerHTML = '<i>Thinking...</i>'; // Simple thinking indicator
        } else {
            if (type === 'error') { messageContainer.classList.add('ai-error'); }

            // Process AI text for links and images
            // Regex to find URLs (http/https) and relative /uploads/ paths for images/PDFs
            // Improved regex to better capture paths and avoid matching partial words
             const urlRegex = /(\b(https?:\/\/[-\w@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-\w()@:%_\+.~#?&//=]*))|(^|\s)(\/uploads\/[\w.-]+\.(png|jpg|jpeg|gif|pdf))\b)/ig;

             let processedHtml = text.replace(/\n/g, '<br>'); // Handle newlines first

             processedHtml = processedHtml.replace(urlRegex, (match, fullUrlOrPath, httpUrl, httpUrlPath, relativePathWithSpace, relativePath, fileExt) => {
                 let url = httpUrl || relativePath; // Choose the matched group
                 if (!url) return match; // Should not happen, but safety check

                 const isImageUrl = /\.(png|jpg|jpeg|gif)$/i.test(url);
                 const isPdfUrl = url.toLowerCase().endsWith('.pdf');
                 // Ensure full URL for relative paths starting with /uploads/
                 const displayUrl = url.startsWith('/') ? window.location.origin + url : url;
                 const shortUrl = url.split('/').pop(); // Get filename for display text

                 console.log(`Processing URL: ${url}, Display: ${displayUrl}, IsImage: ${isImageUrl}, IsPDF: ${isPdfUrl}`); // Debugging

                 if (isImageUrl && url.includes('/uploads/visits_graph_')) {
                     // Special handling for generated graphs: Show image directly
                     return `<br><a href="${displayUrl}" target="_blank" title="Click to open graph in new tab"><img src="${displayUrl}" alt="Visit Graph: ${shortUrl}" class="ai-generated-graph"></a>`;
                 } else if (isImageUrl) {
                     // Link other images, maybe show a small icon?
                     return `<a href="${displayUrl}" target="_blank" title="Open image in new tab">${shortUrl || url} (Image)</a>`;
                 } else if (isPdfUrl) {
                     // Link PDFs
                     return `<a href="${displayUrl}" target="_blank" title="Open PDF in new tab">${shortUrl || url} (PDF)</a>`;
                 } else if (httpUrl) {
                     // Standard HTTP/HTTPS link
                     return `<a href="${displayUrl}" target="_blank" title="Open link in new tab">${url}</a>`;
                 } else {
                      // If it matched relative path but wasn't image/pdf (shouldn't happen often with current regex)
                      return match; // Return original match if type unknown
                 }
             });

            messageSpan.innerHTML = processedHtml; // Use innerHTML for AI responses to render links/images/br
        }
    }

    messageContainer.appendChild(messageSpan);
    display.appendChild(messageContainer);

    // Auto-scroll to the bottom
    display.scrollTop = display.scrollHeight;
}


/** Sends the user query to the AI backend and displays the response */
async function askAI(rolePrefix) {
    const queryInput = document.getElementById(`${rolePrefix}-ai-query`);
    const statusEl = document.getElementById(`${rolePrefix}-ai-status`);
    const chatDisplay = document.getElementById(`${rolePrefix}-ai-chat-display`);
    // Find the button within the same input area as the input field
    const sendButton = queryInput ? queryInput.closest('.ai-chat-input')?.querySelector('button') : null;

    if (!queryInput || !chatDisplay) { console.error("AI UI elements missing for role:", rolePrefix); return; }

    const query = queryInput.value.trim();
    if (!query) { queryInput.focus(); return; } // Do nothing if query is empty

    // Disable input and button
    queryInput.disabled = true;
    if (sendButton) sendButton.disabled = true;
    if (statusEl) statusEl.textContent = 'Sending...'; // Update status

    // Display user message immediately
    addAiChatMessage(rolePrefix, query, 'user');
    queryInput.value = ''; // Clear input field after sending

    // Add a 'thinking' message placeholder
    addAiChatMessage(rolePrefix, '...', 'thinking');
    if (statusEl) statusEl.textContent = 'AI is processing...';

    // Find the thinking message element to remove it later
    const thinkingMsgElement = chatDisplay.querySelector('.ai-thinking');

    console.log(`Sending AI query for ${rolePrefix}: ${query}`);
    const response = await fetchApi('/ask-ai', 'POST', { query: query });
    console.log(`[Debug] Raw AI Response received for ${rolePrefix}:`, response);

    // Remove the 'thinking' message regardless of success or failure
    if (thinkingMsgElement) {
        thinkingMsgElement.remove();
    } else {
         console.warn("Could not find thinking message element to remove.");
    }

    // Handle response
    if (response.ok && response.data && typeof response.data.answer === 'string') {
        console.log(`[Debug] AI success for ${rolePrefix}. Answer length: ${response.data.answer.length}`);
        addAiChatMessage(rolePrefix, response.data.answer, 'ai'); // Display AI's answer
        if(statusEl) statusEl.textContent = ''; // Clear status on success
    } else {
        // Handle errors (network, server, AI-specific error)
        console.error(`[Debug] AI error or no answer for ${rolePrefix}. Response:`, response);
        const errorMessage = response.data?.error || response.data?.message || 'Sorry, I encountered an error or received no answer from the AI.';
        addAiChatMessage(rolePrefix, `Error: ${errorMessage}`, 'error'); // Display error message in chat
        if(statusEl) statusEl.textContent = 'Error processing request'; // Update status
    }

    // Re-enable input and button, and focus input
    queryInput.disabled = false;
    if (sendButton) sendButton.disabled = false;
    queryInput.focus();
}

/** Adds Enter key listener to AI query inputs */
function addAIKeyListener(inputId, rolePrefix) {
    const inputElement = document.getElementById(inputId);
    if (inputElement) {
        inputElement.addEventListener('keypress', (e) => {
            // Check if Enter key was pressed without the Shift key
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault(); // Prevent default Enter behavior (like adding a newline)
                askAI(rolePrefix); // Trigger the AI query function
            }
        });
         console.log(`Added Enter key listener to ${inputId}`);
    } else {
        // This might happen if the role's UI isn't loaded yet or the ID is wrong
         // console.warn(`AI input element not found for key listener: ${inputId}`);
    }
}


// --- General UI Cleanup ---
function clearAllFormsAndDisplays() {
    console.log("Clearing all role-specific forms and displays.");
    // Call individual clear functions
    clearReceptionistForms();
    clearDoctorForms();
    clearLabtechForms();
    clearPharmacistForms();
    clearSuperadminDisplay(); // This includes clearing the superadmin AI chat

    // Explicitly reset AI for Doctor if not covered by clearDoctorForms (it should be, but for safety)
    if (userRole !== 'superadmin') { // Avoid double-resetting if logged out from superadmin
        initializeAiChat('doctor');
    }

    // Clear any top-level dashboard messages if needed
    clearMessage('dashboard-message');
}

// --- Report Viewing Function (for PDFs linked in history) ---
async function viewReport(fileUrl, messageElementId) {
    const msgElement = document.getElementById(messageElementId);
    if (!msgElement) { console.error(`Message element ${messageElementId} not found for report link.`); return; }

    // Show loading state in the specific message span
    msgElement.textContent = ' Loading PDF...';
    msgElement.className = 'temp-message info-message'; // Add class for styling

    console.log(`Attempting to view report: ${fileUrl}`);

    try {
        // Use fetchApi to handle headers and potential errors, expect a Blob
        const response = await fetchApi(fileUrl, 'GET', null, false, true); // expectBlob = true

        if (response.ok && response.data instanceof Blob) {
            const blob = response.data;
            // Double-check blob type (optional but good practice)
            if (blob.type === 'application/pdf') {
                console.log("PDF Blob received successfully.");
                // Create a temporary URL for the blob
                const objectUrl = URL.createObjectURL(blob);
                // Open the PDF in a new tab
                window.open(objectUrl, '_blank');
                // Clear the loading message
                msgElement.textContent = '';
                msgElement.className = 'temp-message'; // Remove styling class
                // Important: Revoke the object URL after a short delay to allow the new tab to load it
                setTimeout(() => {
                    URL.revokeObjectURL(objectUrl);
                    console.log("Revoked temporary PDF URL.");
                }, 500); // 500ms delay
            } else {
                console.error('Received file blob is not a PDF. Type:', blob.type);
                msgElement.textContent = ' Error: File is not a PDF.';
                msgElement.className = 'temp-message error-message';
            }
        } else {
            // Handle fetch errors (404, 401, 500 etc.)
            let errorMessage = `Error loading file (Status: ${response.status})`;
            if (response.data?.message && typeof response.data.message === 'string') {
                errorMessage = response.data.message; // Use message from API if available
            } else if (response.status === 404){ errorMessage = "Error: Report file not found."; }
            else if (response.status === 401 || response.status === 403) { errorMessage = "Error: Unauthorized access to report."; }

            console.error('Error fetching report file:', response);
            msgElement.textContent = ` ${errorMessage}`; // Prepend space for clarity
            msgElement.className = 'temp-message error-message';
        }
    } catch (error) {
        // Catch network errors from fetchApi itself
        console.error('Network error while trying to fetch report:', error);
        msgElement.textContent = ' Network Error accessing report.';
        msgElement.className = 'temp-message error-message';
    }
}


// --- Initial Load Logic ---
document.addEventListener('DOMContentLoaded', async () => {
     console.log("DOM Content Loaded. Initializing application.");

     // 1. Load roles for the login dropdown immediately
     await loadRoles();
     console.log("Roles loaded (or loading initiated).");

     // 2. Check for existing session and load dashboard if valid
     await checkSessionAndLoad();
     console.log("Initial session check and dashboard load attempt complete.");

     // 3. Add event listeners (use event delegation where possible or add directly)
     console.log("Adding primary event listeners...");

     // Login Button Listener
     const loginButton = document.querySelector('#login-form button');
     if (loginButton) {
         loginButton.addEventListener('click', login);
     } else { console.error("Login button not found!"); }

     // Login Form Enter Key Listener (on password field)
     const passwordInput = document.getElementById('password');
     if (passwordInput) {
         passwordInput.addEventListener('keypress', (e) => {
             if (e.key === 'Enter') {
                 e.preventDefault(); // Prevent form submission
                 login(); // Trigger login function
             }
         });
     } else { console.warn("Password input not found for Enter key listener."); }

      // Logout Button Listener
      const logoutButton = document.getElementById('logout-btn');
      if (logoutButton) {
          logoutButton.addEventListener('click', logout);
      } else { console.warn("Logout button not found."); }

     // AI Input Enter Key Listeners (add even if sections initially hidden)
     addAIKeyListener('doctor-ai-query', 'doctor');
     addAIKeyListener('superadmin-ai-query', 'superadmin');

     // AI Send Button Listeners (find buttons within the input area)
     const doctorSendBtn = document.querySelector('#doctor-ai-query + button'); // Assumes button is immediate sibling
     if (doctorSendBtn) doctorSendBtn.addEventListener('click', () => askAI('doctor'));
     else console.warn("Doctor AI send button not found.");

     const adminSendBtn = document.querySelector('#superadmin-ai-query + button');
     if (adminSendBtn) adminSendBtn.addEventListener('click', () => askAI('superadmin'));
     else console.warn("Superadmin AI send button not found.");

     // Add other button listeners using IDs or more specific selectors if not using inline onclick
     // Example (assuming you remove onclick from HTML):
     // document.getElementById('create-patient-btn')?.addEventListener('click', createPatient);
     // document.getElementById('record-visit-btn')?.addEventListener('click', recordVisit);
     // ... etc. for all action buttons ...

     console.log("Event listeners setup complete.");
     console.log("Application initialization finished.");
});