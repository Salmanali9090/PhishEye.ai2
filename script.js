// PhishEye.ai - Upgraded JavaScript
// Mobile menu, Link scanner, Reports page, LocalStorage support

const API_BASE = 'http://localhost:5000/api';
let currentScanType = 'url';
let currentScanData = null;
let scanHistory = [];

// Load data from localStorage on startup
function loadFromStorage() {
    try {
        const saved = localStorage.getItem('phisheye_scans');
        if (saved) {
            scanHistory = JSON.parse(saved);
            console.log('✅ Loaded', scanHistory.length, 'scans from storage');
        }
    } catch (e) {
        console.log('No previous data found');
    }
}

// Save data to localStorage
function saveToStorage() {
    try {
        localStorage.setItem('phisheye_scans', JSON.stringify(scanHistory));
        console.log('💾 Saved', scanHistory.length, 'scans');
    } catch (e) {
        console.error('Failed to save data');
    }
}

// Initialize on page load
loadFromStorage();

// Mobile Menu Toggle
function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    const overlay = document.getElementById('mobile-menu-overlay');
    
    menu.classList.toggle('open');
    
    if (menu.classList.contains('open')) {
        overlay.classList.remove('hidden');
    } else {
        overlay.classList.add('hidden');
    }
}

function showPage(page) {
    document.querySelectorAll('.page-content').forEach(p => p.classList.add('hidden'));
    document.getElementById('page-' + page).classList.remove('hidden');
    
    // Update desktop nav
    document.querySelectorAll('nav button').forEach(btn => {
        btn.classList.remove('bg-cyan-500', 'bg-opacity-20', 'text-cyan-400');
    });
    const navBtn = document.getElementById('nav-' + page);
    if (navBtn) navBtn.classList.add('bg-cyan-500', 'bg-opacity-20', 'text-cyan-400');
    
    // Update mobile nav
    document.querySelectorAll('#mobile-menu button').forEach(btn => {
        btn.classList.remove('bg-cyan-500', 'bg-opacity-20', 'text-cyan-400');
    });
    const mobileNavBtn = document.getElementById('mobile-nav-' + page);
    if (mobileNavBtn) mobileNavBtn.classList.add('bg-cyan-500', 'bg-opacity-20', 'text-cyan-400');
    
    if (page === 'dashboard') updateDashboard();
    if (page === 'reports') updateReports();
}

function setScanType(type) {
    currentScanType = type;
    
    document.querySelectorAll('.scan-type-btn').forEach(btn => {
        if (btn.dataset.type === type) {
            btn.classList.add('bg-cyan-500', 'bg-opacity-20', 'border-cyan-500', 'text-cyan-400');
        } else {
            btn.classList.remove('bg-cyan-500', 'bg-opacity-20', 'border-cyan-500', 'text-cyan-400');
            btn.classList.add('bg-slate-700', 'bg-opacity-50', 'border-slate-600');
        }
    });

    const input = document.getElementById('scan-input');
    const textarea = document.getElementById('scan-textarea');
    const label = document.getElementById('scan-label');
    
    const configs = {
        url: { label: 'URL Scan', placeholder: 'https://example.com', textarea: false },
        domain: { label: 'Domain Scan', placeholder: 'example.com', textarea: false },
        ip: { label: 'IP Scan', placeholder: '8.8.8.8', textarea: false },
        hash: { label: 'Hash Scan', placeholder: 'Enter MD5/SHA256', textarea: false },
        link: { label: 'Link Scanner', placeholder: 'https://suspicious-link.com', textarea: false },
        email: { label: 'Email Analysis', placeholder: 'Paste email...', textarea: true }
    };
    
    const config = configs[type];
    label.textContent = config.label;
    
    if (config.textarea) {
        input.classList.add('hidden');
        textarea.classList.remove('hidden');
        textarea.placeholder = config.placeholder;
        textarea.value = '';
    } else {
        textarea.classList.add('hidden');
        input.classList.remove('hidden');
        input.placeholder = config.placeholder;
        input.value = '';
    }
}

async function startScan(event) {
    event.preventDefault();
    
    const input = currentScanType === 'email' 
        ? document.getElementById('scan-textarea').value 
        : document.getElementById('scan-input').value;
    
    if (!input.trim()) {
        alert('Please enter a value');
        return;
    }

    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    btn.innerHTML = '<svg class="w-5 h-5 inline spinner" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> <span class="ml-2">Scanning...</span>';

    document.getElementById('scan-results').classList.add('hidden');

    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scan_type: currentScanType,
                input_value: input
            })
        });

        if (!response.ok) throw new Error('Scan failed');

        const data = await response.json();
        currentScanData = data;
        displayResults(data);
        addToHistory(data);
        
        document.getElementById('scan-results').classList.remove('hidden');
        document.getElementById('scan-results').scrollIntoView({ behavior: 'smooth' });
        
        // Clear input
        if (currentScanType === 'email') {
            document.getElementById('scan-textarea').value = '';
        } else {
            document.getElementById('scan-input').value = '';
        }
        
    } catch (error) {
        alert('Scan failed. Ensure backend is running on localhost:5000');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>Start Scan</span>';
    }
}

function displayResults(data) {
    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const detectionRatio = document.getElementById('detection-ratio');
    
    statusCard.className = 'glass-card rounded-lg p-6 border-2 ';
    
    const configs = {
        safe: {
            border: 'border-green-500',
            icon: 'text-green-500',
            path: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z'
        },
        suspicious: {
            border: 'border-yellow-500',
            icon: 'text-yellow-500',
            path: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z'
        },
        malicious: {
            border: 'border-red-500',
            icon: 'text-red-500',
            path: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'
        }
    };
    
    const config = configs[data.status] || configs.safe;
    statusCard.classList.add(config.border);
    statusIcon.className = `w-12 h-12 ${config.icon}`;
    statusIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${config.path}"></path>`;
    
    statusText.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
    detectionRatio.textContent = `${data.detection_ratio} | ${data.threats} threats`;
    
    // Summary
    document.getElementById('short-summary').textContent = data.short_summary;
    
    // Detailed - Clean formatting
    const detailedContent = document.getElementById('detailed-content');
    let detailedHTML = data.detailed_summary.split('\n\n')
        .filter(p => p.trim())
        .map(p => `<p class="mb-3">${p.trim()}</p>`)
        .join('');
    
    if (data.vt_details && data.vt_details.vendors && data.vt_details.vendors.length > 0) {
        detailedHTML += `
            <div class="mt-4 pt-4 border-t border-slate-700">
                <p class="font-semibold mb-2">VirusTotal: ${data.vt_details.malicious} malicious, ${data.vt_details.suspicious} suspicious</p>
                ${data.vt_details.vendors.slice(0, 3).map(v => 
                    `<p class="text-sm ml-3">• ${v.name}: ${v.category}</p>`
                ).join('')}
            </div>
        `;
    }
    
    if (data.indicators && data.indicators.length > 0) {
        detailedHTML += `
            <div class="mt-4 pt-4 border-t border-slate-700">
                <p class="font-semibold mb-2">Indicators:</p>
                ${data.indicators.map(ind => `<p class="text-sm ml-3">• ${ind}</p>`).join('')}
            </div>
        `;
    }
    
    if (data.domain) {
        detailedHTML += `
            <div class="mt-4 pt-4 border-t border-slate-700">
                <p class="font-semibold mb-2">Domain Analysis:</p>
                <p class="text-sm ml-3">• Domain: ${data.domain}</p>
            </div>
        `;
    }
    
    detailedContent.innerHTML = detailedHTML;
    
    // Remediation
    const remediationSteps = document.getElementById('remediation-steps');
    remediationSteps.innerHTML = (data.remediation || []).map(step => 
        `<li class="mb-2">${step}</li>`
    ).join('');
    
    // Reset chat
    document.getElementById('chat-messages').innerHTML = 
        '<p class="text-gray-500 text-center py-8">Ask about this scan...</p>';
}

function toggleSection(section) {
    const content = document.getElementById(section + '-content');
    const chevron = document.getElementById(section + '-chevron');
    
    content.classList.toggle('hidden');
    chevron.innerHTML = content.classList.contains('hidden')
        ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>'
        : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"></path>';
}

async function sendChat() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    
    if (!message || !currentScanData) return;
    
    const messagesContainer = document.getElementById('chat-messages');
    
    if (messagesContainer.querySelector('.text-gray-500')) {
        messagesContainer.innerHTML = '';
    }
    
    const userMsg = document.createElement('div');
    userMsg.className = 'flex justify-end';
    userMsg.innerHTML = `<div class="chat-user">${escapeHtml(message)}</div>`;
    messagesContainer.appendChild(userMsg);
    
    input.value = '';
    input.disabled = true;
    
    const typingMsg = document.createElement('div');
    typingMsg.className = 'flex justify-start';
    typingMsg.id = 'typing';
    typingMsg.innerHTML = `<div class="chat-ai">
        <span class="inline-block w-2 h-2 bg-gray-400 rounded-full animate-bounce"></span>
        <span class="inline-block w-2 h-2 bg-gray-400 rounded-full animate-bounce mx-1" style="animation-delay: 0.2s"></span>
        <span class="inline-block w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0.4s"></span>
    </div>`;
    messagesContainer.appendChild(typingMsg);
    
    try {
        const context = `Type: ${currentScanData.type}, Status: ${currentScanData.status}, Detection: ${currentScanData.detection_ratio}`;
        
        const response = await fetch(`${API_BASE}/ai-chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, context })
        });
        
        document.getElementById('typing')?.remove();
        
        if (!response.ok) throw new Error('Chat failed');
        
        const data = await response.json();
        
        const aiMsg = document.createElement('div');
        aiMsg.className = 'flex justify-start';
        aiMsg.innerHTML = `<div class="chat-ai">${escapeHtml(data.response)}</div>`;
        messagesContainer.appendChild(aiMsg);
        
    } catch (error) {
        document.getElementById('typing')?.remove();
        const errorMsg = document.createElement('div');
        errorMsg.className = 'flex justify-start';
        errorMsg.innerHTML = `<div class="chat-ai">Sorry, error occurred.</div>`;
        messagesContainer.appendChild(errorMsg);
    } finally {
        input.disabled = false;
        input.focus();
    }
    
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function addToHistory(data) {
    scanHistory.unshift({
        id: Date.now(),
        type: data.type.toUpperCase(),
        value: data.input.substring(0, 30) + (data.input.length > 30 ? '...' : ''),
        status: data.status,
        date: new Date().toISOString().split('T')[0],
        fullData: data  // Store full data for viewing
    });
    
    if (scanHistory.length > 50) scanHistory = scanHistory.slice(0, 50);
    
    // Save to localStorage
    saveToStorage();
    
    updateDashboard();
}

// VIEW PREVIOUS SCAN
function viewScan(scanId) {
    const scan = scanHistory.find(s => s.id === scanId);
    if (!scan || !scan.fullData) return;
    
    currentScanData = scan.fullData;
    displayResults(scan.fullData);
    
    showPage('scanner');
    document.getElementById('scan-results').classList.remove('hidden');
    document.getElementById('scan-results').scrollIntoView({ behavior: 'smooth' });
}

function updateDashboard() {
    const total = scanHistory.length;
    const safe = scanHistory.filter(s => s.status === 'safe').length;
    const suspicious = scanHistory.filter(s => s.status === 'suspicious').length;
    const malicious = scanHistory.filter(s => s.status === 'malicious').length;
    
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-safe').textContent = safe;
    document.getElementById('stat-suspicious').textContent = suspicious;
    document.getElementById('stat-malicious').textContent = malicious;
    
    const tableBody = document.getElementById('history-table');
    
    if (scanHistory.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" class="py-8 text-center text-gray-500">No scans yet</td></tr>';
    } else {
        const statusColors = {
            safe: 'bg-green-500 bg-opacity-20 text-green-400 border border-green-500',
            suspicious: 'bg-yellow-500 bg-opacity-20 text-yellow-400 border border-yellow-500',
            malicious: 'bg-red-500 bg-opacity-20 text-red-400 border border-red-500'
        };
        
        tableBody.innerHTML = scanHistory.map(scan => `
            <tr class="border-b border-slate-700 hover:bg-slate-700 hover:bg-opacity-30 transition cursor-pointer" onclick="viewScan(${scan.id})">
                <td class="py-3 px-4">
                    <span class="px-2 py-1 bg-slate-700 rounded text-sm">${scan.type}</span>
                </td>
                <td class="py-3 px-4 text-gray-300">${escapeHtml(scan.value)}</td>
                <td class="py-3 px-4">
                    <span class="px-3 py-1 rounded-full text-sm font-medium ${statusColors[scan.status]}">
                        ${scan.status.toUpperCase()}
                    </span>
                </td>
                <td class="py-3 px-4 text-gray-400">${scan.date}</td>
                <td class="py-3 px-4">
                    <button class="text-cyan-400 hover:text-cyan-300" onclick="event.stopPropagation(); viewScan(${scan.id})">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                        </svg>
                    </button>
                </td>
            </tr>
        `).join('');
    }
}

// UPDATE REPORTS PAGE
function updateReports() {
    const reportsList = document.getElementById('reports-list');
    
    if (scanHistory.length === 0) {
        reportsList.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <p class="text-gray-500 text-lg">No reports available yet</p>
                <p class="text-gray-600 text-sm mt-2">Start scanning to generate reports</p>
            </div>
        `;
        return;
    }
    
    const statusColors = {
        safe: 'text-green-400',
        suspicious: 'text-yellow-400',
        malicious: 'text-red-400'
    };
    
    const statusIcons = {
        safe: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
        suspicious: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
        malicious: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'
    };
    
    reportsList.innerHTML = scanHistory.map(scan => `
        <div class="glass-card rounded-lg p-4 flex items-center justify-between hover:bg-slate-700 hover:bg-opacity-30 transition">
            <div class="flex items-center gap-4 flex-1">
                <svg class="w-8 h-8 ${statusColors[scan.status]}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${statusIcons[scan.status]}"></path>
                </svg>
                <div class="flex-1">
                    <div class="flex items-center gap-2 mb-1">
                        <span class="px-2 py-1 bg-slate-700 rounded text-xs font-medium">${scan.type}</span>
                        <span class="text-gray-500 text-xs">${scan.date}</span>
                    </div>
                    <p class="text-gray-300 text-sm">${escapeHtml(scan.value)}</p>
                    <p class="text-xs ${statusColors[scan.status]} mt-1">Status: ${scan.status.toUpperCase()}</p>
                </div>
            </div>
            <button onclick="downloadReportById(${scan.id})" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg flex items-center gap-2 transition ml-4">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <span class="hidden sm:inline">Download PDF</span>
            </button>
        </div>
    `).join('');
}

async function downloadReportById(scanId) {
    const scan = scanHistory.find(s => s.id === scanId);
    if (!scan || !scan.fullData) return;
    
    try {
        const response = await fetch(`${API_BASE}/generate-pdf`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scan.fullData)
        });
        
        if (!response.ok) throw new Error('PDF failed');
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `PhishEye_Report_${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
    } catch (error) {
        alert('PDF generation requires backend on localhost:5000');
    }
}

async function downloadPDF() {
    if (!currentScanData) return;
    
    try {
        const response = await fetch(`${API_BASE}/generate-pdf`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentScanData)
        });
        
        if (!response.ok) throw new Error('PDF failed');
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `PhishEye_${Date.now()}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
    } catch (error) {
        alert('PDF requires backend on localhost:5000');
    }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', function() {
    setScanType('url');
    showPage('home');
    
    // Update dashboard if we have data
    if (scanHistory.length > 0) {
        updateDashboard();
    }
    
    console.log('🛡️ PhishEye.ai loaded');
    console.log('📊 Total scans:', scanHistory.length);
});