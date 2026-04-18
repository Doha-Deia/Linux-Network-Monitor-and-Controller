// Formatting helpers
function fmtBytes(b) {
    if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
    if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
    if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
    return b + ' B';
}

function truncate(str, max) {
    return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

// Status dot
function setStatus(ok) {
    const dot = document.getElementById('statusDot');
    if (dot) dot.className = 'header-dot ' + (ok ? 'online' : 'offline');
    const badge = document.getElementById('lastUpdated');
    if (badge && ok) badge.textContent = 'Updated ' + new Date().toLocaleTimeString();
}

// Inject shared nav
(function injectNav() {
    const pages = [
        { href: 'index.html',     label: 'Overview',   icon: '⬡' },
        { href: 'analytics.html', label: 'Analytics',  icon: '◫' },
        { href: 'search.html',    label: 'Search',     icon: '⌕' },
    ];

    const current = location.pathname.split('/').pop() || 'index.html';

    const navHTML = `
    <nav class="sidenav">
        <div class="sidenav-brand">
            <span class="brand-icon"></span>
            <span class="brand-name">NetMonitor</span>
        </div>
        <ul class="sidenav-links">
            ${pages.map(p => `
            <li>
                <a href="${p.href}" class="nav-link ${current === p.href ? 'active' : ''}">
                    <span class="nav-icon">${p.icon}</span>
                    <span>${p.label}</span>
                </a>
            </li>`).join('')}
        </ul>
        <div class="sidenav-footer">
            <span class="header-dot" id="statusDot"></span>
            <div>
                <div class="footer-live">LIVE</div>
                <div id="lastUpdated" class="footer-time">—</div>
            </div>
        </div>
    </nav>`;

    // Insert before first child of body
    const wrapper = document.createElement('div');
    wrapper.className = 'app-shell';
    wrapper.innerHTML = navHTML + `<main class="page-content" id="pageContent"></main>`;

    // Move all existing body children into page-content
    while (document.body.firstChild) {
        wrapper.querySelector('#pageContent').appendChild(document.body.firstChild);
    }
    document.body.appendChild(wrapper);
})();
