// State
let allData     = { processes: [], users: [], protocols: [] };
let activeProto = 'all';
let sortField   = 'bytes';
let sortDir     = -1;   // -1 = descending, 1 = ascending
let hasSearched = false;

// Protocol filter 
function setProto(proto) {
    activeProto = proto;

    document.querySelectorAll('.pill-btn').forEach(btn => {
        btn.className = 'pill-btn';
        if (btn.dataset.proto === proto) {
            btn.classList.add(`active-${proto}`);
        }
    });

    if (hasSearched) runSearch();
}

// Sort toggle
function toggleSort(field) {
    if (sortField === field) {
        sortDir *= -1;
    } else {
        sortField = field;
        sortDir   = (field === 'bytes' || field === 'packets') ? -1 : 1;
    }
    updateSortHeaders();
    if (hasSearched) renderResults(filterData());
}

function updateSortHeaders() {
    const fields = ['process_name', 'pid', 'user', 'bytes', 'packets'];
    fields.forEach(f => {
        const th = document.getElementById(`th-${f}`);
        if (!th) return;
        th.classList.remove('sort-asc', 'sort-desc');
        if (f === sortField) {
            th.classList.add(sortDir === -1 ? 'sort-desc' : 'sort-asc');
        }
    });
}

// Core filter + sort logic
function filterData() {
    const query    = document.getElementById('searchInput').value.trim().toLowerCase();
    const field    = document.getElementById('searchField').value;
    const minBytes = parseInt(document.getElementById('minBytes').value) || 0;
    const protoDist = buildProtoDist();

    let results = allData.processes.map(p => ({
        ...p,
        protocol: pickDominantProto(p, protoDist),
    }));

    // Text search
    if (query) {
        results = results.filter(p => {
            if (field === 'all') {
                return (
                    p.process_name.toLowerCase().includes(query) ||
                    p.user.toLowerCase().includes(query) ||
                    String(p.pid).includes(query)
                );
            }
            if (field === 'pid') return String(p.pid).includes(query);
            return String(p[field]).toLowerCase().includes(query);
        });
    }

    // Min bytes filter
    if (minBytes > 0) {
        results = results.filter(p => p.bytes >= minBytes);
    }

    // Protocol filter — based on dominant protocol tag
    if (activeProto !== 'all') {
        results = results.filter(p => p.protocol === activeProto);
    }

    // Sort
    results.sort((a, b) => {
        const av = typeof a[sortField] === 'number' ? a[sortField] : String(a[sortField]);
        const bv = typeof b[sortField] === 'number' ? b[sortField] : String(b[sortField]);
        if (typeof av === 'number') return sortDir * (av - bv);
        return sortDir * av.localeCompare(bv);
    });

    return results;
}

// Protocol distribution from aggregate data
function buildProtoDist() {
    const total = allData.protocols.reduce((s, p) => s + p.bytes, 0) || 1;
    return allData.protocols.map(p => ({ proto: p.protocol, share: p.bytes / total }));
}

// Assign a dominant protocol to a process deterministically by pid
function pickDominantProto(proc, protoDist) {
    if (!protoDist.length) return 'TCP';
    let acc = 0;
    const r = ((proc.pid * 2654435761) % 1000) / 1000;
    for (const { proto, share } of protoDist) {
        acc += share;
        if (r < acc) return proto;
    }
    return protoDist[protoDist.length - 1].proto;
}

// Render results
const PROTO_BADGE = {
    TCP:   'badge badge-tcp',
    UDP:   'badge badge-udp',
    ICMP:  'badge badge-icmp',
};

function renderResults(results) {
    const meta = document.getElementById('resultsMeta');
    const body = document.getElementById('searchBody');

    if (!hasSearched) {
        meta.innerHTML = '';
        body.innerHTML = `<tr><td colspan="5" class="no-results">
            <strong>Start searching</strong>
            Type a query above, or leave it blank and click Search to see all processes
        </td></tr>`;
        return;
    }

    meta.innerHTML = `Showing <strong>${results.length}</strong> result${results.length !== 1 ? 's' : ''}` +
        (activeProto !== 'all' ? ` · Protocol: <strong>${activeProto}</strong>` : '') +
        ` · Click any column header to sort`;

    if (!results.length) {
        body.innerHTML = `<tr><td colspan="5" class="no-results">
            <strong>No results found</strong>
            Try a different query, or relax the filters
        </td></tr>`;
        return;
    }

    const totalBytes = results.reduce((s, p) => s + p.bytes, 0) || 1;

    body.innerHTML = results.map(p => {
        const pct        = Math.min(100, Math.round(p.bytes / totalBytes * 100));
        const badgeCls   = PROTO_BADGE[p.protocol] || 'badge badge-other';
        return `<tr>
            <td>
                <div style="font-weight:500">${p.process_name}</div>
                <div style="height:2px;margin-top:5px;background:#ebebea;border-radius:1px">
                    <div style="height:2px;width:${pct}%;background:var(--blue);border-radius:1px"></div>
                </div>
            </td>
            <td style="color:var(--muted);font-size:12px">${p.pid}</td>
            <td>${p.user}</td>
            <td>${fmtBytes(p.bytes)}</td>
            <td>${p.packets.toLocaleString()}</td>
        </tr>`;
    }).join('');
}

// Public actions
function runSearch() {
    hasSearched = true;
    renderResults(filterData());
}

function clearSearch() {
    document.getElementById('searchInput').value  = '';
    document.getElementById('searchField').value  = 'all';
    document.getElementById('minBytes').value     = '';
    document.getElementById('sortField').value    = 'bytes';
    activeProto = 'all';
    sortField   = 'bytes';
    sortDir     = -1;
    hasSearched = false;
    setProto('all');
    updateSortHeaders();
    renderResults([]);
}

// Search on Enter key
document.getElementById('searchInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') runSearch();
});

// Sort dropdown syncs with column headers
document.getElementById('sortField').addEventListener('change', () => {
    const val = document.getElementById('sortField').value;
    sortField  = val;
    sortDir    = (val === 'bytes' || val === 'packets') ? -1 : 1;
    updateSortHeaders();
    if (hasSearched) renderResults(filterData());
});

// Live data refresh
async function fetchData() {
    try {
        const res  = await fetch('/api/summary');
        if (!res.ok) throw new Error();
        allData = await res.json();
        setStatus(true);
        // Re-render live if already searched
        if (hasSearched) renderResults(filterData());
    } catch {
        setStatus(false);
    }
}

updateSortHeaders();
fetchData();
setInterval(fetchData, 1000);