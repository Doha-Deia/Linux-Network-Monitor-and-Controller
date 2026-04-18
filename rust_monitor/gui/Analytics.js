let processChart  = null;
let userChart     = null;
let protocolChart = null;

// Bar chart helper
function drawBarChart(canvasId, items, labelField, valueField, oldChart) {
    if (oldChart) oldChart.destroy();

    const labels = labelField === 'process_name'
        ? items.map(x => `${x.process_name} (${x.pid})`)
        : items.map(x => x[labelField]);

    const values = items.map(x => x[valueField]);

    // Color bars by protocol if this is the protocol chart
    let bgColors = '#378ADD';
    if (labelField === 'protocol') {
        const MAP = { TCP: '#378ADD', UDP: '#EF9F27', ICMP: '#1D9E75' };
        bgColors = items.map(x => MAP[x.protocol] || '#888780');
    }

    return new Chart(document.getElementById(canvasId), {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Bytes',
                data: values,
                backgroundColor: bgColors,
                borderRadius: 5,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: ctx => ` ${fmtBytes(ctx.raw)}`,
                    }
                }
            },
            scales: {
                x: {
                    ticks: { font: { size: 11 }, maxRotation: 35 },
                    grid: { display: false },
                },
                y: {
                    beginAtZero: true,
                    ticks: { callback: v => fmtBytes(v), font: { size: 11 } },
                    grid: { color: 'rgba(0,0,0,0.05)' },
                }
            }
        }
    });
}

// Top-N table per chart 
function renderTopN(divId, items, nameField, n = 5) {
    const top = [...items].sort((a, b) => b.bytes - a.bytes).slice(0, n);
    const hasPid = nameField === 'process_name';

    let html = `<table class="top-table">
        <thead><tr>
            <th>#</th>
            <th>Name</th>
            ${hasPid ? '<th>PID</th>' : ''}
            <th>Bytes</th>
            <th>Pkts</th>
        </tr></thead><tbody>`;

    const totalBytes = items.reduce((s, x) => s + x.bytes, 0) || 1;

    top.forEach((item, i) => {
        const pct = Math.round(item.bytes / totalBytes * 100);
        html += `<tr>
            <td style="color:var(--muted);font-size:11px">${i + 1}</td>
            <td>
                <div style="font-weight:500">${item[nameField]}</div>
                <div style="height:3px;margin-top:4px;border-radius:2px;background:#e8e8e6;width:100%">
                  <div style="height:3px;border-radius:2px;background:var(--blue);width:${pct}%"></div>
                </div>
            </td>
            ${hasPid ? `<td style="color:var(--muted)">${item.pid}</td>` : ''}
            <td>${fmtBytes(item.bytes)}</td>
            <td>${item.packets.toLocaleString()}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    document.getElementById(divId).innerHTML = html;
}

// Full process table
let allProcs = [];
let sortField = 'bytes';
let sortDir   = -1;  // -1 = desc, 1 = asc

function renderAllProcs() {
    const tbody = document.getElementById('allProcsBody');
    if (!allProcs.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="no-results">No data yet</td></tr>';
        return;
    }

    const sorted = [...allProcs].sort((a, b) =>
        sortDir * (typeof a[sortField] === 'number'
            ? a[sortField] - b[sortField]
            : String(a[sortField]).localeCompare(String(b[sortField])))
    );

    tbody.innerHTML = sorted.map(p => `
        <tr>
            <td style="font-weight:500">${p.process_name}</td>
            <td style="color:var(--muted)">${p.pid}</td>
            <td>${p.user}</td>
            <td>${fmtBytes(p.bytes)}</td>
            <td>${p.packets.toLocaleString()}</td>
        </tr>
    `).join('');
}

// Sortable column headers
document.addEventListener('DOMContentLoaded', () => {
    const headers = document.querySelectorAll('#allProcsTable thead th');
    const fields  = ['process_name', 'pid', 'user', 'bytes', 'packets'];

    headers.forEach((th, i) => {
        th.addEventListener('click', () => {
            const field = fields[i];
            if (sortField === field) {
                sortDir *= -1;
            } else {
                sortField = field;
                sortDir   = -1;
            }
            headers.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
            th.classList.add(sortDir === -1 ? 'sort-desc' : 'sort-asc');
            renderAllProcs();
        });
    });

    // Set initial sort indicator
    headers[3].classList.add('sort-desc');
});

// Load loop
async function load() {
    try {
        const res  = await fetch('/api/summary');
        if (!res.ok) throw new Error();
        const data = await res.json();

        setStatus(true);

        processChart  = drawBarChart('processChart',  data.processes, 'process_name', 'bytes', processChart);
        userChart     = drawBarChart('userChart',     data.users,     'user',         'bytes', userChart);
        protocolChart = drawBarChart('protocolChart', data.protocols, 'protocol',     'bytes', protocolChart);

        renderTopN('processTop',  data.processes, 'process_name');
        renderTopN('userTop',     data.users,     'user');
        renderTopN('protocolTop', data.protocols, 'protocol');

        allProcs = data.processes;
        renderAllProcs();
    } catch {
        setStatus(false);
    }
}

load();
setInterval(load, 1000);