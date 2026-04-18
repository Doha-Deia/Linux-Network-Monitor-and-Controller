let processChart = null;
let userChart = null;
let protocolChart = null;

const flowCanvas = document.getElementById('flowCanvas');
const ctx = flowCanvas.getContext('2d');

const PROTO_COLORS = {
    TCP:   { stroke: '#378ADD', fill: 'rgba(55,138,221,0.18)', particle: '#378ADD' },
    UDP:   { stroke: '#BA7517', fill: 'rgba(186,117,23,0.18)',  particle: '#EF9F27' },
    ICMP:  { stroke: '#0F6E56', fill: 'rgba(15,110,86,0.18)',   particle: '#1D9E75' },
    other: { stroke: '#5F5E5A', fill: 'rgba(95,94,90,0.12)',    particle: '#888780' },
};

// Node & particle stores
let flowNodes  = [];   // { id, label, x, y, r, bytes, isLocal }
let flowEdges  = [];   // { src, dst, protocol, bytes, particles[] }
let animFrame  = null;

// Resize canvas to match CSS width
function resizeFlowCanvas() {
    const rect = flowCanvas.parentElement.getBoundingClientRect();
    flowCanvas.width  = rect.width - 32;   // card padding
    flowCanvas.height = Math.max(320, Math.min(480, rect.width * 0.38));
    redrawFlow();
}

window.addEventListener('resize', resizeFlowCanvas);
resizeFlowCanvas();

// Build node/edge graph from summary data
function buildGraph(data) {
    const W = flowCanvas.width;
    const H = flowCanvas.height;
    const cx = W / 2;
    const cy = H / 2;

    const procs = data.processes || [];
    const protos = data.protocols || [];

    // Build nodes: local machine in center, top processes around it
    const topProcs = [...procs].sort((a, b) => b.bytes - a.bytes).slice(0, 8);
    const maxBytes = topProcs.length ? topProcs[0].bytes : 1;

    const nodes = new Map();

    // Central "host" node
    nodes.set('__local__', {
        id: '__local__',
        label: 'localhost',
        x: cx,
        y: cy,
        bytes: procs.reduce((s, p) => s + p.bytes, 0),
        isLocal: true,
        r: 0,  // computed below
    });

    // Protocol distribution for edge coloring
    const totalBytes = protos.reduce((s, p) => s + p.bytes, 1);
    const protoDist = {};
    protos.forEach(p => { protoDist[p.protocol] = p.bytes / totalBytes; });

    // Process nodes arranged in an arc
    const angleStep = (2 * Math.PI) / Math.max(topProcs.length, 1);
    const radius = Math.min(W, H) * 0.34;

    topProcs.forEach((proc, i) => {
        const angle = i * angleStep - Math.PI / 2;
        const id = `proc_${proc.pid}`;
        nodes.set(id, {
            id,
            label: proc.process_name,
            subLabel: `${proc.user} · ${fmtBytes(proc.bytes)}`,
            x: cx + Math.cos(angle) * radius,
            y: cy + Math.sin(angle) * radius,
            bytes: proc.bytes,
            isLocal: false,
            r: 0,
        });
    });

    // Compute radii (log scale)
    const allBytes = [...nodes.values()].map(n => n.bytes).filter(Boolean);
    const maxB = Math.max(...allBytes, 1);
    nodes.forEach(n => {
        n.r = n.isLocal
            ? 28
            : 8 + 20 * Math.pow(n.bytes / maxB, 0.45);
    });

    // Build edges: local → each process
    const edges = [];
    const domProto = (proc) => {
        // Assign a protocol color proportional to protocol share
        const r = Math.random();
        let acc = 0;
        for (const [proto, share] of Object.entries(protoDist)) {
            acc += share;
            if (r < acc) return proto;
        }
        return 'TCP';
    };

    topProcs.forEach((proc, i) => {
        const srcId = '__local__';
        const dstId = `proc_${proc.pid}`;
        const src = nodes.get(srcId);
        const dst = nodes.get(dstId);
        if (!src || !dst) return;

        edges.push({
            srcId, dstId,
            src, dst,
            protocol: domProto(proc),
            bytes: proc.bytes,
            particles: [],
        });
    });

    flowNodes = [...nodes.values()];
    flowEdges = edges;

    // Seed particles on edges
    flowEdges.forEach(edge => {
        if (edge.particles.length === 0) {
            const count = Math.max(1, Math.min(8, Math.round(edge.bytes / maxBytes * 6 + 1)));
            for (let k = 0; k < count; k++) {
                edge.particles.push({
                    t: Math.random(),
                    speed: 0.003 + Math.random() * 0.004,
                    size: 2.5 + Math.random() * 2,
                    opacity: 0.6 + Math.random() * 0.4,
                });
            }
        } else {
            // Update particle count to reflect new traffic levels
            const target = Math.max(1, Math.min(8, Math.round(edge.bytes / maxBytes * 6 + 1)));
            while (edge.particles.length < target) {
                edge.particles.push({
                    t: Math.random(),
                    speed: 0.003 + Math.random() * 0.004,
                    size: 2.5 + Math.random() * 2,
                    opacity: 0.6 + Math.random() * 0.4,
                });
            }
            if (edge.particles.length > target) {
                edge.particles.splice(target);
            }
        }
    });
}

function bezierPoint(p0, p1, cp, t) {
    const mt = 1 - t;
    return {
        x: mt * mt * p0.x + 2 * mt * t * cp.x + t * t * p1.x,
        y: mt * mt * p0.y + 2 * mt * t * cp.y + t * t * p1.y,
    };
}

function edgeControlPoint(src, dst) {
    const mx = (src.x + dst.x) / 2;
    const my = (src.y + dst.y) / 2;
    // Perpendicular offset for curved edges
    const dx = dst.x - src.x;
    const dy = dst.y - src.y;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    const perp = 0.22;
    return {
        x: mx - dy / len * len * perp,
        y: my + dx / len * len * perp,
    };
}

// Draw loop
function redrawFlow() {
    const W = flowCanvas.width;
    const H = flowCanvas.height;
    ctx.clearRect(0, 0, W, H);

    if (flowNodes.length === 0) {
        ctx.fillStyle = 'rgba(136,135,128,0.5)';
        ctx.font = '13px system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Waiting for traffic data…', W / 2, H / 2);
        return;
    }

    // Draw edges (curves)
    flowEdges.forEach(edge => {
        const { src, dst, protocol } = edge;
        const colors = PROTO_COLORS[protocol] || PROTO_COLORS.other;
        const cp = edgeControlPoint(src, dst);

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.quadraticCurveTo(cp.x, cp.y, dst.x, dst.y);
        ctx.strokeStyle = colors.stroke;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.25;
        ctx.stroke();
        ctx.globalAlpha = 1;
    });

    // Advance & draw particles
    flowEdges.forEach(edge => {
        const { src, dst, protocol, particles } = edge;
        const colors = PROTO_COLORS[protocol] || PROTO_COLORS.other;
        const cp = edgeControlPoint(src, dst);

        particles.forEach(p => {
            p.t += p.speed;
            if (p.t > 1) p.t -= 1;

            const pos = bezierPoint(src, dst, cp, p.t);

            ctx.beginPath();
            ctx.arc(pos.x, pos.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = colors.particle;
            ctx.globalAlpha = p.opacity;
            ctx.fill();
            ctx.globalAlpha = 1;
        });
    });

    // Draw nodes on top
    flowNodes.forEach(node => {
        const colors = node.isLocal ? PROTO_COLORS.TCP : PROTO_COLORS.other;
        const fillColor = node.isLocal ? 'rgba(55,138,221,0.15)' : 'rgba(95,94,90,0.12)';
        const strokeColor = node.isLocal ? '#378ADD' : '#888780';

        // Glow ring for local node
        if (node.isLocal) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.r + 8, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(55,138,221,0.07)';
            ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.fillStyle = fillColor;
        ctx.fill();
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = node.isLocal ? 2 : 1.5;
        ctx.stroke();

        // Label
        const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        ctx.fillStyle = isDark ? '#c2c0b6' : '#3d3d3a';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        if (node.isLocal) {
            ctx.font = '500 12px system-ui, sans-serif';
            ctx.fillText(node.label, node.x, node.y);
        } else {
            // Name above node
            ctx.font = '500 11px system-ui, sans-serif';
            const labelY = node.y - node.r - 14;
            ctx.fillText(truncate(node.label, 14), node.x, labelY);
            // Sub-label
            ctx.font = '400 10px system-ui, sans-serif';
            ctx.fillStyle = isDark ? '#888780' : '#73726c';
            ctx.fillText(fmtBytes(node.bytes), node.x, labelY + 13);
        }
    });

    animFrame = requestAnimationFrame(redrawFlow);
}

function truncate(str, max) {
    return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

function fmtBytes(b) {
    if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
    if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
    if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
    return b + ' B';
}

// Bar charts
function drawBarChart(canvasId, items, labelField, valueField, oldChart) {
    if (oldChart) oldChart.destroy();

    let labels;
    if (labelField === 'process_name') {
        labels = items.map(x => `${x.process_name} (${x.pid})`);
    } else {
        labels = items.map(x => x[labelField]);
    }

    const values = items.map(x => x[valueField]);

    return new Chart(document.getElementById(canvasId), {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Bytes',
                data: values,
                backgroundColor: '#378ADD',
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => fmtBytes(ctx.raw),
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Bytes' },
                    ticks: {
                        callback: v => fmtBytes(v),
                    }
                }
            }
        }
    });
}

// Top 3 tables
function renderTop3(divId, items, nameField) {
    const div = document.getElementById(divId);
    let title = '';
    if (nameField === 'process_name') title = 'Top 3 Processes';
    else if (nameField === 'user') title = 'Top 3 Users';
    else if (nameField === 'protocol') title = 'Top 3 Protocols';

    const top3 = [...items].sort((a, b) => b.bytes - a.bytes).slice(0, 3);

    let html = `<h3>${title}</h3><table>
        <thead><tr>
            <th>Name</th>
            ${nameField === 'process_name' ? '<th>PID</th>' : ''}
            <th>Bytes</th>
            <th>Packets</th>
        </tr></thead><tbody>`;

    top3.forEach(item => {
        html += `<tr>
            <td>${item[nameField]}</td>
            ${nameField === 'process_name' ? `<td>${item.pid}</td>` : ''}
            <td>${fmtBytes(item.bytes)}</td>
            <td>${item.packets.toLocaleString()}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    div.innerHTML = html;
}

// Search
function search(type) {
    const query = document.getElementById('searchInput').value.toLowerCase();

    fetch('/api/summary')
        .then(res => res.json())
        .then(data => {
            let items = [];
            if (type === 'process') {
                items = data.processes.filter(p =>
                    p.process_name.toLowerCase().includes(query)
                );
            }
            if (type === 'user') {
                items = data.processes.filter(p =>
                    p.user.toLowerCase().includes(query)
                );
            }
            renderSearchTable(items, type);
        });
}

function renderSearchTable(items, type) {
    const div = document.getElementById('searchResults');

    if (items.length === 0) {
        div.innerHTML = '<p>No results found</p>';
        return;
    }

    let html = `<table>
        <thead><tr>
            <th>User</th><th>Process</th><th>PID</th><th>Bytes</th><th>Packets</th>
        </tr></thead><tbody>`;

    items.forEach(item => {
        html += `<tr>
            <td>${item.user}</td>
            <td>${item.process_name}</td>
            <td>${item.pid}</td>
            <td>${fmtBytes(item.bytes)}</td>
            <td>${item.packets.toLocaleString()}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    div.innerHTML = html;
}

// Status indicator
function setStatus(ok) {
    const dot = document.getElementById('statusDot');
    if (dot) dot.className = 'header-dot ' + (ok ? 'online' : 'offline');
}

// Main load loop
async function load() {
    try {
        const res = await fetch('/api/summary');
        if (!res.ok) throw new Error('API error');
        const data = await res.json();

        setStatus(true);
        document.getElementById('lastUpdated').textContent =
            'Updated ' + new Date().toLocaleTimeString();

        // Charts
        processChart = drawBarChart('processChart', data.processes, 'process_name', 'bytes', processChart);
        userChart    = drawBarChart('userChart',    data.users,     'user',         'bytes', userChart);
        protocolChart= drawBarChart('protocolChart',data.protocols, 'protocol',     'bytes', protocolChart);

        // Top 3
        renderTop3('processTop3',  data.processes, 'process_name');
        renderTop3('userTop3',     data.users,     'user');
        renderTop3('protocolTop3', data.protocols, 'protocol');

        // Flow graph
        buildGraph(data);

    } catch (e) {
        setStatus(false);
    }
}

// Kick off animation loop immediately (shows "waiting" state)
redrawFlow();

load();
setInterval(load, 1000);