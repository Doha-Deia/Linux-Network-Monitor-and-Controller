
const flowCanvas = document.getElementById('flowCanvas');
const ctx = flowCanvas.getContext('2d');

const PROTO_COLORS = {
    TCP:   { stroke: '#378ADD', particle: '#378ADD' },
    UDP:   { stroke: '#BA7517', particle: '#EF9F27' },
    ICMP:  { stroke: '#0F6E56', particle: '#1D9E75' },
    other: { stroke: '#5F5E5A', particle: '#888780' },
};

let flowNodes = [];
let flowEdges = [];

function resizeFlowCanvas() {
    const rect = flowCanvas.parentElement.getBoundingClientRect();
    flowCanvas.width  = rect.width - 44;
    flowCanvas.height = Math.max(300, Math.min(460, (rect.width - 44) * 0.4));
}

window.addEventListener('resize', resizeFlowCanvas);
resizeFlowCanvas();

function buildGraph(data) {
    const W = flowCanvas.width;
    const H = flowCanvas.height;
    const cx = W / 2, cy = H / 2;

    const procs  = data.processes || [];
    const protos = data.protocols || [];

    const topProcs = [...procs].sort((a, b) => b.bytes - a.bytes).slice(0, 8);
    const maxBytes = topProcs.length ? topProcs[0].bytes : 1;

    const protoDist = {};
    const totalBytes = protos.reduce((s, p) => s + p.bytes, 1);
    protos.forEach(p => { protoDist[p.protocol] = p.bytes / totalBytes; });

    // Pick dominant protocol for an edge
    const pickProto = () => {
        let acc = 0, r = Math.random();
        for (const [proto, share] of Object.entries(protoDist)) {
            acc += share;
            if (r < acc) return proto;
        }
        return 'TCP';
    };

    const radius    = Math.min(W, H) * 0.34;
    const angleStep = (2 * Math.PI) / Math.max(topProcs.length, 1);

    const nodes = new Map();

    nodes.set('__local__', {
        id: '__local__', label: 'localhost',
        x: cx, y: cy,
        bytes: procs.reduce((s, p) => s + p.bytes, 0),
        isLocal: true, r: 0,
    });

    topProcs.forEach((proc, i) => {
        const angle = i * angleStep - Math.PI / 2;
        const id = `proc_${proc.pid}`;
        nodes.set(id, {
            id, label: proc.process_name,
            x: cx + Math.cos(angle) * radius,
            y: cy + Math.sin(angle) * radius,
            bytes: proc.bytes, isLocal: false, r: 0,
        });
    });

    const maxB = Math.max(...[...nodes.values()].map(n => n.bytes), 1);
    nodes.forEach(n => {
        n.r = n.isLocal ? 28 : 8 + 20 * Math.pow(n.bytes / maxB, 0.45);
    });

    // Preserve existing particle state by pid
    const oldEdgeMap = new Map(flowEdges.map(e => [e.dstId, e]));

    const edges = [];
    topProcs.forEach(proc => {
        const dstId = `proc_${proc.pid}`;
        const src   = nodes.get('__local__');
        const dst   = nodes.get(dstId);
        if (!src || !dst) return;

        const old       = oldEdgeMap.get(dstId);
        const protocol  = old ? old.protocol : pickProto();
        const target    = Math.max(1, Math.min(8, Math.round(proc.bytes / maxBytes * 6 + 1)));
        const particles = old ? old.particles : [];

        while (particles.length < target) {
            particles.push({
                t: Math.random(),
                speed: 0.003 + Math.random() * 0.004,
                size: 2.5 + Math.random() * 2,
                opacity: 0.6 + Math.random() * 0.4,
            });
        }
        if (particles.length > target) particles.splice(target);

        edges.push({ srcId: '__local__', dstId, src, dst, protocol, bytes: proc.bytes, particles });
    });

    flowNodes = [...nodes.values()];
    flowEdges = edges;
}

function bezierPoint(p0, p1, cp, t) {
    const mt = 1 - t;
    return {
        x: mt * mt * p0.x + 2 * mt * t * cp.x + t * t * p1.x,
        y: mt * mt * p0.y + 2 * mt * t * cp.y + t * t * p1.y,
    };
}

function controlPoint(src, dst) {
    const mx = (src.x + dst.x) / 2;
    const my = (src.y + dst.y) / 2;
    const dx = dst.x - src.x;
    const dy = dst.y - src.y;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    return { x: mx - dy / len * len * 0.22, y: my + dx / len * len * 0.22 };
}

function drawFlow() {
    const W = flowCanvas.width, H = flowCanvas.height;
    ctx.clearRect(0, 0, W, H);

    if (!flowNodes.length) {
        ctx.fillStyle = 'rgba(136,135,128,0.5)';
        ctx.font = '13px system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Waiting for traffic data…', W / 2, H / 2);
        requestAnimationFrame(drawFlow);
        return;
    }

    // Edges
    flowEdges.forEach(({ src, dst, protocol }) => {
        const cp = controlPoint(src, dst);
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.quadraticCurveTo(cp.x, cp.y, dst.x, dst.y);
        ctx.strokeStyle = (PROTO_COLORS[protocol] || PROTO_COLORS.other).stroke;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.22;
        ctx.stroke();
        ctx.globalAlpha = 1;
    });

    // Particles
    flowEdges.forEach(({ src, dst, protocol, particles }) => {
        const cp = controlPoint(src, dst);
        const color = (PROTO_COLORS[protocol] || PROTO_COLORS.other).particle;
        particles.forEach(p => {
            p.t = (p.t + p.speed) % 1;
            const pos = bezierPoint(src, dst, cp, p.t);
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.globalAlpha = p.opacity;
            ctx.fill();
            ctx.globalAlpha = 1;
        });
    });

    // Nodes
    flowNodes.forEach(node => {
        const fillColor   = node.isLocal ? 'rgba(55,138,221,0.13)' : 'rgba(95,94,90,0.10)';
        const strokeColor = node.isLocal ? '#378ADD' : '#888780';

        if (node.isLocal) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.r + 9, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(55,138,221,0.06)';
            ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.fillStyle = fillColor;
        ctx.fill();
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = node.isLocal ? 2 : 1.5;
        ctx.stroke();

        ctx.fillStyle = '#3d3d3a';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        if (node.isLocal) {
            ctx.font = '600 12px system-ui, sans-serif';
            ctx.fillText('localhost', node.x, node.y);
        } else {
            ctx.font = '500 11px system-ui, sans-serif';
            const ly = node.y - node.r - 14;
            ctx.fillText(truncate(node.label, 14), node.x, ly);
            ctx.font = '400 10px system-ui, sans-serif';
            ctx.fillStyle = '#888780';
            ctx.fillText(fmtBytes(node.bytes), node.x, ly + 13);
        }
    });

    requestAnimationFrame(drawFlow);
}

drawFlow();

// Top tables
function renderTopTable(divId, items, nameField) {
    const top5 = [...items].sort((a, b) => b.bytes - a.bytes).slice(0, 5);
    const hasPid = nameField === 'process_name';

    let html = `<table class="top-table">
        <thead><tr>
            <th>Name</th>
            ${hasPid ? '<th>PID</th>' : ''}
            <th>Bytes</th>
            <th>Packets</th>
        </tr></thead><tbody>`;

    top5.forEach(item => {
        html += `<tr>
            <td>${item[nameField]}</td>
            ${hasPid ? `<td style="color:var(--muted)">${item.pid}</td>` : ''}
            <td>${fmtBytes(item.bytes)}</td>
            <td>${item.packets.toLocaleString()}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    document.getElementById(divId).innerHTML = html;
}

// Stat cards 
function updateStats(data) {
    const totalBytes   = data.processes.reduce((s, p) => s + p.bytes, 0);
    const totalPackets = data.processes.reduce((s, p) => s + p.packets, 0);
    const topProto     = [...data.protocols].sort((a, b) => b.bytes - a.bytes)[0];
    const topProtoPct  = topProto
        ? Math.round(topProto.bytes / Math.max(totalBytes, 1) * 100) + '%'
        : '—';

    document.getElementById('statBytes').textContent   = fmtBytes(totalBytes);
    document.getElementById('statPackets').textContent = totalPackets.toLocaleString();
    document.getElementById('statProcs').textContent   = data.processes.length;
    document.getElementById('statUsers').textContent   = data.users.length;
    document.getElementById('statTopProto').textContent    = topProto ? topProto.protocol : '—';
    document.getElementById('statTopProtoPct').textContent = topProto ? `${topProtoPct} of traffic` : '—';
}

// Load loop
async function load() {
    try {
        const res  = await fetch('/api/summary');
        if (!res.ok) throw new Error();
        const data = await res.json();

        setStatus(true);
        updateStats(data);
        buildGraph(data);
        renderTopTable('topProcsTable', data.processes, 'process_name');
        renderTopTable('topUsersTable', data.users,     'user');
    } catch {
        setStatus(false);
    }
}

load();
setInterval(load, 1000);
