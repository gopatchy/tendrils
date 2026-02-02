import { formatBytes, formatPackets, formatMbps, formatPps, formatLinkSpeed } from './format.js';
import { openFlowHash } from './flow.js';
import { portErrors, setErrorPanelCollapsed, errorPanelCollapsed } from './state.js';

export function addClickableValue(container, label, value, plainLines, plainFormat) {
    const lbl = document.createElement('span');
    lbl.className = 'lbl';
    lbl.textContent = label;
    container.appendChild(lbl);
    container.appendChild(document.createTextNode(' '));
    const val = document.createElement('span');
    val.className = 'clickable-value';
    val.textContent = value;
    val.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(value);
    });
    container.appendChild(val);
    plainLines.push(plainFormat ? plainFormat(label, value) : label + ': ' + value);
}

export function buildClickableList(container, items, label, plainFormat, flowInfo) {
    const plainLines = [];
    items.forEach((item, idx) => {
        if (idx > 0) container.appendChild(document.createTextNode('\n'));
        const lbl = document.createElement('span');
        lbl.className = 'lbl';
        lbl.textContent = label;
        container.appendChild(lbl);
        container.appendChild(document.createTextNode(' '));
        const val = document.createElement('span');
        val.className = 'clickable-value';
        val.textContent = item;
        val.addEventListener('click', (e) => {
            e.stopPropagation();
            if (flowInfo && flowInfo.universes && flowInfo.universes[idx] !== undefined) {
                openFlowHash(flowInfo.protocol, flowInfo.universes[idx], flowInfo.nodeName);
            } else {
                navigator.clipboard.writeText(item);
            }
        });
        container.appendChild(val);
        plainLines.push(plainFormat ? plainFormat(label, item) : label + ': ' + item);
    });
    container.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(plainLines.join('\n'));
    });
}

function formatShortMbps(bytesPerSec) {
    const mbps = (bytesPerSec * 8) / 1000000;
    return Math.round(mbps) + 'Mb';
}

function formatShortKpps(pps) {
    const kpps = pps / 1000;
    return kpps.toFixed(1) + 'Kp';
}

function formatUtilization(bytesPerSec, speed) {
    if (!speed) return '?%';
    const util = (bytesPerSec * 8 / speed) * 100;
    return util.toFixed(0) + '%';
}

export function buildLinkStats(container, portLabel, speed, errIn, errOut, rates) {
    const plainLines = [];
    if (portLabel) {
        addClickableValue(container, 'PORT', portLabel, plainLines);
        container.appendChild(document.createTextNode('\n'));
    }
    addClickableValue(container, 'LINK', formatLinkSpeed(speed), plainLines);
    container.appendChild(document.createTextNode('\n'));
    addClickableValue(container, 'ERR', 'RX ' + errIn + ' / TX ' + errOut, plainLines);
    if (rates) {
        const rxUtil = formatUtilization(rates.rxBytes, speed);
        const txUtil = formatUtilization(rates.txBytes, speed);
        container.appendChild(document.createTextNode('\n'));
        addClickableValue(container, 'RX', rxUtil + ' ' + formatShortMbps(rates.rxBytes) + ' ' + formatShortKpps(rates.rxPkts), plainLines);
        container.appendChild(document.createTextNode('\n'));
        addClickableValue(container, 'TX', txUtil + ' ' + formatShortMbps(rates.txBytes) + ' ' + formatShortKpps(rates.txPkts), plainLines);
    }
    container.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(plainLines.join('\n'));
    });
}

export function buildDanteDetail(container, entries, arrow, sourceNodeName, peerNodeNames) {
    const plainLines = [];
    entries.forEach((entry, entryIdx) => {
        const peerNodeName = peerNodeNames ? peerNodeNames[entryIdx] : null;
        entry.split('\n').forEach((line, lineIdx) => {
            if (entryIdx > 0 && lineIdx === 0) {
                container.appendChild(document.createTextNode('\n\n'));
                plainLines.push('');
            } else if (container.childNodes.length > 0) {
                container.appendChild(document.createTextNode('\n'));
            }
            if (line.startsWith(' ')) {
                container.appendChild(document.createTextNode('   ' + line.trim()));
                plainLines.push('   ' + line.trim());
            } else {
                const lbl = document.createElement('span');
                lbl.className = 'lbl';
                lbl.textContent = arrow;
                container.appendChild(lbl);
                container.appendChild(document.createTextNode(' '));
                const val = document.createElement('span');
                val.className = 'clickable-value';
                val.textContent = line;
                val.addEventListener('click', (e) => {
                    e.stopPropagation();
                    if (sourceNodeName && peerNodeName) {
                        const src = arrow === '→' ? sourceNodeName : peerNodeName;
                        const dst = arrow === '→' ? peerNodeName : sourceNodeName;
                        openFlowHash('dante', src, 'to', dst);
                    } else {
                        navigator.clipboard.writeText(line);
                    }
                });
                container.appendChild(val);
                plainLines.push(arrow + ' ' + line);
            }
        });
    });
    container.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(plainLines.join('\n'));
    });
}

export function setConnectionStatus(connected) {
    const el = document.getElementById('connection-status');
    const textEl = el.querySelector('.text');
    if (connected) {
        el.className = 'connected';
        textEl.textContent = 'Connected';
    } else {
        el.className = 'disconnected';
        textEl.textContent = 'Disconnected';
    }
}

export function scrollToNode(typeid) {
    const nodeEl = document.querySelector('.node[data-id="' + typeid + '"]');
    if (nodeEl) {
        nodeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        nodeEl.classList.add('scroll-highlight');
        setTimeout(() => nodeEl.classList.remove('scroll-highlight'), 1000);
    }
}

export async function clearError(id) {
    await fetch('/tendrils/api/errors/clear?id=' + encodeURIComponent(id), { method: 'POST' });
}

export async function clearAllErrors() {
    await fetch('/tendrils/api/errors/clear?all=true', { method: 'POST' });
}

export function updateErrorPanel() {
    const panel = document.getElementById('error-panel');
    const countEl = document.getElementById('error-count');
    const listEl = document.getElementById('error-list');

    if (portErrors.length === 0) {
        panel.classList.remove('has-errors');
        return;
    }

    panel.classList.add('has-errors');
    countEl.textContent = portErrors.length + ' Error' + (portErrors.length !== 1 ? 's' : '');

    listEl.innerHTML = '';
    portErrors.forEach(err => {
        const item = document.createElement('div');
        item.className = 'error-item';

        const nodeEl = document.createElement('div');
        nodeEl.className = 'error-node';
        nodeEl.textContent = err.node_name || err.node_id;
        nodeEl.addEventListener('click', () => scrollToNode(err.node_id));
        item.appendChild(nodeEl);

        if (err.type === 'unreachable') {
            const typeEl = document.createElement('div');
            typeEl.className = 'error-type';
            typeEl.textContent = 'Unreachable';
            item.appendChild(typeEl);
        } else if (err.type === 'high_utilization') {
            const portEl = document.createElement('div');
            portEl.className = 'error-port';
            portEl.textContent = 'Port: ' + err.port;
            item.appendChild(portEl);

            const countsEl = document.createElement('div');
            countsEl.className = 'error-counts';
            countsEl.textContent = 'Utilization: ' + (err.utilization || 0).toFixed(0) + '%';
            item.appendChild(countsEl);

            const typeEl = document.createElement('div');
            typeEl.className = 'error-type';
            typeEl.textContent = 'High link utilization';
            item.appendChild(typeEl);
        } else if (err.type === 'port_flap') {
            const portEl = document.createElement('div');
            portEl.className = 'error-port';
            portEl.textContent = 'Port: ' + err.port;
            item.appendChild(portEl);

            const typeEl = document.createElement('div');
            typeEl.className = 'error-type';
            typeEl.textContent = 'Port flap detected';
            item.appendChild(typeEl);
        } else if (err.type === 'port_down') {
            const portEl = document.createElement('div');
            portEl.className = 'error-port';
            portEl.textContent = 'Port: ' + err.port;
            item.appendChild(portEl);

            const typeEl = document.createElement('div');
            typeEl.className = 'error-type';
            typeEl.textContent = 'Port down';
            item.appendChild(typeEl);
        } else {
            const portEl = document.createElement('div');
            portEl.className = 'error-port';
            portEl.textContent = 'Port: ' + err.port;
            item.appendChild(portEl);

            const countsEl = document.createElement('div');
            countsEl.className = 'error-counts';
            countsEl.textContent = 'rx: ' + (err.in_errors || 0) + ' (+' + (err.in_delta || 0) + ') / tx: ' + (err.out_errors || 0) + ' (+' + (err.out_delta || 0) + ')';
            item.appendChild(countsEl);

            const typeEl = document.createElement('div');
            typeEl.className = 'error-type';
            typeEl.textContent = 'New errors detected';
            item.appendChild(typeEl);
        }

        const dismissBtn = document.createElement('button');
        dismissBtn.textContent = 'Dismiss';
        dismissBtn.addEventListener('click', () => clearError(err.id));
        item.appendChild(dismissBtn);

        listEl.appendChild(item);
    });
}

export function updateBroadcastStats(stats) {
    const panel = document.getElementById('broadcast-stats');
    const ppsEl = document.getElementById('broadcast-pps');
    const bpsEl = document.getElementById('broadcast-bps');
    const bucketsEl = document.getElementById('broadcast-buckets');

    if (!stats) {
        ppsEl.textContent = '0 pps';
        bpsEl.textContent = '0 B/s';
        bucketsEl.innerHTML = '';
        panel.className = '';
        return;
    }

    ppsEl.textContent = formatPackets(stats.packets_per_s);
    bpsEl.textContent = formatBytes(stats.bytes_per_s);

    panel.classList.remove('warning', 'critical');
    if (stats.packets_per_s > 1000) {
        panel.classList.add('critical');
    } else if (stats.packets_per_s > 100) {
        panel.classList.add('warning');
    }

    bucketsEl.innerHTML = '';
    if (stats.buckets && stats.buckets.length > 0) {
        stats.buckets.filter(b => b.packets_per_s >= 0.5).forEach(bucket => {
            const div = document.createElement('div');
            div.className = 'bucket';
            div.innerHTML = '<span class="bucket-name">' + bucket.name + '</span>' +
                '<span class="bucket-rate">' + formatPackets(bucket.packets_per_s) + '</span>';
            bucketsEl.appendChild(div);
        });
    }
}

export function setupErrorPanelListeners() {
    document.getElementById('clear-all-errors').addEventListener('click', clearAllErrors);
    document.getElementById('toggle-errors').addEventListener('click', () => {
        const panel = document.getElementById('error-panel');
        const btn = document.getElementById('toggle-errors');
        const newCollapsed = !errorPanelCollapsed;
        setErrorPanelCollapsed(newCollapsed);
        if (newCollapsed) {
            panel.classList.add('collapsed');
            btn.textContent = 'Show';
        } else {
            panel.classList.remove('collapsed');
            btn.textContent = 'Hide';
        }
    });
}
