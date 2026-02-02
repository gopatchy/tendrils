import { getLabel, getFirstName, isSwitch, getInterfaceSpeed, getInterfaceErrors, getInterfaceRates } from './nodes.js';
import { buildSwitchUplinks } from './topology.js';
import { escapeHtml, formatUniverse } from './format.js';
import { tableData, tableSortKeys, setTableSortKeys } from './state.js';

export function sortTable(column) {
    const existingIdx = tableSortKeys.findIndex(k => k.column === column);
    const newKeys = [...tableSortKeys];
    if (existingIdx === 0) {
        newKeys[0] = { ...newKeys[0], asc: !newKeys[0].asc };
    } else {
        if (existingIdx > 0) {
            newKeys.splice(existingIdx, 1);
        }
        newKeys.unshift({ column, asc: true });
    }
    setTableSortKeys(newKeys);
}

export function sortRows(rows, sortKeys) {
    if (!sortKeys || sortKeys.length === 0) return rows;
    const indexed = rows.map((r, i) => ({ r, i }));
    indexed.sort((a, b) => {
        for (const { column, asc } of sortKeys) {
            let va = a.r[column];
            let vb = b.r[column];
            if (va == null) va = '';
            if (vb == null) vb = '';
            let cmp;
            if (typeof va === 'number' && typeof vb === 'number') {
                cmp = va - vb;
            } else {
                va = String(va).toLowerCase();
                vb = String(vb).toLowerCase();
                cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
            }
            if (cmp !== 0) return asc ? cmp : -cmp;
        }
        return a.i - b.i;
    });
    return indexed.map(x => x.r);
}

export function renderTable() {
    if (!tableData) return;
    const container = document.getElementById('table-container');
    const mode = document.body.classList.contains('dante-mode') ? 'dante' :
                 document.body.classList.contains('artnet-mode') ? 'artnet' :
                 document.body.classList.contains('sacn-mode') ? 'sacn' : 'network';

    let tableHtml = '';
    if (mode === 'network') {
        tableHtml = renderNetworkTable();
    } else if (mode === 'dante') {
        tableHtml = renderDanteTable();
    } else if (mode === 'artnet') {
        tableHtml = renderArtnetTable();
    } else if (mode === 'sacn') {
        tableHtml = renderSacnTable();
    }

    let scrollDiv = container.querySelector('.table-scroll');
    if (!scrollDiv) {
        scrollDiv = document.createElement('div');
        scrollDiv.className = 'table-scroll';
        container.appendChild(scrollDiv);
    }
    const scrollTop = scrollDiv.scrollTop;
    scrollDiv.innerHTML = tableHtml;
    scrollDiv.scrollTop = scrollTop;

    scrollDiv.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            sortTable(th.dataset.sort);
            renderTable();
        });
        const primarySort = tableSortKeys[0];
        if (primarySort && primarySort.column === th.dataset.sort) {
            th.classList.add(primarySort.asc ? 'sorted-asc' : 'sorted-desc');
        }
    });
}

export function renderNetworkTable() {
    const nodes = tableData.nodes || [];
    const links = tableData.links || [];

    const nodesByTypeId = new Map();
    nodes.forEach(node => nodesByTypeId.set(node.id, node));

    const upstreamConnections = new Map();
    const allSwitches = nodes.filter(n => isSwitch(n));
    const switchLinks = [];

    links.forEach(link => {
        const nodeA = nodesByTypeId.get(link.node_a_id);
        const nodeB = nodesByTypeId.get(link.node_b_id);
        if (!nodeA || !nodeB) return;

        const aIsSwitch = isSwitch(nodeA);
        const bIsSwitch = isSwitch(nodeB);

        if (aIsSwitch && !bIsSwitch) {
            upstreamConnections.set(nodeB.id, {
                switchName: getLabel(nodeA),
                port: link.interface_a || '?',
                speed: getInterfaceSpeed(nodeA, link.interface_a),
                errors: getInterfaceErrors(nodeA, link.interface_a),
                rates: getInterfaceRates(nodeA, link.interface_a),
                isLocalPort: false
            });
        } else if (bIsSwitch && !aIsSwitch) {
            upstreamConnections.set(nodeA.id, {
                switchName: getLabel(nodeB),
                port: link.interface_b || '?',
                speed: getInterfaceSpeed(nodeB, link.interface_b),
                errors: getInterfaceErrors(nodeB, link.interface_b),
                rates: getInterfaceRates(nodeB, link.interface_b),
                isLocalPort: false
            });
        } else if (aIsSwitch && bIsSwitch) {
            switchLinks.push({
                switchA: nodeA,
                switchB: nodeB,
                portA: link.interface_a || '?',
                portB: link.interface_b || '?',
                speedA: getInterfaceSpeed(nodeA, link.interface_a),
                speedB: getInterfaceSpeed(nodeB, link.interface_b),
                errorsA: getInterfaceErrors(nodeA, link.interface_a),
                errorsB: getInterfaceErrors(nodeB, link.interface_b),
                ratesA: getInterfaceRates(nodeA, link.interface_a),
                ratesB: getInterfaceRates(nodeB, link.interface_b)
            });
        }
    });

    const switchUplinks = buildSwitchUplinks(allSwitches, switchLinks);
    for (const [switchId, uplink] of switchUplinks) {
        if (uplink === 'ROOT') {
            upstreamConnections.set(switchId, 'ROOT');
        } else {
            upstreamConnections.set(switchId, {
                switchName: uplink.parentName,
                port: uplink.localPort,
                speed: uplink.speed,
                errors: uplink.errors,
                rates: uplink.rates,
                isLocalPort: true
            });
        }
    }

    const formatMbpsLocal = (bytesPerSec) => {
        const mbps = (bytesPerSec * 8) / 1000000;
        return Math.round(mbps);
    };

    const formatKppsLocal = (pps) => {
        return (pps / 1000).toFixed(1);
    };

    const formatUtilLocal = (bytesPerSec, speed) => {
        if (!speed) return '';
        const util = (bytesPerSec * 8 / speed) * 100;
        return util.toFixed(0);
    };

    let rows = nodes.map(node => {
        const name = getLabel(node);
        const ips = [];
        (node.interfaces || []).forEach(iface => {
            if (iface.ips) iface.ips.forEach(ip => ips.push(ip));
        });

        const conn = upstreamConnections.get(node.id);
        const isRoot = conn === 'ROOT';
        const upstream = isRoot ? 'ROOT' : (conn ? conn.switchName + ':' + conn.port : '');
        const speed = isRoot ? null : (conn?.speed || 0);
        const errors = isRoot ? null : (conn?.errors || { in: 0, out: 0 });
        const rates = isRoot ? null : (conn?.rates || { inBytes: 0, outBytes: 0 });
        const useLocalPerspective = isRoot || conn?.isLocalPort;

        const isUnreachable = node.unreachable;
        const speedStr = speed == null ? '' : (speed >= 1e9 ? (speed/1e9)+'G' : speed >= 1e6 ? (speed/1e6)+'M' : speed > 0 ? speed : '0');

        const inRateVal = rates == null ? null : (useLocalPerspective ? rates.inBytes : rates.outBytes);
        const outRateVal = rates == null ? null : (useLocalPerspective ? rates.outBytes : rates.inBytes);

        return {
            name,
            ip: ips[0] || '',
            upstream,
            speed,
            speedStr,
            inErrors: errors == null ? null : (useLocalPerspective ? errors.in : errors.out),
            outErrors: errors == null ? null : (useLocalPerspective ? errors.out : errors.in),
            inRate: inRateVal,
            outRate: outRateVal,
            inUtil: inRateVal == null || !speed ? null : (inRateVal * 8 / speed) * 100,
            outUtil: outRateVal == null || !speed ? null : (outRateVal * 8 / speed) * 100,
            inPkts: rates == null ? null : (useLocalPerspective ? rates.inPkts : rates.outPkts),
            outPkts: rates == null ? null : (useLocalPerspective ? rates.outPkts : rates.inPkts),
            status: isUnreachable ? 'unreachable' : (errors && (errors.in + errors.out) > 0 ? 'errors' : 'ok')
        };
    });

    rows = sortRows(rows, tableSortKeys);

    let html = '<table class="data-table"><thead>';
    html += '<tr class="header-group">';
    html += '<th colspan="4"></th>';
    html += '<th colspan="4" class="group-in">In</th>';
    html += '<th colspan="4" class="group-out">Out</th>';
    html += '<th></th>';
    html += '</tr><tr>';
    html += '<th data-sort="name">Name</th>';
    html += '<th data-sort="ip">IP</th>';
    html += '<th data-sort="upstream">Upstream</th>';
    html += '<th data-sort="speed">Speed</th>';
    html += '<th data-sort="inErrors" class="group-in">Err</th>';
    html += '<th data-sort="inUtil" class="group-in">%</th>';
    html += '<th data-sort="inRate" class="group-in">Mb</th>';
    html += '<th data-sort="inPkts" class="group-in">Kp</th>';
    html += '<th data-sort="outErrors" class="group-out">Err</th>';
    html += '<th data-sort="outUtil" class="group-out">%</th>';
    html += '<th data-sort="outRate" class="group-out">Mb</th>';
    html += '<th data-sort="outPkts" class="group-out">Kp</th>';
    html += '<th data-sort="status">Status</th>';
    html += '</tr></thead><tbody>';

    rows.forEach(r => {
        const statusClass = r.status === 'unreachable' ? 'status-error' : r.status === 'errors' ? 'status-warn' : 'status-ok';
        html += '<tr>';
        html += '<td>' + escapeHtml(r.name) + '</td>';
        html += '<td>' + escapeHtml(r.ip) + '</td>';
        html += '<td>' + escapeHtml(r.upstream) + '</td>';
        html += '<td class="numeric">' + r.speedStr + '</td>';
        html += '<td class="numeric group-in">' + (r.inErrors == null ? '' : r.inErrors) + '</td>';
        html += '<td class="numeric group-in">' + (r.inRate == null ? '' : formatUtilLocal(r.inRate, r.speed)) + '</td>';
        html += '<td class="numeric group-in">' + (r.inRate == null ? '' : formatMbpsLocal(r.inRate)) + '</td>';
        html += '<td class="numeric group-in">' + (r.inPkts == null ? '' : formatKppsLocal(r.inPkts)) + '</td>';
        html += '<td class="numeric group-out">' + (r.outErrors == null ? '' : r.outErrors) + '</td>';
        html += '<td class="numeric group-out">' + (r.outRate == null ? '' : formatUtilLocal(r.outRate, r.speed)) + '</td>';
        html += '<td class="numeric group-out">' + (r.outRate == null ? '' : formatMbpsLocal(r.outRate)) + '</td>';
        html += '<td class="numeric group-out">' + (r.outPkts == null ? '' : formatKppsLocal(r.outPkts)) + '</td>';
        html += '<td class="' + statusClass + '">' + r.status + '</td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
}

export function renderDanteTable() {
    const nodes = tableData.nodes || [];
    const nodesByTypeId = new Map();
    nodes.forEach(node => nodesByTypeId.set(node.id, node));
    let rows = [];
    nodes.forEach(node => {
        const name = getFirstName(node);
        const nameTitle = getLabel(node);
        const tx = node.dante_flows?.tx || [];
        tx.forEach(peer => {
            const peerNode = nodesByTypeId.get(peer.node_id);
            const peerName = peerNode ? getFirstName(peerNode) : '??';
            const peerTitle = peerNode ? getLabel(peerNode) : '??';
            (peer.channels || []).forEach(ch => {
                rows.push({
                    source: name,
                    sourceTitle: nameTitle,
                    dest: peerName,
                    destTitle: peerTitle,
                    txChannel: ch.tx_channel,
                    rxChannel: ch.rx_channel,
                    type: ch.type || '',
                    status: ch.status || 'active'
                });
            });
            if (!peer.channels || peer.channels.length === 0) {
                rows.push({ source: name, sourceTitle: nameTitle, dest: peerName, destTitle: peerTitle, txChannel: '', rxChannel: 0, type: '', status: 'active' });
            }
        });
    });

    rows = sortRows(rows, tableSortKeys);

    let html = '<table class="data-table"><thead><tr>';
    html += '<th data-sort="source">Source</th>';
    html += '<th data-sort="txChannel">TX Channel</th>';
    html += '<th data-sort="dest">Destination</th>';
    html += '<th data-sort="rxChannel">RX Channel</th>';
    html += '<th data-sort="type">Type</th>';
    html += '<th data-sort="status">Status</th>';
    html += '</tr></thead><tbody>';

    rows.forEach(r => {
        const statusClass = r.status === 'no-source' ? 'status-warn' : 'status-ok';
        html += '<tr>';
        html += '<td' + (r.sourceTitle !== r.source ? ' data-tooltip="' + escapeHtml(r.sourceTitle) + '"' : '') + '>' + escapeHtml(r.source) + '</td>';
        html += '<td>' + escapeHtml(r.txChannel) + '</td>';
        html += '<td' + (r.destTitle !== r.dest ? ' data-tooltip="' + escapeHtml(r.destTitle) + '"' : '') + '>' + escapeHtml(r.dest) + '</td>';
        html += '<td class="numeric">' + (r.rxChannel || '') + '</td>';
        html += '<td>' + escapeHtml(r.type) + '</td>';
        html += '<td class="' + statusClass + '">' + escapeHtml(r.status) + '</td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
}

export function renderArtnetTable() {
    const nodes = tableData.nodes || [];
    const txByUniverse = new Map();
    const rxByUniverse = new Map();

    nodes.forEach(node => {
        const name = getFirstName(node);
        const title = getLabel(node);
        (node.artnet_inputs || []).forEach(u => {
            if (!txByUniverse.has(u)) txByUniverse.set(u, []);
            txByUniverse.get(u).push({ name, title });
        });
        (node.artnet_outputs || []).forEach(u => {
            if (!rxByUniverse.has(u)) rxByUniverse.set(u, []);
            rxByUniverse.get(u).push({ name, title });
        });
    });

    const allUniverses = new Set([...txByUniverse.keys(), ...rxByUniverse.keys()]);
    let rows = [];
    allUniverses.forEach(u => {
        const txNodes = txByUniverse.get(u) || [];
        const rxNodes = rxByUniverse.get(u) || [];
        const maxLen = Math.max(txNodes.length, rxNodes.length, 1);
        for (let i = 0; i < maxLen; i++) {
            rows.push({
                universe: u,
                universeStr: formatUniverse(u),
                tx: txNodes[i]?.name || '',
                txTitle: txNodes[i]?.title || '',
                rx: rxNodes[i]?.name || '',
                rxTitle: rxNodes[i]?.title || ''
            });
        }
    });

    rows = sortRows(rows, tableSortKeys);

    let html = '<table class="data-table"><thead><tr>';
    html += '<th data-sort="tx">TX</th>';
    html += '<th data-sort="universe">Universe</th>';
    html += '<th data-sort="rx">RX</th>';
    html += '</tr></thead><tbody>';

    rows.forEach(r => {
        html += '<tr>';
        html += '<td' + (r.txTitle && r.txTitle !== r.tx ? ' data-tooltip="' + escapeHtml(r.txTitle) + '"' : '') + '>' + escapeHtml(r.tx) + '</td>';
        html += '<td>' + r.universeStr + '</td>';
        html += '<td' + (r.rxTitle && r.rxTitle !== r.rx ? ' data-tooltip="' + escapeHtml(r.rxTitle) + '"' : '') + '>' + escapeHtml(r.rx) + '</td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
}

export function renderSacnTable() {
    const nodes = tableData.nodes || [];
    const txByUniverse = new Map();
    const rxByUniverse = new Map();

    nodes.forEach(node => {
        const name = getFirstName(node);
        const title = getLabel(node);
        (node.sacn_outputs || []).forEach(u => {
            if (!txByUniverse.has(u)) txByUniverse.set(u, []);
            txByUniverse.get(u).push({ name, title });
        });
        (node.multicast_groups || []).forEach(g => {
            if (typeof g === 'string' && g.startsWith('sacn:')) {
                const u = parseInt(g.substring(5), 10);
                if (!isNaN(u)) {
                    if (!rxByUniverse.has(u)) rxByUniverse.set(u, []);
                    rxByUniverse.get(u).push({ name, title });
                }
            }
        });
        (node.sacn_unicast_inputs || []).forEach(u => {
            if (!rxByUniverse.has(u)) rxByUniverse.set(u, []);
            const existing = rxByUniverse.get(u);
            if (!existing.some(e => e.name === name)) {
                existing.push({ name, title });
            }
        });
    });

    const allUniverses = new Set([...txByUniverse.keys(), ...rxByUniverse.keys()]);
    let rows = [];
    allUniverses.forEach(u => {
        const txNodes = txByUniverse.get(u) || [];
        const rxNodes = rxByUniverse.get(u) || [];
        const maxLen = Math.max(txNodes.length, rxNodes.length, 1);
        for (let i = 0; i < maxLen; i++) {
            rows.push({
                universe: u,
                tx: txNodes[i]?.name || '',
                txTitle: txNodes[i]?.title || '',
                rx: rxNodes[i]?.name || '',
                rxTitle: rxNodes[i]?.title || ''
            });
        }
    });

    rows = sortRows(rows, tableSortKeys);

    let html = '<table class="data-table"><thead><tr>';
    html += '<th data-sort="tx">TX</th>';
    html += '<th data-sort="universe">Universe</th>';
    html += '<th data-sort="rx">RX</th>';
    html += '</tr></thead><tbody>';

    rows.forEach(r => {
        html += '<tr>';
        html += '<td' + (r.txTitle && r.txTitle !== r.tx ? ' data-tooltip="' + escapeHtml(r.txTitle) + '"' : '') + '>' + escapeHtml(r.tx) + '</td>';
        html += '<td class="numeric">' + r.universe + '</td>';
        html += '<td' + (r.rxTitle && r.rxTitle !== r.rx ? ' data-tooltip="' + escapeHtml(r.rxTitle) + '"' : '') + '>' + escapeHtml(r.rx) + '</td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
}
