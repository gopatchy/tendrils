import { getLabel, getShortLabel, getFirstName, isSwitch, isAP, getSpeedClass } from './nodes.js';
import { addClickableValue, buildLinkStats, buildDanteDetail, buildClickableList, removeNode } from './ui.js';
import { nodeElements, locationElements, usedNodeIds, usedLocationIds } from './state.js';

export function createNodeElement(node, switchConnection, nodeLocation, uplinkInfo, danteInfo, artnetInfo, sacnInfo, hasError, isUnreachable) {
    let div = nodeElements.get(node.id);
    if (!div) {
        div = document.createElement('div');
        div.dataset.id = node.id;
        div.addEventListener('click', () => {
            const nodeData = div._nodeData;
            if (!nodeData) return;
            let copyText = nodeData.names?.length > 0 ? nodeData.names.join('\n') : getLabel(nodeData);
            navigator.clipboard.writeText(copyText).then(() => {
                div.classList.add('copied');
                setTimeout(() => div.classList.remove('copied'), 300);
            });
        });
        nodeElements.set(node.id, div);
    }
    div._nodeData = node;

    div.className = 'node' + (isSwitch(node) ? ' switch' : '') + (isAP(node) ? ' ap' : '');
    if (hasError) div.classList.add('has-error');
    if (isUnreachable) div.classList.add('unreachable');
    if (danteInfo?.isTx) div.classList.add('dante-tx');
    if (danteInfo?.isRx) div.classList.add('dante-rx');
    if (artnetInfo?.isOut) div.classList.add('artnet-out');
    if (artnetInfo?.isIn) div.classList.add('artnet-in');
    if (sacnInfo?.isOut) div.classList.add('sacn-out');
    if (sacnInfo?.isIn) div.classList.add('sacn-in');

    if (!isSwitch(node) && switchConnection) {
        let container = div.querySelector(':scope > .port-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'port-hover';
            container.innerHTML = '<div class="switch-port"></div><div class="link-stats-wrapper"><div class="link-stats"></div></div>';
            div.appendChild(container);
        }
        const portEl = container.querySelector('.switch-port');
        portEl.className = 'switch-port';
        if (switchConnection.external) portEl.classList.add('external');
        const speedClass = getSpeedClass(switchConnection.speed);
        if (speedClass) portEl.classList.add(speedClass);
        const portLabel = switchConnection.showSwitchName
            ? switchConnection.switchName + ':' + switchConnection.port
            : switchConnection.port;
        portEl.textContent = portLabel;

        const statsEl = container.querySelector('.link-stats');
        statsEl.innerHTML = '';
        const errIn = switchConnection.errors?.in || 0;
        const errOut = switchConnection.errors?.out || 0;
        const r = switchConnection.rates;
        buildLinkStats(statsEl, portLabel, switchConnection.speed, errIn, errOut,
            r ? {rxBytes: r.outBytes, rxPkts: r.outPkts, txBytes: r.inBytes, txPkts: r.inPkts} : null,
            switchConnection.uptime, switchConnection.lastError);
    } else {
        const container = div.querySelector(':scope > .port-hover');
        if (container) container.remove();
    }

    let labelEl = div.querySelector(':scope > .node-label');
    if (!labelEl) {
        labelEl = document.createElement('span');
        labelEl.className = 'node-label';
        div.appendChild(labelEl);
    }
    labelEl.innerHTML = '';
    if (node.names && node.names.length > 0) {
        node.names.forEach((name, idx) => {
            if (idx > 0) labelEl.appendChild(document.createTextNode('\n'));
            const nameSpan = document.createElement('span');
            nameSpan.className = 'node-name';
            nameSpan.textContent = name;
            nameSpan.addEventListener('click', (e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(name).then(() => {
                    div.classList.add('copied');
                    setTimeout(() => div.classList.remove('copied'), 300);
                });
            });
            labelEl.appendChild(nameSpan);
        });
    } else {
        labelEl.textContent = getLabel(node);
    }

    const hasNodeInfo = node.interfaces && (
        node.interfaces.some(i => i.ips?.length > 0) ||
        node.interfaces.some(i => i.mac)
    );
    if (hasNodeInfo) {
        let wrapper = div.querySelector(':scope > .node-info-wrapper');
        if (!wrapper) {
            wrapper = document.createElement('div');
            wrapper.className = 'node-info-wrapper';
            wrapper.innerHTML = '<div class="node-info"></div>';
            div.appendChild(wrapper);
        }
        const nodeInfo = wrapper.querySelector('.node-info');
        nodeInfo.innerHTML = '';
        const ips = [];
        const macs = [];
        node.interfaces.forEach(iface => {
            if (iface.ips) iface.ips.forEach(ip => { if (!ips.includes(ip)) ips.push(ip); });
            if (iface.mac && !macs.includes(iface.mac)) macs.push(iface.mac);
        });
        ips.sort();
        macs.sort();
        const plainLines = [];
        ips.forEach((ip, idx) => {
            if (idx > 0) nodeInfo.appendChild(document.createTextNode('\n'));
            addClickableValue(nodeInfo, 'IP', ip, plainLines);
        });
        macs.forEach((mac, idx) => {
            if (ips.length > 0 || idx > 0) nodeInfo.appendChild(document.createTextNode('\n'));
            addClickableValue(nodeInfo, 'MAC', mac, plainLines);
        });
        if (plainLines.length > 0) {
            nodeInfo.onclick = (e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(plainLines.join('\n'));
            };
        }
    } else {
        const wrapper = div.querySelector(':scope > .node-info-wrapper');
        if (wrapper) wrapper.remove();
    }

    if ((isSwitch(node) || isAP(node)) && uplinkInfo === 'ROOT') {
        const container = div.querySelector(':scope > .uplink-hover');
        if (container) container.remove();

        let rootEl = div.querySelector(':scope > .root-label');
        if (!rootEl) {
            rootEl = document.createElement('div');
            rootEl.className = 'root-label';
            rootEl.textContent = 'ROOT';
            div.appendChild(rootEl);
        }
    } else if ((isSwitch(node) || isAP(node)) && uplinkInfo) {
        const rootEl = div.querySelector(':scope > .root-label');
        if (rootEl) rootEl.remove();

        let container = div.querySelector(':scope > .uplink-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'uplink-hover';
            container.innerHTML = '<div class="uplink"></div><div class="link-stats-wrapper"><div class="link-stats"></div></div>';
            div.appendChild(container);
        }
        const uplinkEl = container.querySelector('.uplink');
        uplinkEl.className = 'uplink';
        const speedClass = getSpeedClass(uplinkInfo.speed);
        if (speedClass) uplinkEl.classList.add(speedClass);
        const uplinkLabel = isAP(node)
            ? uplinkInfo.parentName + ':' + uplinkInfo.remotePort
            : uplinkInfo.localPort + ' → ' + uplinkInfo.parentName + ':' + uplinkInfo.remotePort;
        uplinkEl.textContent = uplinkLabel;

        const statsEl = container.querySelector('.link-stats');
        statsEl.innerHTML = '';
        const errIn = uplinkInfo.errors?.in || 0;
        const errOut = uplinkInfo.errors?.out || 0;
        const r = uplinkInfo.rates;
        buildLinkStats(statsEl, uplinkLabel, uplinkInfo.speed, errIn, errOut,
            r ? {rxBytes: r.inBytes, rxPkts: r.inPkts, txBytes: r.outBytes, txPkts: r.outPkts} : null,
            uplinkInfo.uptime, uplinkInfo.lastError);
    } else {
        const rootEl = div.querySelector(':scope > .root-label');
        if (rootEl) rootEl.remove();
        const container = div.querySelector(':scope > .uplink-hover');
        if (container) container.remove();
    }

    if (danteInfo?.isTx) {
        let container = div.querySelector(':scope > .dante-tx-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'dante-hover dante-tx-hover';
            container.innerHTML = '<div class="dante-info tx-info"><span class="lbl">→</span> <span class="dante-pill-text"></span></div><div class="dante-detail-wrapper"><div class="dante-detail"></div></div>';
            div.appendChild(container);
        }
        const textEl = container.querySelector('.dante-pill-text');
        const firstDest = danteInfo.txTo[0].split('\n')[0];
        const txMore = danteInfo.txTo.length > 1 ? ', ...' : '';
        textEl.textContent = firstDest + txMore;

        const detail = container.querySelector('.dante-detail');
        detail.innerHTML = '';
        buildDanteDetail(detail, danteInfo.txTo, '→', danteInfo.nodeName, danteInfo.txToPeerNames);
    } else {
        const container = div.querySelector(':scope > .dante-tx-hover');
        if (container) container.remove();
    }

    if (danteInfo?.isRx) {
        let container = div.querySelector(':scope > .dante-rx-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'dante-hover dante-rx-hover';
            container.innerHTML = '<div class="dante-info rx-info"><span class="lbl">←</span> <span class="dante-pill-text"></span></div><div class="dante-detail-wrapper"><div class="dante-detail"></div></div>';
            div.appendChild(container);
        }
        const textEl = container.querySelector('.dante-pill-text');
        const firstSource = danteInfo.rxFrom[0].split('\n')[0];
        const rxMore = danteInfo.rxFrom.length > 1 ? ', ...' : '';
        textEl.textContent = firstSource + rxMore;

        const detail = container.querySelector('.dante-detail');
        detail.innerHTML = '';
        buildDanteDetail(detail, danteInfo.rxFrom, '←', danteInfo.nodeName, danteInfo.rxFromPeerNames);
    } else {
        const container = div.querySelector(':scope > .dante-rx-hover');
        if (container) container.remove();
    }

    if (artnetInfo?.isOut) {
        let container = div.querySelector(':scope > .artnet-out-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'artnet-hover artnet-out-hover';
            container.innerHTML = '<div class="artnet-info out-info"><span class="lbl">←</span> <span class="artnet-pill-text"></span></div><div class="artnet-detail-wrapper"><div class="artnet-detail"></div></div>';
            div.appendChild(container);
        }
        const textEl = container.querySelector('.artnet-pill-text');
        const firstOut = artnetInfo.outputs[0];
        const outLabel = firstOut.firstTarget || firstOut.display;
        const outMore = artnetInfo.outputs.length > 1 ? ', ...' : '';
        textEl.textContent = outLabel + outMore;

        const detail = container.querySelector('.artnet-detail');
        detail.innerHTML = '';
        buildClickableList(detail, artnetInfo.outputs.map(o => o.display), '←', (l, v) => l + ' ' + v,
            { protocol: 'artnet', nodeName: getFirstName(node), universes: artnetInfo.outputs.map(o => o.universe) });
    } else {
        const container = div.querySelector(':scope > .artnet-out-hover');
        if (container) container.remove();
    }

    if (artnetInfo?.isIn) {
        let container = div.querySelector(':scope > .artnet-in-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'artnet-hover artnet-in-hover';
            container.innerHTML = '<div class="artnet-info in-info"><span class="lbl">→</span> <span class="artnet-pill-text"></span></div><div class="artnet-detail-wrapper"><div class="artnet-detail"></div></div>';
            div.appendChild(container);
        }
        const textEl = container.querySelector('.artnet-pill-text');
        const firstIn = artnetInfo.inputs[0];
        const inLabel = firstIn.firstTarget || firstIn.display;
        const inMore = artnetInfo.inputs.length > 1 ? ', ...' : '';
        textEl.textContent = inLabel + inMore;

        const detail = container.querySelector('.artnet-detail');
        detail.innerHTML = '';
        buildClickableList(detail, artnetInfo.inputs.map(i => i.display), '→', (l, v) => l + ' ' + v,
            { protocol: 'artnet', nodeName: getFirstName(node), universes: artnetInfo.inputs.map(i => i.universe) });
    } else {
        const container = div.querySelector(':scope > .artnet-in-hover');
        if (container) container.remove();
    }

    if (sacnInfo?.isOut) {
        let container = div.querySelector(':scope > .sacn-out-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'sacn-hover sacn-out-hover';
            container.innerHTML = '<div class="sacn-info out-info"><span class="lbl">←</span> <span class="sacn-pill-text"></span></div><div class="sacn-detail-wrapper"><div class="sacn-detail"></div></div>';
            div.appendChild(container);
        }
        const textEl = container.querySelector('.sacn-pill-text');
        const firstOut = sacnInfo.outputs[0];
        const outLabel = firstOut.firstTarget || firstOut.display;
        const outMore = sacnInfo.outputs.length > 1 ? ', ...' : '';
        textEl.textContent = outLabel + outMore;

        const detail = container.querySelector('.sacn-detail');
        detail.innerHTML = '';
        buildClickableList(detail, sacnInfo.outputs.map(o => o.display), '←', (l, v) => l + ' ' + v,
            { protocol: 'sacn', nodeName: getFirstName(node), universes: sacnInfo.outputs.map(o => o.universe) });
    } else {
        const container = div.querySelector(':scope > .sacn-out-hover');
        if (container) container.remove();
    }

    if (sacnInfo?.isIn) {
        let container = div.querySelector(':scope > .sacn-in-hover');
        if (!container) {
            container = document.createElement('div');
            container.className = 'sacn-hover sacn-in-hover';
            container.innerHTML = '<div class="sacn-info in-info"><span class="lbl">→</span> <span class="sacn-pill-text"></span></div><div class="sacn-detail-wrapper"><div class="sacn-detail"></div></div>';
            div.appendChild(container);
        }
        const textEl = container.querySelector('.sacn-pill-text');
        const firstIn = sacnInfo.inputs[0];
        const inLabel = firstIn.firstTarget || firstIn.display;
        const inMore = sacnInfo.inputs.length > 1 ? ', ...' : '';
        textEl.textContent = inLabel + inMore;

        const detail = container.querySelector('.sacn-detail');
        detail.innerHTML = '';
        buildClickableList(detail, sacnInfo.inputs.map(i => i.display), '→', (l, v) => l + ' ' + v,
            { protocol: 'sacn', nodeName: getFirstName(node), universes: sacnInfo.inputs.map(i => i.universe) });
    } else {
        const container = div.querySelector(':scope > .sacn-in-hover');
        if (container) container.remove();
    }

    if (node.unreachable && !node.in_config) {
        let removeBtn = div.querySelector(':scope > .remove-node-btn');
        if (!removeBtn) {
            removeBtn = document.createElement('button');
            removeBtn.className = 'remove-node-btn';
            removeBtn.textContent = 'X';
            removeBtn.title = 'Remove node';
            removeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                removeNode(node.id);
            });
            div.appendChild(removeBtn);
        }
    } else {
        const removeBtn = div.querySelector(':scope > .remove-node-btn');
        if (removeBtn) removeBtn.remove();
    }

    return div;
}

export function renderLocation(loc, assignedNodes, isTopLevel, switchConnections, switchUplinks, danteNodes, artnetNodes, sacnNodes, errorNodeIds, unreachableNodeIds, usedNodeIdsSet, usedLocationIdsSet) {
    const nodes = assignedNodes.get(loc) || [];
    const hasNodes = nodes.length > 0;

    const childElements = loc.children
        .map(child => renderLocation(child, assignedNodes, false, switchConnections, switchUplinks, danteNodes, artnetNodes, sacnNodes, errorNodeIds, unreachableNodeIds, usedNodeIdsSet, usedLocationIdsSet))
        .filter(el => el !== null);

    if (!hasNodes && childElements.length === 0) {
        return null;
    }

    usedLocationIdsSet.add(loc.id);
    let container = locationElements.get(loc.id);
    if (!container) {
        container = document.createElement('div');
        container.dataset.locid = loc.id;
        locationElements.set(loc.id, container);
    }
    let classes = 'location';
    if (loc.anonymous && !loc.isAPLocation) classes += ' anonymous';
    if (loc.isAPLocation) classes += ' ap-location';
    if (isTopLevel) classes += ' top-level';
    container.className = classes;

    let nameEl = container.querySelector(':scope > .location-name');
    if (!nameEl) {
        nameEl = document.createElement('div');
        nameEl.className = 'location-name';
        container.insertBefore(nameEl, container.firstChild);
    }
    nameEl.textContent = loc.name;

    const switchRowId = loc.id + '_sw';
    const nodeRowId = loc.id + '_nd';

    if (hasNodes) {
        const switches = nodes.filter(n => isSwitch(n) || isAP(n));
        const nonSwitches = nodes.filter(n => !isSwitch(n) && !isAP(n));

        if (switches.length > 0) {
            let switchRow = container.querySelector(':scope > .node-row[data-rowid="' + switchRowId + '"]');
            if (!switchRow) {
                switchRow = document.createElement('div');
                switchRow.className = 'node-row';
                switchRow.dataset.rowid = switchRowId;
                const insertPt = container.querySelector(':scope > .node-row, :scope > .children');
                container.insertBefore(switchRow, insertPt);
            }
            const currentIds = new Set(switches.map(n => n.id));
            Array.from(switchRow.children).forEach(ch => {
                if (!currentIds.has(ch.dataset.id)) ch.remove();
            });
            switches.forEach(node => {
                usedNodeIdsSet.add(node.id);
                const uplink = switchUplinks.get(node.id);
                const danteInfo = danteNodes.get(node.id);
                const artnetInfo = artnetNodes.get(node.id);
                const sacnInfo = sacnNodes.get(node.id);
                const hasError = errorNodeIds.has(node.id);
                const isUnreachable = unreachableNodeIds.has(node.id);
                const el = createNodeElement(node, null, loc, uplink, danteInfo, artnetInfo, sacnInfo, hasError, isUnreachable);
                if (el.parentNode !== switchRow) switchRow.appendChild(el);
            });
        } else {
            const switchRow = container.querySelector(':scope > .node-row[data-rowid="' + switchRowId + '"]');
            if (switchRow) switchRow.remove();
        }

        if (nonSwitches.length > 0) {
            let nodeRow = container.querySelector(':scope > .node-row[data-rowid="' + nodeRowId + '"]');
            if (!nodeRow) {
                nodeRow = document.createElement('div');
                nodeRow.className = 'node-row';
                nodeRow.dataset.rowid = nodeRowId;
                const insertPt = container.querySelector(':scope > .children');
                container.insertBefore(nodeRow, insertPt);
            }
            const currentIds = new Set(nonSwitches.map(n => n.id));
            Array.from(nodeRow.children).forEach(ch => {
                if (!currentIds.has(ch.dataset.id)) ch.remove();
            });
            nonSwitches.forEach(node => {
                usedNodeIdsSet.add(node.id);
                const conn = switchConnections.get(node.id);
                const danteInfo = danteNodes.get(node.id);
                const artnetInfo = artnetNodes.get(node.id);
                const sacnInfo = sacnNodes.get(node.id);
                const hasError = errorNodeIds.has(node.id);
                const isUnreachable = unreachableNodeIds.has(node.id);
                const el = createNodeElement(node, conn, loc, null, danteInfo, artnetInfo, sacnInfo, hasError, isUnreachable);
                if (el.parentNode !== nodeRow) nodeRow.appendChild(el);
            });
        } else {
            const nodeRow = container.querySelector(':scope > .node-row[data-rowid="' + nodeRowId + '"]');
            if (nodeRow) nodeRow.remove();
        }
    } else {
        const switchRow = container.querySelector(':scope > .node-row[data-rowid="' + switchRowId + '"]');
        if (switchRow) switchRow.remove();
        const nodeRow = container.querySelector(':scope > .node-row[data-rowid="' + nodeRowId + '"]');
        if (nodeRow) nodeRow.remove();
    }

    if (childElements.length > 0) {
        let childrenContainer = container.querySelector(':scope > .children');
        if (!childrenContainer) {
            childrenContainer = document.createElement('div');
            container.appendChild(childrenContainer);
        }
        childrenContainer.className = 'children ' + loc.direction;
        childElements.forEach(el => {
            if (el.parentNode !== childrenContainer) childrenContainer.appendChild(el);
        });
    } else {
        const childrenContainer = container.querySelector(':scope > .children');
        if (childrenContainer) childrenContainer.remove();
    }

    return container;
}
