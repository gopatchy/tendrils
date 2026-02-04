import { getLabel, getShortLabel, isSwitch, isAP, getInterfaceSpeed, getInterfaceErrors, getInterfaceRates, getInterfaceUptime, getInterfaceLastError, getFirstName } from './nodes.js';
import { buildSwitchUplinks, buildLocationTree, buildNodeIndex, findLocationForNode, findEffectiveSwitch } from './topology.js';
import { formatUniverse } from './format.js';
import { createNodeElement, renderLocation } from './components.js';
import { updateErrorPanel, updateBroadcastStats } from './ui.js';
import { renderTable } from './table.js';
import { showFlowView } from './flow.js';
import {
    nodeElements, locationElements,
    setUsedNodeIds, setUsedLocationIds, setPortErrors,
    setTableData, setFlowViewData, currentView,
    resetAnonCounter
} from './state.js';

export function render(data, config) {
    resetAnonCounter();

    const nodes = data.nodes || [];
    const links = data.links || [];

    setPortErrors(data.errors || []);
    const unreachableNodeIds = new Set(nodes.filter(n => n.unreachable).map(n => n.id));
    const errorNodeIds = new Set((data.errors || []).filter(e => e.type !== 'unreachable').map(e => e.node_id));

    const locationTree = buildLocationTree(config.locations || [], null);
    const nodeIndex = new Map();
    buildNodeIndex(locationTree, nodeIndex);

    const nodesByTypeId = new Map();
    nodes.forEach(node => {
        nodesByTypeId.set(node.id, node);
    });

    const nodeLocations = new Map();
    const assignedNodes = new Map();
    const unassignedNodes = [];

    nodes.forEach(node => {
        const loc = findLocationForNode(node, nodeIndex);
        if (loc) {
            nodeLocations.set(node.id, loc);
            if (!assignedNodes.has(loc)) {
                assignedNodes.set(loc, []);
            }
            assignedNodes.get(loc).push(node);
        } else {
            unassignedNodes.push(node);
        }
    });

    const apClients = new Map();
    links.forEach(link => {
        const nodeA = nodesByTypeId.get(link.node_a_id);
        const nodeB = nodesByTypeId.get(link.node_b_id);
        if (!nodeA || !nodeB) return;

        if (isAP(nodeA) && link.interface_a === 'wifi' && !isSwitch(nodeB) && !isAP(nodeB)) {
            if (!apClients.has(nodeA)) apClients.set(nodeA, []);
            apClients.get(nodeA).push(nodeB);
        } else if (isAP(nodeB) && link.interface_b === 'wifi' && !isSwitch(nodeA) && !isAP(nodeA)) {
            if (!apClients.has(nodeB)) apClients.set(nodeB, []);
            apClients.get(nodeB).push(nodeA);
        }
    });

    apClients.forEach((clients, ap) => {
        const apLoc = nodeLocations.get(ap.id);
        const apSubLoc = {
            id: 'ap_' + ap.id,
            name: '',
            anonymous: true,
            isAPLocation: true,
            direction: 'horizontal',
            nodeRefs: [],
            parent: apLoc || null,
            children: []
        };

        if (apLoc) {
            const apLocNodes = assignedNodes.get(apLoc) || [];
            const idx = apLocNodes.indexOf(ap);
            if (idx !== -1) apLocNodes.splice(idx, 1);
            apLoc.children.push(apSubLoc);
        } else {
            const idx = unassignedNodes.indexOf(ap);
            if (idx !== -1) unassignedNodes.splice(idx, 1);
            locationTree.push(apSubLoc);
        }

        assignedNodes.set(apSubLoc, [ap]);
        nodeLocations.set(ap.id, apSubLoc);

        clients.forEach(client => {
            const clientLoc = nodeLocations.get(client.id);
            if (clientLoc && clientLoc !== apSubLoc) {
                const clientLocNodes = assignedNodes.get(clientLoc) || [];
                const idx = clientLocNodes.indexOf(client);
                if (idx !== -1) clientLocNodes.splice(idx, 1);
            } else {
                const idx = unassignedNodes.indexOf(client);
                if (idx !== -1) unassignedNodes.splice(idx, 1);
            }
            assignedNodes.get(apSubLoc).push(client);
            nodeLocations.set(client.id, apSubLoc);
        });
    });

    const switchConnections = new Map();
    const switchLinks = [];
    const allSwitches = nodes.filter(n => isSwitch(n) || isAP(n));

    links.forEach(link => {
        const nodeA = nodesByTypeId.get(link.node_a_id);
        const nodeB = nodesByTypeId.get(link.node_b_id);
        if (!nodeA || !nodeB) return;

        const aIsSwitch = isSwitch(nodeA) || isAP(nodeA);
        const bIsSwitch = isSwitch(nodeB) || isAP(nodeB);

        if (aIsSwitch && bIsSwitch) {
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
                ratesB: getInterfaceRates(nodeB, link.interface_b),
                uptimeA: getInterfaceUptime(nodeA, link.interface_a),
                uptimeB: getInterfaceUptime(nodeB, link.interface_b),
                lastErrorA: getInterfaceLastError(nodeA, link.interface_a),
                lastErrorB: getInterfaceLastError(nodeB, link.interface_b)
            });
        } else if (aIsSwitch && !bIsSwitch) {
            const nodeLoc = nodeLocations.get(nodeB.id);
            const effectiveSwitch = findEffectiveSwitch(nodeLoc, assignedNodes);
            const isLocalSwitch = effectiveSwitch && effectiveSwitch.id === nodeA.id;
            switchConnections.set(nodeB.id, {
                port: link.interface_a || '?',
                switchName: getLabel(nodeA),
                showSwitchName: !isLocalSwitch,
                external: effectiveSwitch && !isLocalSwitch,
                speed: getInterfaceSpeed(nodeA, link.interface_a),
                errors: getInterfaceErrors(nodeA, link.interface_a),
                rates: getInterfaceRates(nodeA, link.interface_a),
                uptime: getInterfaceUptime(nodeA, link.interface_a),
                lastError: getInterfaceLastError(nodeA, link.interface_a)
            });
        } else if (bIsSwitch && !aIsSwitch) {
            const nodeLoc = nodeLocations.get(nodeA.id);
            const effectiveSwitch = findEffectiveSwitch(nodeLoc, assignedNodes);
            const isLocalSwitch = effectiveSwitch && effectiveSwitch.id === nodeB.id;
            switchConnections.set(nodeA.id, {
                port: link.interface_b || '?',
                switchName: getLabel(nodeB),
                showSwitchName: !isLocalSwitch,
                external: effectiveSwitch && !isLocalSwitch,
                speed: getInterfaceSpeed(nodeB, link.interface_b),
                errors: getInterfaceErrors(nodeB, link.interface_b),
                rates: getInterfaceRates(nodeB, link.interface_b),
                uptime: getInterfaceUptime(nodeB, link.interface_b),
                lastError: getInterfaceLastError(nodeB, link.interface_b)
            });
        }
    });

    const danteNodes = new Map();

    const formatDanteChannel = (ch) => {
        let str = ch.tx_channel + ' → ' + String(ch.rx_channel).padStart(2, '0');
        if (ch.type) str += ' [' + ch.type + ']';
        if (ch.status === 'no-source') str += ' ⚠';
        return str;
    };

    nodes.forEach(node => {
        const nodeId = node.id;
        const danteTx = node.dante_flows?.tx || [];
        const danteRx = node.dante_flows?.rx || [];

        if (danteTx.length === 0 && danteRx.length === 0) return;

        const txEntries = danteTx.map(peer => {
            const peerNode = nodesByTypeId.get(peer.node_id);
            const peerName = peerNode ? getFirstName(peerNode) : '??';
            const channels = (peer.channels || []).map(formatDanteChannel);
            const channelSummary = channels.length > 0 ? '\n  ' + channels.join('\n  ') : '';
            return { text: peerName + channelSummary, peerName };
        });

        const rxEntries = danteRx.map(peer => {
            const peerNode = nodesByTypeId.get(peer.node_id);
            const peerName = peerNode ? getFirstName(peerNode) : '??';
            const channels = (peer.channels || []).map(formatDanteChannel);
            const channelSummary = channels.length > 0 ? '\n  ' + channels.join('\n  ') : '';
            return { text: peerName + channelSummary, peerName };
        });

        txEntries.sort((a, b) => a.text.split('\n')[0].localeCompare(b.text.split('\n')[0]));
        rxEntries.sort((a, b) => a.text.split('\n')[0].localeCompare(b.text.split('\n')[0]));

        danteNodes.set(nodeId, {
            isTx: danteTx.length > 0,
            isRx: danteRx.length > 0,
            txTo: txEntries.map(e => e.text),
            txToPeerNames: txEntries.map(e => e.peerName),
            rxFrom: rxEntries.map(e => e.text),
            rxFromPeerNames: rxEntries.map(e => e.peerName),
            nodeName: getFirstName(node)
        });
    });

    const artnetNodes = new Map();

    const universeInputs = new Map();
    const universeOutputs = new Map();

    nodes.forEach(node => {
        const name = getFirstName(node);
        (node.artnet_inputs || []).forEach(u => {
            if (!universeInputs.has(u)) universeInputs.set(u, []);
            universeInputs.get(u).push(name);
        });
        (node.artnet_outputs || []).forEach(u => {
            if (!universeOutputs.has(u)) universeOutputs.set(u, []);
            universeOutputs.get(u).push(name);
        });
    });

    const collapseNames = (names) => {
        const counts = {};
        names.forEach(n => counts[n] = (counts[n] || 0) + 1);
        return Object.entries(counts).map(([name, count]) => count > 1 ? name + ' x' + count : name);
    };

    nodes.forEach(node => {
        const nodeId = node.id;
        const artnetInputs = node.artnet_inputs || [];
        const artnetOutputs = node.artnet_outputs || [];

        if (artnetInputs.length === 0 && artnetOutputs.length === 0) return;

        const sortedInputs = artnetInputs.slice().sort((a, b) => a - b);
        const sortedOutputs = artnetOutputs.slice().sort((a, b) => a - b);

        const inputs = sortedInputs.map(u => {
            const sources = collapseNames(universeOutputs.get(u) || []);
            const uniStr = formatUniverse(u, 'artnet');
            if (sources.length > 0) {
                return { display: sources[0] + ' [' + uniStr + ']', firstTarget: sources[0], universe: u };
            }
            return { display: uniStr, firstTarget: null, universe: u };
        });
        const outputs = sortedOutputs.map(u => {
            const dests = collapseNames(universeInputs.get(u) || []);
            const uniStr = formatUniverse(u, 'artnet');
            if (dests.length > 0) {
                return { display: dests[0] + ' [' + uniStr + ']', firstTarget: dests[0], universe: u };
            }
            return { display: uniStr, firstTarget: null, universe: u };
        });

        artnetNodes.set(nodeId, {
            isOut: outputs.length > 0,
            isIn: inputs.length > 0,
            outputs: outputs,
            inputs: inputs
        });
    });

    const sacnNodes = new Map();

    const sacnUniverseInputs = new Map();
    const sacnUniverseOutputs = new Map();

    function getSacnInputs(node) {
        const inputs = [];
        (node.multicast_groups || []).forEach(g => {
            if (typeof g === 'string' && g.startsWith('sacn:')) {
                const u = parseInt(g.substring(5), 10);
                if (!isNaN(u)) inputs.push(u);
            }
        });
        (node.sacn_unicast_inputs || []).forEach(u => {
            if (!inputs.includes(u)) inputs.push(u);
        });
        return inputs;
    }

    nodes.forEach(node => {
        const name = getFirstName(node);
        getSacnInputs(node).forEach(u => {
            if (!sacnUniverseInputs.has(u)) sacnUniverseInputs.set(u, []);
            sacnUniverseInputs.get(u).push(name);
        });
        (node.sacn_outputs || []).forEach(u => {
            if (!sacnUniverseOutputs.has(u)) sacnUniverseOutputs.set(u, []);
            sacnUniverseOutputs.get(u).push(name);
        });
    });

    const sacnCollapseNames = (names) => {
        const counts = {};
        names.forEach(n => counts[n] = (counts[n] || 0) + 1);
        return Object.entries(counts).map(([name, count]) => count > 1 ? name + ' x' + count : name);
    };

    nodes.forEach(node => {
        const nodeId = node.id;
        const sacnInputs = getSacnInputs(node);
        const sacnOutputs = node.sacn_outputs || [];

        if (sacnInputs.length === 0 && sacnOutputs.length === 0) return;

        const sortedSacnInputs = sacnInputs.slice().sort((a, b) => a - b);
        const sortedSacnOutputs = sacnOutputs.slice().sort((a, b) => a - b);

        const inputs = sortedSacnInputs.map(u => {
            const sources = sacnCollapseNames(sacnUniverseOutputs.get(u) || []);
            if (sources.length > 0) {
                return { display: sources[0] + ' [' + u + ']', firstTarget: sources[0], universe: u };
            }
            return { display: String(u), firstTarget: null, universe: u };
        });
        const outputs = sortedSacnOutputs.map(u => {
            const dests = sacnCollapseNames(sacnUniverseInputs.get(u) || []);
            if (dests.length > 0) {
                return { display: dests[0] + ' [' + u + ']', firstTarget: dests[0], universe: u };
            }
            return { display: String(u), firstTarget: null, universe: u };
        });

        sacnNodes.set(nodeId, {
            isOut: outputs.length > 0,
            isIn: inputs.length > 0,
            outputs: outputs,
            inputs: inputs
        });
    });

    const switchUplinks = buildSwitchUplinks(allSwitches, switchLinks);

    const container = document.getElementById('container');
    const usedNodeIdsSet = new Set();
    const usedLocationIdsSet = new Set();

    locationTree.forEach(loc => {
        const el = renderLocation(loc, assignedNodes, true, switchConnections, switchUplinks, danteNodes, artnetNodes, sacnNodes, errorNodeIds, unreachableNodeIds, usedNodeIdsSet, usedLocationIdsSet);
        if (el && el.parentNode !== container) container.appendChild(el);
    });

    let unassignedLoc = locationElements.get('__unassigned__');
    if (unassignedNodes.length > 0) {
        if (!unassignedLoc) {
            unassignedLoc = document.createElement('div');
            unassignedLoc.className = 'location top-level';
            const nameEl = document.createElement('div');
            nameEl.className = 'location-name';
            nameEl.textContent = 'Unassigned';
            unassignedLoc.appendChild(nameEl);
            locationElements.set('__unassigned__', unassignedLoc);
        }

        const switches = unassignedNodes.filter(n => isSwitch(n));
        const nonSwitches = unassignedNodes.filter(n => !isSwitch(n));

        let switchRow = unassignedLoc.querySelector(':scope > .node-row.switch-row');
        if (switches.length > 0) {
            if (!switchRow) {
                switchRow = document.createElement('div');
                switchRow.className = 'node-row switch-row';
                unassignedLoc.appendChild(switchRow);
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
                const el = createNodeElement(node, null, null, uplink, danteInfo, artnetInfo, sacnInfo, hasError, isUnreachable);
                if (el.parentNode !== switchRow) switchRow.appendChild(el);
            });
        } else if (switchRow) {
            switchRow.remove();
        }

        let nodeRow = unassignedLoc.querySelector(':scope > .node-row:not(.switch-row)');
        if (nonSwitches.length > 0) {
            if (!nodeRow) {
                nodeRow = document.createElement('div');
                nodeRow.className = 'node-row';
                unassignedLoc.appendChild(nodeRow);
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
                const el = createNodeElement(node, conn, null, null, danteInfo, artnetInfo, sacnInfo, hasError, isUnreachable);
                if (el.parentNode !== nodeRow) nodeRow.appendChild(el);
            });
        } else if (nodeRow) {
            nodeRow.remove();
        }

        if (unassignedLoc.parentNode !== container) container.appendChild(unassignedLoc);
        usedLocationIdsSet.add('__unassigned__');
    } else if (unassignedLoc) {
        unassignedLoc.remove();
    }

    setUsedNodeIds(usedNodeIdsSet);
    setUsedLocationIds(usedLocationIdsSet);

    locationElements.forEach((el, id) => {
        if (!usedLocationIdsSet.has(id) && el.parentNode) {
            el.remove();
        }
    });

    updateErrorPanel();
    updateBroadcastStats(data.broadcast_stats);

    setTableData(data);
    setFlowViewData(data);
    if (currentView === 'table') {
        renderTable();
    }
    const hash = window.location.hash;
    if (hash.startsWith('#flow/')) {
        showFlowView(hash.slice(6));
    }
}
