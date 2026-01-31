import { getShortLabel, isSwitch, findInterface } from './nodes.js';
import { flowViewData, currentMode, currentView } from './state.js';

function scrollToNode(typeid) {
    const nodeEl = document.querySelector('.node[data-id="' + typeid + '"]');
    if (nodeEl) {
        nodeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        nodeEl.classList.add('scroll-highlight');
        setTimeout(() => nodeEl.classList.remove('scroll-highlight'), 1000);
    }
}

export function buildNetworkGraph(nodes, links) {
    const graph = new Map();
    const nodesByTypeId = new Map();
    nodes.forEach(n => {
        nodesByTypeId.set(n.id, n);
        graph.set(n.id, []);
    });
    links.forEach(link => {
        const nodeA = nodesByTypeId.get(link.node_a_id);
        const nodeB = nodesByTypeId.get(link.node_b_id);
        if (!nodeA || !nodeB) return;
        graph.get(link.node_a_id).push({
            nodeId: link.node_b_id,
            viaInterface: link.interface_a,
            fromInterface: link.interface_b
        });
        graph.get(link.node_b_id).push({
            nodeId: link.node_a_id,
            viaInterface: link.interface_b,
            fromInterface: link.interface_a
        });
    });
    return { graph, nodesByTypeId };
}

export function findPath(graph, sourceId, destId) {
    if (sourceId === destId) return [{ nodeId: sourceId }];
    const visited = new Set([sourceId]);
    const queue = [[{ nodeId: sourceId }]];
    while (queue.length > 0) {
        const path = queue.shift();
        const current = path[path.length - 1];
        const edges = graph.get(current.nodeId) || [];
        for (const edge of edges) {
            if (visited.has(edge.nodeId)) continue;
            const newPath = [...path, edge];
            if (edge.nodeId === destId) return newPath;
            visited.add(edge.nodeId);
            queue.push(newPath);
        }
    }
    return null;
}

export function resolveNodeId(identifier, nodes) {
    const lower = identifier.toLowerCase();
    for (const node of nodes) {
        if (node.id === identifier) return node.id;
        if (node.names) {
            for (const name of node.names) {
                if (name.toLowerCase() === lower) return node.id;
            }
        }
    }
    return null;
}

export function showFlowView(flowSpec) {
    if (!flowViewData) return;
    const { nodes, links } = flowViewData;
    const { graph, nodesByTypeId } = buildNetworkGraph(nodes, links);

    const parts = flowSpec.split('/');
    const protocol = parts[0];
    let title = '', paths = [], error = '';
    let flowProtocol, flowUniverse;

    if (protocol === 'dante') {
        if (parts.includes('to')) {
            const toIdx = parts.indexOf('to');
            const sourceIdent = parts.slice(1, toIdx).join('/');
            const destIdent = parts.slice(toIdx + 1).join('/');
            const sourceId = resolveNodeId(sourceIdent, nodes);
            const destId = resolveNodeId(destIdent, nodes);
            if (!sourceId) { error = 'Source node not found: ' + sourceIdent; }
            else if (!destId) { error = 'Destination node not found: ' + destIdent; }
            else {
                const sourceNode = nodesByTypeId.get(sourceId);
                const destNode = nodesByTypeId.get(destId);
                title = 'Dante: ' + getShortLabel(sourceNode) + ' → ' + getShortLabel(destNode);
                const path = findPath(graph, sourceId, destId);
                if (path) paths.push({ path, sourceId, destId });
                else error = 'No path found between nodes';
            }
        } else {
            const sourceIdent = parts[1];
            const txChannel = parts[2];
            const sourceId = resolveNodeId(sourceIdent, nodes);
            if (!sourceId) { error = 'Source node not found: ' + sourceIdent; }
            else {
                const sourceNode = nodesByTypeId.get(sourceId);
                const danteTx = sourceNode.dante_flows?.tx || [];
                title = 'Dante TX: ' + getShortLabel(sourceNode) + (txChannel ? ' ch ' + txChannel : '');
                const destIds = new Set();
                danteTx.forEach(peer => {
                    if (txChannel) {
                        const hasChannel = (peer.channels || []).some(ch => ch.tx_channel === txChannel);
                        if (hasChannel) destIds.add(peer.node_id);
                    } else {
                        destIds.add(peer.node_id);
                    }
                });
                destIds.forEach(destId => {
                    const path = findPath(graph, sourceId, destId);
                    if (path) paths.push({ path, sourceId, destId });
                });
                if (paths.length === 0 && destIds.size > 0) error = 'No paths found to destinations';
                else if (destIds.size === 0) error = 'No active flows' + (txChannel ? ' for channel ' + txChannel : '');
            }
        }
    } else if (protocol === 'sacn' || protocol === 'artnet') {
        const universe = parseInt(parts[1], 10);
        const sourceIdent = parts[2];
        const protoName = protocol === 'sacn' ? 'sACN' : 'Art-Net';
        flowUniverse = universe;
        flowProtocol = protocol;
        if (isNaN(universe)) { error = 'Invalid universe'; }
        else {
            const sourceIds = [];
            const destIds = [];
            nodes.forEach(node => {
                if (protocol === 'sacn') {
                    if ((node.sacn_outputs || []).includes(universe)) sourceIds.push(node.id);
                    const groups = node.multicast_groups || [];
                    const unicastInputs = node.sacn_unicast_inputs || [];
                    if (groups.some(g => g === 'sacn:' + universe) || unicastInputs.includes(universe)) destIds.push(node.id);
                } else {
                    if ((node.artnet_outputs || []).includes(universe)) sourceIds.push(node.id);
                    if ((node.artnet_inputs || []).includes(universe)) destIds.push(node.id);
                }
            });
            if (sourceIdent) {
                const clickedNodeId = resolveNodeId(sourceIdent, nodes);
                if (!clickedNodeId) { error = 'Node not found: ' + sourceIdent; }
                else {
                    const clickedNode = nodesByTypeId.get(clickedNodeId);
                    const isSource = sourceIds.includes(clickedNodeId);
                    const isDest = destIds.includes(clickedNodeId);
                    if (isSource) {
                        const destNames = destIds.filter(id => id !== clickedNodeId).map(id => getShortLabel(nodesByTypeId.get(id))).join(', ');
                        title = protoName + ' ' + universe + ': ' + getShortLabel(clickedNode) + ' → ' + (destNames || '?');
                        destIds.forEach(destId => {
                            if (destId !== clickedNodeId) {
                                const path = findPath(graph, clickedNodeId, destId);
                                if (path) paths.push({ path, sourceId: clickedNodeId, destId });
                            }
                        });
                    } else if (isDest) {
                        const sourceNames = sourceIds.map(id => getShortLabel(nodesByTypeId.get(id))).join(', ');
                        title = protoName + ' ' + universe + ': ' + (sourceNames || '?') + ' → ' + getShortLabel(clickedNode);
                        sourceIds.forEach(sourceId => {
                            const path = findPath(graph, sourceId, clickedNodeId);
                            if (path) paths.push({ path, sourceId, destId: clickedNodeId });
                        });
                    } else {
                        error = 'Node is not a source or destination for universe ' + universe;
                    }
                }
            } else {
                title = protoName + ' Universe ' + universe;
                sourceIds.forEach(sourceId => {
                    destIds.forEach(destId => {
                        if (sourceId !== destId) {
                            const path = findPath(graph, sourceId, destId);
                            if (path) paths.push({ path, sourceId, destId });
                        }
                    });
                });
            }
            if (!error && paths.length === 0) error = 'No active flows for universe ' + universe;
        }
    } else {
        error = 'Unknown protocol: ' + protocol;
    }

    renderFlowOverlay(title, paths, error, nodesByTypeId, flowProtocol, flowUniverse);
}

export function renderFlowOverlay(title, paths, error, nodesByTypeId, flowProtocol, flowUniverse) {
    let overlay = document.getElementById('flow-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'flow-overlay';
        overlay.className = 'flow-overlay';
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeFlowView();
        });
        document.body.appendChild(overlay);
    }
    overlay.innerHTML = '';
    overlay.style.display = 'flex';

    const titleEl = document.createElement('div');
    titleEl.className = 'flow-title';
    titleEl.textContent = title;
    titleEl.addEventListener('click', (e) => e.stopPropagation());
    overlay.appendChild(titleEl);

    if (error) {
        const errEl = document.createElement('div');
        errEl.className = 'flow-error';
        errEl.textContent = error;
        errEl.addEventListener('click', (e) => e.stopPropagation());
        overlay.appendChild(errEl);
        return;
    }

    if (paths.length === 0) {
        const errEl = document.createElement('div');
        errEl.className = 'flow-error';
        errEl.textContent = 'No paths to display';
        errEl.addEventListener('click', (e) => e.stopPropagation());
        overlay.appendChild(errEl);
        return;
    }

    if (paths.length === 1) {
        const pathEl = renderFlowPath(paths[0], nodesByTypeId, flowUniverse, flowProtocol);
        pathEl.addEventListener('click', (e) => e.stopPropagation());
        overlay.appendChild(pathEl);
    } else {
        const summary = document.createElement('div');
        summary.className = 'flow-receivers-summary';
        summary.textContent = paths.length + ' flow paths (click to expand)';
        const listEl = document.createElement('div');
        listEl.className = 'flow-receiver-list';
        summary.addEventListener('click', (e) => {
            e.stopPropagation();
            listEl.classList.toggle('expanded');
            summary.textContent = listEl.classList.contains('expanded')
                ? paths.length + ' flow paths (click to collapse)'
                : paths.length + ' flow paths (click to expand)';
        });
        paths.forEach(p => {
            const pathEl = renderFlowPath(p, nodesByTypeId, flowUniverse, flowProtocol);
            pathEl.addEventListener('click', (e) => e.stopPropagation());
            listEl.appendChild(pathEl);
        });
        overlay.appendChild(summary);
        overlay.appendChild(listEl);
        if (paths.length <= 5) {
            listEl.classList.add('expanded');
            summary.textContent = paths.length + ' flow paths (click to collapse)';
        }
    }
}

export function renderFlowPath(pathInfo, nodesByTypeId, flowUniverse, flowProtocol) {
    const { path, sourceId, destId } = pathInfo;
    const container = document.createElement('div');
    container.className = 'flow-path';

    path.forEach((step, idx) => {
        const node = nodesByTypeId.get(step.nodeId);
        if (!node) return;

        if (idx > 0) {
            const linkEl = document.createElement('div');
            linkEl.className = 'flow-link';

            const prevNode = nodesByTypeId.get(path[idx - 1].nodeId);

            const portLabels = document.createElement('div');
            portLabels.className = 'port-labels';
            const leftPort = document.createElement('span');
            leftPort.textContent = path[idx].viaInterface || '?';
            const rightPort = document.createElement('span');
            rightPort.textContent = path[idx].fromInterface || '?';
            portLabels.appendChild(leftPort);
            portLabels.appendChild(rightPort);
            linkEl.appendChild(portLabels);

            let iface = findInterface(prevNode, path[idx].viaInterface);
            let flipped = false;
            if (!iface?.stats) {
                iface = findInterface(node, path[idx].fromInterface);
                flipped = true;
            }

            const line = document.createElement('div');
            line.className = 'line';
            if (!path[idx].viaInterface && !path[idx].fromInterface) line.classList.add('unknown');
            if (iface?.stats && ((iface.stats.in_errors || 0) > 0 || (iface.stats.out_errors || 0) > 0)) {
                line.classList.add('has-errors');
            }
            linkEl.appendChild(line);

            const stats = document.createElement('div');
            stats.className = 'stats';
            const statLines = [];
            if (iface?.stats) {
                const speed = iface.stats.speed;
                const speedStr = speed >= 1e9 ? (speed/1e9)+'G' : speed >= 1e6 ? (speed/1e6)+'M' : '?';
                statLines.push(speedStr);
                const inBytes = iface.stats.in_bytes_rate || 0;
                const outBytes = iface.stats.out_bytes_rate || 0;
                if (speed > 0 && (inBytes > 0 || outBytes > 0)) {
                    const inPct = ((inBytes * 8) / speed * 100).toFixed(0);
                    const outPct = ((outBytes * 8) / speed * 100).toFixed(0);
                    if (flipped) {
                        statLines.push('↓' + inPct + '% ↑' + outPct + '%');
                    } else {
                        statLines.push('↓' + outPct + '% ↑' + inPct + '%');
                    }
                }
            }
            stats.textContent = statLines.join('\n');
            linkEl.appendChild(stats);

            container.appendChild(linkEl);
        }

        const nodeEl = document.createElement('div');
        nodeEl.className = 'flow-node';
        if (isSwitch(node)) nodeEl.classList.add('switch');
        if (step.nodeId === sourceId && sourceId !== destId) nodeEl.classList.add('source');
        else if (step.nodeId === destId) nodeEl.classList.add('dest');
        nodeEl.textContent = getShortLabel(node);
        nodeEl.addEventListener('click', (e) => {
            e.stopPropagation();
            closeFlowView();
            scrollToNode(step.nodeId);
        });
        container.appendChild(nodeEl);

        if (node.artmap_mappings && node.artmap_mappings.length > 0 && flowUniverse !== undefined) {
            const relevantMappings = getRelevantMappings(node.artmap_mappings, flowProtocol, flowUniverse);
            if (relevantMappings.length > 0) {
                const mappingsEl = document.createElement('div');
                mappingsEl.className = 'flow-artmap-mappings';
                relevantMappings.forEach(m => {
                    const mappingEl = document.createElement('div');
                    mappingEl.className = 'artmap-mapping';
                    mappingEl.textContent = m.from + ' → ' + m.to;
                    mappingEl.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const toProto = m.to.split(':')[0];
                        const toUniverse = parseInt(m.to.split(':')[1], 10);
                        if (!isNaN(toUniverse)) {
                            openFlowHash(toProto, toUniverse);
                        }
                    });
                    mappingsEl.appendChild(mappingEl);
                });
                container.appendChild(mappingsEl);
            }
        }
    });

    return container;
}

function getRelevantMappings(mappings, protocol, universe) {
    const prefix = protocol + ':' + universe;
    return mappings.filter(m => {
        const fromBase = m.from.split(':').slice(0, 2).join(':');
        const toBase = m.to.split(':').slice(0, 2).join(':');
        return fromBase === prefix || toBase === prefix;
    });
}

export function closeFlowView() {
    const overlay = document.getElementById('flow-overlay');
    if (overlay) overlay.style.display = 'none';
    const hash = window.location.hash;
    if (hash.startsWith('#flow/')) {
        let newHash = '';
        if (currentMode !== 'network') newHash = currentMode;
        if (currentView === 'table') newHash += (newHash ? '-' : '') + 'table';
        history.pushState(null, '', window.location.pathname + window.location.search + (newHash ? '#' + newHash : ''));
    }
}

export function openFlowHash(protocol, ...args) {
    window.location.hash = 'flow/' + protocol + '/' + args.join('/');
}
