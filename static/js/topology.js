import { getLabel, getNodeIdentifiers, isSwitch } from './nodes.js';
import { incrementAnonCounter } from './state.js';

export function buildSwitchUplinks(allSwitches, switchLinks) {
    const uplinks = new Map();
    if (allSwitches.length === 0 || switchLinks.length === 0) return uplinks;

    const adjacency = new Map();
    allSwitches.forEach(sw => adjacency.set(sw.id, []));

    switchLinks.forEach(link => {
        adjacency.get(link.switchA.id).push({
            neighbor: link.switchB,
            localPort: link.portA,
            remotePort: link.portB,
            localSpeed: link.speedA,
            localErrors: link.errorsA,
            localRates: link.ratesA
        });
        adjacency.get(link.switchB.id).push({
            neighbor: link.switchA,
            localPort: link.portB,
            remotePort: link.portA,
            localSpeed: link.speedB,
            localErrors: link.errorsB,
            localRates: link.ratesB
        });
    });

    for (const edges of adjacency.values()) {
        edges.sort((a, b) => getLabel(a.neighbor).localeCompare(getLabel(b.neighbor)));
    }

    const sortedSwitches = [...allSwitches].sort((a, b) =>
        getLabel(a).localeCompare(getLabel(b)));

    let bestRoot = sortedSwitches[0];
    let bestReachable = 0;
    let bestMaxDepth = Infinity;

    for (const candidate of sortedSwitches) {
        const visited = new Set([candidate.id]);
        const queue = [{ sw: candidate, depth: 0 }];
        let maxDepth = 0;

        while (queue.length > 0) {
            const { sw, depth } = queue.shift();
            maxDepth = Math.max(maxDepth, depth);
            for (const edge of adjacency.get(sw.id) || []) {
                if (!visited.has(edge.neighbor.id)) {
                    visited.add(edge.neighbor.id);
                    queue.push({ sw: edge.neighbor, depth: depth + 1 });
                }
            }
        }

        const reachable = visited.size;
        if (reachable > bestReachable ||
            (reachable === bestReachable && maxDepth < bestMaxDepth)) {
            bestReachable = reachable;
            bestMaxDepth = maxDepth;
            bestRoot = candidate;
        }
    }

    uplinks.set(bestRoot.id, 'ROOT');

    const visited = new Set([bestRoot.id]);
    const queue = [bestRoot];

    while (queue.length > 0) {
        const current = queue.shift();
        for (const edge of adjacency.get(current.id) || []) {
            if (!visited.has(edge.neighbor.id)) {
                visited.add(edge.neighbor.id);
                const reverseEdge = adjacency.get(edge.neighbor.id).find(e => e.neighbor.id === current.id);
                uplinks.set(edge.neighbor.id, {
                    localPort: reverseEdge?.localPort || '?',
                    remotePort: reverseEdge?.remotePort || '?',
                    parentNode: current,
                    parentName: getLabel(current),
                    speed: reverseEdge?.localSpeed || 0,
                    errors: reverseEdge?.localErrors || null,
                    rates: reverseEdge?.localRates || null
                });
                queue.push(edge.neighbor);
            }
        }
    }

    return uplinks;
}

export function buildLocationTree(locations, parent) {
    if (!locations) return [];
    return locations.map((loc, idx) => {
        let locId;
        let anonymous = false;
        if (loc.name) {
            locId = 'loc_' + loc.name.replace(/[^a-zA-Z0-9]/g, '_');
        } else {
            locId = 'loc_anon_' + incrementAnonCounter();
            anonymous = true;
        }
        const locObj = {
            id: locId,
            name: loc.name || '',
            anonymous: anonymous,
            direction: loc.direction || 'horizontal',
            nodeRefs: (loc.nodes || []).flatMap(n => [
                ...(n.names || []).map(name => name.toLowerCase()),
                ...(n.macs || []).map(mac => mac.toLowerCase()),
                ...(n.ips || [])
            ]),
            parent: parent,
            children: []
        };
        locObj.children = buildLocationTree(loc.children, locObj);
        return locObj;
    });
}

export function getSwitchesInLocation(loc, assignedNodes) {
    const switches = [];
    const nodes = assignedNodes.get(loc) || [];
    nodes.forEach(n => {
        if (isSwitch(n)) switches.push(n);
    });
    loc.children.forEach(child => {
        if (child.anonymous) {
            switches.push(...getSwitchesInLocation(child, assignedNodes));
        }
    });
    return switches;
}

export function findEffectiveSwitch(loc, assignedNodes) {
    if (!loc) return null;
    const switches = getSwitchesInLocation(loc, assignedNodes);
    if (switches.length === 1) {
        return switches[0];
    }
    if (loc.parent) {
        return findEffectiveSwitch(loc.parent, assignedNodes);
    }
    return null;
}

export function buildNodeIndex(locations, index) {
    locations.forEach(loc => {
        loc.nodeRefs.forEach(ref => {
            index.set(ref, loc);
        });
        buildNodeIndex(loc.children, index);
    });
}

export function findLocationForNode(node, nodeIndex) {
    const identifiers = getNodeIdentifiers(node);
    for (const ident of identifiers) {
        if (nodeIndex.has(ident)) {
            return nodeIndex.get(ident);
        }
    }
    return null;
}
