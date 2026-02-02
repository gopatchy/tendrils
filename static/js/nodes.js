export function getLabel(node) {
    if (node.names && node.names.length > 0) return node.names.join('\n');
    if (node.interfaces && node.interfaces.length > 0) {
        const ips = [];
        node.interfaces.forEach(iface => {
            if (iface.ips) iface.ips.forEach(ip => ips.push(ip));
        });
        if (ips.length > 0) return ips.join('\n');
        const macs = [];
        node.interfaces.forEach(iface => {
            if (iface.mac) macs.push(iface.mac);
        });
        if (macs.length > 0) return macs.join('\n');
    }
    return '??';
}

export function getShortLabel(node) {
    if (node.names && node.names.length > 0) return node.names.join('\n');
    if (node.interfaces && node.interfaces.length > 0) {
        const ips = [];
        node.interfaces.forEach(iface => {
            if (iface.ips) iface.ips.forEach(ip => ips.push(ip));
        });
        if (ips.length > 0) return ips.join('\n');
        const macs = [];
        node.interfaces.forEach(iface => {
            if (iface.mac) macs.push(iface.mac);
        });
        if (macs.length > 0) return macs.join('\n');
    }
    return '??';
}

export function getFirstName(node) {
    if (node.names && node.names.length > 0) return node.names[0];
    if (node.interfaces && node.interfaces.length > 0) {
        for (const iface of node.interfaces) {
            if (iface.ips && iface.ips.length > 0) return iface.ips[0];
        }
        for (const iface of node.interfaces) {
            if (iface.mac) return iface.mac;
        }
    }
    return '??';
}

export function getNodeIdentifiers(node) {
    const ids = [];
    if (node.names) {
        node.names.forEach(n => ids.push(n.toLowerCase()));
    }
    if (node.interfaces) {
        node.interfaces.forEach(iface => {
            if (iface.mac) ids.push(iface.mac.toLowerCase());
        });
    }
    return ids;
}

export function isSwitch(node) {
    return !!(node.poe_budget);
}

export function getSpeedClass(speed) {
    if (!speed || speed === 0) return '';
    if (speed >= 10000000000) return 'speed-10g';
    if (speed >= 1000000000) return 'speed-1g';
    if (speed >= 100000000) return 'speed-100m';
    return 'speed-slow';
}

export function findInterface(node, ifaceName) {
    if (!node || !node.interfaces) return null;
    return node.interfaces.find(i => i.name === ifaceName) || null;
}

export function getInterfaceSpeed(node, ifaceName) {
    const iface = findInterface(node, ifaceName);
    return iface?.stats?.speed || 0;
}

export function getInterfaceErrors(node, ifaceName) {
    const iface = findInterface(node, ifaceName);
    if (!iface?.stats) return null;
    const inErr = iface.stats.in_errors || 0;
    const outErr = iface.stats.out_errors || 0;
    if (inErr === 0 && outErr === 0) return null;
    return { in: inErr, out: outErr };
}

export function getInterfaceRates(node, ifaceName) {
    const iface = findInterface(node, ifaceName);
    if (!iface?.stats) return null;
    return {
        inPkts: iface.stats.in_pkts_rate || 0,
        outPkts: iface.stats.out_pkts_rate || 0,
        inBytes: iface.stats.in_bytes_rate || 0,
        outBytes: iface.stats.out_bytes_rate || 0
    };
}

export function getInterfaceUptime(node, ifaceName) {
    const iface = findInterface(node, ifaceName);
    return iface?.stats?.uptime || 0;
}

export function getInterfaceLastError(node, ifaceName) {
    const iface = findInterface(node, ifaceName);
    return iface?.stats?.last_error || null;
}
