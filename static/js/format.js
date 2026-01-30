export function formatBytes(bytes) {
    if (bytes < 1024) return bytes.toFixed(0) + ' B/s';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB/s';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB/s';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB/s';
}

export function formatPackets(pps) {
    if (pps < 1000) return pps.toFixed(0) + ' pps';
    if (pps < 1000000) return (pps / 1000).toFixed(1) + 'K pps';
    return (pps / 1000000).toFixed(1) + 'M pps';
}

export function formatMbps(bytesPerSec) {
    const mbps = (bytesPerSec * 8) / 1000000;
    return Math.round(mbps).toLocaleString() + ' Mbit/s';
}

export function formatPps(pps) {
    return Math.round(pps).toLocaleString() + ' pps';
}

export function formatLinkSpeed(bps) {
    if (!bps) return '?';
    const mbps = bps / 1000000;
    return mbps.toLocaleString() + ' Mbit/s';
}

export function formatUniverse(u) {
    const net = (u >> 8) & 0x7f;
    const subnet = (u >> 4) & 0x0f;
    const universe = u & 0x0f;
    return net + ':' + subnet + ':' + universe + ' (' + u + ')';
}

export function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
