import { setConnectionStatus, setupErrorPanelListeners } from './ui.js';
import { render } from './render.js';
import { renderTable } from './table.js';
import { showFlowView, closeFlowView } from './flow.js';
import {
    setCurrentConfig, setCurrentMode, setCurrentView, setTableSortKeys,
    currentMode, currentView, flowViewData
} from './state.js';

let currentConfig = null;

function connectSSE() {
    const evtSource = new EventSource('/api/status/stream');
    let heartbeatTimeout = null;

    function resetHeartbeat() {
        if (heartbeatTimeout) clearTimeout(heartbeatTimeout);
        heartbeatTimeout = setTimeout(() => {
            setConnectionStatus(false);
            evtSource.close();
            setTimeout(connectSSE, 2000);
        }, 10000);
    }

    evtSource.addEventListener('status', (event) => {
        resetHeartbeat();
        const data = JSON.parse(event.data);
        currentConfig = data.config || {};
        setCurrentConfig(currentConfig);
        render(data, currentConfig);
    });

    evtSource.onopen = () => {
        setConnectionStatus(true);
        resetHeartbeat();
    };

    evtSource.onerror = () => {
        if (heartbeatTimeout) clearTimeout(heartbeatTimeout);
        setConnectionStatus(false);
        evtSource.close();
        setTimeout(connectSSE, 2000);
    };
}

function updateHash() {
    let hash = '';
    if (currentMode !== 'network') hash = currentMode;
    if (currentView === 'table') hash += (hash ? '-' : '') + 'table';
    window.location.hash = hash;
}

function setMode(mode) {
    setCurrentMode(mode);
    document.body.classList.remove('dante-mode', 'artnet-mode', 'sacn-mode');
    document.getElementById('mode-network').classList.remove('active');
    document.getElementById('mode-dante').classList.remove('active');
    document.getElementById('mode-artnet').classList.remove('active');
    document.getElementById('mode-sacn').classList.remove('active');

    if (mode === 'dante') {
        document.body.classList.add('dante-mode');
        document.getElementById('mode-dante').classList.add('active');
    } else if (mode === 'artnet') {
        document.body.classList.add('artnet-mode');
        document.getElementById('mode-artnet').classList.add('active');
    } else if (mode === 'sacn') {
        document.body.classList.add('sacn-mode');
        document.getElementById('mode-sacn').classList.add('active');
    } else {
        document.getElementById('mode-network').classList.add('active');
    }

    updateHash();
    setTableSortKeys([]);
    if (currentView === 'table') {
        renderTable();
    }
}

function setView(view) {
    setCurrentView(view);
    document.getElementById('view-map').classList.toggle('active', view === 'map');
    document.getElementById('view-table').classList.toggle('active', view === 'table');
    document.body.classList.toggle('table-view', view === 'table');
    updateHash();
    if (view === 'table') {
        renderTable();
    }
}

function parseHash() {
    const hash = window.location.hash.slice(1);
    if (hash.startsWith('flow/')) {
        if (flowViewData) showFlowView(hash.slice(5));
        return;
    }
    closeFlowView();
    const hashParts = hash.split('-');
    const hashMode = hashParts[0];
    const hashView = hashParts.includes('table') ? 'table' : 'map';

    if (hashMode === 'dante' || hashMode === 'artnet' || hashMode === 'sacn') {
        setMode(hashMode);
    } else if (currentMode !== 'network') {
        setMode('network');
    }
    if (hashView === 'table' && currentView !== 'table') {
        setView('table');
    } else if (hashView !== 'table' && currentView === 'table') {
        setView('map');
    }
}

document.getElementById('mode-network').addEventListener('click', () => setMode('network'));
document.getElementById('mode-dante').addEventListener('click', () => setMode('dante'));
document.getElementById('mode-artnet').addEventListener('click', () => setMode('artnet'));
document.getElementById('mode-sacn').addEventListener('click', () => setMode('sacn'));
document.getElementById('view-map').addEventListener('click', () => setView('map'));
document.getElementById('view-table').addEventListener('click', () => setView('table'));

setupErrorPanelListeners();

window.addEventListener('hashchange', parseHash);
parseHash();

connectSSE();
