export const nodeElements = new Map();
export const locationElements = new Map();
export let usedNodeIds = new Set();
export let usedLocationIds = new Set();
export let anonCounter = 0;
export let portErrors = [];
export let errorPanelCollapsed = false;
export let currentConfig = null;
export let currentMode = 'network';
export let currentView = 'map';
export let tableData = null;
export let tableSortKeys = [];
export let flowViewData = null;

export function resetAnonCounter() {
    anonCounter = 0;
}

export function incrementAnonCounter() {
    return anonCounter++;
}

export function setUsedNodeIds(ids) {
    usedNodeIds = ids;
}

export function setUsedLocationIds(ids) {
    usedLocationIds = ids;
}

export function setPortErrors(errors) {
    portErrors = errors;
}

export function setErrorPanelCollapsed(collapsed) {
    errorPanelCollapsed = collapsed;
}

export function setCurrentConfig(config) {
    currentConfig = config;
}

export function setCurrentMode(mode) {
    currentMode = mode;
}

export function setCurrentView(view) {
    currentView = view;
}

export function setTableData(data) {
    tableData = data;
}

export function setTableSortKeys(keys) {
    tableSortKeys = keys;
}

export function setFlowViewData(data) {
    flowViewData = data;
}
