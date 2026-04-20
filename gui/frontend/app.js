let currentBuildId = "";
let isGenerating = false;
let isRunning = false;
let buildsCache = [];

const $ = (id) => document.getElementById(id);

const terminal = $("terminal");
const buildStatus = $("build-status");
const buildSelect = $("build-select");
const targetFolder = $("target-folder");
const extInput = $("ext-input");
const btnGenerate = $("btn-generate");
const btnEncrypt = $("btn-encrypt");
const btnDecrypt = $("btn-decrypt");
const btnBrowse = $("btn-browse");
const btnClearTarget = $("btn-clear-target");
const btnClearLog = $("btn-clear-log");
const btnRefresh = $("btn-refresh");
const projectBanner = $("project-banner");
const historyBody = $("history-body");
const historyTableWrap = $("history-table-wrap");
const noBuilds = $("no-builds");
const scopeCard = $("scope-card");
const scopeBadge = $("scope-badge");
const scopeDescription = $("scope-description");
const scopeFootnote = $("scope-footnote");
const terminalCount = $("terminal-count");
const historyMeta = $("history-meta");

document.addEventListener("DOMContentLoaded", async () => {
    setupEventListeners();
    updateTerminalMeta();
    updateTargetScope();
    updateActionButtons();

    try {
        const dir = await window.go.main.App.GetProjectDir();
        if (!dir) {
            projectBanner.classList.remove("hidden");
            addLog("Project directory not found. Please select it.", "warning");
        } else {
            addLog("Project directory: " + dir, "info");
        }
    } catch (error) {
        projectBanner.classList.remove("hidden");
        addLog("Unable to verify the project directory.", "warning");
    }

    await refreshBuilds("", { silent: true });

    if (window.runtime?.EventsOn) {
        window.runtime.EventsOn("log", (data) => {
            addLog(data?.message ?? "", data?.type ?? "info", data?.time);
        });
    }
});

function setupEventListeners() {
    $("btn-minimize").addEventListener("click", () => window.runtime?.WindowMinimise?.());
    $("btn-maximize").addEventListener("click", () => window.runtime?.WindowToggleMaximise?.());
    $("btn-close").addEventListener("click", () => window.runtime?.Quit?.());

    $("btn-select-project").addEventListener("click", selectProjectDir);
    btnGenerate.addEventListener("click", handleGenerate);
    btnBrowse.addEventListener("click", handleBrowse);
    btnClearTarget.addEventListener("click", clearTargetFolder);
    btnEncrypt.addEventListener("click", handleEncrypt);
    btnDecrypt.addEventListener("click", handleDecrypt);
    btnClearLog.addEventListener("click", clearLog);
    btnRefresh.addEventListener("click", () => refreshBuilds(currentBuildId, { silent: false }));

    buildSelect.addEventListener("change", () => {
        setCurrentBuild(buildSelect.value);
    });

    extInput.addEventListener("input", () => {
        extInput.style.borderColor = "";
    });
}

async function selectProjectDir() {
    try {
        const dir = await window.go.main.App.SelectProjectDir();
        if (dir) {
            projectBanner.classList.add("hidden");
            addLog("Project directory set: " + dir, "success");
            await refreshBuilds("", { silent: false });
            return;
        }

        addLog("Invalid directory. Required templates were not found.", "error");
    } catch (error) {
        addLog("Failed to select directory: " + error, "error");
    }
}

async function handleGenerate() {
    if (isGenerating) {
        return;
    }

    isGenerating = true;
    setGenerateLoading(true);
    addLog("Generate request started.", "system");

    try {
        const result = await window.go.main.App.Generate();

        if (result?.success) {
            showBuildStatus(result);
            currentBuildId = result.id;
            await refreshBuilds(result.id, { silent: false });
            addLog("Build #" + result.id + " is ready for execution.", "success");
            addLog("-".repeat(44), "system");
        } else {
            addLog("Build failed: " + (result?.error || "Unknown error"), "error");
        }
    } catch (error) {
        addLog("Generate error: " + error, "error");
    } finally {
        isGenerating = false;
        setGenerateLoading(false);
        updateActionButtons();
    }
}

function setGenerateLoading(loading) {
    btnGenerate.disabled = loading;
    btnGenerate.setAttribute("aria-busy", String(loading));

    const content = btnGenerate.querySelector(".btn-generate-content");
    const loader = btnGenerate.querySelector(".btn-loader");

    if (loading) {
        content.classList.add("hidden");
        loader.classList.remove("hidden");
    } else {
        content.classList.remove("hidden");
        loader.classList.add("hidden");
    }
}

function showBuildStatus(result) {
    buildStatus.classList.remove("hidden");
    $("stat-id").textContent = "#" + result.id;
    $("stat-enc").textContent = result.encFile;
    $("stat-dec").textContent = result.decFile;
    $("stat-key").textContent = result.keyFile;
    $("stat-time").textContent = result.timestamp;

    buildStatus.querySelectorAll(".status-item").forEach((item, index) => {
        item.style.animation = "none";
        item.offsetHeight;
        item.style.animation = "cardEnter 0.3s ease-out " + (index * 0.05) + "s both";
    });
}

async function handleBrowse() {
    try {
        const path = await window.go.main.App.SelectFolder();
        if (!path) {
            return;
        }

        targetFolder.value = path;
        updateTargetScope();
        updateActionButtons();
        addLog("Target folder selected: " + path, "info");
    } catch (error) {
        addLog("Browse error: " + error, "error");
    }
}

function clearTargetFolder() {
    if (!targetFolder.value) {
        return;
    }

    targetFolder.value = "";
    updateTargetScope();
    updateActionButtons();
    addLog("Target scope reset to ALL DRIVES.", "system");
}

async function handleEncrypt() {
    if (isRunning || !currentBuildId) {
        return;
    }

    isRunning = true;
    updateActionButtons();
    addLog("Encrypt requested for build #" + currentBuildId + ".", "system");

    try {
        await window.go.main.App.RunEncryptor(currentBuildId, targetFolder.value.trim());
    } catch (error) {
        addLog("Encrypt error: " + error, "error");
    } finally {
        isRunning = false;
        updateActionButtons();
    }
}

async function handleDecrypt() {
    if (isRunning || !currentBuildId) {
        return;
    }

    const ext = extInput.value.trim();
    if (!ext) {
        addLog("Please enter the file extension for decryption.", "warning");
        extInput.focus();
        extInput.style.borderColor = "var(--warning)";
        setTimeout(() => {
            extInput.style.borderColor = "";
        }, 1800);
        return;
    }

    isRunning = true;
    updateActionButtons();
    addLog("Decrypt requested for build #" + currentBuildId + " using ." + ext + ".", "system");

    try {
        await window.go.main.App.RunDecryptor(currentBuildId, ext, targetFolder.value.trim());
    } catch (error) {
        addLog("Decrypt error: " + error, "error");
    } finally {
        isRunning = false;
        updateActionButtons();
    }
}

function updateActionButtons() {
    const hasBuild = !!currentBuildId;

    btnEncrypt.disabled = isRunning || !hasBuild;
    btnDecrypt.disabled = isRunning || !hasBuild;
    btnBrowse.disabled = isRunning;
    btnClearTarget.disabled = isRunning || !targetFolder.value.trim();

    updateTargetScope();
}

async function refreshBuilds(preferredBuildId = currentBuildId, options = {}) {
    const { silent = true } = options;

    try {
        const builds = await window.go.main.App.GetBuilds();
        renderBuilds(builds || [], preferredBuildId);
    } catch (error) {
        renderBuilds([], "");
        if (!silent) {
            addLog("Failed to refresh build history: " + error, "error");
        }
    }
}

function renderBuilds(builds, preferredBuildId = currentBuildId) {
    buildsCache = Array.isArray(builds) ? builds : [];
    historyBody.innerHTML = "";
    buildSelect.innerHTML = "";

    if (buildsCache.length === 0) {
        currentBuildId = "";
        buildStatus.classList.add("hidden");
        buildSelect.innerHTML = '<option value="">No builds available</option>';
        noBuilds.classList.remove("hidden");
        historyTableWrap.classList.add("hidden");
        updateHistoryMeta(0);
        updateActionButtons();
        return;
    }

    const hasPreferred = buildsCache.some((build) => build.id === preferredBuildId);
    currentBuildId = hasPreferred ? preferredBuildId : buildsCache[0].id;

    buildsCache.forEach((build) => {
        const option = document.createElement("option");
        option.value = build.id;
        option.textContent = "#" + build.id + " - " + (build.timestamp || "Unknown");
        if (build.id === currentBuildId) {
            option.selected = true;
        }
        buildSelect.appendChild(option);
    });

    const fragment = document.createDocumentFragment();
    buildsCache.forEach((build) => {
        const row = document.createElement("tr");
        row.dataset.buildId = build.id;
        if (build.id === currentBuildId) {
            row.classList.add("selected");
        }

        row.innerHTML = `
            <td>
                <div class="history-build">
                    <strong>#${escapeHtml(build.id)}</strong>
                    <span class="history-subtext">${build.id === currentBuildId ? "Active selection" : "Click to make active"}</span>
                </div>
            </td>
            <td>
                <div class="history-file">
                    <span class="history-file-name">${escapeHtml(build.timestamp || "-")}</span>
                    <span class="history-file-size">Generated artifact bundle</span>
                </div>
            </td>
            <td>${renderFileCell(build.encFile, build.encSize, "Encryptor ready")}</td>
            <td>${renderFileCell(build.decFile, build.decSize, "Decryptor ready")}</td>
            <td>${renderKeyCell(build.keyFile)}</td>
        `;

        row.addEventListener("click", () => {
            setCurrentBuild(build.id);
        });

        fragment.appendChild(row);
    });

    historyBody.appendChild(fragment);
    noBuilds.classList.add("hidden");
    historyTableWrap.classList.remove("hidden");
    updateHistoryMeta(buildsCache.length);
    setCurrentBuild(currentBuildId);
}

function renderFileCell(fileName, fileSize, fallbackLabel) {
    if (!fileName) {
        return '<span class="badge badge-muted">Unavailable</span>';
    }

    return `
        <div class="history-file">
            <span class="history-file-name">${escapeHtml(fileName)}</span>
            <span class="history-file-size">${escapeHtml(fileSize || fallbackLabel)}</span>
        </div>
    `;
}

function renderKeyCell(keyFile) {
    if (!keyFile) {
        return '<span class="badge badge-muted">Missing</span>';
    }

    return `
        <div class="history-file">
            <span class="history-file-name">${escapeHtml(keyFile)}</span>
            <span class="history-file-size">Key material ready</span>
        </div>
    `;
}

function setCurrentBuild(buildId) {
    currentBuildId = buildId || "";
    buildSelect.value = currentBuildId;
    syncSelectedHistoryRow();
    updateActionButtons();
}

function syncSelectedHistoryRow() {
    historyBody.querySelectorAll("tr").forEach((row) => {
        row.classList.toggle("selected", row.dataset.buildId === currentBuildId);
    });
}

function updateTargetScope() {
    const folder = targetFolder.value.trim();
    const hasFolder = !!folder;
    const activeBuildLabel = currentBuildId ? "Build #" + currentBuildId : "The selected action";

    scopeCard.classList.toggle("is-global", !hasFolder);
    scopeCard.classList.toggle("is-focused", hasFolder);
    scopeBadge.classList.toggle("scope-focused", hasFolder);
    scopeBadge.textContent = hasFolder ? "Selected Folder" : "All Drives";

    if (hasFolder) {
        scopeDescription.textContent = activeBuildLabel + " will operate only inside " + folder + ".";
        scopeFootnote.textContent = "Focused scope is safer for testing and easier to verify before wider execution.";
    } else if (currentBuildId) {
        scopeDescription.textContent = activeBuildLabel + " will run across all available drives if you proceed.";
        scopeFootnote.textContent = "Leave the target blank only when you intentionally want full-drive scope.";
    } else {
        scopeDescription.textContent = "Select a build first, then decide whether you want a focused folder or full-drive scope.";
        scopeFootnote.textContent = "Used by both Encrypt and Decrypt actions.";
    }
}

function updateHistoryMeta(total) {
    historyMeta.textContent = total === 1 ? "1 build" : total + " builds";
}

function addLog(message, type = "info", timeString = "") {
    const text = String(message ?? "");
    const lines = text.split(/\r?\n/);
    const cursor = terminal.querySelector(".terminal-cursor");
    const shouldStick = isTerminalNearBottom();
    let appended = 0;

    lines.forEach((rawLine) => {
        if (!rawLine.trim() && lines.length > 1) {
            return;
        }

        const line = document.createElement("div");
        line.className = "terminal-line " + (type || "info");
        line.innerHTML = `
            <span class="t-marker" aria-hidden="true"></span>
            <span class="t-time">[${escapeHtml(timeString || createTimeString())}]</span>
            <span class="t-msg">${escapeHtml(rawLine)}</span>
        `;

        terminal.insertBefore(line, cursor);
        appended += 1;
    });

    trimLogLines();
    updateTerminalMeta();

    if (shouldStick || appended === 0) {
        requestAnimationFrame(() => {
            terminal.scrollTop = terminal.scrollHeight;
        });
    }
}

function trimLogLines() {
    const lines = terminal.querySelectorAll(".terminal-line");
    const overflow = lines.length - 500;

    if (overflow <= 0) {
        return;
    }

    for (let index = 0; index < overflow; index += 1) {
        lines[index]?.remove();
    }
}

function clearLog() {
    terminal.querySelectorAll(".terminal-line").forEach((line) => line.remove());
    updateTerminalMeta();
    addLog("Terminal cleared.", "system");
}

function updateTerminalMeta() {
    const total = terminal.querySelectorAll(".terminal-line").length;
    terminalCount.textContent = total === 1 ? "1 entry" : total + " entries";
}

function isTerminalNearBottom() {
    const threshold = 28;
    return terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight < threshold;
}

function createTimeString() {
    const now = new Date();
    return [
        now.getHours().toString().padStart(2, "0"),
        now.getMinutes().toString().padStart(2, "0"),
        now.getSeconds().toString().padStart(2, "0"),
    ].join(":");
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
