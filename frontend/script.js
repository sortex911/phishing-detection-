const API_URL = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" ? "http://127.0.0.1:5000/check" : "/check";
const HISTORY_KEY = "sortex_history";

// ──────────────────────────────────────────────────────────────────────────────
// DOM References
// ──────────────────────────────────────────────────────────────────────────────
const urlInput       = document.getElementById("url-input");
const scanForm       = document.getElementById("scan-form");
const scanBtn        = document.getElementById("scan-btn");
const loadingDiv     = document.getElementById("loading");
const errorDiv       = document.getElementById("error-message");
const resultsPanel   = document.getElementById("results-panel");
const resultStatus   = document.getElementById("result-status");
const historyList    = document.getElementById("history-list");
const copyBtn        = document.getElementById("copy-btn");
const resetBtn       = document.getElementById("reset-btn");
const alertOverlay   = document.getElementById("alert-overlay");
const mainContainer  = document.getElementById("main-container");
const vtNotice       = document.getElementById("vt-notice");
const heuristicPanel = document.getElementById("heuristic-panel");
const heuristicScore = document.getElementById("heuristic-score");
const heuristicList  = document.getElementById("heuristic-reasons");

// Matter.js state
let engine, render, runner;
let physicsBodies = [];
let isPhysicsActive = false;
let updateInterval;

// ──────────────────────────────────────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    loadHistory();
    scanForm.addEventListener("submit", handleScan);
    copyBtn.addEventListener("click", copyResult);
    resetBtn.addEventListener("click", resetSystem);
});

// ──────────────────────────────────────────────────────────────────────────────
// resetUI — Single source of truth for ALL state clearing.
// Called before every scan AND by the Reset System button.
// Tears down: physics engine, red overlay, all panels, theme classes,
// inline styles on falling elements, and scan-related flags.
// ──────────────────────────────────────────────────────────────────────────────
function resetUI() {
    // ── 1. Stop & destroy Matter.js physics if it is running ─────────────────
    if (isPhysicsActive) {
        clearInterval(updateInterval);       // stop DOM sync loop
        Matter.Render.stop(render);          // stop render loop
        Matter.Runner.stop(runner);          // stop physics runner
        if (render && render.canvas) render.canvas.remove(); // remove hidden canvas

        // Restore every falling element back to normal document flow
        physicsBodies.forEach(({ element: el }) => {
            el.classList.remove("is-falling");
            el.removeAttribute("style");     // wipe position/transform/width/height
        });

        physicsBodies = [];
        isPhysicsActive = false;
    }

    // ── 2. Remove red vignette overlay ───────────────────────────────────────
    alertOverlay.classList.remove("phishing-active");

    // ── 3. Hide all result panels ─────────────────────────────────────────────
    resultsPanel.classList.add("hidden");
    heuristicPanel.classList.add("hidden");
    vtNotice.classList.add("hidden");
    errorDiv.classList.add("hidden");
    resetBtn.classList.add("hidden");

    // ── 4. Clear theme class — removes safe/suspicious/malicious coloring ────
    // We clear className entirely so no previous theme bleeds through.
    document.body.className = "";

    // ── 5. Reset status label text so stale text never flashes ───────────────
    resultStatus.textContent = "";

    // ── 6. Clear the shareable copy buffer ───────────────────────────────────
    window.lastResultText = null;
}

// ──────────────────────────────────────────────────────────────────────────────
// handleScan — Orchestrates a full scan lifecycle.
// ──────────────────────────────────────────────────────────────────────────────
async function handleScan(e) {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    // ✅ FIX: Reset ALL UI state at the top of every scan.
    // This guarantees no red overlay, no physics debris, no stale panels
    // survive from any previous scan — regardless of what result it had.
    resetUI();

    scanBtn.disabled = true;
    loadingDiv.classList.remove("hidden");

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 25000); // 25s timeout

        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        // Backend always returns JSON — parse unconditionally
        const data = await response.json();

        if (!response.ok || data.error) {
            throw new Error(data.error || "Unknown server error.");
        }

        updateUI(url, data);              // apply new result
        saveToHistory(url, data.status);

    } catch (err) {
        console.error("[Sortex Error]", err);
        errorDiv.textContent = err.name === "AbortError"
            ? "⏱ Request timed out. Check the backend is running on port 5000."
            : `⚠ ${err.message}`;
        errorDiv.classList.remove("hidden");
    } finally {
        scanBtn.disabled = false;
        loadingDiv.classList.add("hidden");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// updateUI — Pure result renderer. Only adds state, never removes it.
// All clearing is handled exclusively by resetUI() before this runs.
// ──────────────────────────────────────────────────────────────────────────────
function updateUI(url, data) {
    const status = data.status; // "safe" | "suspicious" | "malicious"
    const stats  = data.stats || {};

    // ── 1. Apply a single theme class — body is blank thanks to resetUI() ────
    // No need to strip old classes; resetUI() guarantees a clean slate.
    document.body.className = `theme-${status}`;

    // ── 2. Status badge ──────────────────────────────────────────────────────
    const LABELS = { safe: "✅ SAFE", suspicious: "⚠️ SUSPICIOUS", malicious: "🚨 MALICIOUS" };
    resultStatus.textContent = LABELS[status] ?? status.toUpperCase();

    // ── 3. VirusTotal stats grid ─────────────────────────────────────────────
    document.getElementById("stat-malicious").textContent  = stats.malicious  ?? "–";
    document.getElementById("stat-suspicious").textContent = stats.suspicious ?? "–";
    document.getElementById("stat-harmless").textContent   = stats.harmless   ?? "–";
    document.getElementById("stat-undetected").textContent = stats.undetected ?? "–";

    // ── 4. Show results panel ────────────────────────────────────────────────
    resultsPanel.classList.remove("hidden");

    // ── 5. Heuristic breakdown ───────────────────────────────────────────────
    if (data.heuristic) {
        const h = data.heuristic;
        heuristicScore.textContent = `Risk Score: ${h.score} / 100  (${h.status.toUpperCase()})`;
        heuristicList.innerHTML = "";
        const reasons = (h.reasons && h.reasons.length) ? h.reasons : ["No suspicious patterns detected."];
        reasons.forEach(r => {
            const li = document.createElement("li");
            li.textContent = `⚑ ${r}`;
            heuristicList.appendChild(li);
        });
        heuristicPanel.classList.remove("hidden");
    }

    // ── 6. VirusTotal notice (pending / rate-limited / error) ────────────────
    if (data.vt_error) {
        vtNotice.textContent = `ℹ VT: ${data.vt_error}`;
        vtNotice.classList.remove("hidden");
    }

    // ── 7. Build shareable copy-text ─────────────────────────────────────────
    window.lastResultText = [
        `Sortex Phishing Detection Report`,
        `URL      : ${url}`,
        `Status   : ${status.toUpperCase()}`,
        `H-Score  : ${data.heuristic?.score ?? "N/A"} — ${(data.heuristic?.reasons || []).join("; ")}`,
        `VT Stats : Malicious=${stats.malicious} | Suspicious=${stats.suspicious} | Harmless=${stats.harmless}`
    ].join("\n");

    // ── 8. Trigger status-specific effects ───────────────────────────────────
    if (status === "malicious") {
        triggerPhishingAlert();   // red vignette + Matter.js physics
    }
    // suspicious: shake is applied purely via CSS (.theme-suspicious animation)
    // safe: stable green UI — no extra effects needed
}

// ──────────────────────────────────────────────────────────────────────────────
// Phishing Alert + Matter.js Anti-Gravity
// ──────────────────────────────────────────────────────────────────────────────
function triggerPhishingAlert() {
    alertOverlay.classList.add("phishing-active");
    resetBtn.classList.remove("hidden");
    initPhysics();
}

function initPhysics() {
    if (isPhysicsActive) return;
    isPhysicsActive = true;

    const { Engine, Render, Runner, Bodies, World, Body } = Matter;

    engine = Engine.create();

    // Hidden canvas drives the simulation — we sync DOM to it
    render = Render.create({
        element: document.body,
        engine,
        options: {
            width: window.innerWidth,
            height: window.innerHeight,
            wireframes: false,
            background: "transparent"
        }
    });
    Object.assign(render.canvas.style, {
        position: "fixed", top: "0", left: "0",
        pointerEvents: "none", zIndex: "9000", opacity: "0"
    });

    // Invisible floor so elements pile up instead of falling forever
    const ground = Bodies.rectangle(
        window.innerWidth / 2, window.innerHeight + 50,
        window.innerWidth * 2, 100, { isStatic: true }
    );
    World.add(engine.world, [ground]);

    // Turn every .physics-element into a physics body
    document.querySelectorAll(".physics-element").forEach(el => {
        const rect = el.getBoundingClientRect();
        const body = Bodies.rectangle(
            rect.left + rect.width / 2,
            rect.top  + rect.height / 2,
            Math.max(rect.width, 10),
            Math.max(rect.height, 10),
            { restitution: 0.5, friction: 0.1, density: 0.04 }
        );

        // Random lateral impulse for chaotic breakup
        Body.applyForce(body, body.position, {
            x: (Math.random() - 0.5) * 0.15,
            y: -Math.random() * 0.05
        });

        physicsBodies.push({ element: el, body, initialRect: rect });
        World.add(engine.world, [body]);
    });

    runner = Runner.create();
    Runner.run(runner, engine);
    Render.run(render);

    // Sync DOM positions to physics bodies at ~60fps
    updateInterval = setInterval(() => {
        physicsBodies.forEach(({ element: el, body, initialRect: r }) => {
            if (!el.classList.contains("is-falling")) {
                el.style.width  = `${r.width}px`;
                el.style.height = `${r.height}px`;
                el.classList.add("is-falling");
            }
            el.style.left      = `${body.position.x - r.width  / 2}px`;
            el.style.top       = `${body.position.y - r.height / 2}px`;
            el.style.transform = `rotate(${body.angle}rad)`;
        });
    }, 16);
}

// ──────────────────────────────────────────────────────────────────────────────
// resetSystem — called by the "RESET SYSTEM" button after a malicious scan.
// Delegates all teardown to resetUI() then clears the URL input.
// ──────────────────────────────────────────────────────────────────────────────
function resetSystem() {
    resetUI();             // single source of truth — handles everything
    urlInput.value = "";   // only extra step: wipe the input field
}

// ──────────────────────────────────────────────────────────────────────────────
// Copy to Clipboard
// ──────────────────────────────────────────────────────────────────────────────
function copyResult() {
    if (!window.lastResultText) return;
    navigator.clipboard.writeText(window.lastResultText).then(() => {
        const orig = copyBtn.innerText;
        copyBtn.innerText = "✅ Copied!";
        setTimeout(() => { copyBtn.innerText = orig; }, 2000);
    });
}

// ──────────────────────────────────────────────────────────────────────────────
// Scan History (localStorage)
// ──────────────────────────────────────────────────────────────────────────────
function loadHistory() {
    const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    historyList.innerHTML = "";
    if (!history.length) {
        historyList.innerHTML = "<li class='history-empty'>No scans yet.</li>";
        return;
    }
    history.forEach(item => {
        const li = document.createElement("li");
        li.className = `history-item ${item.status}`;
        const icon = { safe: "✅", suspicious: "⚠️", malicious: "🚨" }[item.status] || "🔍";
        li.innerHTML = `<span class="hist-url">${item.url}</span>
                        <strong class="hist-badge">${icon} ${item.status.toUpperCase()}</strong>`;
        historyList.appendChild(li);
    });
}

function saveToHistory(url, status) {
    const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    history.unshift({ url, status, date: new Date().toISOString() });
    if (history.length > 7) history.pop();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    loadHistory();
}
