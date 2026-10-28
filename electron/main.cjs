const { app, BrowserWindow, ipcMain, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const http = require("http");

const isDev = Boolean(process.env.VITE_DEV_SERVER_URL);
let mainWindow = null;
let floatingWindow = null;
let serverProc = null;
let apiPort = 7832;

const ROOT = app.isPackaged
  ? path.join(process.resourcesPath, "app.asar.unpacked")
  : path.join(__dirname, "..");

const PORT_FILE = path.join(
  app.isPackaged ? app.getPath("userData") : path.join(ROOT, ".aegis"),
  "port",
);
const DATA_DIR = app.isPackaged
  ? app.getPath("userData")
  : path.join(ROOT, ".aegis");

function readPortFile() {
  try {
    if (!fs.existsSync(PORT_FILE)) return null;
    const n = Number(fs.readFileSync(PORT_FILE, "utf8").trim());
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

function deletePortFile() {
  try {
    if (fs.existsSync(PORT_FILE)) fs.unlinkSync(PORT_FILE);
  } catch {
    /* ignore */
  }
}

function waitForHealth(port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      const req = http.get(
        { host: "127.0.0.1", port, path: "/api/v1/health", timeout: 400 },
        (res) => {
          res.resume();
          resolve(res.statusCode === 200);
        },
      );
      req.on("error", () => {
        if (Date.now() - start > timeoutMs) resolve(false);
        else setTimeout(tick, 60);
      });
      req.on("timeout", () => {
        req.destroy();
        if (Date.now() - start > timeoutMs) resolve(false);
        else setTimeout(tick, 60);
      });
    };
    tick();
  });
}

function resolveNodeBinary() {
  // Packaged app: use system node if present; otherwise Electron's helper node is unavailable.
  // Prefer spawning via `node` from PATH; fall back to process.execPath only in dev.
  const candidates = [
    process.env.AEGIS_NODE,
    "/usr/local/bin/node",
    "/opt/homebrew/bin/node",
    path.join(process.execPath, "..", "..", "node"),
  ];
  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }
  return null;
}

function spawnServer(entry) {
  const asarModules = app.isPackaged
    ? path.join(process.resourcesPath, "app.asar", "node_modules")
    : "";
  const unpackedModules = app.isPackaged
    ? path.join(process.resourcesPath, "app.asar.unpacked", "node_modules")
    : "";
  const nodePath = [asarModules, unpackedModules].filter(Boolean).join(path.delimiter);
  const env = {
    ...process.env,
    AEGIS_DATA_DIR: DATA_DIR,
    ...(nodePath
      ? { NODE_PATH: [nodePath, process.env.NODE_PATH].filter(Boolean).join(path.delimiter) }
      : {}),
  };
  const node = resolveNodeBinary();
  if (node) {
    return spawn(node, [entry], { stdio: "inherit", env, cwd: ROOT });
  }
  return spawn(process.execPath, [entry], {
    stdio: "inherit",
    env: { ...env, ELECTRON_RUN_AS_NODE: "1" },
    cwd: ROOT,
  });
}

async function startCoreServer() {
  const existingPort = readPortFile() ?? 7832;
  const alreadyHealthy = await waitForHealth(existingPort, 500);
  if (alreadyHealthy) {
    return existingPort;
  }

  deletePortFile();
  const distEntry = path.join(ROOT, "dist-server", "index.js");
  const tsx = path.join(ROOT, "node_modules", ".bin", "tsx");
  const serverTs = path.join(ROOT, "server", "index.ts");

  if (fs.existsSync(distEntry)) {
    serverProc = spawnServer(distEntry);
  } else if (!app.isPackaged && fs.existsSync(tsx)) {
    serverProc = spawn(tsx, [serverTs], {
      stdio: "inherit",
      env: { ...process.env, AEGIS_DATA_DIR: DATA_DIR },
      cwd: ROOT,
    });
  } else {
    return 7832;
  }

  // The core server writes the port file right after it binds. Wait for that
  // file (not a fixed delay) so we never guess a wrong port: the app may be
  // running next to another instance that already holds 7832.
  const bindDeadline = Date.now() + 15000;
  let port = null;
  while (Date.now() < bindDeadline) {
    port = readPortFile();
    if (port) break;
    if (serverProc && serverProc.exitCode !== null) break; // server died
    await new Promise((r) => setTimeout(r, 40));
  }
  if (!port) return 7832;

  const healthDeadline = Date.now() + 10000;
  while (Date.now() < healthDeadline) {
    const ok = await waitForHealth(port, 800);
    if (ok) return port;
    if (serverProc && serverProc.exitCode !== null) break;
  }
  // Health never came up: the port file is still the best information we have.
  return port;
}

function createFloatingWindow() {
  const { screen } = require("electron");
  const display = screen.getPrimaryDisplay();
  const { workArea } = display;
  const width = 228;
  const height = 52;

  floatingWindow = new BrowserWindow({
    width,
    height,
    x: Math.round(workArea.x + (workArea.width - width) / 2),
    y: Math.round(workArea.y + 10),
    frame: false,
    transparent: true,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    hasShadow: false,
    focusable: false,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "floating-preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  floatingWindow.setAlwaysOnTop(true, "screen-saver");
  floatingWindow.setVisibleOnAllWorkspaces(true, {
    visibleOnFullScreen: true,
  });

  floatingWindow.once("ready-to-show", () => {
    floatingWindow.showInactive();
  });

  // Reset anchor when user moves the float — future resizes keep that spot
  floatingWindow.on("moved", () => {
    if (!floatingWindow || floatingWindow.isDestroyed()) return;
    const [x, y] = floatingWindow.getPosition();
    const [w] = floatingWindow.getSize();
    floatAnchor = { x, y, width: w };
  });

  floatingWindow.on("closed", () => {
    floatingWindow = null;
  });
}

/** Load the floating UI once the core server port is known. */
function loadFloatingUi() {
  if (!floatingWindow || floatingWindow.isDestroyed()) return;
  floatingWindow.loadFile(path.join(__dirname, "floating.html"), {
    query: { port: String(apiPort) },
  });
}

function createWindow() {
  const iconPath = path.join(ROOT, "build", "icon.png");
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 960,
    minHeight: 640,
    title: "Aegis",
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    backgroundColor: "#fafafa",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

/** Load the main UI once the core server port is known. */
async function loadMainUi() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const target = isDev
    ? process.env.VITE_DEV_SERVER_URL
    : `http://127.0.0.1:${apiPort}/`;

  const load = async (attempt = 0) => {
    try {
      await mainWindow.loadURL(target);
    } catch (err) {
      if (attempt < 12) {
        await new Promise((r) => setTimeout(r, 50));
        return load(attempt + 1);
      }
      console.error("[aegis-electron] failed to load", target, err);
    }
  };
  await load();
}

ipcMain.handle("aegis:get-api-base", () => `http://127.0.0.1:${apiPort}/api/v1`);
ipcMain.handle("aegis:get-token", () => {
  try {
    const p = path.join(DATA_DIR, "token");
    if (fs.existsSync(p)) return fs.readFileSync(p, "utf8").trim();
  } catch {
    /* ignore */
  }
  return null;
});
let floatAnchor = null; // {x, y, width} — center-stable resize base
let floatCompact = true;

ipcMain.on("aegis:open-main", () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  }
});

ipcMain.on("aegis:float-anchor-lock", () => {
  if (!floatingWindow || floatingWindow.isDestroyed()) return;
  const [x, y] = floatingWindow.getPosition();
  const [w] = floatingWindow.getSize();
  floatAnchor = { x, y, width: w };
});

ipcMain.on("aegis:float-size", (_e, compact) => {
  if (!floatingWindow || floatingWindow.isDestroyed()) return;
  floatCompact = Boolean(compact);
  const targetWidth = floatCompact ? 228 : 500;
  const height = 52;

  // Stable visual center: use current center at animation start; never re-jump after.
  if (!floatAnchor) {
    const [x, y] = floatingWindow.getPosition();
    const [w] = floatingWindow.getSize();
    floatAnchor = { x, y, width: w };
  }
  const centerX = floatAnchor.x + floatAnchor.width / 2;
  const y = floatAnchor.y;

  const [cx] = floatingWindow.getPosition();
  const [cw] = floatingWindow.getSize();
  const from = cw;
  const to = targetWidth;
  const finishX = Math.round(centerX - to / 2);

  if (Math.abs(to - from) < 2) {
    floatingWindow.setBounds({ x: finishX, y, width: to, height });
    floatAnchor = { x: finishX, y, width: to };
    return;
  }

  const start = Date.now();
  const duration = 400;
  const fromX = cx;
  const tick = () => {
    if (!floatingWindow || floatingWindow.isDestroyed()) return;
    const t = Math.min(1, (Date.now() - start) / duration);
    const e = 1 - Math.pow(1 - t, 3);
    const width = Math.round(from + (to - from) * e);
    // interpolate toward the same center — ends exactly at finishX, no post-jump
    const x = Math.round(fromX + (finishX - fromX) * e);
    floatingWindow.setBounds({ x, y, width, height });
    if (t < 1) {
      setImmediate(tick);
    } else {
      floatAnchor = { x: finishX, y, width: to };
    }
  };
  tick();
});

app.whenReady().then(async () => {
  // Windows are created immediately (fast boot), but their content is loaded
  // only after the core server bound its port — otherwise the UI would point
  // at a stale/foreign port (7832 may already be taken by another instance).
  createWindow();
  createFloatingWindow();
  apiPort = await startCoreServer();
  await loadMainUi();
  loadFloatingUi();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    if (serverProc) serverProc.kill();
    app.quit();
  }
});

app.on("before-quit", () => {
  if (serverProc) serverProc.kill();
});

app.on("activate", async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    if (!serverProc || serverProc.killed) {
      apiPort = await startCoreServer();
    }
    createWindow();
    createFloatingWindow();
    await loadMainUi();
    loadFloatingUi();
  }
});
