const { app, BrowserWindow, ipcMain, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const http = require("http");

const isDev = Boolean(process.env.VITE_DEV_SERVER_URL);
let mainWindow = null;
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

function waitForHealth(port, timeoutMs = 12000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      const req = http.get(
        { host: "127.0.0.1", port, path: "/api/v1/health", timeout: 1000 },
        (res) => {
          res.resume();
          resolve(res.statusCode === 200);
        },
      );
      req.on("error", () => {
        if (Date.now() - start > timeoutMs) resolve(false);
        else setTimeout(tick, 200);
      });
      req.on("timeout", () => {
        req.destroy();
        if (Date.now() - start > timeoutMs) resolve(false);
        else setTimeout(tick, 200);
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
  const env = {
    ...process.env,
    AEGIS_DATA_DIR: DATA_DIR,
  };
  const node = resolveNodeBinary();
  if (node) {
    return spawn(node, [entry], { stdio: "inherit", env, cwd: ROOT });
  }
  // Electron-as-Node: standard way to ship a Node server inside a packaged app.
  return spawn(process.execPath, [entry], {
    stdio: "inherit",
    env: { ...env, ELECTRON_RUN_AS_NODE: "1" },
    cwd: ROOT,
  });
}

async function startCoreServer() {
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

  const start = Date.now();
  while (Date.now() - start < 12000) {
    const p = readPortFile();
    if (p) {
      const ok = await waitForHealth(p, 4000);
      if (ok) return p;
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return 7832;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 960,
    minHeight: 640,
    title: "Aegis",
    backgroundColor: "#fafafa",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      additionalArguments: [`--aegis-api-port=${apiPort}`],
    },
  });

  const target = isDev
    ? process.env.VITE_DEV_SERVER_URL
    : `http://127.0.0.1:${apiPort}/`;

  const load = async (attempt = 0) => {
    try {
      await mainWindow.loadURL(target);
    } catch (err) {
      if (attempt < 8) {
        await new Promise((r) => setTimeout(r, 400));
        return load(attempt + 1);
      }
      console.error("[aegis-electron] failed to load", target, err);
    }
  };
  load();

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

ipcMain.handle("aegis:get-api-base", () => `http://127.0.0.1:${apiPort}/api/v1`);

app.whenReady().then(async () => {
  apiPort = await startCoreServer();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (serverProc) serverProc.kill();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  if (serverProc) serverProc.kill();
});
