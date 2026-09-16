const { app, BrowserWindow, ipcMain, shell } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const fs = require("fs");

const isDev = Boolean(process.env.VITE_DEV_SERVER_URL);
let mainWindow = null;
let serverProc = null;
let apiPort = 7832;

const PORT_FILE = path.join(__dirname, "..", ".aegis", "port");

function readPortFile() {
  try {
    if (!fs.existsSync(PORT_FILE)) return null;
    const n = Number(fs.readFileSync(PORT_FILE, "utf8").trim());
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

function waitForPort(timeoutMs = 8000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      const p = readPortFile();
      if (p) {
        resolve(p);
        return;
      }
      if (Date.now() - start > timeoutMs) {
        resolve(7832);
        return;
      }
      setTimeout(tick, 150);
    };
    tick();
  });
}

function startCoreServer() {
  return new Promise((resolve, reject) => {
    if (isDev) {
      // Dev: concurrently starts server; port file may already exist
      const existing = readPortFile();
      resolve(existing ?? 7832);
      return;
    }
    const serverEntry = path.join(__dirname, "..", "server", "index.ts");
    const distEntry = path.join(__dirname, "..", "dist-server", "index.js");
    if (fs.existsSync(distEntry)) {
      serverProc = spawn(process.execPath, [distEntry], {
        stdio: "inherit",
        env: { ...process.env },
      });
    } else {
      const tsx = path.join(__dirname, "..", "node_modules", ".bin", "tsx");
      serverProc = spawn(tsx, [serverEntry], {
        stdio: "inherit",
        env: { ...process.env },
      });
    }
    serverProc.on("error", reject);
    waitForPort().then(resolve);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 920,
    minHeight: 620,
    title: "Aegis",
    backgroundColor: "#ffffff",
    vibrancy: "under-window",
    visualEffectState: "active",
    transparent: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      additionalArguments: [`--aegis-api-port=${apiPort}`],
    },
  });

  if (isDev) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    // Same-origin with API (express serves dist/) so CORS/Origin stay clean.
    mainWindow.loadURL(`http://127.0.0.1:${apiPort}/`);
  }

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
