const { app, BrowserWindow, ipcMain, shell } = require("electron");
const path = require("path");
const { spawn } = require("child_process");

const isDev = Boolean(process.env.VITE_DEV_SERVER_URL);
let mainWindow = null;
let serverProc = null;
let apiPort = 7832;

function startCoreServer() {
  return new Promise((resolve, reject) => {
    if (isDev) {
      // Dev: user runs `npm run dev:server` separately via concurrently
      resolve(7832);
      return;
    }
    const serverEntry = path.join(__dirname, "..", "server", "index.ts");
    // Prefer compiled JS if present, else tsx
    const distEntry = path.join(__dirname, "..", "dist-server", "index.js");
    const fs = require("fs");
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
    // Give the server a moment; UI polls health
    setTimeout(() => resolve(7832), 800);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 920,
    minHeight: 620,
    title: "Aegis",
    backgroundColor: "#070b14",
    vibrancy: "under-window",
    visualEffectState: "active",
    transparent: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (isDev) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
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
