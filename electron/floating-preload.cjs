const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aegisFloating", {
  openMain: () => ipcRenderer.send("aegis:open-main"),
});
