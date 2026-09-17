const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aegisFloating", {
  openMain: () => ipcRenderer.send("aegis:open-main"),
  setCompact: (compact) => ipcRenderer.send("aegis:float-size", Boolean(compact)),
});
