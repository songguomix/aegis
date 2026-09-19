const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aegisFloating", {
  openMain: () => ipcRenderer.send("aegis:open-main"),
  setCompact: (compact) => ipcRenderer.send("aegis:float-size", Boolean(compact)),
  lockAnchor: () => ipcRenderer.send("aegis:float-anchor-lock"),
  getToken: () => ipcRenderer.invoke("aegis:get-token"),
});
