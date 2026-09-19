const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aegis", {
  getApiBase: () => ipcRenderer.invoke("aegis:get-api-base"),
  getToken: () => ipcRenderer.invoke("aegis:get-token"),
});
