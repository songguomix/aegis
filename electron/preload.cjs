const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("aegis", {
  getApiBase: () => Promise.resolve("http://127.0.0.1:7832/api/v1"),
});
