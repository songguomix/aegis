const { contextBridge } = require("electron");

function resolvePort() {
  const arg = process.argv.find((a) => a.startsWith("--aegis-api-port="));
  if (arg) {
    const n = Number(arg.split("=")[1]);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return 7832;
}

const port = resolvePort();

contextBridge.exposeInMainWorld("aegis", {
  getApiBase: () => Promise.resolve(`http://127.0.0.1:${port}/api/v1`),
});
