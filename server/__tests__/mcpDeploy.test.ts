import { describe, it, expect } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { buildDeployBundle, buildDeployZip } from "../services/mcpDeploy.js";

const root = process.cwd();
const jsEntry = path.join(root, "dist-server", "index.js");
const tsEntry = path.join(root, "server", "index.ts");
const entry = fs.existsSync(jsEntry) ? jsEntry : tsEntry;

describe("mcp deploy bundle", () => {
  it("includes mcp json, skill, readme, install.sh", () => {
    const b = buildDeployBundle(entry);
    const names = b.files.map((f) => f.filename);
    expect(names).toContain("mcp.claude.json");
    expect(names).toContain("SKILL.md");
    expect(names).toContain("install.sh");
    const json = b.files.find((f) => f.filename === "mcp.claude.json")!.content;
    expect(json).toContain("aegis");
    expect(json).toContain("--mcp");
    expect(b.mcpEntry).toContain("index.");
  });

  it("install.sh matches mcp.claude.json command for node entry", () => {
    if (!fs.existsSync(jsEntry)) return;
    const b = buildDeployBundle(jsEntry);
    const json = JSON.parse(
      b.files.find((f) => f.filename === "mcp.claude.json")!.content,
    ) as { mcpServers: { aegis: { command: string; args: string[] } } };
    const sh = b.files.find((f) => f.filename === "install.sh")!.content;
    expect(json.mcpServers.aegis.command).toBe("node");
    expect(sh).toContain('COMMAND="node"');
    expect(sh).toContain(jsEntry);
  });

  it("install.sh uses npx tsx when entry is TypeScript", () => {
    const b = buildDeployBundle(tsEntry);
    const json = JSON.parse(
      b.files.find((f) => f.filename === "mcp.claude.json")!.content,
    ) as { mcpServers: { aegis: { command: string; args: string[] } } };
    const sh = b.files.find((f) => f.filename === "install.sh")!.content;
    expect(json.mcpServers.aegis.command).toBe("npx");
    expect(sh).toContain('COMMAND="npx"');
    expect(sh).toContain('"tsx"');
  });

  it("rejects shell-metachar entry override", () => {
    const bad = buildDeployBundle("/tmp/evil$(id)/index.js");
    expect(bad.mcpEntry).not.toContain("$(");
    const sh = bad.files.find((f) => f.filename === "install.sh")!.content;
    const entryLine = sh.split("\n").find((l) => l.startsWith("ENTRY=")) ?? "";
    expect(entryLine).not.toContain("$(");
  });

  it("includes AEGIS_DATA_DIR in mcp config", () => {
    const b = buildDeployBundle(entry);
    const json = JSON.parse(
      b.files.find((f) => f.filename === "mcp.claude.json")!.content,
    ) as { mcpServers: { aegis: { env?: Record<string, string> } } };
    expect(json.mcpServers.aegis.env?.AEGIS_DATA_DIR).toBeTruthy();
  });

  it("zip has PK header and file entries", () => {
    const b = buildDeployBundle(entry);
    const zip = buildDeployZip(b);
    expect(zip.subarray(0, 2).toString("latin1")).toBe("PK");
    expect(zip.includes(Buffer.from("mcp.claude.json"))).toBe(true);
    expect(zip.includes(Buffer.from("install.sh"))).toBe(true);
  });
});
