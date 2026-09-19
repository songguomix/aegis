import { describe, it, expect } from "vitest";
import { buildDeployBundle, buildDeployZip } from "../services/mcpDeploy.js";

describe("mcp deploy bundle", () => {
  it("includes mcp json, skill, readme, install.sh", () => {
    const b = buildDeployBundle("/tmp/fake/dist-server/index.js");
    const names = b.files.map((f) => f.filename);
    expect(names).toContain("mcp.claude.json");
    expect(names).toContain("SKILL.md");
    expect(names).toContain("install.sh");
    const json = b.files.find((f) => f.filename === "mcp.claude.json")!.content;
    expect(json).toContain("aegis");
    expect(json).toContain("--mcp");
    expect(b.mcpEntry).toContain("index.js");
  });

  it("install.sh matches mcp.claude.json command for node entry", () => {
    const b = buildDeployBundle("/tmp/fake/dist-server/index.js");
    const json = JSON.parse(
      b.files.find((f) => f.filename === "mcp.claude.json")!.content,
    ) as { mcpServers: { aegis: { command: string; args: string[] } } };
    const sh = b.files.find((f) => f.filename === "install.sh")!.content;
    expect(json.mcpServers.aegis.command).toBe("node");
    expect(sh).toContain('COMMAND="node"');
    expect(sh).toContain("/tmp/fake/dist-server/index.js");
  });

  it("install.sh uses npx tsx when entry is TypeScript", () => {
    const b = buildDeployBundle("/tmp/fake/server/index.ts");
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
    expect(sh).not.toContain("$(");
  });

  it("includes AEGIS_DATA_DIR in mcp config", () => {
    const b = buildDeployBundle("/tmp/fake/dist-server/index.js");
    const json = JSON.parse(
      b.files.find((f) => f.filename === "mcp.claude.json")!.content,
    ) as { mcpServers: { aegis: { env?: Record<string, string> } } };
    expect(json.mcpServers.aegis.env?.AEGIS_DATA_DIR).toBeTruthy();
  });

  it("zip has PK header and file entries", () => {
    const b = buildDeployBundle("/tmp/fake/dist-server/index.js");
    const zip = buildDeployZip(b);
    expect(zip.subarray(0, 2).toString("latin1")).toBe("PK");
    expect(zip.includes(Buffer.from("mcp.claude.json"))).toBe(true);
    expect(zip.includes(Buffer.from("install.sh"))).toBe(true);
  });
});
