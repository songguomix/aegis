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

  it("zip has PK header and file entries", () => {
    const b = buildDeployBundle("/tmp/fake/dist-server/index.js");
    const zip = buildDeployZip(b);
    expect(zip.subarray(0, 2).toString("latin1")).toBe("PK");
    expect(zip.includes(Buffer.from("mcp.claude.json"))).toBe(true);
    expect(zip.includes(Buffer.from("install.sh"))).toBe(true);
  });
});
