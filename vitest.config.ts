import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["server/**/*.test.ts", "src/**/*.test.ts"],
    setupFiles: ["server/__tests__/setup.ts"],
  },
});
