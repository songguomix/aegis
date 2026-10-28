import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Every test file gets its own throw-away data directory so the suite never
 * touches the user's real .aegis folder (config, history, token, reviews).
 */
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-test-"));
process.env.AEGIS_DATA_DIR = dir;
