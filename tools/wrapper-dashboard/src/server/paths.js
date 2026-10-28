import { readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const ROOT = resolve(process.env.MDVPN_DASHBOARD_ROOT || process.cwd());
export const PORT = Number(process.env.MDVPN_DASHBOARD_PORT || 18080);
export const PUBLIC_DIR = join(APP_ROOT, "public");
export const CONFIG_FILE = join(ROOT, "client_config.toml");
export const RESOLVERS_FILE = join(ROOT, "client_resolvers.txt");
export const SCHEMA_FILE = join(ROOT, ".config-schema.json");
export const LOG_FILE = join(ROOT, "dashboard-client.log");
export const RULES_FILE = join(ROOT, "optimizer-rules.json");
export const RUNS_FILE = join(ROOT, "dashboard-runs.json");
export const GOOD_RESOLVERS_FILE = join(ROOT, "known-good-resolvers.txt");
export const BINARY = findBinary();

function findBinary() {
  const found = readdirSync(ROOT).find((file) => file.startsWith("MasterDnsVPN_Client_Linux_AMD64_v"));
  return found ? join(ROOT, found) : null;
}
