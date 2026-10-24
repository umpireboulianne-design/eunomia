import { readFileSync } from "node:fs";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { fileCache, type KnownPayeeCache } from "./cache.js";
import { resolveCredential, type Credential } from "./credential.js";
import { homeDir, resolveNetwork, type NetworkConfig } from "./network.js";
import { fileExceptionStore, filePurchaseLog, type ExceptionStore, type PurchaseLog } from "./store.js";
import { registerSpendTools } from "./spendTools.js";
import { registerTools } from "./tools.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  name: string;
  version: string;
};

export const SERVER_NAME = pkg.name;
export const SERVER_VERSION = pkg.version;

export interface ServerContext {
  net: NetworkConfig;
  /** null until EUNOMIA_TREASURY is set — tools then explain how, instead of crashing */
  treasuryId: string | null;
  credential: Credential | null;
  cache: KnownPayeeCache;
  /** exception requests this agent filed (bookmarks; the chain is the truth) */
  exceptions: ExceptionStore;
  /** what call_service bought (absent in tests that do not buy) */
  purchases?: PurchaseLog;
  /** where the owner approves things — budget requests link here */
  appUrl?: string;
  /** unix seconds; injectable for tests */
  now?: () => number;
}

export function contextFromEnv(env: NodeJS.ProcessEnv): ServerContext {
  const net = resolveNetwork(env);
  const home = homeDir(env);
  const treasuryId = env.EUNOMIA_TREASURY?.trim() || null;
  return {
    net,
    treasuryId,
    credential: treasuryId ? resolveCredential(env, home, net.name, treasuryId) : null,
    cache: fileCache(join(home, net.name)),
    exceptions: fileExceptionStore(join(home, net.name)),
    purchases: filePurchaseLog(join(home, net.name)),
    appUrl: env.EUNOMIA_APP_URL?.trim() || "https://eunomia.finance",
  };
}

export function createServer(ctx: ServerContext): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });
  registerTools(server, ctx);
  registerSpendTools(server, ctx);
  return server;
}
