// `eunomia-mcp init --client <name>` writes the MCP client's config itself. Copy-paste was
// where setup went wrong in every recorded session: a docs placeholder left in, a hidden
// character pasted along, a JSON comma lost. The file is merged, never replaced — other
// servers in it stay as they were — and the previous version is kept beside it as .bak.
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export type ClientName = "claude-desktop" | "cursor" | "claude-code";
export const CLIENTS: ClientName[] = ["claude-desktop", "cursor", "claude-code"];

export interface ServerEntry {
  command: string;
  args: string[];
  env: Record<string, string>;
}

/** How the client should start the server. On Windows a desktop app spawning `npx` directly
 *  finds no executable (it is npx.cmd), so it goes through cmd. */
export function serverEntry(env: Record<string, string>, platform: NodeJS.Platform = process.platform): ServerEntry {
  return platform === "win32"
    ? { command: "cmd", args: ["/c", "npx", "-y", "eunomia-mcp"], env }
    : { command: "npx", args: ["-y", "eunomia-mcp"], env };
}

/** Printed by `eunomia-mcp config` and by `init` when it cannot write the client file itself.
 *  Built from `serverEntry()` so Windows gets the `cmd /c` wrapper and Claude Code gets `--scope user`. */
export function configSnippet(
  env: Record<string, string>,
  client: ClientName | "json" = "json",
  platform: NodeJS.Platform = process.platform,
): string {
  const entry = serverEntry(env, platform);
  switch (client) {
    case "claude-code": {
      const flags = Object.entries(entry.env).map(([k, v]) => `-e ${k}=${v}`).join(" ");
      return `claude mcp add --scope user eunomia ${flags} -- ${[entry.command, ...entry.args].join(" ")}`;
    }
    case "claude-desktop":
    case "cursor":
    case "json":
      return JSON.stringify({ mcpServers: { eunomia: entry } }, null, 2);
    default:
      throw new Error(`Unknown --client "${client}" — use json, claude-desktop, cursor or claude-code.`);
  }
}

/** Where each client keeps its MCP servers. */
export function configPath(
  client: Exclude<ClientName, "claude-code">,
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  home = homedir(),
): string {
  if (client === "cursor") return join(home, ".cursor", "mcp.json");
  if (platform === "win32") return join(env.APPDATA ?? join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
  if (platform === "darwin") return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  return join(home, ".config", "Claude", "claude_desktop_config.json");
}

/** `existing` with the eunomia server set, everything else untouched. Throws on a file that
 *  is not a JSON object rather than overwrite something we cannot read. */
export function mergeServer(existing: string | null, entry: ServerEntry, name = "eunomia"): string {
  let doc: Record<string, unknown> = {};
  if (existing && existing.trim()) {
    const parsed: unknown = JSON.parse(existing);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("the existing config is not a JSON object — fix or move it, then run init again");
    }
    doc = parsed as Record<string, unknown>;
  }
  const servers = (doc.mcpServers && typeof doc.mcpServers === "object" ? doc.mcpServers : {}) as Record<string, unknown>;
  return `${JSON.stringify({ ...doc, mcpServers: { ...servers, [name]: entry } }, null, 2)}\n`;
}

export interface WriteResult {
  client: ClientName;
  /** the file written, or the command run for claude-code */
  where: string;
  backup?: string;
}

export function writeClientConfig(client: ClientName, env: Record<string, string>): WriteResult {
  if (client === "claude-code") {
    // Claude Code owns its config; `claude mcp add` is the supported way in.
    const entry = serverEntry(env);
    const args = ["mcp", "add", "--scope", "user", "eunomia"];
    for (const [k, v] of Object.entries(entry.env)) args.push("-e", `${k}=${v}`);
    args.push("--", entry.command, ...entry.args);
    execFileSync(process.platform === "win32" ? "claude.cmd" : "claude", args, { stdio: "ignore" });
    return { client, where: `claude ${args.join(" ")}` };
  }
  const path = configPath(client);
  const existing = existsSync(path) ? readFileSync(path, "utf8") : null;
  const next = mergeServer(existing, serverEntry(env));
  mkdirSync(dirname(path), { recursive: true });
  let backup: string | undefined;
  if (existing !== null) {
    backup = `${path}.bak`;
    copyFileSync(path, backup);
  }
  writeFileSync(path, next);
  return { client, where: path, ...(backup ? { backup } : {}) };
}
