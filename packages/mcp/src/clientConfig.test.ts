import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { configPath, mergeServer, PINNED_PACKAGE, serverEntry, writeClientConfig } from "./clientConfig.js";
import { SERVER_VERSION } from "./server.js";

const ENV = { EUNOMIA_TREASURY: "CTREASURY", EUNOMIA_NETWORK: "pubnet" };
const VALID_TREASURY = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

test("SERVER_VERSION matches package.json version", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
  assert.equal(SERVER_VERSION, pkg.version);
  assert.equal(PINNED_PACKAGE, `eunomia-mcp@${pkg.version}`);
});

test("the config is merged: other servers and settings survive", () => {
  const existing = JSON.stringify({ theme: "dark", mcpServers: { other: { command: "x", args: [] } } });
  const out = JSON.parse(mergeServer(existing, serverEntry(ENV, "linux")));
  assert.equal(out.theme, "dark");
  assert.deepEqual(out.mcpServers.other, { command: "x", args: [] });
  assert.deepEqual(out.mcpServers.eunomia, { command: "npx", args: ["-y", `eunomia-mcp@${SERVER_VERSION}`], env: ENV });
});

test("a missing or empty config starts fresh", () => {
  assert.deepEqual(Object.keys(JSON.parse(mergeServer(null, serverEntry(ENV, "linux"))).mcpServers), ["eunomia"]);
  assert.deepEqual(Object.keys(JSON.parse(mergeServer("  ", serverEntry(ENV, "linux"))).mcpServers), ["eunomia"]);
});

test("a config that is not a JSON object is never overwritten", () => {
  assert.throws(() => mergeServer("[1,2]", serverEntry(ENV, "linux")), /not a JSON object/);
  assert.throws(() => mergeServer("{ broken", serverEntry(ENV, "linux")));
});

test("on Windows the desktop clients start npx through cmd with the pinned version", () => {
  assert.deepEqual(serverEntry(ENV, "win32").args, ["/c", "npx", "-y", `eunomia-mcp@${SERVER_VERSION}`]);
  assert.equal(serverEntry(ENV, "win32").command, "cmd");
});

test("each client's config lives where the client reads it", () => {
  assert.match(configPath("claude-desktop", "win32", { APPDATA: "C:/Users/u/AppData/Roaming" }, "C:/Users/u"), /Roaming[\\/]Claude[\\/]claude_desktop_config\.json$/);
  assert.match(configPath("claude-desktop", "darwin", {}, "/Users/u"), /Library[\\/]Application Support[\\/]Claude[\\/]claude_desktop_config\.json$/);
  assert.match(configPath("claude-desktop", "linux", {}, "/home/u"), /\.config[\\/]Claude[\\/]claude_desktop_config\.json$/);
  assert.match(configPath("cursor", "linux", {}, "/home/u"), /\.cursor[\\/]mcp\.json$/);
});

test("the agent's secret never goes into a client config", () => {
  const entry = serverEntry(ENV, "linux");
  assert.ok(!JSON.stringify(entry).includes("SECRET"));
});

test("writeClientConfig writes the pinned package version to disk and to claude-code args", () => {
  const tmpHome = mkdtempSync(join(tmpdir(), "eunomia-client-cfg-"));
  try {
    const written = writeClientConfig("cursor", ENV, { home: tmpHome, platform: "linux" });
    const content = JSON.parse(readFileSync(written.where, "utf8"));
    assert.ok(content.mcpServers.eunomia.args.includes(`eunomia-mcp@${SERVER_VERSION}`));

    let spawnedArgs: string[] = [];
    const codeRes = writeClientConfig("claude-code", ENV, {
      platform: "linux",
      exec: (_cmd, args) => {
        spawnedArgs = args;
      },
    });
    assert.ok(spawnedArgs.includes(`eunomia-mcp@${SERVER_VERSION}`));
    assert.match(codeRes.where, new RegExp(`eunomia-mcp@${SERVER_VERSION.replace(/\./g, "\\.")}$`));
  } finally {
    rmSync(tmpHome, { recursive: true, force: true });
  }
});

test("init --client and config CLI output carry the pinned package version", () => {
  const tmpHome = mkdtempSync(join(tmpdir(), "eunomia-cli-cfg-"));
  try {
    const cliPath = fileURLToPath(new URL("./cli.ts", import.meta.url));
    const tsxCli = fileURLToPath(new URL("../node_modules/tsx/dist/cli.mjs", import.meta.url));

    const configOut = execFileSync(
      process.execPath,
      [tsxCli, cliPath, "config", "--client", "json", "--treasury", VALID_TREASURY],
      { encoding: "utf8" },
    );
    const parsedConfig = JSON.parse(configOut);
    assert.deepEqual(parsedConfig.mcpServers.eunomia.args, ["-y", `eunomia-mcp@${SERVER_VERSION}`]);

    const initFallbackOut = execFileSync(
      process.execPath,
      [tsxCli, cliPath, "init", "--treasury", VALID_TREASURY, "--skip-fund"],
      {
        encoding: "utf8",
        env: { ...process.env, EUNOMIA_HOME: join(tmpHome, ".eunomia") },
      },
    );
    assert.match(initFallbackOut, new RegExp(`eunomia-mcp@${SERVER_VERSION.replace(/\./g, "\\.")}`));
  } finally {
    rmSync(tmpHome, { recursive: true, force: true });
  }
});
