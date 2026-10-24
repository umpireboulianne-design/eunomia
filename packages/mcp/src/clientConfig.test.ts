import { test } from "node:test";
import assert from "node:assert/strict";
import { configPath, configSnippet, mergeServer, serverEntry } from "./clientConfig.js";

const ENV = { EUNOMIA_TREASURY: "CTREASURY", EUNOMIA_NETWORK: "pubnet" };

test("the config is merged: other servers and settings survive", () => {
  const existing = JSON.stringify({ theme: "dark", mcpServers: { other: { command: "x", args: [] } } });
  const out = JSON.parse(mergeServer(existing, serverEntry(ENV, "linux")));
  assert.equal(out.theme, "dark");
  assert.deepEqual(out.mcpServers.other, { command: "x", args: [] });
  assert.deepEqual(out.mcpServers.eunomia, { command: "npx", args: ["-y", "eunomia-mcp"], env: ENV });
});

test("a missing or empty config starts fresh", () => {
  assert.deepEqual(Object.keys(JSON.parse(mergeServer(null, serverEntry(ENV, "linux"))).mcpServers), ["eunomia"]);
  assert.deepEqual(Object.keys(JSON.parse(mergeServer("  ", serverEntry(ENV, "linux"))).mcpServers), ["eunomia"]);
});

test("a config that is not a JSON object is never overwritten", () => {
  assert.throws(() => mergeServer("[1,2]", serverEntry(ENV, "linux")), /not a JSON object/);
  assert.throws(() => mergeServer("{ broken", serverEntry(ENV, "linux")));
});

test("on Windows the desktop clients start npx through cmd", () => {
  assert.deepEqual(serverEntry(ENV, "win32").args, ["/c", "npx", "-y", "eunomia-mcp"]);
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

test("configSnippet builds all 3 clients from serverEntry across posix and win32", () => {
  const posixJson = JSON.stringify(
    {
      mcpServers: {
        eunomia: {
          command: "npx",
          args: ["-y", "eunomia-mcp"],
          env: ENV,
        },
      },
    },
    null,
    2,
  );
  const win32Json = JSON.stringify(
    {
      mcpServers: {
        eunomia: {
          command: "cmd",
          args: ["/c", "npx", "-y", "eunomia-mcp"],
          env: ENV,
        },
      },
    },
    null,
    2,
  );

  assert.equal(configSnippet(ENV, "claude-desktop", "linux"), posixJson);
  assert.equal(configSnippet(ENV, "cursor", "linux"), posixJson);
  assert.equal(configSnippet(ENV, "json", "linux"), posixJson);
  assert.equal(
    configSnippet(ENV, "claude-code", "linux"),
    "claude mcp add --scope user eunomia -e EUNOMIA_TREASURY=CTREASURY -e EUNOMIA_NETWORK=pubnet -- npx -y eunomia-mcp",
  );

  assert.equal(configSnippet(ENV, "claude-desktop", "win32"), win32Json);
  assert.equal(configSnippet(ENV, "cursor", "win32"), win32Json);
  assert.equal(configSnippet(ENV, "json", "win32"), win32Json);
  assert.equal(
    configSnippet(ENV, "claude-code", "win32"),
    "claude mcp add --scope user eunomia -e EUNOMIA_TREASURY=CTREASURY -e EUNOMIA_NETWORK=pubnet -- cmd /c npx -y eunomia-mcp",
  );

  assert.throws(() => configSnippet(ENV, "unknown" as never, "linux"), /Unknown --client "unknown"/);
});

