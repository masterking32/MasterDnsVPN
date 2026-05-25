import { createServer } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import net from "node:net";
import {
  BINARY,
  CONFIG_FILE,
  GOOD_RESOLVERS_FILE,
  LOG_FILE,
  PORT,
  RESOLVERS_FILE,
  ROOT,
  RULES_FILE,
  RUNS_FILE,
  SCHEMA_FILE
} from "./paths.js";
import { serveStatic } from "./static.js";
import { sendJson } from "./utils/http.js";

let clientProcess = null;
let startedAt = null;
let runStatus = "disconnected";
let logLines = [];
let parsedEvents = [];
let metrics = defaultMetrics();
let telemetry = defaultTelemetry();
const ignoredRecommendationIds = new Set();
const sseClients = new Set();

const directRecommendations = [
  {
    key: "RESOLVER_BALANCING_STRATEGY",
    recommended: 6,
    profile: "balanced",
    impact: "throughput + resolver distribution",
    risk: "low",
    requiresServerChange: false,
    applyMode: "direct",
    rationale: "Loss Then Latency balances quality and distribution better than pure least-loss on large pools."
  },
  {
    key: "SAVE_MTU_SERVERS_TO_FILE",
    recommended: true,
    profile: "balanced",
    impact: "maintainability + resolver reuse",
    risk: "low",
    requiresServerChange: false,
    applyMode: "direct",
    rationale: "Exports successful MTU-tested resolvers after startup."
  },
  {
    key: "MTU_SERVERS_FILE_FORMAT",
    recommended: "{IP}",
    profile: "balanced",
    impact: "clean resolver export",
    risk: "low",
    requiresServerChange: false,
    applyMode: "direct",
    rationale: "Produces a directly reusable one-IP-per-line resolver file."
  },
  {
    key: "DATA_ENCRYPTION_METHOD",
    recommended: 2,
    profile: "security",
    impact: "stronger tunnel encryption",
    risk: "medium",
    requiresServerChange: true,
    applyMode: "manual-server-coordinated",
    rationale: "ChaCha20 is a better security/performance compromise than XOR, but the server must match."
  }
];

const stages = [
  { id: "resource-load", title: "Resource Load", dependencies: [], target: "Load markdown, schema, TOML, resolvers, and binary version." },
  { id: "config-validation", title: "Config Validation", dependencies: ["resource-load"], target: "Check required keys, ranges, cross-field constraints, and port conflicts." },
  { id: "optimization-review", title: "Optimization Review", dependencies: ["config-validation"], target: "Show direct, optional, and server-coordinated recommendations." },
  { id: "apply-preview", title: "Apply Preview", dependencies: ["optimization-review"], target: "Render a diff before changing TOML." },
  { id: "run-observe", title: "Run & Observe", dependencies: ["apply-preview"], target: "Start/stop client and parse lifecycle log events." },
  { id: "feedback-loop", title: "Feedback Loop", dependencies: ["run-observe"], target: "Adapt recommendations from MTU, loss, latency, and errors." }
];

export const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === "/api/events") return handleEvents(req, res);
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url);
    return await serveStatic(req, res, url);
  } catch (error) {
    sendJson(res, 500, { error: error.message });
  }
});

export function startDashboard() {
  ensureOptimizerRulesFile();
  loadExistingLogFile();
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`MasterDnsVPN dashboard: http://127.0.0.1:${PORT}`);
  });
  return server;
}

async function handleApi(req, res, url) {
  if (req.method === "GET" && url.pathname === "/api/state") {
    return sendJson(res, 200, await buildState());
  }
  if (req.method === "GET" && url.pathname === "/api/config") {
    return sendJson(res, 200, { config: parseToml(readText(CONFIG_FILE)), raw: readText(CONFIG_FILE) });
  }
  if (req.method === "GET" && url.pathname === "/api/editor") {
    return sendJson(res, 200, {
      configText: readText(CONFIG_FILE),
      resolverText: readText(RESOLVERS_FILE),
      running: Boolean(clientProcess)
    });
  }
  if (req.method === "POST" && url.pathname === "/api/save-editor") {
    const body = await readRequestJson(req);
    const result = await saveEditor(body);
    return sendJson(res, 200, result);
  }
  if (req.method === "POST" && url.pathname === "/api/strip-config-comments") {
    const body = await readRequestJson(req);
    const configText = removeTomlComments(String(body.configText || ""));
    return sendJson(res, 200, { configText });
  }
  if (req.method === "GET" && url.pathname === "/api/recommendations") {
    return sendJson(res, 200, buildRecommendations(parseToml(readText(CONFIG_FILE))));
  }
  if (req.method === "GET" && url.pathname === "/api/telemetry") {
    return sendJson(res, 200, buildTelemetrySnapshot(parseToml(readText(CONFIG_FILE))));
  }
  if (req.method === "GET" && url.pathname === "/api/rules") {
    const config = parseToml(readText(CONFIG_FILE));
    return sendJson(res, 200, { rules: loadOptimizerRules(), evaluation: buildDynamicRecommendations(config) });
  }
  if (req.method === "GET" && url.pathname === "/api/recommendations/dynamic") {
    return sendJson(res, 200, buildDynamicRecommendations(parseToml(readText(CONFIG_FILE))));
  }
  if (req.method === "POST" && url.pathname === "/api/network-context") {
    const body = await readRequestJson(req);
    return sendJson(res, 200, setNetworkContext(body.context));
  }
  if (req.method === "GET" && url.pathname === "/api/ai-context") {
    return sendJson(res, 200, buildAIContext(parseToml(readText(CONFIG_FILE))));
  }
  if (req.method === "GET" && url.pathname === "/api/run-summaries") {
    return sendJson(res, 200, { runs: loadRunSummaries() });
  }
  if (req.method === "POST" && url.pathname === "/api/recommendations/preview-patch") {
    const body = await readRequestJson(req);
    return sendJson(res, 200, previewRecommendationPatch(body));
  }
  if (req.method === "POST" && url.pathname === "/api/recommendations/ignore") {
    const body = await readRequestJson(req);
    if (body.id) ignoredRecommendationIds.add(String(body.id));
    return sendJson(res, 200, { ignored: Array.from(ignoredRecommendationIds) });
  }
  if (req.method === "POST" && url.pathname === "/api/resolvers/export-good") {
    const body = await readRequestJson(req);
    return sendJson(res, 200, exportGoodResolvers(body.context));
  }
  if (req.method === "GET" && url.pathname === "/api/preview-balanced") {
    return sendJson(res, 200, previewBalanced());
  }
  if (req.method === "POST" && url.pathname === "/api/apply-balanced") {
    const applied = applyBalanced();
    return sendJson(res, 200, { applied, state: await buildState() });
  }
  if (req.method === "POST" && url.pathname === "/api/start") {
    return sendJson(res, 200, startClient());
  }
  if (req.method === "POST" && url.pathname === "/api/stop") {
    return sendJson(res, 200, stopClient());
  }
  if (req.method === "POST" && url.pathname === "/api/smoke") {
    return sendJson(res, 200, await runSmokeTest());
  }
  if (req.method === "GET" && url.pathname === "/api/resolvers") {
    return sendJson(res, 200, getResolvers(url));
  }
  sendJson(res, 404, { error: "Not found" });
}

async function buildState() {
  const config = parseToml(readText(CONFIG_FILE));
  const schema = JSON.parse(readText(SCHEMA_FILE));
  const docs = await markdownInventory();
  const resolverCount = lineCount(readText(RESOLVERS_FILE));
  const version = await binaryVersion();
  const validations = await validateConfig(config, schema);
  const recommendations = buildRecommendations(config);
  const dynamicRecommendations = buildDynamicRecommendations(config);
  const telemetrySnapshot = buildTelemetrySnapshot(config);
  return {
    app: { root: ROOT, port: PORT, binary: BINARY ? basename(BINARY) : null },
    runtime: {
      status: runStatus,
      pid: clientProcess?.pid || null,
      startedAt,
      uptimeSeconds: startedAt ? Math.floor((Date.now() - startedAt) / 1000) : 0,
      logFile: LOG_FILE
    },
    facts: {
      version,
      resolverCount,
      proxy: `${config.LISTEN_IP || "127.0.0.1"}:${config.LISTEN_PORT || 18000}`,
      localDnsEnabled: Boolean(config.LOCAL_DNS_ENABLED)
    },
    stages: buildStages(validations, recommendations),
    config,
    docs,
    validations,
    recommendations,
    dynamicRecommendations,
    telemetry: telemetrySnapshot,
    metrics,
    logs: logLines.slice(-200),
    parsedEvents: parsedEvents.slice(-100),
    schematic: [
      ["Overview", "Plan Stages", "Config Optimizer"],
      ["Resolver Pool", "Run Logs", "AI Monitor"],
      ["Profiles", "Apply Preview", "Smoke Tests"]
    ]
  };
}

function buildStages(validations, recommendations) {
  const directRemaining = recommendations.items.filter((item) => item.applyMode === "direct" && item.current !== item.recommended);
  return stages.map((stage) => {
    if (stage.id === "resource-load") return stageState(stage, "done", 100);
    if (stage.id === "config-validation") return stageState(stage, validations.errors.length ? "blocked" : "done", validations.errors.length ? 55 : 100);
    if (stage.id === "optimization-review") return stageState(stage, "done", 100);
    if (stage.id === "apply-preview") return stageState(stage, directRemaining.length ? "running" : "done", directRemaining.length ? 65 : 100);
    if (stage.id === "run-observe") return stageState(stage, clientProcess ? "running" : "pending", clientProcess ? 60 : 0);
    return stageState(stage, metrics.runs > 0 ? "done" : "pending", metrics.runs > 0 ? 100 : 0);
  });
}

function stageState(stage, status, progress) {
  return { ...stage, status, progress, actions: stageActions(stage.id, status) };
}

function stageActions(id, status) {
  if (id === "apply-preview") return ["Preview Balanced", "Apply Balanced"];
  if (id === "run-observe") return clientProcess ? ["Stop Client"] : ["Start Client"];
  if (id === "feedback-loop") return ["Run Smoke Test", "Review AI Monitor"];
  return status === "blocked" ? ["Fix Validation"] : [];
}

async function validateConfig(config, schema) {
  const errors = [];
  const warnings = [];
  const props = schema.properties || {};
  for (const [key, spec] of Object.entries(props)) {
    if ((spec.required || schema.required?.includes(key)) && config[key] === undefined) {
      errors.push(`${key} is required.`);
    }
    if (config[key] === undefined) continue;
    const value = config[key];
    if (spec.type === "integer" && !Number.isInteger(value)) errors.push(`${key} must be an integer.`);
    if (spec.type === "number" && typeof value !== "number") errors.push(`${key} must be a number.`);
    if (spec.type === "boolean" && typeof value !== "boolean") errors.push(`${key} must be a boolean.`);
    if (spec.type === "string" && typeof value !== "string") errors.push(`${key} must be a string.`);
    if (spec.type === "array" && !Array.isArray(value)) errors.push(`${key} must be an array.`);
    if (typeof value === "number") {
      if (spec.minimum !== undefined && value < spec.minimum) errors.push(`${key} is below minimum ${spec.minimum}.`);
      if (spec.maximum !== undefined && value > spec.maximum) errors.push(`${key} is above maximum ${spec.maximum}.`);
      if (spec.exclusiveMinimum !== undefined && value <= spec.exclusiveMinimum) errors.push(`${key} must be greater than ${spec.exclusiveMinimum}.`);
    }
    if (spec.enum && !spec.enum.includes(value)) errors.push(`${key} is not one of ${spec.enum.join(", ")}.`);
  }
  if ((config.MIN_UPLOAD_MTU ?? 0) > (config.MAX_UPLOAD_MTU ?? Infinity)) errors.push("MIN_UPLOAD_MTU must be <= MAX_UPLOAD_MTU.");
  if ((config.MIN_DOWNLOAD_MTU ?? 0) > (config.MAX_DOWNLOAD_MTU ?? Infinity)) errors.push("MIN_DOWNLOAD_MTU must be <= MAX_DOWNLOAD_MTU.");
  if ((config.PING_AGGRESSIVE_INTERVAL_SECONDS ?? 0) >= (config.PING_LAZY_INTERVAL_SECONDS ?? Infinity)) warnings.push("PING_AGGRESSIVE_INTERVAL_SECONDS should be lower than PING_LAZY_INTERVAL_SECONDS.");
  if ((config.PING_WARM_THRESHOLD_SECONDS ?? 0) >= (config.PING_COOL_THRESHOLD_SECONDS ?? Infinity)) warnings.push("PING_WARM_THRESHOLD_SECONDS should be lower than PING_COOL_THRESHOLD_SECONDS.");
  if (config.DATA_ENCRYPTION_METHOD === 1) warnings.push("DATA_ENCRYPTION_METHOD=1 uses XOR. ChaCha20 is recommended only with matching server config.");
  if (config.LOCAL_DNS_ENABLED && await isPortOpen(config.LOCAL_DNS_IP || "127.0.0.1", config.LOCAL_DNS_PORT || 53)) {
    errors.push(`LOCAL_DNS ${config.LOCAL_DNS_IP}:${config.LOCAL_DNS_PORT} appears to be in use.`);
  }
  return { errors, warnings };
}

async function validateConfigText(configText) {
  const schema = JSON.parse(readText(SCHEMA_FILE));
  const config = parseToml(configText);
  const validations = await validateConfig(config, schema);
  if (!configText.trim()) validations.errors.push("Configuration cannot be empty.");
  if (!Object.hasOwn(config, "DOMAINS")) validations.errors.push("DOMAINS is required.");
  if (!Object.hasOwn(config, "ENCRYPTION_KEY")) validations.errors.push("ENCRYPTION_KEY is required.");
  if (Array.isArray(config.DOMAINS) && config.DOMAINS.length === 0) validations.errors.push("DOMAINS must contain at least one domain.");
  if (typeof config.ENCRYPTION_KEY === "string" && !config.ENCRYPTION_KEY.trim()) validations.errors.push("ENCRYPTION_KEY cannot be empty.");
  return { config, validations };
}

async function saveEditor(body) {
  const configText = String(body.configText ?? "");
  const resolverText = String(body.resolverText ?? "");
  const shouldRestart = Boolean(body.restart);
  const resolvers = normalizeResolvers(resolverText);
  const { config, validations } = await validateConfigText(configText);

  if (resolvers.length === 0) validations.errors.push("Add at least one resolver before saving.");
  if (validations.errors.length) {
    return { saved: false, errors: validations.errors, warnings: validations.warnings };
  }

  writeFileSync(CONFIG_FILE, ensureTrailingNewline(configText), "utf8");
  writeFileSync(RESOLVERS_FILE, `${resolvers.join("\n")}\n`, "utf8");

  const restartResult = shouldRestart && clientProcess ? restartClient() : null;

  return {
    saved: true,
    config,
    resolverCount: resolvers.length,
    warnings: validations.warnings,
    running: Boolean(clientProcess),
    restartResult,
    message: clientProcess && !shouldRestart
      ? "Saved. Restart the client for changes to affect the running process."
      : "Saved."
  };
}

function normalizeResolvers(text) {
  const seen = new Set();
  const resolvers = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (seen.has(line)) continue;
    seen.add(line);
    resolvers.push(line);
  }
  return resolvers;
}

function buildRecommendations(config) {
  const items = directRecommendations.map((item) => ({ ...item, current: config[item.key] }));
  const monitor = [];
  if (metrics.timeoutWarnings > 20) monitor.push("Many resolver timeout warnings detected; consider lowering MTU_TEST_PARALLELISM or increasing MTU_TEST_TIMEOUT.");
  if (metrics.mtuRejected > 50 && metrics.mtuValid === 0) monitor.push("Last run rejected many resolvers with no valid MTU path. Verify DOMAINS delegation, server reachability on UDP 53, ENCRYPTION_KEY, and DATA_ENCRYPTION_METHOD before tuning performance.");
  if (metrics.lastRejectReason === "UPLOAD_MTU") monitor.push("Upload MTU rejections dominated the last run; increasing MTU_TEST_TIMEOUT or reducing MTU_TEST_PARALLELISM may help only after server/domain reachability is confirmed.");
  if (metrics.noValidConnections) monitor.push("The client exited because MTU testing found no valid connections.");
  if (metrics.arqEvents > 10) monitor.push("ARQ retransmission/NACK activity is high; consider Reliability profile.");
  if (metrics.syncedUploadMtu && metrics.syncedUploadMtu < 80) monitor.push("Synced upload MTU is low; keep AUTO_REMOVE_LOW_MTU_SERVERS enabled and export healthy resolvers.");
  if (!monitor.length) monitor.push("No run-derived changes yet. Start the client or run a smoke test to collect feedback.");
  return { profile: "balanced", items, monitor };
}

function buildTelemetrySnapshot(config) {
  const validRatio = metrics.mtuTotal ? (metrics.mtuValid || 0) / metrics.mtuTotal : null;
  const now = Date.now();
  const recentStreams = telemetry.streams.timestamps.filter((time) => now - time <= 60_000);
  const context = contextSummary();
  const evaluationContext = effectiveNetworkContext(context.selected);
  const activeResolvers = contextActiveResolvers(evaluationContext);
  return {
    generatedAt: new Date().toISOString(),
    networkContext: context,
    config: {
      resolverStrategy: config.RESOLVER_BALANCING_STRATEGY,
      packetDuplication: config.PACKET_DUPLICATION_COUNT,
      uploadCompression: config.UPLOAD_COMPRESSION_TYPE,
      downloadCompression: config.DOWNLOAD_COMPRESSION_TYPE,
      minUploadMtu: config.MIN_UPLOAD_MTU,
      maxUploadMtu: config.MAX_UPLOAD_MTU,
      minDownloadMtu: config.MIN_DOWNLOAD_MTU,
      maxDownloadMtu: config.MAX_DOWNLOAD_MTU,
      mtuParallelism: config.MTU_TEST_PARALLELISM,
      tunnelProcessWorkers: config.TUNNEL_PROCESS_WORKERS,
      tunnelPacketTimeout: config.TUNNEL_PACKET_TIMEOUT_SECONDS
    },
    mtu: {
      totalResolvers: metrics.mtuTotal,
      validResolvers: metrics.mtuValid,
      rejectedResolvers: metrics.mtuRejected,
      validRatio,
      syncedUploadMtu: metrics.syncedUploadMtu,
      syncedDownloadMtu: metrics.syncedDownloadMtu,
      rejectsByReason: Object.fromEntries(telemetry.mtu.rejectsByReason),
      validTable: telemetry.mtu.validResolvers.slice(-100)
    },
    compression: telemetry.compression,
    session: telemetry.session,
    runtime: {
      status: runStatus,
      pid: clientProcess?.pid || null,
      rxTxWorkers: telemetry.runtime.rxTxWorkers,
      processWorkers: telemetry.runtime.processWorkers,
      stateDrift: detectStateDrift()
    },
    streams: {
      total: telemetry.streams.total,
      perMinute: recentStreams.length,
      topTargets: topEntries(telemetry.streams.targets, 12)
    },
    resolvers: {
      activeTotal: activeResolvers,
      disabled: Array.from(telemetry.resolvers.disabled.values()).slice(-100),
      reactivated: Array.from(telemetry.resolvers.reactivated.values()).slice(-100),
      knownGood: knownGoodResolvers(evaluationContext).slice(0, 200)
    },
    scores: buildOptimizerScores(validRatio, activeResolvers, recentStreams.length),
    recentImportantEvents: importantEvents(80)
  };
}

function buildDynamicRecommendations(config) {
  const rules = loadOptimizerRules();
  const recs = [];
  const context = contextSummary();
  const selectedContext = effectiveNetworkContext(context.selected);
  const validRatio = metrics.mtuTotal ? (metrics.mtuValid || 0) / metrics.mtuTotal : null;
  const rejectReasons = Object.fromEntries(telemetry.mtu.rejectsByReason);
  const uploadRejects = rejectReasons.UPLOAD_MTU || 0;
  const downloadRejects = rejectReasons.DOWNLOAD_MTU || 0;
  const recentStreamRate = telemetry.streams.timestamps.filter((time) => Date.now() - time <= 60_000).length;
  const activeTotal = contextActiveResolvers(selectedContext);
  const stateDrift = detectStateDrift();

  if (selectedContext !== "unfiltered" && validRatio !== null && validRatio < 0.01 && telemetry.session.initialized) {
    recs.push(ruleRecommendation(rules, "low-valid-ratio-session-ok", {
      configPatch: {
        SAVE_MTU_SERVERS_TO_FILE: true,
        MTU_SERVERS_FILE_FORMAT: "{IP}"
      },
      evidence: [
        `${metrics.mtuValid || 0}/${metrics.mtuTotal || 0} resolvers passed MTU testing.`,
        `Session initialized successfully${telemetry.session.id ? ` with ID ${telemetry.session.id}` : ""}.`
      ]
    }));
  }

  if (selectedContext !== "unfiltered" && uploadRejects > downloadRejects && config.MIN_UPLOAD_MTU === config.MAX_UPLOAD_MTU && config.MIN_UPLOAD_MTU <= 64) {
    recs.push(ruleRecommendation(rules, "keep-fixed-low-upload-mtu", {
      configPatch: {
        MIN_UPLOAD_MTU: config.MIN_UPLOAD_MTU,
        MAX_UPLOAD_MTU: config.MAX_UPLOAD_MTU
      },
      evidence: [
        `UPLOAD_MTU rejects dominate (${uploadRejects} upload vs ${downloadRejects} download).`,
        `Upload MTU is fixed at ${config.MIN_UPLOAD_MTU}.`
      ]
    }));
  }

  if (selectedContext !== "unfiltered" && downloadRejects > 0 && metrics.syncedDownloadMtu && config.MAX_DOWNLOAD_MTU > metrics.syncedDownloadMtu) {
    recs.push(ruleRecommendation(rules, "lower-download-mtu-upper-bound", {
      configPatch: {
        MAX_DOWNLOAD_MTU: metrics.syncedDownloadMtu
      },
      evidence: [
        `${downloadRejects} DOWNLOAD_MTU rejects were observed.`,
        `Synced download MTU settled at ${metrics.syncedDownloadMtu}, below MAX_DOWNLOAD_MTU=${config.MAX_DOWNLOAD_MTU}.`
      ]
    }));
  }

  if (selectedContext !== "unfiltered" && telemetry.compression.uploadDisabledReason && telemetry.compression.effectiveUpload === "OFF") {
    recs.push(ruleRecommendation(rules, "disable-upload-compression-low-mtu", {
      configPatch: {
        UPLOAD_COMPRESSION_TYPE: 0,
        DOWNLOAD_COMPRESSION_TYPE: config.DOWNLOAD_COMPRESSION_TYPE
      },
      evidence: [
        `Upload compression disabled by runtime: ${telemetry.compression.uploadDisabledReason}.`,
        `Effective compression is Upload=${telemetry.compression.effectiveUpload}, Download=${telemetry.compression.effectiveDownload || "unknown"}.`
      ]
    }));
  }

  if (telemetry.resolvers.reactivated.size > 0 && selectedContext !== "filtered") {
    recs.push(ruleRecommendation(rules, "wait-and-export-reactivated-resolvers", {
      configPatch: {},
      evidence: [
        `${telemetry.resolvers.reactivated.size} resolvers reactivated after startup.`,
        `Active resolver total reached ${telemetry.context.reactivationBurst.maxActive || activeTotal}.`
      ]
    }));
  }

  if (telemetry.resolvers.disabled.size > 0) {
    recs.push(ruleRecommendation(rules, "downgrade-lossy-resolvers", {
      configPatch: {},
      evidence: [
        `${telemetry.resolvers.disabled.size} resolvers disabled during runtime.`,
        "Disabled resolvers will be excluded from known-good export."
      ]
    }));
  }

  if (telemetry.session.initialized && recentStreamRate > 60 && activeTotal > 0 && activeTotal < 10) {
    recs.push(ruleRecommendation(rules, "high-stream-rate-low-active-resolvers", {
      configPatch: {},
      evidence: [
        `${recentStreamRate} SOCKS streams opened in the last minute.`,
        `Only ${activeTotal} active resolvers are currently known.`
      ]
    }));
  }

  if (stateDrift) {
    recs.push(ruleRecommendation(rules, "wrapper-state-drift", {
      configPatch: {},
      evidence: [
        `Dashboard state is ${runStatus} while PID ${clientProcess?.pid || "unknown"} still appears active.`
      ]
    }));
  }

  return {
    generatedAt: new Date().toISOString(),
    networkContext: context,
    ignored: Array.from(ignoredRecommendationIds),
    recommendations: recs.filter((rec) => !ignoredRecommendationIds.has(rec.id))
  };
}

function ruleRecommendation(rules, id, override) {
  const rule = rules.find((item) => item.id === id) || {};
  return {
    id,
    severity: rule.severity || "info",
    condition: rule.condition || "",
    recommendation: rule.recommendation || "",
    confidence: rule.confidence || "medium",
    requiresRestart: Boolean(rule.requiresRestart),
    requiresServerChange: Boolean(rule.requiresServerChange),
    configPatch: override.configPatch || rule.configPatch || {},
    evidence: override.evidence || [],
    applyMode: Object.keys(override.configPatch || {}).length ? "preview-only" : "advisory"
  };
}

function previewRecommendationPatch(body) {
  const selectedIds = new Set((body.ids || []).map(String));
  const dynamic = buildDynamicRecommendations(parseToml(readText(CONFIG_FILE))).recommendations;
  const patch = {};
  for (const rec of dynamic) {
    if (selectedIds.size && !selectedIds.has(rec.id)) continue;
    if (rec.requiresServerChange) continue;
    for (const [key, value] of Object.entries(rec.configPatch || {})) {
      if (["DOMAINS", "ENCRYPTION_KEY", "DATA_ENCRYPTION_METHOD"].includes(key)) continue;
      patch[key] = value;
    }
  }
  const original = readText(CONFIG_FILE);
  const updated = updateToml(original, Object.entries(patch).map(([key, recommended]) => ({ key, recommended })));
  return {
    changed: original !== updated,
    patch,
    diff: simpleDiff(original, updated)
  };
}

function buildAIContext(config) {
  const redactedConfig = {};
  const keys = [
    "DOMAINS",
    "DATA_ENCRYPTION_METHOD",
    "ENCRYPTION_KEY",
    "RESOLVER_BALANCING_STRATEGY",
    "PACKET_DUPLICATION_COUNT",
    "SETUP_PACKET_DUPLICATION_COUNT",
    "UPLOAD_COMPRESSION_TYPE",
    "DOWNLOAD_COMPRESSION_TYPE",
    "MIN_UPLOAD_MTU",
    "MAX_UPLOAD_MTU",
    "MIN_DOWNLOAD_MTU",
    "MAX_DOWNLOAD_MTU",
    "MTU_TEST_RETRIES",
    "MTU_TEST_TIMEOUT",
    "MTU_TEST_PARALLELISM",
    "AUTO_REMOVE_LOW_MTU_SERVERS",
    "TUNNEL_PROCESS_WORKERS",
    "RX_TX_WORKERS",
    "TUNNEL_PACKET_TIMEOUT_SECONDS",
    "ARQ_WINDOW_SIZE",
    "LOG_LEVEL"
  ];
  for (const key of keys) {
    if (key in config) redactedConfig[key] = key === "ENCRYPTION_KEY" ? maskSecret(config[key]) : config[key];
  }
  return {
    generatedAt: new Date().toISOString(),
    version: BINARY ? basename(BINARY) : null,
    networkContext: contextSummary(),
    config: redactedConfig,
    telemetry: buildTelemetrySnapshot(config),
    recommendations: buildDynamicRecommendations(config).recommendations,
    topWarnings: importantEvents(50).filter((event) => ["mtu-reject", "mtu-failed", "resolver-disabled", "compression"].includes(event.type)).slice(-20)
  };
}

function previewBalanced() {
  const original = readText(CONFIG_FILE);
  const updated = updateToml(original, directRecommendations.filter((item) => item.applyMode === "direct"));
  return { changed: original !== updated, diff: simpleDiff(original, updated) };
}

function applyBalanced() {
  const original = readText(CONFIG_FILE);
  const direct = directRecommendations.filter((item) => item.applyMode === "direct");
  const updated = updateToml(original, direct);
  if (updated !== original) writeFileSync(CONFIG_FILE, updated);
  return direct.map((item) => item.key);
}

function updateToml(text, recommendations) {
  let next = text;
  for (const item of recommendations) {
    const value = formatTomlValue(item.recommended);
    const pattern = new RegExp(`^(${escapeRegExp(item.key)}\\s*=\\s*).*$`, "m");
    if (pattern.test(next)) next = next.replace(pattern, `$1${value}`);
  }
  return next;
}

function startClient() {
  if (clientProcess) return { status: "already-running", pid: clientProcess.pid };
  if (!BINARY) return { status: "error", error: "Client binary not found." };
  logLines = [];
  parsedEvents = [];
  metrics = defaultMetrics();
  telemetry = defaultTelemetry();
  startedAt = Date.now();
  runStatus = "connecting";
  writeFileSync(LOG_FILE, "");
  clientProcess = spawn(BINARY, ["-config", CONFIG_FILE], { cwd: ROOT });
  attachProcessStream(clientProcess.stdout, "stdout");
  attachProcessStream(clientProcess.stderr, "stderr");
  clientProcess.on("exit", (code, signal) => {
    appendLog(`[INFO] Client exited code=${code} signal=${signal || "none"}`, "system");
    persistRunSummary(code, signal);
    clientProcess = null;
    runStatus = "disconnected";
    metrics.runs += 1;
    broadcast({ type: "state", payload: { status: runStatus } });
  });
  return { status: "started", pid: clientProcess.pid };
}

function stopClient() {
  if (!clientProcess) return { status: "not-running" };
  clientProcess.kill("SIGTERM");
  runStatus = "stopping";
  return { status: "stopping", pid: clientProcess.pid };
}

function restartClient() {
  if (!clientProcess) return startClient();
  const pid = clientProcess.pid;
  clientProcess.once("exit", () => {
    setTimeout(() => startClient(), 300);
  });
  stopClient();
  return { status: "restarting", pid };
}

async function runSmokeTest() {
  const config = parseToml(readText(CONFIG_FILE));
  const proxy = `${config.LISTEN_IP || "127.0.0.1"}:${config.LISTEN_PORT || 18000}`;
  const result = await runCommand("curl", ["--socks5", proxy, "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "10", "http://httpbin.org/ip"], 15000);
  metrics.smokeTests += 1;
  metrics.lastSmoke = { proxy, ok: result.stdout.trim() === "200", output: result.stdout.trim(), error: result.stderr.trim(), code: result.code };
  broadcast({ type: "metrics", payload: metrics });
  return metrics.lastSmoke;
}

function attachProcessStream(stream, source) {
  const rl = createInterface({ input: stream });
  rl.on("line", (line) => appendLog(line, source));
}

function appendLog(line, source) {
  const item = { time: new Date().toISOString(), source, line };
  logLines.push(item);
  if (logLines.length > 1000) logLines.shift();
  parseLogLine(item);
  writeFileSync(LOG_FILE, logLines.map((entry) => `${entry.time} ${entry.source} ${entry.line}`).join("\n") + "\n");
  broadcast({ type: "log", payload: item });
}

function loadExistingLogFile() {
  if (!existsSync(LOG_FILE)) return;
  const lines = readText(LOG_FILE).split(/\r?\n/).filter(Boolean).slice(-1000);
  for (const line of lines) {
    const match = line.match(/^(\S+)\s+(\S+)\s+(.+)$/);
    const item = match
      ? { time: match[1], source: match[2], line: match[3] }
      : { time: new Date().toISOString(), source: "file", line };
    logLines.push(item);
    parseLogLine(item, false);
  }
}

function parseLogLine(item) {
  const line = item.line;
  let type = null;
  let details = {};
  if (/Async Runtime Initialized:/i.test(line)) {
    type = "runtime";
    const match = line.match(/Async Runtime Initialized:\s+(\d+)\s+RX\/TX Workers,\s+(\d+)\s+Processors/i);
    if (match) {
      telemetry.runtime.rxTxWorkers = Number(match[1]);
      telemetry.runtime.processWorkers = Number(match[2]);
      details = { rxTxWorkers: telemetry.runtime.rxTxWorkers, processWorkers: telemetry.runtime.processWorkers };
    }
  } else if (/session.*init|initialized|SESSION_ACCEPT/i.test(line)) {
    type = "session";
    const attempt = line.match(/Session init attempt with\s+(\S+)\s+and resolver\s+(\S+)/i);
    const success = line.match(/Session Initialized Successfully \(ID:\s*(\d+)\)/i);
    if (attempt) {
      telemetry.session.attempts += 1;
      telemetry.session.initDomain = attempt[1];
      telemetry.session.initResolver = attempt[2];
      details = { domain: attempt[1], resolver: attempt[2], phase: "attempt", attempts: telemetry.session.attempts };
    }
    if (success) {
      runStatus = "connected";
      telemetry.session.initialized = true;
      telemetry.session.id = Number(success[1]);
      details = { id: telemetry.session.id, phase: "success" };
    }
    if (/Session initialization failed/i.test(line)) {
      telemetry.session.failures += 1;
      details = { phase: "failure", failures: telemetry.session.failures };
    }
    const retry = line.match(/Session init retry backoff:\s+(\S+)/i);
    if (retry) {
      telemetry.session.retries += 1;
      details = { phase: "retry", retries: telemetry.session.retries, backoff: retry[1] };
    }
  } else if (/MTU discovery.*start|Starting MTU/i.test(line)) {
    type = "mtu-start";
    metrics.mtuStartedAt = item.time;
  } else if (/MTU discovery.*complete|Synced .*MTU/i.test(line)) {
    type = "mtu";
    const upload = line.match(/Upload MTU:?\s*(\d+)/i);
    const download = line.match(/Download MTU:?\s*(\d+)/i);
    if (upload) metrics.syncedUploadMtu = Number(upload[1]);
    if (download) metrics.syncedDownloadMtu = Number(download[1]);
    details = { syncedUploadMtu: metrics.syncedUploadMtu, syncedDownloadMtu: metrics.syncedDownloadMtu };
  } else if (/^\d{4}\/\d{2}\/\d{2}.*\s+\d+\s+\d+\s+\S+\s+\S+/.test(line) && /\[INFO\]\s+\S+:\d+\s+\d+\s+\d+/.test(line)) {
    type = "valid-resolver";
    const valid = line.match(/\[INFO\]\s+(\S+:\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)/);
    if (valid) {
      details = {
        resolver: valid[1],
        uploadMtu: Number(valid[2]),
        downloadMtu: Number(valid[3]),
        resolveTime: valid[4],
        domain: valid[5]
      };
      upsertByKey(telemetry.mtu.validResolvers, details, "resolver");
    }
  } else if (/Session Compression Upload:.*Disabled/i.test(line)) {
    type = "compression";
    const match = line.match(/Session Compression Upload:\s+(\S+)\s+\(Disabled due to ([^)]+)\)/i);
    if (match) {
      telemetry.compression.requestedUpload = match[1];
      telemetry.compression.uploadDisabledReason = match[2];
      details = { requestedUpload: match[1], disabledReason: match[2] };
    }
  } else if (/Effective Compression Upload:/i.test(line)) {
    type = "compression";
    const match = line.match(/Effective Compression Upload:\s+(\S+)\s+Download:\s+(\S+)/i);
    if (match) {
      telemetry.compression.effectiveUpload = match[1];
      telemetry.compression.effectiveDownload = match[2];
      details = { effectiveUpload: match[1], effectiveDownload: match[2] };
    }
  } else if (/New SOCKS5 TCP CONNECT/i.test(line)) {
    type = "stream";
    const match = line.match(/CONNECT to\s+(.+?):(\d+),\s+Stream ID:\s+(\d+)/i);
    if (match) {
      const target = `${match[1]}:${match[2]}`;
      telemetry.streams.total += 1;
      telemetry.streams.timestamps.push(Date.parse(item.time) || Date.now());
      if (telemetry.streams.timestamps.length > 2000) telemetry.streams.timestamps = telemetry.streams.timestamps.slice(-2000);
      telemetry.streams.targets.set(target, (telemetry.streams.targets.get(target) || 0) + 1);
      details = { host: match[1], port: Number(match[2]), streamId: Number(match[3]), target };
    }
  } else if (/DNS Resolver disabled/i.test(line)) {
    type = "resolver-disabled";
    const match = line.match(/DNS Resolver disabled \(([^)]+)\):\s+(\S+).*Remaining:\s+(\d+)/i);
    if (match) {
      const entry = { resolver: match[2], reason: match[1], remaining: Number(match[3]), time: item.time };
      telemetry.resolvers.disabled.set(entry.resolver, entry);
      telemetry.resolvers.activeTotal = entry.remaining;
      telemetry.context.lowestActiveAfterDisable = telemetry.context.lowestActiveAfterDisable === null
        ? entry.remaining
        : Math.min(telemetry.context.lowestActiveAfterDisable, entry.remaining);
      details = entry;
    }
  } else if (/DNS Resolver Reactivated/i.test(line)) {
    type = "resolver-reactivated";
    const match = line.match(/DNS Resolver Reactivated:\s+(\S+).*Total Active:\s+(\d+)/i);
    if (match) {
      const entry = { resolver: match[1], activeTotal: Number(match[2]), time: item.time };
      telemetry.resolvers.reactivated.set(entry.resolver, entry);
      telemetry.resolvers.activeTotal = entry.activeTotal;
      recordReactivationBurst(entry);
      details = entry;
    }
  } else if (/timeout/i.test(line)) {
    type = "timeout";
    metrics.timeoutWarnings += 1;
  } else if (/Rejected .*reason=/i.test(line)) {
    type = "mtu-reject";
    metrics.mtuRejectedEvents += 1;
    const totals = line.match(/totals:\s*valid=(\d+),\s*rejected=(\d+)/i);
    const total = line.match(/Rejected\s*\((\d+)\/(\d+)\)/i);
    const reason = line.match(/reason=([A-Z0-9_]+)/i);
    if (totals) {
      metrics.mtuValid = Number(totals[1]);
      metrics.mtuRejected = Math.max(metrics.mtuRejected, Number(totals[2]));
    } else {
      metrics.mtuRejected = Math.max(metrics.mtuRejected, metrics.mtuRejectedEvents);
    }
    if (total) metrics.mtuTotal = Number(total[2]);
    if (reason) metrics.lastRejectReason = reason[1];
    if (reason) telemetry.mtu.rejectsByReason.set(reason[1], (telemetry.mtu.rejectsByReason.get(reason[1]) || 0) + 1);
    details = {
      resolver: line.match(/via\s+(\S+)/i)?.[1] || null,
      domain: line.match(/Rejected \([^)]*\):\s+(\S+)/i)?.[1] || null,
      reason: reason?.[1] || null,
      value: Number(line.match(/value=(\d+)/i)?.[1] || 0),
      valid: metrics.mtuValid,
      rejected: metrics.mtuRejected,
      total: metrics.mtuTotal
    };
  } else if (/retransmit|NACK|ARQ/i.test(line)) {
    type = "arq";
    metrics.arqEvents += 1;
  } else if (/No valid connections|MTU tests failed/i.test(line)) {
    type = "mtu-failed";
    metrics.errors += 1;
    metrics.noValidConnections = true;
  } else if (/\[ERROR\]|error/i.test(line)) {
    type = "error";
    metrics.errors += 1;
  }
  if (type) {
    const event = { ...item, type, details };
    parsedEvents.push(event);
    if (parsedEvents.length > 300) parsedEvents.shift();
    telemetry.events.push(event);
    if (telemetry.events.length > 1000) telemetry.events.shift();
    updateContextDetection();
    broadcast({ type: "parsed-event", payload: event });
  }
}

function handleEvents(req, res) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive"
  });
  res.write(`data: ${JSON.stringify({ type: "hello", payload: { status: runStatus } })}\n\n`);
  sseClients.add(res);
  req.on("close", () => sseClients.delete(res));
}

function broadcast(message) {
  for (const client of sseClients) {
    client.write(`data: ${JSON.stringify(message)}\n\n`);
  }
}

function getResolvers(url) {
  const query = (url.searchParams.get("q") || "").trim().toLowerCase();
  const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
  const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 100)));
  const all = readText(RESOLVERS_FILE).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const filtered = query ? all.filter((resolver) => resolver.toLowerCase().includes(query)) : all;
  return { total: all.length, filtered: filtered.length, offset, limit, items: filtered.slice(offset, offset + limit).map((value, index) => ({ index: offset + index + 1, value })) };
}

async function markdownInventory() {
  const files = await listMarkdown(ROOT);
  return files.map((file) => {
    const text = readText(file);
    return {
      path: file.replace(`${ROOT}/`, ""),
      title: (text.match(/^#\s+(.+)$/m)?.[1] || basename(file)),
      lines: lineCount(text)
    };
  });
}

async function listMarkdown(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await listMarkdown(full));
    if (entry.isFile() && entry.name.endsWith(".md")) files.push(full);
  }
  return files.sort();
}

function parseToml(text) {
  const config = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const [rawKey, ...rest] = line.split("=");
    const key = rawKey.trim();
    const value = stripInlineComment(rest.join("=").trim());
    config[key] = parseTomlValue(value);
  }
  return config;
}

function removeTomlComments(text) {
  const lines = text
    .split(/\r?\n/)
    .map(stripTomlComment)
    .filter((line, index, all) => line.trim() || (index > 0 && all[index - 1].trim()));
  return ensureTrailingNewline(lines.join("\n"));
}

function stripTomlComment(line) {
  let result = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    const previous = index > 0 ? line[index - 1] : "";
    if (character === '"' && previous !== "\\" && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
    } else if (character === "'" && previous !== "\\" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
    } else if (character === "#" && !inSingleQuote && !inDoubleQuote) {
      break;
    }
    result += character;
  }
  return result.trimEnd();
}

function parseTomlValue(value) {
  if (value.startsWith("[") && value.endsWith("]")) {
    const inner = value.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(",").map((part) => parseTomlValue(part.trim()));
  }
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) return value.slice(1, -1);
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return value;
}

function stripInlineComment(value) {
  let quoted = false;
  let quote = "";
  for (let i = 0; i < value.length; i += 1) {
    if ((value[i] === '"' || value[i] === "'") && value[i - 1] !== "\\") {
      quoted = !quoted;
      quote = quoted ? value[i] : "";
    }
    if (!quoted && value[i] === "#") return value.slice(0, i).trim();
  }
  return value.trim();
}

function ensureTrailingNewline(text) {
  return text.endsWith("\n") ? text : `${text}\n`;
}

function readRequestJson(req) {
  return new Promise((resolveRequest, rejectRequest) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
      if (body.length > 2_000_000) {
        req.destroy();
        rejectRequest(new Error("Request body is too large."));
      }
    });
    req.on("end", () => {
      if (!body.trim()) return resolveRequest({});
      try {
        resolveRequest(JSON.parse(body));
      } catch (error) {
        rejectRequest(new Error(`Invalid JSON body: ${error.message}`));
      }
    });
    req.on("error", rejectRequest);
  });
}

function formatTomlValue(value) {
  if (typeof value === "string") return `"${value.replaceAll('"', '\\"')}"`;
  if (Array.isArray(value)) return `[${value.map(formatTomlValue).join(", ")}]`;
  return String(value);
}

function simpleDiff(before, after) {
  const a = before.split(/\r?\n/);
  const b = after.split(/\r?\n/);
  const rows = [];
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) {
      if (a[i] !== undefined) rows.push({ type: "remove", line: i + 1, text: a[i] });
      if (b[i] !== undefined) rows.push({ type: "add", line: i + 1, text: b[i] });
    }
  }
  return rows;
}

async function binaryVersion() {
  if (!BINARY) return null;
  const result = await runCommand(BINARY, ["-version"], 5000);
  return result.stdout.trim() || result.stderr.trim() || null;
}

function runCommand(command, args, timeoutMs) {
  return new Promise((resolveResult) => {
    const child = spawn(command, args, { cwd: ROOT });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", (chunk) => stdout += chunk.toString());
    child.stderr.on("data", (chunk) => stderr += chunk.toString());
    child.on("close", (code) => {
      clearTimeout(timer);
      resolveResult({ code, stdout, stderr });
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolveResult({ code: -1, stdout, stderr: error.message });
    });
  });
}

function isPortOpen(host, port) {
  return new Promise((resolveResult) => {
    const socket = net.createConnection({ host, port, timeout: 300 });
    socket.on("connect", () => {
      socket.destroy();
      resolveResult(true);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolveResult(false);
    });
    socket.on("error", () => resolveResult(false));
  });
}

function defaultMetrics() {
  return {
    runs: 0,
    smokeTests: 0,
    timeoutWarnings: 0,
    mtuRejected: 0,
    mtuRejectedEvents: 0,
    mtuValid: null,
    mtuTotal: null,
    lastRejectReason: null,
    noValidConnections: false,
    arqEvents: 0,
    errors: 0,
    syncedUploadMtu: null,
    syncedDownloadMtu: null,
    mtuStartedAt: null,
    lastSmoke: null
  };
}

function defaultTelemetry() {
  return {
    events: [],
    mtu: {
      rejectsByReason: new Map(),
      validResolvers: []
    },
    compression: {
      requestedUpload: null,
      requestedDownload: null,
      effectiveUpload: null,
      effectiveDownload: null,
      uploadDisabledReason: null
    },
    session: {
      initialized: false,
      id: null,
      initDomain: null,
      initResolver: null,
      attempts: 0,
      failures: 0,
      retries: 0
    },
    runtime: {
      rxTxWorkers: null,
      processWorkers: null
    },
    streams: {
      total: 0,
      timestamps: [],
      targets: new Map()
    },
    resolvers: {
      activeTotal: null,
      disabled: new Map(),
      reactivated: new Map()
    },
    context: {
      selected: "unknown",
      detected: "unknown",
      mixed: false,
      notes: [],
      lowestActiveAfterDisable: null,
      reactivationBurst: {
        count: 0,
        firstAt: null,
        lastAt: null,
        maxActive: null
      }
    }
  };
}

function ensureOptimizerRulesFile() {
  if (existsSync(RULES_FILE)) return;
  writeFileSync(RULES_FILE, JSON.stringify(defaultOptimizerRules(), null, 2) + "\n", "utf8");
}

function defaultOptimizerRules() {
  return [
    {
      id: "low-valid-ratio-session-ok",
      severity: "warn",
      condition: "validResolvers / totalResolvers < 0.01 && session.initialized",
      recommendation: "Export and reuse working resolvers; reduce resolver-list noise after observing recovery.",
      configPatch: { SAVE_MTU_SERVERS_TO_FILE: true, MTU_SERVERS_FILE_FORMAT: "{IP}" },
      confidence: "high",
      requiresRestart: false,
      requiresServerChange: false
    },
    {
      id: "keep-fixed-low-upload-mtu",
      severity: "info",
      condition: "UPLOAD_MTU dominates rejects && MIN_UPLOAD_MTU == MAX_UPLOAD_MTU <= 64",
      recommendation: "Keep the fixed low upload MTU profile because this network rejects most upload probes.",
      configPatch: {},
      confidence: "medium",
      requiresRestart: true,
      requiresServerChange: false
    },
    {
      id: "lower-download-mtu-upper-bound",
      severity: "warn",
      condition: "DOWNLOAD_MTU rejects exist && MAX_DOWNLOAD_MTU > syncedDownloadMtu",
      recommendation: "Lower MAX_DOWNLOAD_MTU to the observed synced download MTU to reduce failed probing.",
      configPatch: {},
      confidence: "medium",
      requiresRestart: true,
      requiresServerChange: false
    },
    {
      id: "disable-upload-compression-low-mtu",
      severity: "info",
      condition: "upload compression disabled due to low MTU",
      recommendation: "Set upload compression OFF while keeping effective download compression if it works.",
      configPatch: { UPLOAD_COMPRESSION_TYPE: 0 },
      confidence: "high",
      requiresRestart: true,
      requiresServerChange: false
    },
    {
      id: "wait-and-export-reactivated-resolvers",
      severity: "info",
      condition: "resolver reactivation count > 0",
      recommendation: "Wait for background rechecks, then export active/reactivated resolvers as a cleaner resolver file.",
      configPatch: {},
      confidence: "medium",
      requiresRestart: false,
      requiresServerChange: false
    },
    {
      id: "downgrade-lossy-resolvers",
      severity: "warn",
      condition: "resolver disabled for runtime loss",
      recommendation: "Exclude 100% loss resolvers from known-good exports and future candidate lists.",
      configPatch: {},
      confidence: "high",
      requiresRestart: false,
      requiresServerChange: false
    },
    {
      id: "high-stream-rate-low-active-resolvers",
      severity: "warn",
      condition: "session.initialized && streamRate > 60/min && activeResolvers < 10",
      recommendation: "High stream pressure with few active resolvers depends heavily on packet duplication; avoid lowering duplication yet.",
      configPatch: {},
      confidence: "medium",
      requiresRestart: false,
      requiresServerChange: false
    },
    {
      id: "wrapper-state-drift",
      severity: "error",
      condition: "dashboard state is stopping while child process is alive",
      recommendation: "Reconcile wrapper process state so dashboard status matches the actual client process.",
      configPatch: {},
      confidence: "high",
      requiresRestart: false,
      requiresServerChange: false
    }
  ];
}

function loadOptimizerRules() {
  try {
    const parsed = JSON.parse(readText(RULES_FILE));
    return Array.isArray(parsed) ? parsed : defaultOptimizerRules();
  } catch {
    return defaultOptimizerRules();
  }
}

function loadRunSummaries() {
  try {
    const parsed = JSON.parse(readText(RUNS_FILE));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistRunSummary(code, signal) {
  const config = parseToml(readText(CONFIG_FILE));
  const summary = {
    time: new Date().toISOString(),
    code,
    signal: signal || null,
    runtimeSeconds: startedAt ? Math.floor((Date.now() - startedAt) / 1000) : null,
    metrics: { ...metrics },
    networkContext: contextSummary(),
    telemetry: {
      mtu: buildTelemetrySnapshot(config).mtu,
      compression: telemetry.compression,
      session: telemetry.session,
      streams: buildTelemetrySnapshot(config).streams,
      resolvers: {
        activeTotal: telemetry.resolvers.activeTotal,
        disabledCount: telemetry.resolvers.disabled.size,
        reactivatedCount: telemetry.resolvers.reactivated.size
      }
    }
  };
  const runs = loadRunSummaries();
  runs.push(summary);
  writeFileSync(RUNS_FILE, JSON.stringify(runs.slice(-50), null, 2) + "\n", "utf8");
}

function buildOptimizerScores(validRatio, activeResolvers, streamRate) {
  const resolverScore = validRatio === null ? 50 : clamp(Math.round(validRatio * 1000), 0, 100);
  const activeScore = clamp(activeResolvers * 8, 0, 100);
  const mtuScore = metrics.syncedUploadMtu && metrics.syncedDownloadMtu
    ? clamp(Math.round((metrics.syncedUploadMtu / 150) * 40 + (metrics.syncedDownloadMtu / 1000) * 60), 0, 100)
    : 0;
  const compressionScore = telemetry.compression.effectiveDownload === "LZ4" || telemetry.compression.effectiveDownload === "ZSTD" ? 75 : 45;
  const pressureScore = streamRate > 60 && activeResolvers < 10 ? 35 : streamRate > 60 ? 60 : 85;
  const healthScore = Math.round((resolverScore + activeScore + mtuScore + compressionScore + pressureScore) / 5);
  return { healthScore, activeResolverScore: activeScore, mtuScore, compressionScore, streamPressureScore: pressureScore };
}

function importantEvents(limit) {
  return telemetry.events
    .filter((event) => ["mtu", "mtu-failed", "valid-resolver", "compression", "session", "runtime", "resolver-disabled", "resolver-reactivated", "arq", "error"].includes(event.type))
    .slice(-limit);
}

function topEntries(map, limit) {
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

function upsertByKey(list, item, key) {
  const index = list.findIndex((entry) => entry[key] === item[key]);
  if (index >= 0) list[index] = item;
  else list.push(item);
}

function setNetworkContext(context) {
  const normalized = normalizeNetworkContext(context);
  telemetry.context.selected = normalized;
  return contextSummary();
}

function normalizeNetworkContext(context) {
  return ["filtered", "unfiltered", "unknown"].includes(context) ? context : "unknown";
}

function recordReactivationBurst(entry) {
  const burst = telemetry.context.reactivationBurst;
  burst.count += 1;
  burst.firstAt ||= entry.time;
  burst.lastAt = entry.time;
  burst.maxActive = Math.max(burst.maxActive || 0, entry.activeTotal);
}

function updateContextDetection() {
  const validRatio = metrics.mtuTotal ? (metrics.mtuValid || 0) / metrics.mtuTotal : null;
  const filteredSignals = [
    validRatio !== null && validRatio < 0.01,
    telemetry.session.failures > 0,
    telemetry.resolvers.disabled.size > 0,
    telemetry.context.lowestActiveAfterDisable !== null && telemetry.context.lowestActiveAfterDisable <= 10
  ].filter(Boolean).length;
  const unfilteredSignals = [
    telemetry.context.reactivationBurst.count >= 20,
    (telemetry.context.reactivationBurst.maxActive || 0) >= 50
  ].filter(Boolean).length;
  telemetry.context.mixed = filteredSignals >= 2 && unfilteredSignals >= 1;
  telemetry.context.detected = telemetry.context.mixed
    ? "mixed"
    : filteredSignals >= 2
      ? "filtered"
      : unfilteredSignals >= 1
        ? "unfiltered"
        : "unknown";
  const notes = [];
  if (filteredSignals >= 2) notes.push("Filtered-network signals: low valid ratio, session retries/failures, resolver loss, or very low active count.");
  if (unfilteredSignals >= 1) notes.push(`Unfiltered-network signals: ${telemetry.context.reactivationBurst.count} resolver reactivations and active total up to ${telemetry.context.reactivationBurst.maxActive || 0}.`);
  if (telemetry.context.mixed) notes.push("Mixed log context detected; do not use unfiltered reactivation bursts to tune the filtered profile.");
  telemetry.context.notes = notes;
}

function contextSummary() {
  updateContextDetection();
  return {
    selected: telemetry.context.selected,
    detected: telemetry.context.detected,
    mixed: telemetry.context.mixed,
    notes: telemetry.context.notes,
    lowestActiveAfterDisable: telemetry.context.lowestActiveAfterDisable,
    reactivationBurst: telemetry.context.reactivationBurst
  };
}

function contextActiveResolvers(context = telemetry.context.selected) {
  context = effectiveNetworkContext(context);
  if (context === "filtered") return telemetry.context.lowestActiveAfterDisable ?? metrics.mtuValid ?? 0;
  if (context === "unfiltered") return telemetry.context.reactivationBurst.maxActive ?? telemetry.resolvers.activeTotal ?? metrics.mtuValid ?? 0;
  return telemetry.resolvers.activeTotal ?? metrics.mtuValid ?? 0;
}

function knownGoodResolvers(context = telemetry.context.selected) {
  context = effectiveNetworkContext(context);
  const disabled = new Set(telemetry.resolvers.disabled.keys());
  const baseCandidates = telemetry.mtu.validResolvers.map((item) => item.resolver);
  const candidates = context === "filtered"
    ? baseCandidates
    : [...baseCandidates, ...Array.from(telemetry.resolvers.reactivated.keys())];
  return Array.from(new Set(candidates)).filter((resolver) => resolver && !disabled.has(resolver));
}

function exportGoodResolvers(context) {
  const selectedContext = effectiveNetworkContext(normalizeNetworkContext(context || telemetry.context.selected));
  const resolvers = knownGoodResolvers(selectedContext);
  const target = selectedContext === "unknown"
    ? GOOD_RESOLVERS_FILE
    : GOOD_RESOLVERS_FILE.replace(/\.txt$/i, `-${selectedContext}.txt`);
  writeFileSync(target, `${resolvers.join("\n")}${resolvers.length ? "\n" : ""}`, "utf8");
  return { file: target, context: selectedContext, count: resolvers.length, resolvers };
}

function effectiveNetworkContext(context = telemetry.context.selected) {
  const normalized = normalizeNetworkContext(context);
  return normalized === "unknown" && telemetry.context.mixed ? "filtered" : normalized;
}

function detectStateDrift() {
  if (!clientProcess || runStatus !== "stopping") return false;
  try {
    process.kill(clientProcess.pid, 0);
    return true;
  } catch {
    return false;
  }
}

function maskSecret(value) {
  const text = String(value || "");
  if (text.length <= 8) return "***";
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function readText(file) {
  return readFileSync(file, "utf8");
}

function lineCount(text) {
  return text.split(/\r?\n/).filter(Boolean).length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function shutdownDashboard() {
  if (clientProcess) clientProcess.kill("SIGTERM");
  server.close(() => process.exit(0));
}
