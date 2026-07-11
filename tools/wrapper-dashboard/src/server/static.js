import { createReadStream, existsSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { PUBLIC_DIR } from "./paths.js";
import { sendText } from "./utils/http.js";

export async function serveStatic(req, res, url) {
  const requested = url.pathname === "/" ? "/index.html" : url.pathname;
  const target = resolve(join(PUBLIC_DIR, requested));
  if (!target.startsWith(PUBLIC_DIR)) return sendText(res, 403, "Forbidden");
  if (!existsSync(target)) return sendText(res, 404, "Not found");
  const type = contentType(extname(target));
  res.writeHead(200, { "Content-Type": type });
  createReadStream(target).pipe(res);
}

function contentType(ext) {
  return {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml"
  }[ext] || "application/octet-stream";
}
