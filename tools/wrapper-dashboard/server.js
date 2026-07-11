import { shutdownDashboard, startDashboard } from "./src/server/app.js";

startDashboard();

process.on("SIGINT", shutdownDashboard);
process.on("SIGTERM", shutdownDashboard);
