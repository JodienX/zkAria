// Entry point: start the Proof Gatekeeper HTTP service.
//
// Configuration is loaded from the environment (see .env.example).
// A missing AGENT_GAMES_HMAC_SECRET is fatal in production: the service
// must never run without the ability to verify inbound signatures.
import * as http from "node:http";
import { loadConfig, type GatekeeperConfig } from "./config";
import { createServer, logStartup } from "./routes";
import { ReplayStore } from "./replay";
import { error as logError, info } from "./logger";

export interface RunningServer {
  server: http.Server;
  port: number;
  config: GatekeeperConfig;
  replay: ReplayStore;
}

export function createGatekeeperServer(
  config: GatekeeperConfig,
): RunningServer {
  const replay = new ReplayStore(config.dataDir);
  const server = createServer({ config, replay });
  return { server, port: config.port, config, replay };
}

export function listen(
  running: RunningServer,
  port?: number,
  host?: string,
): Promise<number> {
  const listenPort = port ?? running.config.port;
  return new Promise((resolve, reject) => {
    running.server.once("error", reject);
    running.server.listen(listenPort, host ?? "0.0.0.0", () => {
      const address = running.server.address();
      const actualPort =
        typeof address === "object" && address !== null
          ? address.port
          : listenPort;
      logStartup(running.config, actualPort);
      resolve(actualPort);
    });
  });
}

async function main(): Promise<void> {
  const config = loadConfig();
  const running = createGatekeeperServer(config);
  await listen(running);

  const shutdown = () => {
    info("gatekeeper_shutting_down", {});
    running.server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

if (require.main === module) {
  main().catch((err: unknown) => {
    logError("gatekeeper_startup_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
    process.exit(1);
  });
}
