import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { randomUUID } from "crypto";
import { saveCredentials, loadCredentials, clearCredentials } from "../core/auth.js";
import { logger } from "../core/logger.js";

const DASHBOARD_URL = process.env.BREACHSCOPE_DASHBOARD_URL ?? "https://breachscope.dev";
const POLL_INTERVAL_MS = 2000;
const POLL_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

async function openBrowser(url: string) {
  const { default: open } = await import("open").catch(() => ({ default: null }));
  if (open) {
    await open(url);
  } else {
    logger.info(`Open this URL in your browser: ${url}`);
  }
}

export function makeLoginCommand(): Command {
  return new Command("login")
    .description("Authenticate the CLI with your BreachScope dashboard")
    .option("--token <token>", "Authenticate directly with an API key (skip browser flow)")
    .option("--dashboard <url>", "Dashboard URL (default: https://breachscope.dev)")
    .action(async (opts) => {
      const dashboardUrl = opts.dashboard ?? DASHBOARD_URL;

      // Direct token flow
      if (opts.token) {
        saveCredentials(opts.token, dashboardUrl);
        logger.success("Authenticated with provided API key.");
        logger.info(`Dashboard: ${dashboardUrl}`);
        return;
      }

      // Check existing credentials
      const existing = loadCredentials();
      if (existing) {
        logger.info("Already authenticated. Run `breachscope logout` first to switch accounts.");
        return;
      }

      // Device flow
      const state = randomUUID();

      const initSpinner = ora("Initiating authentication…").start();
      let authUrl: string;

      try {
        const res = await fetch(`${dashboardUrl}/api/cli/auth`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ state }),
        });

        if (!res.ok) {
          initSpinner.fail("Failed to initiate authentication. Is the dashboard reachable?");
          process.exit(1);
        }

        const data: unknown = await res.json();
        if (
          typeof data !== "object" ||
          data === null ||
          typeof (data as Record<string, unknown>)["authUrl"] !== "string"
        ) {
          initSpinner.fail("Dashboard returned an unexpected response format.");
          process.exit(1);
        }
        authUrl = (data as Record<string, unknown>)["authUrl"] as string;
        initSpinner.succeed("Authentication session created.");
      } catch (err) {
        initSpinner.fail(`Cannot reach dashboard at ${dashboardUrl}`);
        process.exit(1);
      }

      console.log();
      console.log(chalk.white("  Opening browser to complete authentication…"));
      console.log(chalk.gray(`  URL: ${authUrl}`));
      console.log();

      await openBrowser(authUrl);

      const pollSpinner = ora("Waiting for browser authentication…").start();

      const deadline = Date.now() + POLL_TIMEOUT_MS;
      let token: string | null = null;

      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));

        try {
          const res = await fetch(`${dashboardUrl}/api/cli/auth/poll?state=${state}`);
          if (!res.ok) continue;

          const raw: unknown = await res.json();
          if (typeof raw !== "object" || raw === null) continue;
          const data = raw as Record<string, unknown>;

          if (data["status"] === "complete" && typeof data["token"] === "string") {
            token = data["token"];
            break;
          }

          if (data["status"] === "expired") {
            pollSpinner.fail("Authentication session expired. Please try again.");
            process.exit(1);
          }
        } catch {
          // network blip — keep polling
        }
      }

      if (!token) {
        pollSpinner.fail("Authentication timed out after 5 minutes.");
        process.exit(1);
      }

      saveCredentials(token, dashboardUrl);
      pollSpinner.succeed(chalk.green("Authenticated successfully!"));

      console.log();
      console.log(chalk.gray("  Credentials stored at ~/.config/breachscope/credentials.json"));
      console.log(chalk.gray("  Run `breachscope scan` to start scanning."));
      console.log();
    });
}

export function makeLogoutCommand(): Command {
  return new Command("logout")
    .description("Remove stored credentials from this machine")
    .action(() => {
      clearCredentials();
      logger.success("Logged out. Credentials removed.");
    });
}

export function makeWhoamiCommand(): Command {
  return new Command("whoami")
    .description("Show current authentication status")
    .action(() => {
      const creds = loadCredentials();
      if (!creds) {
        logger.warn("Not authenticated. Run `breachscope login`.");
        return;
      }
      logger.info(`Authenticated to: ${creds.dashboardUrl}`);
      logger.info(`Token: ${creds.token.slice(0, 20)}…`);
      logger.info(`Saved: ${new Date(creds.savedAt).toLocaleString()}`);
    });
}
