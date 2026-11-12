// The browser reload lane: tests/web/reload.spec.mjs in Chromium, Firefox and WebKit (Safari's
// engine, which the iOS WebView uses). The page is served from tests/web/page on port 8123 by
// the workflow (both 127.0.0.1 and localhost, which are two origins).
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  retries: 0,
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
