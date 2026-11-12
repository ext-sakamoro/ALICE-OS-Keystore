// Oracle 7b: a real reload. The page seals a value with the browser key store, the test
// reloads it, and the reloaded page opens the value with the key read back from IndexedDB;
// a second origin cannot open it (the keys belong to the origin).
//
// `tests/web/page/` loads the package built by
// `wasm-pack build --target web --out-dir tests/web/page/pkg -- --features web-page`.
//
// Run (from tests/web, with the page served on port 8123):
// npx playwright test --reporter=json > web-report.json, then
// python3 scripts/web_test_count.py --playwright web-report.json (fails on 0 passed, and
// when any of chromium, firefox or webkit ran none).
import { test, expect } from "@playwright/test";

const PAGE = process.env.ALICE_KEYSTORE_PAGE ?? "http://127.0.0.1:8123/index.html";
const OTHER_ORIGIN = process.env.ALICE_KEYSTORE_OTHER ?? "http://localhost:8123/index.html";

test("a value sealed before a reload opens after it", async ({ page }) => {
  await page.goto(PAGE);
  await page.waitForFunction(() => window.keystoreReady === true);
  const sealed = await page.evaluate(async () => {
    await window.keystore.reset("reload");
    await window.keystore.rotate();
    return Array.from(await window.keystore.seal("aad", "kept across a reload"));
  });
  expect(sealed.slice(0, 4)).toEqual([0x41, 0x4d, 0x53, 0x32]); // "AMS2"

  await page.reload();
  await page.waitForFunction(() => window.keystoreReady === true);
  const opened = await page.evaluate(async (bytes) => {
    await window.keystore.attach("reload");
    const extractable = await window.keystore.anyKeyExtractable();
    return { text: await window.keystore.open("aad", Uint8Array.from(bytes)), extractable };
  }, sealed);
  expect(opened).toEqual({ text: "kept across a reload", extractable: false });

  // another origin has its own IndexedDB: it has no key for this value
  await page.goto(OTHER_ORIGIN);
  await page.waitForFunction(() => window.keystoreReady === true);
  const refused = await page.evaluate(async (bytes) => {
    await window.keystore.attach("reload");
    try {
      await window.keystore.open("aad", Uint8Array.from(bytes));
      return "opened";
    } catch (e) {
      return String(e);
    }
  }, sealed);
  expect(refused).not.toBe("opened");
});
