// Optional real browser check. Credentials arrive only through stdin; no trace/video is retained.
const { chromium } = require("playwright");
const fs = require("node:fs");
(async () => {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1100 },
    });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.name));
    await page.goto(input.url);
    await page.getByLabel("Username", { exact: true }).fill("admin");
    await page
      .getByLabel("Password (14+ characters)", { exact: true })
      .fill(input.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page
      .getByRole("heading", { name: "Your directory at a glance." })
      .waitFor();
    await page
      .locator("nav")
      .getByRole("button", { name: "Settings", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Certificate lifecycle" })
      .waitFor();
    await page.getByText("v0.4.0 / 4", { exact: true }).waitFor();
    await page
      .getByText("Primary configured certificate", { exact: true })
      .waitFor();
    await page.getByRole("link", { name: "Export NDJSON" }).waitFor();
    await page.getByLabel("Search events").fill("no-such-event-browser-test");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await page.getByText("No matching events.", { exact: true }).waitFor();
    await page.screenshot({
      path: "/output/settings-dark.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: "Toggle theme" }).click();
    await page.screenshot({
      path: "/output/settings-light.png",
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: "/output/settings-mobile.png",
      fullPage: true,
    });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    if (overflow) throw Error("Settings overflows mobile viewport");
    await page
      .locator("nav")
      .getByRole("button", { name: "Directory Servers", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Enroll a second Docker host" })
      .waitFor();
    if (errors.length || (await page.getByRole("alert").count()))
      throw Error("Browser reported an application error");
    console.log(
      "PASS: real Chromium login, Settings API rendering, audit search/export link, dark/light themes, mobile layout and directory navigation.",
    );
  } finally {
    await browser.close();
  }
})().catch(() => {
  console.error(
    "Browser verification failed; inspect the local screenshots/application.",
  );
  process.exit(1);
});
