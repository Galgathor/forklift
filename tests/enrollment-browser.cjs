// A private TLS proxy is used only by the disposable test fixture.
const { chromium } = require("playwright");
const fs = require("node:fs");
(async () => {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({
      ignoreHTTPSErrors: true,
      viewport: { width: 1200, height: 950 },
    });
    await page.goto(input.url);
    await page.getByLabel("Username", { exact: true }).fill("admin");
    await page
      .getByLabel("Password (14+ characters)", { exact: true })
      .fill(input.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page
      .locator("nav")
      .getByRole("button", { name: "Directory Servers", exact: true })
      .click();
    await page.getByRole("button", { name: "Add server", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Add directory server" });
    await dialog
      .getByText("Do not install or configure LDAP on the new machine first.", {
        exact: true,
      })
      .waitFor();
    await dialog
      .getByRole("button", { name: "Check primary & continue", exact: true })
      .click();
    await dialog
      .getByLabel("Friendly name", { exact: true })
      .fill("Wizard preview");
    await dialog
      .getByLabel("New server DNS name", { exact: true })
      .fill("wizard.replication.test");
    await dialog
      .getByLabel("New Docker host private IPv4 address", { exact: true })
      .fill("192.168.1.25");
    await dialog
      .getByRole("button", { name: "Review deployment", exact: true })
      .click();
    const download = page.waitForEvent("download");
    await dialog
      .getByRole("button", { name: "Download deployment", exact: true })
      .click();
    const file = await download;
    await file.saveAs("/output/wizard.tar.gz");
    fs.chmodSync("/output/wizard.tar.gz", 0o600);
    await dialog
      .getByText("Waiting for the new machine to enroll", { exact: true })
      .waitFor();
    if (
      !(await dialog
        .locator("pre")
        .innerText()
        .then((t) => t.includes("./start.sh")))
    )
      throw Error("Missing installation command");
    await dialog.screenshot({ path: "/output/wizard.png" });
    await page.setViewportSize({ width: 390, height: 844 });
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth + 1,
      )
    )
      throw Error("Mobile setup overflows");
    const id = file
      .suggestedFilename()
      .match(/^forklift-replica-([a-f0-9]{32})\.tar\.gz$/)?.[1];
    if (!id) throw Error("Missing scoped deployment filename");
    console.log(JSON.stringify({ id }));
  } finally {
    await browser.close();
  }
})().catch(() => {
  console.error(
    "Enrollment browser test failed; no credentials or downloads are logged.",
  );
  process.exit(1);
});
