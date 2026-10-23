# Publishing CrawlBouncer on GitHub: step by step

You do not need to know Git well. Pick **Option A** (no tools, just a browser) or **Option B** (command line).

## 0. Before you start

1. Create a free account at <https://github.com>.
2. Search GitHub for `crawlbouncer` to see if the name is taken. If it is, pick another and run a search-and-replace on the old name.
3. The links in the README, landing page and issue templates already use the GitHub username `nayan-mis`. If you create the repository under a different name or account, search for `nayan-mis` and `crawlbouncer` and update them.
4. Check `.env` is **not** in the folder (only `.env.example`). Never upload secrets.

## Option A: browser only

1. On GitHub click **+ → New repository**. Name it `crawlbouncer`, choose **Public**, leave "Add README" **unticked**, click **Create**.
2. Click **uploading an existing file**, drag in the *contents* of the unzipped folder (including the hidden `.github` folder), then **Commit changes**.
   (If drag-and-drop skips hidden folders, use Option B.)

## Option B: command line

```bash
cd crawlbouncer
git init
git add .
git commit -m "Initial open-source release"
git branch -M main
git remote add origin https://github.com/nayan-mis/crawlbouncer.git
git push -u origin main
```

## 1. Fill in the repository page

**Description** (the box at the top right, ⚙️ next to *About*):

> Self-hosted bouncer for AI crawlers. Allow or block GPTBot, ClaudeBot and friends per site and per path. Includes a dashboard, web firewall and robots.txt generator.

**Website:** leave empty or add your demo URL.

**Topics** (these make it findable): `ai-crawlers`, `web-crawler`, `bot-detection`, `bot-protection`, `robots-txt`, `gptbot`, `fastapi`, `react`, `self-hosted`, `reverse-proxy`, `waf`, `privacy`

## 2. Turn on the free safety features

In **Settings**:
- **General → Features:** enable *Issues* and *Discussions*.
- **Code security:** enable *Dependabot alerts*, *Dependabot security updates*, *Secret scanning* and *Private vulnerability reporting* (all free for public repos).
- **Branches → Add rule** for `main`: require a pull request and require the **CI** check to pass.

## 3. Check that CI is green

Open the **Actions** tab. The backend, frontend and bolt-on jobs should pass. This is the first real run of the Python tests, so if something is red, open it, copy the error into a new issue (or send it to your AI assistant) and fix it before announcing the project.

## 4. Create the first release

**Releases → Draft a new release →** tag `v0.1.0`, title `CrawlBouncer 0.1.0`, paste this:

> First public release. A self-hosted gateway that lets you allow or block AI crawlers per site and per path, with a dashboard, a web firewall and a robots.txt generator.
> Early software: see `docs/KNOWN_LIMITATIONS.md`. Feedback and contributions welcome.

## 5. Make it easy to contribute

Create these issues and label them **good first issue** (Settings → Labels if it doesn't exist yet):

1. Add more AI crawler User-Agent signatures (with tests)
2. Verify crawlers by published IP ranges / reverse DNS
3. Per-domain crawler statistics on the Crawlers page
4. Postgres support as an alternative to SQLite
5. Password reset for invited team members
6. Dark/light polish and mobile layout fixes in the dashboard
7. Translate the landing page and README
8. Add a Kubernetes / Helm example
9. Write a "How to protect a WordPress site" guide
10. Add automated tests for the nginx/njs bolt-on script

## 6. Tell people

Short post to adapt:

> I built CrawlBouncer, a free, self-hosted tool that lets you allow or block AI crawlers on your own site, per bot and per path. It's early and open source (MIT); I'd love feedback and contributors. <link>

Good places: Hacker News ("Show HN"), r/selfhosted, r/opensource, the FastAPI and self-hosting communities, and your own social accounts. Be upfront that it is early and say what you want help with.

## 7. Keep it healthy

- Reply to the first few issues quickly; it sets the tone.
- Merge Dependabot updates when CI is green.
- Tag a new release when you merge something notable and add a line to `CHANGELOG.md`.
