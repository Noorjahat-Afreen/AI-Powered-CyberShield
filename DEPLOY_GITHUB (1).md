# Deploy CyberShield on GitHub Pages (free, ~5 minutes)

The site is 100% static, so GitHub Pages hosts it for free.

---

## FIX: Getting a 404 on your live Pages URL?

**Cause:** GitHub Pages needs `index.html` at the ROOT of your repository.
If you uploaded the `.zip` file itself, GitHub does NOT unzip it - the repo
only contains a zip, so there is no `index.html` to serve and Pages shows 404.

**Fix for repo `Noorjahat-Afreen/AI-Powered-CyberShield` (5 minutes):**

1. Extract `AI_CyberShield_UPLOAD_THESE_FILES.zip` on your PC
   (right-click -> Extract All). After extracting you will see files like
   `index.html`, `config.js`, folders `css/`, `js/`, `ml-training/`.
2. Open the extracted folder, press **Ctrl+A** to select ALL files inside it.
3. Go to your repo on GitHub: `github.com/Noorjahat-Afreen/AI-Powered-CyberShield`
4. Delete the old zip file: click `AI_CyberShield_GitHub_Ready.zip` ->
   the **...** menu / trash icon -> confirm delete -> Commit changes.
5. Click **Add file -> Upload files**, drag all selected files into the page
   (or click "choose your files" and select them all), then **Commit changes**.
   - Check after upload: `index.html` must appear directly in the repo file
     list (NOT inside any folder).
6. Settings -> Pages -> Source: **Deploy from a branch**, Branch: **main**,
   Folder: **/ (root)** -> Save. (If already set, click Save anyway to
   re-trigger the build.)
7. Wait 1-2 minutes, then open:
   **https://noorjahat-afreen.github.io/AI-Powered-CyberShield/**

---

## Option A - Upload through the GitHub website (easiest, no commands)

1. Go to <https://github.com/new>
   - Repository name: `cybershield` (or anything)
   - Visibility: **Public** (required for free GitHub Pages)
   - Click **Create repository**

2. On the new repo page click **"uploading an existing file"** link.

3. Drag-and-drop ALL files from this folder (index.html, config.js, css/, js/,
   ml-training/, README.md, DEPLOY_GITHUB.md, .nojekyll).
   - To select hidden `.nojekyll` in a file dialog, enable "show hidden files",
     or skip it - it is optional.

4. Click **Commit changes** and wait for the upload to finish.

5. Enable Pages:
   - Repo → **Settings** → left menu **Pages**
   - Under "Build and deployment", Source: **Deploy from a branch**
   - Branch: **main** / Folder: **/ (root)** → **Save**

6. Wait 1-2 minutes. Your live URL appears on the same Settings → Pages page:
   `https://<your-username>.github.io/<repo-name>/`

Done - the site is live. Share that link anywhere.

---

## Option B - Git command line

```bash
cd <this folder>

git init
git add .
git commit -m "AI CyberShield - phishing detection with ML"

# create an empty repo on github.com first (Option A step 1), then:
git branch -M main
git remote add origin https://github.com/<your-username>/cybershield.git
git push -u origin main

# enable Pages: repo -> Settings -> Pages -> Branch: main / root -> Save
```

---

## Updating the live site

Just re-upload (or `git push`) changed files. Pages redeploys automatically in
about a minute. Hard-refresh with `Ctrl+Shift+R` if you see an old version.

## Custom domain (optional)

Settings → Pages → Custom domain. Add the DNS records GitHub shows you.
Enable "Enforce HTTPS" once the certificate is issued.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| 404 on the live URL | Wait 2 minutes; check Settings → Pages shows a source branch |
| CSS/JS not loading | Make sure the `css/` and `js/` folders were uploaded, names are exact |
| Site works but AI chat says unavailable | The API key in `config.js` is empty/rejected - the ML scanners still work; paste a valid key |
| Models missing | `js/models.js` must be present (80 KB file) - re-upload it |
