# Landing page

The site uses static HTML and compiled Tailwind CSS. It requires Node.js 24 to build, with no browser JavaScript or external font requests.

From this directory:

```sh
npm ci
npm run build
python3 -m http.server 8000 --directory dist
```

Open `http://localhost:8000`. Edit `index.html` and `styles.css`, then rebuild to preview changes.

The existing Pages workflow builds and publishes `docs/dist` when changes under `docs/` or the workflow are pushed to `main`. GitHub Pages uses GitHub Actions as its publishing source.
