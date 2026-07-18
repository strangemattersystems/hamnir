# hamnir example: log in with a web app in docker compose

This runs hamnir and a tiny relying-party web app together with docker compose so you can see the whole login flow end to end — the way you'd drop hamnir in beside your own app.

## How to run it?

```bash
cd examples
docker compose up --build
```

Then open **[http://localhost:8080](http://localhost:8080)**, click **Log in with hamnir**, pick a persona, and you'll land back on the app showing the claims from the verified ID token and the userinfo endpoint.

- Web app: [http://localhost:8080](http://localhost:8080)
- hamnir discovery: [http://localhost:5556/.well-known/openid-configuration](http://localhost:5556/.well-known/openid-configuration)

Stop with `Ctrl-C`; `docker compose down` removes the containers.

## What's here?

- `docker-compose.yml` — hamnir and the web app on one Compose network
- `hamnir.yaml` — eight personas across two groups, with the web app registered as a client; its comments walk through each setting
- `webapp/` — the relying party: a small Go app (`webapp/main.go`) whose two pages live in `home.html` and `claims.html`

## Why there are two hamnir URLs?

In Compose there are two vantage points on hamnir, so it's given two URLs (explained field-by-field in `hamnir.yaml`):

- the **web app container** reaches it at `http://hamnir:5556` (the Compose service name) — the `issuer`, used for everything server-to-server: discovery, token exchange, userinfo and JWKS
- your **browser** reaches it at `http://localhost:5556` (a published port) — the `browser_url`, where hamnir sends the browser for the `/authorize` step

Pointing both sides at one URL only one of them can reach is the usual first stumble here — the split is what avoids it.

---

Avatars from [Open Peeps](https://www.openpeeps.com) by Pablo Stanley, dedicated to the public domain under CC0 1.0 Universal. No attribution required.