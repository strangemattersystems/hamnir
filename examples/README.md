# hamnir example: log in from a web app via Docker Compose

This runs hamnir and a tiny relying-party web app together with Docker Compose so
you can see the whole login flow end to end — the way you'd drop hamnir in beside
your own app.

## Run it

```bash
cd examples
docker compose up --build
```

Then open **http://localhost:8080**, click **Log in with hamnir**, pick a persona,
and you'll land back on the app showing the claims from the verified ID token.

- Web app: http://localhost:8080
- hamnir discovery: http://localhost:5556/.well-known/openid-configuration

Stop with `Ctrl-C`; `docker compose down` removes the containers.

## What's here

- `docker-compose.yml` — hamnir + the web app on one network
- `hamnir.yaml` — two personas across two groups, and the web app registered as a client
- `webapp/` — the relying party, a small Go app (`webapp/main.go`)

## The networking bit (why there are two URLs)

An OIDC issuer has to look the same to everyone who talks to it, but in Compose
there are two vantage points on hamnir:

- your **browser** reaches it at `http://localhost:5556` (a published port)
- the **web app container** reaches it at `http://hamnir:5556` (the Compose service name)

So hamnir runs here **without a fixed `issuer:`** — it derives the issuer from each
request's host. The web app is given both URLs:

| Env var | Used for |
| --- | --- |
| `HAMNIR_INTERNAL_URL=http://hamnir:5556` | discovery, token exchange, JWKS (server-to-server) |
| `HAMNIR_PUBLIC_URL=http://localhost:5556` | the URL the browser is redirected to |

Discovery, the token exchange and JWKS all happen over the container network, while
the browser is sent to a URL it can actually reach. Because hamnir mints the ID
token's `iss` from the (internal) token-endpoint request, it matches what the app
discovered — so verification succeeds. This is what hamnir's dynamic issuer is for.
