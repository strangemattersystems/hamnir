# hamnir

hamnir is an OpenID Connect provider for local development: its users are personas you define, and signing in can be a single click.

So you've built an app with OIDC/OAuth SSO — awesome! Now you're developing against it and want to log in as different users to try things out — ugh! That's what hamnir solves: it's a real OpenID Connect provider that lets you sign in as any of a set of users you define. Because it speaks real OIDC, you're exercising the actual login flow — not a stub that drifts from production — without special-casing your code for development.

Why hamnir though? It's small and quick — the container image is ~25MB, and it starts basically instantly — and your personas live in one relatively easy-to-maintain config file. Commit that file next to your app and your whole team logs in as the same people.

## Quick start

Two steps: create a config that lists your personas, then run the server on it. Both work the same whether you install the CLI or use the container image.

### 1. Create a config

Scaffold a starter config as `./hamnir.yaml`.

With the CLI — `go install` it, or grab a prebuilt binary for macOS, Linux or Windows from the [releases page](https://github.com/strangemattersystems/hamnir/releases/latest):

```bash
go install github.com/strangemattersystems/hamnir/cmd/hamnir@latest
hamnir init
```

With Docker — runs as you (`-u`) so the file it writes back is yours to edit:

```bash
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD:/out" -e HAMNIR_CONFIG=/out/hamnir.yaml \
  ghcr.io/strangemattersystems/hamnir init
```

Open `hamnir.yaml` and add or adjust personas to match your app. Take a look at the [example config](examples/hamnir.yaml) for settings you can copy over as you need them.

### 2. Run the server

Serve OIDC at `http://localhost:5556`.

With the CLI:

```bash
hamnir serve
```

With Docker:

```bash
docker run --rm -p 5556:5556 \
  -v "$PWD/hamnir.yaml:/etc/hamnir/hamnir.yaml:ro" \
  -e HAMNIR_CONFIG=/etc/hamnir/hamnir.yaml \
  ghcr.io/strangemattersystems/hamnir
```

Then point your app's OIDC discovery at `http://localhost:5556`. hamnir starts in **permissive mode** — with no clients registered it accepts any `client_id` and redirect URI — so most apps connect with no extra setup. Trigger a login and you'll get the persona picker; click a persona and your app receives its tokens and claims.

The [example compose file](examples/docker-compose.yml) shows how to wire the container image up as a basic service in Docker Compose.

> [!WARNING]
> hamnir is a development tool — it allows you to authenticate without restriction as arbitrarily configured users. You should ensure it's not exposed to untrusted networks and that you understand the power it grants.

## Example

[`examples/`](examples/) runs hamnir next to a small relying-party web app with Docker Compose, so you can watch the whole flow — picker, redirect, token exchange, claims — in a browser. Start there if you'd rather see it than read about it.

## Log in programmatically

Tests, scripts and CI jobs can skip the picker entirely. Give a persona one or more `tokens:` — any string you like — and exchange one for real tokens with a single request, using the standard OAuth token exchange grant (RFC 8693):

```yaml
personas:
  - name: Alice
    claims:
      sub: usr_alice
      email: alice@example.test
    tokens: [alice-ci]
```

```bash
curl -u myapp: http://localhost:5556/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=alice-ci \
  -d subject_token_type=https://hamnir.dev/token-type/persona \
  -d scope="openid profile email"
```

The response is a standard token response for Alice, with the same claims, lifetimes and revocation behaviour as a picker login. That `subject_token_type` URI is hamnir's stable identifier for persona tokens — RFC 8693 reserves the standard types for tokens an authorization server actually issued, and invites exactly this kind of URI for everything else.

Against the [example config](examples/hamnir.yaml) — which registers `example-webapp` as a public client rather than running permissive mode — the same call is `curl -u example-webapp: http://localhost:5556/oauth/token -d ... -d subject_token=tkn-marcus ...`.

The knobs:

- `scope` defaults to `openid profile email` when omitted.
- Also want a refresh token? Request it with `-d requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` — the response then carries both tokens (the access token in `access_token` and the refresh token in `refresh_token`; `issued_token_type` reflects your request).
- Ask for an ID token instead with `-d requested_token_type=urn:ietf:params:oauth:token-type:id_token`.
- Your configured `audiences:` apply to exchanged tokens just like every other flow. Override per request with `-d audience=https://other.test` — the override applies to the tokens from that exchange; refreshed tokens re-derive their audience from config.
- In permissive mode, `-u myapp:` just names the client your tokens are minted for (any id, no secret). With registered clients, use one of them: a client with a `secret` authenticates as usual (`-u id:secret`), and a public client simply identifies itself with an empty secret (`-u id:`).

## Skip the picker

Browser flows can be hands-free too: send the standard OIDC `login_hint` parameter on the authorization request and hamnir signs the matching persona straight in — no picker, no click. A hint matches a persona's `sub` exactly or its `email` ignoring case; anything else — including a hint matching two personas — just pre-fills the picker's search box. Send `prompt=select_account` (or `prompt=login`) to get the picker back.

This makes browser end-to-end tests fully non-interactive: start your app's login with a hint — the [example webapp](examples/) forwards `/login?hint=alice@example.test` — and the whole redirect dance completes without touching the page.

## What you can configure

Everything lives in one config file — `hamnir init` scaffolds it and `hamnir validate` checks it. The [example config](examples/hamnir.yaml) walks through each of these in comments:

- **Personas** — your test users and whatever claims you want them to carry: email, name, roles, anything custom.
- **Programmatic login** — give a persona `tokens:` and exchange one for real tokens in a single request — no browser needed.
- **Groups** — organise personas into labelled sections in the picker.
- **Avatars & static content** — serve local images and reference them from a persona's `picture` claim.
- **Clients** — register specific clients to leave permissive mode and match redirect URIs exactly.
- **Audiences** — set the `aud` on issued tokens for APIs that validate it.
- **Token lifetimes** — tune how long access, ID and refresh tokens live.

The config is schema-annotated ([`api/hamnir.schema.json`](api/hamnir.schema.json)), so a YAML-aware editor autocompletes fields and flags mistakes as you type.
