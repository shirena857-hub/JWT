# FF Ultimate API v7.0

> **Merged from ffinfoo + sulavcodex** — Real protobuf-based player info (src type), all extra endpoints, `/ai` Q&A, Vercel-ready.

## Quick Start

```bash
pip install -r requirements.txt
python app.py
# API runs on http://localhost:5000
```

## Vercel Deploy

```bash
vercel --prod
```
`vercel.json` is pre-configured. Just deploy the folder.

### Custom domain and subdomains

Vercel domains are attached in the Vercel project settings; they cannot be
created from Python or safely embedded in a ZIP. Add the project domain
`sulavcodex.com`, then add any aliases you want, for example:

- `api.sulavcodex.com`
- `ff.sulavcodex.com`
- `freefire.sulavcodex.com`

Point each hostname to the same Vercel project. Every hostname serves the same
API routes automatically. The API never returns environment secrets, access
tokens, or server filesystem paths in its public metadata.

## Info Type: **protobuf-src** (real)

Unlike the old direct type (killersharmabot.online), this API calls Free Fire game servers directly:
- AES-CBC encrypted protobuf messages → `client.{region}.freefiremobile.com`
- Per-region service account tokens (IND, SG, ID, BR, VN, TH, ME, PK, CIS, US, RU, TW)
- Automatic region detection & caching

## Example Calls

```
GET /player-info?uid=3074306062         → real player data (protobuf)
GET /level?uid=3074306062               → level + XP progress
GET /guild-info?uid=3074306062          → guild details
GET /rank?uid=3074306062                → rank & tier
GET /char-info?uid=3074306062           → character/avatar
GET /pet-info?uid=3074306062            → pet info
GET /outfit-info?uid=3074306062         → outfit slots
GET /kill-stats?uid=3074306062          → kill statistics
GET /duo?uid=3074306062&password=PASS   → Dynamic Duo
GET /banner?uid=3074306062              → banner image (PNG)
GET /outfit?uid=3074306062              → outfit image (PNG)
GET /ai?question=Free+Fire+tips         → AI answer
GET /ai?q=Free+Fire+tips&model=mistral  → AI answer with model selection
GET /token?uid=UID&password=PASS        → JWT token
GET /item/info?q=Nulla                  → item search
GET /item/info?item_id=123              → exact item lookup
GET /base64/encode?data=hello           → base64 encode
GET /base64/decode?data=aGVsbG8=        → base64 decode
GET /custom-banner?playername=SULAV     → custom banner without UID
GET /custom-outfit?character=...        → custom outfit without UID
GET /asset-url?id=...                   → CDN asset URL
GET /weapon-info?weapon_id=901000001    → weapon details
GET /leaderboard?limit=10               → leaderboard
GET /game-modes                         → all game modes
GET /maps                               → all maps
GET /seasons                            → season info
GET /status                             → server status
GET /                                   → full endpoint list
```

## All Endpoints — 40+

Visit `GET /` or `GET /help` for the full interactive endpoint list with examples.
