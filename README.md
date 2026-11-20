# PicoClaw Railway Template (1-click deploy)

This repo packages **PicoClaw** for Railway with a web-based configuration UI and gateway management dashboard.

## What you get

- **PicoClaw Gateway** managed as a subprocess with auto-restart
- A web **Configuration UI** at `/` (protected by Basic Auth) for editing providers, channels, agent defaults, and tools
- A **Status Dashboard** with live gateway state, provider/channel status, cron jobs, and real-time logs
- Persistent state via **Railway Volume** (config, workspace, sessions, and cron survive redeploys)

## How it works

- The container builds PicoClaw from source and runs a Python web server alongside it
- The web server provides a configuration editor for PicoClaw's config (schema v3): settings go to `~/.picoclaw/config.json` and credentials (API keys, bot tokens) to `~/.picoclaw/.security.yml`, the same split PicoClaw itself uses
- Configs from older template versions are migrated automatically on startup
- On startup, if any provider API key is configured, the gateway starts automatically
- The gateway subprocess output is captured into a 500-line log buffer viewable from the Status tab

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | `admin` | Username for Basic Auth |
| `ADMIN_PASSWORD` | *(auto-generated)* | Password for Basic Auth. **Check deploy logs for the generated password if not set.** |
| `PICOCLAW_VERSION` | `v0.3.1` | Git tag/branch to build PicoClaw from (build arg). Pinned to a tested release; newer versions may change the config schema |

## Getting chat tokens

### Telegram bot token

1. Open Telegram and message **@BotFather**
2. Run `/newbot` and follow the prompts
3. BotFather will give you a token like: `123456789:AA...`
4. Paste it into the Telegram channel config and add your user ID to the allow list

### Discord bot token

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications)
2. **New Application** → pick a name
3. Open the **Bot** tab → **Add Bot**
4. Enable **MESSAGE CONTENT INTENT** under Privileged Gateway Intents
5. Copy the **Bot Token** and paste it into the Discord channel config
6. Invite the bot to your server (OAuth2 URL Generator → scopes: `bot`, `applications.commands`)

## Local testing

```bash
docker build -t picoclaw-railway-template .

docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e ADMIN_PASSWORD=test \
  -v $(pwd)/.tmpdata:/data \
  picoclaw-railway-template

# Open http://localhost:8080 (username: admin, password: test)
```

## FAQ

**Q: How do I access the configuration page?**

A: Go to your deployed instance's URL. When prompted for credentials, use `admin` as the username and the `ADMIN_PASSWORD` from your Railway Variables as the password.

**Q: Where do I find the auto-generated password?**

A: Check the deploy logs in Railway. The password is printed at startup: `Generated admin password: ...`

**Q: How do I change the AI model?**

A: Go to the Configuration tab → Agent Defaults → Model field. Pick any model from the Providers list. To add one, open a provider, click **+ Add model**, and enter a display name and the provider's model ID (e.g. `claude-opus-4-5`, `gpt-4.1`).

**Q: The gateway isn't starting. What should I check?**

A: Make sure at least one provider has an API key configured. The gateway auto-starts only when an API key is present. You can also manually start it from the Status tab.
