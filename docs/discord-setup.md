# 🔔 Discord Webhook Setup Guide

> Set up a Discord server and channel to receive real-time Falco security alerts from your Kubernetes cluster.

---

## Step 1 — Create a Discord Server

1. Open [Discord](https://discord.com) — log in or create a free account
2. Click the **+** button on the left sidebar (Add a Server)
3. Select **Create My Own** → **For me and my friends**
4. Name it `k8s-security-alerts` (or any name you prefer)
5. Click **Create**

---

## Step 2 — Create an Alerts Channel

1. In your new server, click the **+** next to **TEXT CHANNELS**
2. Name the channel `falco-alerts`
3. Keep it as a **Text Channel**
4. Click **Create Channel**

---

## Step 3 — Create the Webhook

1. Right-click on `#falco-alerts` → **Edit Channel**
2. Click **Integrations** in the left menu
3. Click **Webhooks** → **New Webhook**
4. Name it `Falco Security Bot`
5. Optionally upload a bot avatar (use a shield or Falco logo)
6. Click **Copy Webhook URL** — save this, you'll need it in the next step

The URL format looks like:
```
https://discord.com/api/webhooks/1234567890123456789/abcdefghijklmnopqrstuvwxyz
```

> ⚠️ **Treat this URL like a password.** Anyone with this URL can post to your channel. Never commit it to git.

---

## Step 4 — Add the URL to your project

Open `falco/values.yaml` from your project root:

```bash
nano falco/values.yaml
```

Find this line and replace with your copied URL:

```yaml
    discord:
      webhookurl: "REPLACE_WITH_YOUR_DISCORD_WEBHOOK_URL"
```

Becomes:

```yaml
    discord:
      webhookurl: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

Save: `Ctrl+O` → `Enter` → `Ctrl+X`

---

## Step 5 — Test the webhook

Send a test message directly to Discord to confirm the URL works:

```bash
curl -s -X POST "YOUR_DISCORD_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "embeds": [{
      "title": "✅ Webhook Test",
      "description": "Falco Discord integration is working!",
      "color": 65280
    }]
  }'
```

You should see a green embed message appear in `#falco-alerts`.

---

## Alert Format

Alerts arrive as Discord embeds with fields like:

| Field | Example Value |
|---|---|
| Rule | `Terminal shell in container` |
| Priority | `Critical` |
| Pod | `attacker` |
| Namespace | `default` |
| Time | `2026-03-17T04:19:06Z` |

---

*Back to [README.md](../README.md)*
