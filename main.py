import os
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import discord
from discord import AuditLogAction

# === 🔧 Konfiguration (aus Railway ENV Variablen) ===
TOKEN = os.getenv("TOKEN")  # in Railway als Variable setzen!
NOTIFY_CHANNEL_ID = int(os.getenv("NOTIFY_CHANNEL_ID", "0"))  # Channel-ID
WHITELIST_IDS = os.getenv("WHITELIST_IDS", "")  # Kommagetrennte IDs, z. B. 123,456,789

# === 🧠 Optionen ===
AUDIT_LOOKBACK_SECONDS = 5
TIMEOUT_HOURS = 2

# === 🧾 Logging ===
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("anti-webhook")

# === 🔍 Whitelist vorbereiten ===
WHITELIST = set()
if WHITELIST_IDS:
    try:
        WHITELIST = {int(uid.strip()) for uid in WHITELIST_IDS.split(",") if uid.strip().isdigit()}
    except Exception:
        log.warning("Konnte WHITELIST_IDS nicht korrekt parsen – überprüfe Format!")

# === 🧠 Discord Setup ===
intents = discord.Intents.default()
intents.guilds = True
intents.members = True

class AntiWebhookBot(discord.Client):
    async def on_ready(self):
        log.info(f"✅ Eingeloggt als {self.user} (ID: {self.user.id})")

        # Debug: zeig wichtige ENV Variablen
        log.info(f"📡 Notify Channel: {NOTIFY_CHANNEL_ID}")
        log.info(f"👤 Whitelist: {list(WHITELIST)}")

    async def on_webhooks_update(self, channel: discord.abc.GuildChannel):
        try:
            guild = channel.guild
            if guild is None:
                return

            # AuditLog abfragen
            async for entry in guild.audit_logs(limit=5, action=AuditLogAction.webhook_create):
                executor = entry.user
                created_at = entry.created_at
                if not executor or not created_at:
                    continue

                age = (datetime.now(timezone.utc) - created_at).total_seconds()
                if age > AUDIT_LOOKBACK_SECONDS:
                    continue  # zu alt

                # Wenn erlaubt -> abbrechen
                if executor.id in WHITELIST:
                    log.info(f"✅ {executor} ist whitelisted – kein Eingriff.")
                    return

                log.warning(f"⚠️ {executor} (ID {executor.id}) hat Webhook erstellt!")

                # 1️⃣ Webhooks im Channel löschen (neueste)
                try:
                    webhooks = await channel.webhooks()
                    for wh in webhooks:
                        await wh.delete(reason="Nicht whitelisted webhook creation")
                    log.info(f"🗑️ Alle Webhooks in #{channel.name} gelöscht.")
                except discord.Forbidden:
                    log.error("Fehler: Keine Rechte, um Webhooks zu löschen!")
                except Exception as e:
                    log.exception(f"Webhook-Löschfehler: {e}")

                # 2️⃣ Timeout für 2 Stunden
                try:
                    member = guild.get_member(executor.id)
                    if member:
                        await member.edit(
                            timeout=timedelta(hours=TIMEOUT_HOURS),
                            reason="Anti-Webhook: Nicht whitelisted",
                        )
                        log.info(f"⏰ {executor} wurde {TIMEOUT_HOURS}h getimeoutet.")
                except discord.Forbidden:
                    log.error("Fehler: Keine Rechte, um Member zu timeouten.")
                except Exception as e:
                    log.exception(f"Timeout-Fehler: {e}")

                # 3️⃣ Benachrichtigung im Log-Channel
                try:
                    if NOTIFY_CHANNEL_ID:
                        notify_ch = guild.get_channel(NOTIFY_CHANNEL_ID)
                        if notify_ch:
                            embed = discord.Embed(
                                title="🚨 Unbefugte Webhook-Erstellung erkannt!",
                                color=discord.Color.red(),
                                timestamp=datetime.utcnow(),
                            )
                            embed.add_field(name="User", value=f"{executor.mention} (`{executor.id}`)", inline=False)
                            embed.add_field(name="Channel", value=f"{channel.mention}", inline=True)
                            embed.add_field(name="Timeout", value=f"{TIMEOUT_HOURS}h", inline=True)
                            await notify_ch.send(embed=embed)
                except Exception as e:
                    log.exception(f"Fehler beim Senden der Benachrichtigung: {e}")

                return  # Nur ersten passenden AuditLog behandeln

        except Exception as e:
            log.exception(f"Fehler in on_webhooks_update: {e}")

def main():
    if not TOKEN:
        log.error("❌ TOKEN nicht gefunden! Bitte in Railway unter Variables setzen.")
        return

    client = AntiWebhookBot(intents=intents)
    client.run(TOKEN)

if __name__ == "__main__":
    main()
