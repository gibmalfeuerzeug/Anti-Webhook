import os
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import discord
from discord import AuditLogAction

# ---------- CONFIG ----------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
NOTIFY_CHANNEL_ID = 123456789012345678  # Channel-ID für Benachrichtigungen (int)
WHITELIST = {
    111111111111111111,  # erlaubte User-IDs (als ints)
    222222222222222222,
}
AUDIT_LOOKBACK_SECONDS = 5  # wie frisch der Audit-Log-Eintrag sein muss
TIMEOUT_HOURS = 2  # Timeout-Dauer für Verstöße
# ----------------------------

# Intents – angepasst für discord.py 2.4.x
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True

# Logging Setup
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
log = logging.getLogger("anti-webhook")


class AntiWebhookBot(discord.Client):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def on_ready(self):
        log.info(f"✅ Bot ready: {self.user} (id: {self.user.id})")

    async def on_webhooks_update(self, channel: discord.abc.GuildChannel):
        """
        Wird aufgerufen, wenn Webhooks in einem Channel erstellt, gelöscht oder bearbeitet werden.
        Wir prüfen die Audit-Logs auf unautorisierte Erstellungen.
        """
        try:
            guild = channel.guild
            if guild is None:
                return

            log.info(f"⚙️ Webhooks updated in #{channel.name} ({channel.id}) – prüfe Audit-Logs...")

            # Hole den neuesten Audit-Log-Eintrag für webhook_create
            entry = None
            async for e in guild.audit_logs(limit=6, action=AuditLogAction.webhook_create):
                entry = e
                break

            if entry is None:
                log.warning("⚠️ Kein AuditLog-Eintrag für webhook_create gefunden.")
                return

            executor = entry.user
            created_at = entry.created_at

            if executor is None or created_at is None:
                log.warning("⚠️ Audit-Log hat keinen executor/created_at — ignoriere.")
                return

            # Prüfe, ob der Audit-Log-Eintrag frisch genug ist
            now = datetime.now(timezone.utc)
            age = (now - created_at).total_seconds()
            if age > AUDIT_LOOKBACK_SECONDS:
                log.info(f"⌛ Audit-Entry ist {age:.1f}s alt (> {AUDIT_LOOKBACK_SECONDS}s) — ignoriere.")
                return

            log.info(f"🔍 Webhook erstellt von {executor} (id={executor.id}) vor {age:.1f}s")

            # Wenn in Whitelist -> nichts tun
            if executor.id in WHITELIST:
                log.info("🟢 Executor ist whitelisted – kein Eingriff erforderlich.")
                return

            # Nicht whitelisted -> Strafmaßnahmen
            deleted_webhooks = []
            try:
                webhooks = await channel.webhooks()
                candidates = []

                for wh in webhooks:
                    wh_created = getattr(wh, "created_at", None)
                    if wh_created:
                        wh_age = (now - wh_created).total_seconds()
                        if wh_age < 15:  # sehr frisch
                            candidates.append(wh)
                    else:
                        candidates.append(wh)

                target_id = getattr(entry, "target_id", None)
                if hasattr(entry, "target") and entry.target:
                    tid = getattr(entry.target, "id", None)
                    if tid:
                        target_id = int(tid)

                # Versuche gezielt zu löschen
                if target_id:
                    for wh in candidates:
                        try:
                            if int(getattr(wh, "id", 0)) == int(target_id):
                                await wh.delete(reason="Anti-Webhook: Created by non-whitelisted user")
                                deleted_webhooks.append(wh)
                                log.info(f"🗑️ Webhook {wh.id} gelöscht (Match target_id).")
                        except Exception as e:
                            log.exception("Fehler beim gezielten Löschen eines Webhooks: %s", e)

                # Fallback: lösche alle Kandidaten
                if not deleted_webhooks and candidates:
                    for wh in candidates:
                        try:
                            await wh.delete(reason="Anti-Webhook: Created by non-whitelisted user (fallback)")
                            deleted_webhooks.append(wh)
                            log.info(f"🗑️ Webhook {wh.id} gelöscht (Fallback candidate).")
                        except Exception as e:
                            log.exception("Fehler beim Fallback-Löschen eines Webhooks: %s", e)

            except discord.Forbidden:
                log.error("🚫 Bot hat keine Rechte, um Webhooks zu verwalten (Manage Webhooks).")
            except Exception as e:
                log.exception("Fehler beim Verarbeiten von Webhooks: %s", e)

            # Timeout setzen
            try:
                member = guild.get_member(executor.id) or await guild.fetch_member(executor.id)
                if member:
                    until = datetime.now(timezone.utc) + timedelta(hours=TIMEOUT_HOURS)
                    await member.edit(timeout=until, reason="Anti-Webhook: Nicht whitelisted webhook create")
                    log.info(f"⏰ Member {member} in Timeout gesetzt ({TIMEOUT_HOURS}h).")
                else:
                    log.warning("⚠️ Konnte Member nicht finden, kein Timeout gesetzt.")
            except discord.Forbidden:
                log.error("🚫 Bot hat keine Rechte, um Member zu timeouten (Moderate Members).")
            except Exception as e:
                log.exception("Fehler beim Setzen des Timeouts: %s", e)

            # Benachrichtigung senden
            try:
                notify_ch = guild.get_channel(NOTIFY_CHANNEL_ID) or await guild.fetch_channel(NOTIFY_CHANNEL_ID)
                if notify_ch:
                    embed = discord.Embed(
                        title="🚨 Anti-Webhook: Unbefugte Erstellung erkannt",
                        color=discord.Color.red(),
                        timestamp=datetime.now(timezone.utc),
                    )
                    embed.add_field(name="Executor", value=f"{executor} (`{executor.id}`)", inline=False)
                    embed.add_field(name="Channel", value=f"{channel.mention} (`{channel.id}`)", inline=True)
                    embed.add_field(name="Gelöschte Webhooks", value=str(len(deleted_webhooks)), inline=True)
                    embed.set_footer(text=f"Automatisch • Timeout: {TIMEOUT_HOURS} h")

                    await notify_ch.send(embed=embed)
                    log.info("📢 Benachrichtigung gesendet.")
                else:
                    log.warning("⚠️ Notify-Channel nicht gefunden.")
            except Exception as e:
                log.exception("Fehler beim Senden der Benachrichtigung: %s", e)

        except Exception as outer_e:
            log.exception("Unerwarteter Fehler in on_webhooks_update: %s", outer_e)


def main():
    if not TOKEN:
        log.error("❌ Kein DISCORD_TOKEN gefunden! Bitte Environment-Variable setzen.")
        return
    client = AntiWebhookBot(intents=intents)
    client.run(TOKEN)


if __name__ == "__main__":
    main()

