import asyncio
import logging
from datetime import datetime, timedelta, timezone

import discord
from discord import AuditLogAction, PermissionOverwrite

# ---------- CONFIG ----------
TOKEN = "DEIN_BOT_TOKEN_HIER"
NOTIFY_CHANNEL_ID = 123456789012345678  # Channel-ID für Benachrichtigungen (int)
WHITELIST = {
    111111111111111111,  # erlaubte User-IDs (als ints)
    222222222222222222,
}
AUDIT_LOOKBACK_SECONDS = 5  # wie frisch der Audit-Log-Eintrag sein muss
TIMEOUT_HOURS = 2  # Timeout-Dauer für Verstöße
# ----------------------------

intents = discord.Intents.default()
intents.guilds = True
intents.guild_messages = True
intents.members = True  # benötigt, um Member zu timeouten / fetchen

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("anti-webhook")

class AntiWebhookBot(discord.Client):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def on_ready(self):
        log.info(f"Bot ready: {self.user} (id: {self.user.id})")

    async def on_webhooks_update(self, channel: discord.abc.GuildChannel):
        """
        Wird aufgerufen, wenn Webhooks in einem Channel erstellt/gelöscht/editiert wurden.
        Wir prüfen die Audit-Logs auf das neueste WebhookCreate Eintrag.
        """
        try:
            guild = channel.guild
            if guild is None:
                return

            log.info(f"Webhooks updated in #{channel.name} ({channel.id}) - prüfe Audit-Logs...")

            # Hole Audit-Log Einträge für WebhookCreate (neueste zuerst)
            entry = None
            async for e in guild.audit_logs(limit=6, action=AuditLogAction.webhook_create):
                entry = e
                break

            if entry is None:
                log.warning("Kein AuditLog Eintrag für webhook_create gefunden.")
                return

            executor = entry.user or entry.executor  # je nach discord.py version
            created_at = entry.created_at  # datetime in UTC

            if executor is None or created_at is None:
                log.warning("Audit-Log hat keinen executor/created_at — ignoriere.")
                return

            # Prüfe Zeit-Differenz zwischen Audit-Eintrag und jetzt
            now = datetime.now(timezone.utc)
            age = (now - created_at).total_seconds()
            if age > AUDIT_LOOKBACK_SECONDS:
                log.info(f"Audit-Entry ist {age:.1f}s alt (> {AUDIT_LOOKBACK_SECONDS}s) — ignoriere.")
                return

            log.info(f"Webhook erstellt von {executor} (id={executor.id}) vor {age:.1f}s")

            # Wenn in Whitelist -> nichts tun
            if executor.id in WHITELIST:
                log.info("Executor ist in whitelist — erlaube Webhook.")
                return

            # Nicht whitelisted -> Strafmaßnahmen
            # 1) Versuch den/die neuen Webhook(s) zu finden & löschen
            deleted_webhooks = []
            try:
                webhooks = await channel.webhooks()
                # Suche Webhooks, die sehr frisch sind (letzte ~10s)
                candidates = []
                for wh in webhooks:
                    # wh.created_at kann None sein bei manchen Objekten; safe fallback
                    wh_created = getattr(wh, "created_at", None)
                    if wh_created:
                        wh_age = (now - wh_created).total_seconds()
                        if wh_age < 15:  # heuristischer Schwellenwert
                            candidates.append(wh)
                    else:
                        # Falls kein created_at vorhanden, nehme trotzdem als candidate
                        candidates.append(wh)

                # Versuche gezielt Webhook mit ID == entry.target_id (falls vorhanden)
                target_id = getattr(entry, "target_id", None) or getattr(entry, "target", None)
                # Manche discord.py builds haben entry.target_id, manche entry.target.id
                if isinstance(target_id, discord.Object):
                    target_id = int(target_id.id)
                try:
                    if hasattr(entry, "target") and entry.target:
                        # entry.target kann das Webhook-Objekt repräsentieren
                        tid = getattr(entry.target, "id", None)
                        if tid:
                            target_id = int(tid)
                except Exception:
                    pass

                if target_id:
                    for wh in candidates:
                        try:
                            if int(getattr(wh, "id", 0)) == int(target_id):
                                await wh.delete(reason="Anti-Webhook: Created by non-whitelisted user")
                                deleted_webhooks.append(wh)
                                log.info(f"Webhook {wh.id} gelöscht (Match target_id).")
                        except Exception as e:
                            log.exception("Fehler beim Löschen eines Webhooks (target_id-match): %s", e)

                # Fallback: falls noch nichts gelöscht, lösche alle candidate-webhooks (vorsichtig)
                if not deleted_webhooks and candidates:
                    for wh in candidates:
                        try:
                            await wh.delete(reason="Anti-Webhook: Created by non-whitelisted user (fallback)")
                            deleted_webhooks.append(wh)
                            log.info(f"Webhook {wh.id} gelöscht (Fallback candidate).")
                        except Exception as e:
                            log.exception("Fehler beim Löschen eines Webhooks (fallback): %s", e)

            except discord.Forbidden:
                log.error("Bot hat nicht die notwendigen Rechte, um Webhooks zu verwalten (Manage Webhooks).")
            except Exception as e:
                log.exception("Fehler beim Verarbeiten von Webhooks: %s", e)

            # 2) Timeout für den Executor verhängen (2h)
            try:
                member = guild.get_member(executor.id) or await guild.fetch_member(executor.id)
                if member:
                    timeout_duration = timedelta(hours=TIMEOUT_HOURS)
                    until = datetime.utcnow() + timeout_duration
                    # member.edit(timeout=...) erwartet aware datetime in discord.py 2.x
                    await member.edit(timeout=timedelta(hours=TIMEOUT_HOURS), reason="Anti-Webhook: Nicht whitelisted webhook create")
                    log.info(f"Member {member} in Timeout gesetzt ({TIMEOUT_HOURS}h).")
                else:
                    log.warning("Konnte Member nicht finden, kein Timeout gesetzt.")
            except discord.Forbidden:
                log.error("Bot hat nicht die Rechte, um Member zu timeouten (Moderate Members).")
            except Exception as e:
                log.exception("Fehler beim Setzen des Timeouts: %s", e)

            # 3) Benachrichtigung in Channel senden (konfigurierter Channel)
            try:
                notify_ch = guild.get_channel(NOTIFY_CHANNEL_ID) or await guild.fetch_channel(NOTIFY_CHANNEL_ID)
                if notify_ch:
                    embed = discord.Embed(title="Anti-Webhook: Unbefugte Erstellung erkannt",
                                          color=discord.Color.red(),
                                          timestamp=datetime.utcnow())
                    embed.add_field(name="Executor", value=f"{executor} (`{executor.id}`)", inline=False)
                    embed.add_field(name="Channel", value=f"{channel.mention} (`{channel.id}`)", inline=True)
                    embed.add_field(name="Gelöschte Webhooks", value=str(len(deleted_webhooks)), inline=True)
                    embed.set_footer(text=f"Automatisch | Timeout: {TIMEOUT_HOURS}h")

                    await notify_ch.send(embed=embed)
                    log.info("Benachrichtigung gesendet.")
                else:
                    log.warning("Notify-Channel nicht gefunden.")
            except Exception as e:
                log.exception("Fehler beim Senden der Benachrichtigung: %s", e)

        except Exception as outer_e:
            log.exception("Unerwarteter Fehler in on_webhooks_update: %s", outer_e)


def main():
    client = AntiWebhookBot(intents=intents)
    client.run(TOKEN)

if __name__ == "__main__":
    main()
