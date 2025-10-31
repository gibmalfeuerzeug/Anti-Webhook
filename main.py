import os
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import discord
from discord import AuditLogAction
from discord.ext import commands

# ---------- CONFIG ----------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
NOTIFY_CHANNEL_ID = 1427757113706418291   # Channel-ID für Benachrichtigungen (int)
BOT_ADMIN_ID = 662596869221908480 # nur dieser User darf die Whitelist bearbeiten
AUDIT_LOOKBACK_SECONDS = 5
TIMEOUT_HOURS = 2
# ----------------------------

# Whitelist-Speicher (flüchtig)
whitelists: dict[int, set[int]] = defaultdict(set)

# Intents
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True

# Logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
log = logging.getLogger("anti-webhook")


# ---------- Bot ----------
bot = commands.Bot(command_prefix="!", intents=intents)


def is_bot_admin(interaction: discord.Interaction) -> bool:
    return interaction.user.id == BOT_ADMIN_ID or (
        interaction.guild and interaction.user.id == interaction.guild.owner_id
    )


def is_whitelisted(guild: discord.Guild, user_id: int) -> bool:
    return user_id in whitelists[guild.id]


@bot.event
async def on_ready():
    log.info(f"✅ Bot ready: {bot.user} (id: {bot.user.id})")
    try:
        await bot.tree.sync()
        log.info("🌐 Slash-Commands global synchronisiert.")
    except Exception as e:
        log.exception("Fehler beim Synchronisieren der Slash-Commands: %s", e)


@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    """Wird aufgerufen, wenn Webhooks in einem Channel erstellt/gelöscht/editiert wurden."""
    try:
        guild = channel.guild
        if guild is None:
            return

        log.info(f"⚙️ Webhooks updated in #{channel.name} ({channel.id}) – prüfe Audit-Logs...")

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

        now = datetime.now(timezone.utc)
        age = (now - created_at).total_seconds()
        if age > AUDIT_LOOKBACK_SECONDS:
            log.info(f"⌛ Audit-Entry ist {age:.1f}s alt (> {AUDIT_LOOKBACK_SECONDS}s) — ignoriere.")
            return

        log.info(f"🔍 Webhook erstellt von {executor} (id={executor.id}) vor {age:.1f}s")

        # Wenn in Whitelist -> nichts tun
        if is_whitelisted(guild, executor.id):
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
                    if wh_age < 15:
                        candidates.append(wh)
                else:
                    candidates.append(wh)

            target_id = getattr(entry, "target_id", None)
            if hasattr(entry, "target") and entry.target:
                tid = getattr(entry.target, "id", None)
                if tid:
                    target_id = int(tid)

            if target_id:
                for wh in candidates:
                    try:
                        if int(getattr(wh, "id", 0)) == int(target_id):
                            await wh.delete(reason="Anti-Webhook: Created by non-whitelisted user")
                            deleted_webhooks.append(wh)
                            log.info(f"🗑️ Webhook {wh.id} gelöscht (Match target_id).")
                    except Exception as e:
                        log.exception("Fehler beim gezielten Löschen eines Webhooks: %s", e)

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

        # Benachrichtigung
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


# ---------- Slash Commands ----------
@bot.tree.command(name="addwhitelist", description="Fügt einen User zur Whitelist hinzu (Admin Only)")
async def add_whitelist(interaction: discord.Interaction, user: discord.User):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message("❌ Keine Berechtigung.", ephemeral=True)
    whitelists[interaction.guild.id].add(user.id)
    await interaction.response.send_message(
        f"✅ User `{user}` wurde in **{interaction.guild.name}** zur Whitelist hinzugefügt.",
        ephemeral=True,
    )


@bot.tree.command(name="removewhitelist", description="Entfernt einen User von der Whitelist (Admin Only)")
async def remove_whitelist(interaction: discord.Interaction, user: discord.User):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message("❌ Keine Berechtigung.", ephemeral=True)
    whitelists[interaction.guild.id].discard(user.id)
    await interaction.response.send_message(
        f"✅ User `{user}` wurde in **{interaction.guild.name}** von der Whitelist entfernt.",
        ephemeral=True,
    )


# ---------- Main ----------
if __name__ == "__main__":
    if not TOKEN:
        log.error("❌ Kein DISCORD_TOKEN gefunden! Bitte Environment-Variable setzen.")
    else:
        bot.run(TOKEN)


