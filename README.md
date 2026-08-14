# MikroTik Security Config Watchdog

A small RouterOS script + scheduler job that periodically re-checks a handful of security invariants on a hardened MikroTik router and logs (loudly, only when something's wrong) any drift — a default-deny rule that vanished, a default admin account that got re-enabled, WPS that came back on, a service that should be off coming back on.

**Tested on:** MikroTik RB951G-2HnD, RouterOS 7.23.3

## Why this exists

Hardening a router once is the easy part. Configs drift — someone applies a script that reorders rules, a Safe Mode session gets committed by mistake, a "just for testing" change never gets reverted. On a real deployment I was maintaining, a single firewall rule silently disappeared between sessions with no clear cause. Nothing caught it until a manual check — which is exactly the kind of thing that shouldn't depend on a human remembering to look.

This isn't a diff against a full config snapshot (too brittle — it'd flag every legitimate change too). It's a short list of specific, deliberately-chosen invariants that should never be false on a hardened router, checked independently of each other.

## What it checks

| Check | Why it matters |
|---|---|
| Explicit `drop all` exists in both `input` and `forward` | RouterOS's chain default is *accept*, not deny — this is the single most important invariant on the whole router. |
| No account with a known default/predictable name is active | The classic first thing to fix, and the easiest thing to forget you fixed. |
| WPS is disabled on every active wireless interface | WPS PINs are brute-forceable regardless of Wi-Fi password strength. |
| Specific services (FTP/Telnet/API/SSH/etc.) stay disabled | Catches a service silently re-enabled by a later change, a restore, or a mistake. |
| Static firewall rule count matches expectation | Catches rules that vanished *or* got added unexpectedly — see the pitfall below. |

Silent on success (aside from an INFO-level heartbeat, so you can confirm the schedule is actually still running). Logs a `warning` per failed check.

## One real pitfall — read before you set the rule-count check

If your router runs the Hotspot feature, RouterOS auto-generates its own firewall rules at runtime (flagged `D` for dynamic in `/ip firewall filter print`) — jump targets, per-session accept/reject rules, etc. These aren't part of your manual configuration and their count isn't fixed. If you count *all* rules for the drift check, you'll get a confusing false alarm the moment Hotspot's internal rule count shifts for reasons that have nothing to do with your actual security posture.

The fix is one word: filter the count to `dynamic=no`.

```
/ip firewall filter print count-only where dynamic=no
```

This is already how `scripts/config-watchdog.rsc` does it — worth understanding why, in case you adapt this for a feature that generates its own dynamic rules in some other way.

## Quick start

1. Get your own baseline count: `/ip firewall filter print count-only where dynamic=no`.
2. Open `scripts/config-watchdog.rsc`, fill in the `CONFIGURE` block at the top (risky usernames, services that should be off, your default-deny comment text, the count from step 1, check interval).
3. Import it: `/import file=config-watchdog.rsc` — this creates both the script and the recurring scheduler job.
4. Run it manually once and check the log:
   ```
   /system script run config-watchdog
   /log print where message~"watchdog"
   ```
5. **Actually test that it catches things** — temporarily re-enable a service that should be off, re-run manually, confirm the warning appears, then revert. A watchdog you haven't seen fail is a watchdog you don't actually trust yet.

Full write-up in [GUIDE.md](GUIDE.md).

## Related

- [mikrotik-hardening-toolkit](https://github.com/GAGAUTKA228/mikrotik-hardening-toolkit) — the baseline hardened setup this watchdog assumes and checks against.
- [mikrotik-port-knocking](https://github.com/GAGAUTKA228/mikrotik-port-knocking) — optional add-on for gated remote admin access.

## License

MIT — see [LICENSE](LICENSE).
