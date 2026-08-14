# Full Guide: Security Config Watchdog

## The problem this solves

A hardened firewall configuration is a snapshot in time. Nothing about RouterOS guarantees it stays that way — rules get reordered during later changes, a Safe Mode session can get committed with an unintended state if you're not paying close attention, backups get restored from an older point, someone with access makes a "temporary" change and forgets to revert it. None of that shows up anywhere unless you go looking.

This script automates the looking. It runs on a schedule, checks a small set of specific claims about the router's state, and only makes noise when one of those claims turns out to be false.

## Design choice: invariants, not diffs

An earlier version of this idea compared the *entire* firewall rule set against a saved baseline. That's the wrong tool: any legitimate change (adding a rule for a new device, adjusting a port) triggers a false alarm, which trains you to ignore the alerts — the worst possible outcome for a monitoring tool.

Instead, this checks a short list of things that should be true on *any* correctly hardened router, independent of the specific rule set:

- A default-deny catch-all exists in both `input` and `forward`.
- No account with an easily-guessed default name is currently enabled.
- WPS is off everywhere.
- Specific services you've decided you don't need stay off.
- The count of rules *you* wrote by hand hasn't silently changed.

Each check is independent — you can lose one and the script still correctly evaluates the rest.

## Setup

### 1. Establish your baseline rule count

```
/ip firewall filter print count-only where dynamic=no
```

Write this number down — it goes into the script's `CONFIGURE` block. Re-run this any time you *intentionally* add or remove a static rule, and update the script accordingly; otherwise the watchdog will (correctly) flag your own deliberate change as drift.

### 2. Fill in the configuration block

Open `scripts/config-watchdog.rsc` and edit the `CONFIGURE` section at the top:

```
:local riskyUsernames {"admin"}
:local servicesShouldBeOff {"ftp";"telnet";"api";"api-ssl";"ssh"}
:local denyComment "drop all else (default deny)"
:local expectedFilterCount <the number from step 1>
```

- `riskyUsernames` — any default/predictable account names that should never be active. Add more if you've dealt with other default accounts beyond the built-in `admin`.
- `servicesShouldBeOff` — trim this to match your actual setup. If you legitimately use SSH, remove it from the list — otherwise you'll get a permanent false alarm.
- `denyComment` — must match the exact comment text on your default-deny rules. If you named yours differently, change this string.

### 3. Import

```
/import file=config-watchdog.rsc
```

This does two things in one shot: creates a `/system script` named `config-watchdog` containing the check logic, and a `/system scheduler` entry that runs it on an interval (default in the template: every 30 minutes — adjust the `interval=` value to taste).

### 4. Verify it actually runs correctly

```
/system script run config-watchdog
/log print where message~"watchdog"
```

You should see either a single `info` line (`OK - all checks passed`) or one `warning` per failed check plus a summary line. If you see a warning about the filter rule count on the very first run, double-check step 1 — it's more likely your `expectedFilterCount` doesn't match reality yet than that something's actually wrong.

### 5. Prove to yourself that it catches real problems

Don't trust a watchdog you've never seen fail. Pick something safe to temporarily break:

```
/ip service enable ftp
/system script run config-watchdog
/log print where message~"watchdog"
```

Confirm the FTP warning shows up, then revert:

```
/ip service disable ftp
/system script run config-watchdog
```

The next log entry should be clean again (the earlier warning stays in the log history — that's expected, logs aren't a live status display, they're a history).

### 6. Let one real scheduled cycle run

Wait out a full `interval` and confirm a new log entry appears without you manually running anything. That's the actual proof the scheduler is wired up correctly, not just the script logic.

## The dynamic-rules pitfall, in detail

If you run RouterOS's Hotspot feature, checking `/ip firewall filter print` (no filter) shows rules with a `D` flag — `hs-input`, `hs-unauth`, jump targets, per-client accept/reject rules. These are generated and managed by the Hotspot service itself at runtime, not something you configured by hand, and their exact count isn't fixed — it can shift based on RouterOS version, active hotspot profiles, or internal implementation details that have nothing to do with your security posture.

If your rule-count check naively counts everything, you'll get a false "drift detected" alarm the first time that dynamic count changes for entirely benign reasons — and a monitoring tool that cries wolf gets ignored. The fix is scoping the count to only what you actually wrote:

```
/ip firewall filter print count-only where dynamic=no
```

This is a specific instance of a general rule worth internalizing for any RouterOS automation: **always check whether a feature you're using generates its own dynamic rules before writing a check that assumes a static rule table.** Hotspot is the one I hit; other features (like certain VPN or CAPsMAN setups) do similar things.

## Extending this

A few natural next steps, not included here to keep the base version simple to audit and trust:

- **Email/notification on failure** — RouterOS has a built-in `/tool e-mail send` you can call from inside the `:if ($issues > 0)` block, if you configure SMTP settings (`/tool e-mail set ...`).
- **Escalating alerts** — track how many consecutive runs have failed and only notify loudly after N consecutive failures, to smooth over transient blips.
- **More checks** — DNS fallback server configured, NAT rule count, hotspot user list not containing unexpected accounts. The pattern (independent, specific, silent-on-pass) extends cleanly.
