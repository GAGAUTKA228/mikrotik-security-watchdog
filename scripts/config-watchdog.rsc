# =============================================================================
# MikroTik Security Config Watchdog — config-watchdog.rsc
#
# Periodically re-verifies a handful of security invariants on a hardened
# MikroTik router and logs (silently, unless something's wrong) any drift:
# default-deny rules missing, default admin account re-enabled, WPS turned
# back on, a service that should be off coming back on, or the static
# firewall rule count changing unexpectedly.
#
# See ../GUIDE.md for the full story, including one real pitfall (dynamic
# hotspot-generated rules inflating the count check) that will otherwise
# produce a confusing false alarm.
#
# Tested on: MikroTik RB951G-2HnD, RouterOS 7.23.3
#
# BEFORE RUNNING:
#   1. Adjust every value in the CONFIGURE block below to match your setup.
#   2. Import this once — it creates a /system script AND a scheduler job
#      that re-runs it automatically. No need to re-import on every check.
# =============================================================================

/system script
add name=config-watchdog policy=read,write,test source={

    # ============================ CONFIGURE =================================
    # Usernames that should never be active. Add any default/predictable
    # account names you've renamed or disabled.
    :local riskyUsernames {"admin"}

    # Services that should be disabled. Remove any you actually use.
    :local servicesShouldBeOff {"ftp";"telnet";"api";"api-ssl";"ssh"}

    # Exact comment text of your default-deny rules in each chain.
    :local denyComment "drop all else (default deny)"

    # Expected count of your OWN static firewall filter rules — NOT
    # including anything RouterOS generates dynamically (see GUIDE.md).
    # Get this number with: /ip firewall filter print count-only where dynamic=no
    :local expectedFilterCount <expected-static-rule-count>
    # ==========================================================================

    :local issues 0

    :local denyInput [/ip firewall filter print count-only where chain=input comment=$denyComment]
    :local denyForward [/ip firewall filter print count-only where chain=forward comment=$denyComment]
    :if ($denyInput = 0) do={
        :log warning "[watchdog] CRITICAL: no default-deny rule in input chain!"
        :set issues ($issues + 1)
    }
    :if ($denyForward = 0) do={
        :log warning "[watchdog] CRITICAL: no default-deny rule in forward chain!"
        :set issues ($issues + 1)
    }

    :foreach uname in=$riskyUsernames do={
        :local activeCount [/user print count-only where name=$uname disabled=no]
        :if ($activeCount > 0) do={
            :log warning "[watchdog] Account '$uname' is ACTIVE and should not be"
            :set issues ($issues + 1)
        }
    }

    :foreach i in=[/interface wireless find disabled=no] do={
        :local wps [/interface wireless get $i wps-mode]
        :local ifname [/interface wireless get $i name]
        :if ($wps != "disabled") do={
            :log warning "[watchdog] WPS is NOT disabled on wireless interface: $ifname"
            :set issues ($issues + 1)
        }
    }

    :foreach svc in=$servicesShouldBeOff do={
        :local isDisabled [/ip service get $svc disabled]
        :if ($isDisabled = false) do={
            :log warning "[watchdog] Service '$svc' is ENABLED but should be disabled"
            :set issues ($issues + 1)
        }
    }

    # Only count STATIC rules — RouterOS features like Hotspot generate
    # their own dynamic (D-flagged) rules automatically; their count isn't
    # fixed and isn't part of your manual configuration. See GUIDE.md.
    :local actualFilterCount [/ip firewall filter print count-only where dynamic=no]
    :if ($actualFilterCount != $expectedFilterCount) do={
        :log warning "[watchdog] Static filter rule count drifted! expected=$expectedFilterCount actual=$actualFilterCount"
        :set issues ($issues + 1)
    }

    :if ($issues = 0) do={
        :log info "[watchdog] OK - all checks passed"
    } else={
        :log warning "[watchdog] $issues issue(s) found -- see warnings above"
    }
}

/system scheduler
add name=config-watchdog-schedule interval=<check-interval, e.g. 30m> \
    on-event="/system script run config-watchdog" \
    comment="Security posture watchdog - re-checks critical invariants on a schedule"
