# netbox-scripts

## cisco-psirt-advisories/cisco_psirt_advisories.py

NetBox custom script. For each software version in use by Cisco devices, it queries the
[Cisco PSIRT openVuln API](https://developer.cisco.com/docs/psirt/) and writes one journal entry per
advisory to the version's **platform** (once per platform, however many devices run it). Entries are
deduplicated on advisory ID, so re-runs never repeat one.

Form options: manufacturer (default Cisco), device types (default all), severities (default Critical,
High, Medium) and lookback days (default 90, by first-published date). Journal kind: Critical = danger,
High = warning, Medium/Low/Informational = info.

### Enrichment

Each entry also shows [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) status
(known exploited, kind becomes danger whatever Cisco's rating) and the highest
[FIRST EPSS](https://www.first.org/epss/) exploit probability, as of the run date. If an advisory's CVE
is added to KEV after it was journaled, one follow-up entry is written. Both feeds are public, need no
credentials, and the worker needs outbound access to `cisa.gov` and `api.first.org`. If a feed is
unreachable the run warns and continues without it.

### Platforms

The version comes only from the device's platform, which must be a tree of OS > version. The leaf
name is sent to Cisco as written:

```
Cisco
  IOS-XE
    17.18.2
```

Recognised OS platforms (by slug or name): `ios`, `ios-xe`/`iosxe`, `nxos`/`nx-os`, `asa`, `ftd`,
`fmc`, `fxos`. Use Cisco's version format: `17.18.2` (IOS XE), `15.2(7)E2` (IOS), `10.4(3)` (NX-OS).

Devices with no platform or a platform outside an OS tree are skipped with a warning. So is a platform
whose version Cisco rejects or whose API call fails (one warning per platform). Advisories Cisco later
revises are not re-posted, and EPSS is not refreshed after an entry is written.

### Credentials

Read from the environment of the NetBox worker process (never from the form, as inputs are stored on
the Job):

| Variable | Purpose |
|---|---|
| `CISCO_KEY` | Cisco API Console key |
| `CISCO_CLIENT_SECRET` | Cisco API Console client secret |
| `CISCO_CLIENT_SECRET_FILE` | Path to a file holding the secret (preferred over the variable) |
| `CISCO_PSIRT_BASE_URL`, `CISCO_PSIRT_TOKEN_URL` | Optional endpoint overrides |

On systemd, scripts run in `netbox-rq.service`. Pass the secret as a credential, not `Environment=`:

```ini
# sudo systemctl edit netbox-rq
[Service]
LoadCredential=cisco_client_secret:/etc/netbox/cisco_client_secret
Environment=CISCO_CLIENT_SECRET_FILE=%d/cisco_client_secret
Environment=CISCO_KEY=<key>
```

### Install

Upload in the UI (Customization > Scripts > Add), or:

```bash
curl -X POST -H "Authorization: Bearer $NETBOX_TOKEN" \
  -F "file=@cisco-psirt-advisories/cisco_psirt_advisories.py" "$NETBOX_URL/api/extras/scripts/upload/"
```

Runs as a dry run by default (`commit_default = False`); scheduling is enabled, e.g. daily.
