# netbox-scripts

## cisco-psirt-advisories/cisco_psirt_advisories.py

NetBox custom script that pulls Cisco security advisories from the
[PSIRT openVuln API](https://developer.cisco.com/docs/psirt/) for the software version each device
runs, and writes one journal entry per advisory to the **platform's** journal, nowhere else: the
advisories depend on the OS and version, so each is written once per version platform however many
devices run it. Only version platforms that at least one device in scope uses get entries. Entries are
deduplicated on advisory ID, so re-runs and scheduled runs never repeat an entry. Default scope:
Critical, High and Medium advisories first published in the last 90 days. Journal kind: Critical =
danger, High = warning, Medium/Low = info. Each entry lists the release the advisory was first fixed in.
Find the entries under the platform's Journal tab (reached from the Platform link on a device).

### Platforms

The version comes **only** from the device's platform, which must be a tree of OS > version:

```
Cisco
  IOS
    15.2(7)E2
  IOS-XE
    17.18.2
  NXOS
    10.4(3)
```

The script expects the platform to be correct and sends the leaf platform's name to Cisco as written.
The OS level is recognised by its slug or name: `ios`, `ios-xe`/`iosxe`, `nxos`/`nx-os`, `asa`, `ftd`,
`fmc`, `fxos`. Cisco is strict about the version format: IOS and NX-OS need `15.2(7)E2` / `10.4(3)`
(`15.2.7.E2` and `10.4.3` are rejected), IOS XE uses `17.18.2`. NetBox platform names may contain
parentheses; only the slug may not.

A **device is skipped with a warning** in the script output if it has no platform or if its platform is
not under an OS platform. A **platform is skipped with one warning** (not one per device) if Cisco does
not recognise the version or the Cisco API returns an error. Nothing is guessed or corrected.

Limits: an advisory that Cisco later revises is not re-posted. The journal entry does not list the
devices affected, because that list would go stale; use the platform's device list.

Links in journal entries open in the same tab: NetBox strips `target` from links when it renders
Markdown, so a script cannot change that.

### Credentials

Never entered in the script form: script inputs are stored on the Job record and shown in the UI.
Read at run time from the environment of the process that runs scripts (the RQ worker):

| Variable | Purpose |
|---|---|
| `CISCO_KEY` | Cisco API Console "KEY" |
| `CISCO_CLIENT_SECRET` | Cisco API Console "CLIENT SECRET" |
| `CISCO_CLIENT_SECRET_FILE` | Path to a file holding the secret (preferred) |
| `CISCO_PSIRT_BASE_URL`, `CISCO_PSIRT_TOKEN_URL` | Optional endpoint overrides |

Dev (`netbox-dev`): put the variables in `env/netbox.env` (git-ignored) and recreate the containers,
because `restart` does not re-read env files: `podman-compose up -d --force-recreate netbox netbox-worker`.

Production (bare metal, systemd). Scripts run in `netbox-rq.service`, not the gunicorn service:

```bash
sudo install -m 600 -o root -g root /dev/stdin /etc/netbox/cisco_client_secret <<< "<secret>"
sudo systemctl edit netbox-rq
```
```ini
[Service]
LoadCredential=cisco_client_secret:/etc/netbox/cisco_client_secret
Environment=CISCO_CLIENT_SECRET_FILE=%d/cisco_client_secret
Environment=CISCO_KEY=<key>
```
```bash
sudo systemctl restart netbox-rq
```

systemd copies the credential into a private per-service directory, so the `netbox` user cannot read
`/etc/netbox/cisco_client_secret`. On systemd >= 250 use `systemd-creds encrypt` with
`LoadCredentialEncrypted=` for encryption at rest. Do not put the secret in `Environment=` or
`EnvironmentFile=`: it is visible in `/proc/<pid>/environ` and `systemctl show`.

Also: use a separate Cisco API Console app for production (PSIRT scope only) and rotate its secret;
restrict `extras.add_scriptmodule` and script-run permissions to trusted admins, since script code
runs with the worker's credentials; consider shipping the script through a NetBox git Data Source.

### Install

Upload through the UI (Customization > Scripts > Add), or:

```bash
curl -X POST -H "Authorization: Bearer $NETBOX_TOKEN" \
  -F "file=@cisco-psirt-advisories/cisco_psirt_advisories.py" "$NETBOX_URL/api/extras/scripts/upload/"
```

Runs as a dry run by default (`commit_default = False`). Schedule it daily from the script's run form.
