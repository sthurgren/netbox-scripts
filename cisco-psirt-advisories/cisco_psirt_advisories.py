"""
Cisco PSIRT advisories -> NetBox platform journals.

Pulls security advisories from the Cisco PSIRT openVuln API for the software version each device runs
and records each one as a journal entry on that version's platform, once however many devices run it.
The version comes only from the device's platform, which must be a tree of OS > version
(Cisco > IOS-XE > 17.18.2) and is expected to be correct: a device whose platform cannot be used is
skipped with a warning. Re-runs never repeat an entry.

Credentials are read at run time from the environment, never from the form (script inputs are stored
on the Job record). See README.md.
"""
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
from django.contrib.contenttypes.models import ContentType

from dcim.models import Device, DeviceType, Manufacturer, Platform
from extras.models import JournalEntry
from extras.scripts import (
    IntegerVar, MultiChoiceVar, MultiObjectVar, ObjectVar, Script,
)
from utilities.exceptions import AbortScript

DEFAULT_BASE_URL = 'https://apix.cisco.com/security/advisories/v2'
DEFAULT_TOKEN_URL = 'https://id.cisco.com/oauth2/default/v1/token'

SEVERITY_CHOICES = (
    ('Critical', 'Critical'),
    ('High', 'High'),
    ('Medium', 'Medium'),
    ('Low', 'Low'),
    ('Informational', 'Informational'),
)
# Cisco Security Impact Rating -> JournalEntry.kind
SEVERITY_KIND = {
    'critical': 'danger',
    'high': 'warning',
    'medium': 'info',
    'low': 'info',
    'informational': 'info',
}

# Platform slug/name of the OS level -> openVuln OSType
OS_TYPES = {
    'ios': 'ios',
    'ios-xe': 'iosxe',
    'iosxe': 'iosxe',
    'nxos': 'nxos',
    'nx-os': 'nxos',
    'asa': 'asa',
    'ftd': 'ftd',
    'fmc': 'fmc',
    'fxos': 'fxos',
}

MAX_RETRIES = 5
REQUEST_INTERVAL = 0.5  # seconds between API calls


class PSIRTError(Exception):
    pass


class PSIRTUnknownVersion(PSIRTError):
    """Cisco does not recognise the software version (INVALID_<OS>_VERSION)."""


def load_credentials():
    """Return (key, client_secret) as shown in the Cisco API Console; either may be None."""
    key = os.environ.get('CISCO_KEY')
    secret = os.environ.get('CISCO_CLIENT_SECRET')
    secret_file = os.environ.get('CISCO_CLIENT_SECRET_FILE')
    if not secret and secret_file:
        try:
            with open(secret_file) as f:
                secret = f.read().strip()
        except OSError as e:
            raise AbortScript(f"Cannot read CISCO_CLIENT_SECRET_FILE ({secret_file}): {e.strerror}")
    return key, secret


def parse_date(value):
    """Parse a Cisco timestamp; returns an aware datetime or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def os_type_for(platform):
    return OS_TYPES.get(platform.slug.lower()) or OS_TYPES.get(platform.name.lower())


def software_of(platform):
    """
    (os_type, version) from a platform tree of OS > version (Cisco > IOS-XE > 17.18.2), or None.

    The platform's name is the version, sent to Cisco as written, and the nearest ancestor that names
    an OS gives the OS type.
    """
    node = platform.parent
    while node is not None:
        os_type = os_type_for(node)
        if os_type:
            return os_type, platform.name
        node = node.parent
    return None


class PSIRTClient:
    """Minimal openVuln client: OAuth2 client credentials, retry on 429, 404 == no results."""

    def __init__(self, client_id, client_secret, base_url=None, token_url=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip('/')
        self.token_url = token_url or DEFAULT_TOKEN_URL
        self.session = requests.Session()
        self.token = None
        self._last_call = 0.0

    def authenticate(self):
        try:
            resp = self.session.post(
                self.token_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                },
                timeout=30,
            )
        except requests.RequestException as e:
            raise PSIRTError(f"token request failed: {e.__class__.__name__}")
        if resp.status_code != 200:
            raise PSIRTError(f"token request returned HTTP {resp.status_code}")
        self.token = resp.json().get('access_token')
        if not self.token:
            raise PSIRTError("token response had no access_token")

    def _get(self, path, params=None):
        reauthed = False
        for attempt in range(MAX_RETRIES):
            wait = REQUEST_INTERVAL - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            try:
                resp = self.session.get(
                    f'{self.base_url}/{path}',
                    params=params,
                    headers={'Authorization': f'Bearer {self.token}', 'Accept': 'application/json'},
                    timeout=60,
                )
            except requests.RequestException as e:
                raise PSIRTError(f"{path}: {e.__class__.__name__}")
            self._last_call = time.monotonic()
            if resp.status_code == 429:
                time.sleep(float(resp.headers.get('Retry-After') or 2 ** attempt))
                continue
            if resp.status_code == 401 and not reauthed:
                reauthed = True
                self.authenticate()
                continue
            if resp.status_code == 404:
                return []
            if resp.status_code == 406 and re.search(r'INVALID_\w+_VERSION', resp.text):
                raise PSIRTUnknownVersion(f"{path}: version not recognised by Cisco")
            if resp.status_code != 200:
                raise PSIRTError(f"{path}: HTTP {resp.status_code}")
            return resp.json().get('advisories') or []
        raise PSIRTError(f"{path}: gave up after {MAX_RETRIES} attempts (rate limited)")

    def by_software(self, os_type, version):
        return self._get(f'OSType/{os_type}', {'version': version})


def render_entry(advisory, os_type, version):
    """Markdown body for one advisory. The first line carries the advisory ID (used for dedup)."""
    adv_id = advisory.get('advisoryId')
    published = parse_date(advisory.get('firstPublished'))
    facts = [
        advisory.get('sir') or 'Unrated',
        f"CVSS {advisory['cvssBaseScore']}" if advisory.get('cvssBaseScore') else None,
        f"first published {published:%Y-%m-%d}" if published else None,
    ]
    lines = [
        f"**{adv_id}**",
        '',
        f"### {advisory.get('advisoryTitle') or adv_id}",
        ' · '.join(f for f in facts if f),
        '',
    ]
    cves = advisory.get('cves') or []
    if cves:
        lines += [f"CVEs: {', '.join(cves)}", '']
    affects = f"Affects `{os_type} {version}`"
    first_fixed = advisory.get('firstFixed') or []
    if first_fixed:
        affects += f"; first fixed in {', '.join(first_fixed)}"
    lines.append(affects)
    if advisory.get('publicationUrl'):
        lines += ['', f"[Cisco advisory]({advisory['publicationUrl']})"]
    return '\n'.join(lines)


class CiscoPSIRTAdvisories(Script):
    class Meta:
        name = "Cisco PSIRT Advisories"
        description = (
            "Pull Cisco security advisories from the PSIRT openVuln API for the software version each "
            "device runs, and write each one to the platform journal."
        )
        commit_default = False
        scheduling_enabled = True
        job_timeout = 600
        fieldsets = (
            ('Scope', ('manufacturer', 'device_types')),
            ('Advisories', ('severities', 'lookback_days')),
        )

    manufacturer = ObjectVar(
        model=Manufacturer,
        required=False,
        description="Manufacturer whose devices are processed. Defaults to Cisco.",
    )
    device_types = MultiObjectVar(
        model=DeviceType,
        required=False,
        query_params={'manufacturer_id': '$manufacturer'},
        description="Limit to devices of these device types. Leave empty for all of the manufacturer's.",
    )
    severities = MultiChoiceVar(
        choices=SEVERITY_CHOICES,
        default=['Critical', 'High', 'Medium'],
        description="Cisco Security Impact Ratings to include.",
    )
    lookback_days = IntegerVar(
        default=90, min_value=1, max_value=3650,
        description="Only advisories first published within this many days.",
    )

    def run(self, data, commit):
        key, secret = load_credentials()
        if not (key and secret):
            raise AbortScript(
                "Cisco API credentials not configured: set CISCO_KEY and CISCO_CLIENT_SECRET "
                "(or CISCO_CLIENT_SECRET_FILE) in the NetBox worker's environment."
            )
        client = PSIRTClient(
            key, secret,
            base_url=os.environ.get('CISCO_PSIRT_BASE_URL'),
            token_url=os.environ.get('CISCO_PSIRT_TOKEN_URL'),
        )
        try:
            client.authenticate()
        except PSIRTError as e:
            raise AbortScript(f"Cisco authentication failed: {e}")
        self.log_debug("Obtained Cisco API token.")

        manufacturer = data.get('manufacturer') or Manufacturer.objects.filter(slug='cisco').first()
        if manufacturer is None:
            raise AbortScript("No manufacturer selected and no manufacturer with slug 'cisco' exists.")
        device_types = data.get('device_types') or DeviceType.objects.filter(manufacturer=manufacturer)
        devices = Device.objects.filter(device_type__in=device_types).select_related('platform')

        severities = {s.lower() for s in data['severities']}
        cutoff = datetime.now(timezone.utc) - timedelta(days=data['lookback_days'])
        user = getattr(self.request, 'user', None)
        if not getattr(user, 'is_authenticated', False):
            user = None
        ct = ContentType.objects.get_for_model(Platform)

        cache = {}  # (os_type, version) -> advisories, or None if Cisco does not recognise the version
        platforms = {}  # platform -> (software, device names); only platforms that a device uses
        totals = {'created': 0, 'existing': 0, 'devices skipped': 0, 'platforms skipped': 0}

        for device in devices:
            if device.platform is None:
                self.log_warning("Skipped: the device has no platform.", device)
                totals['devices skipped'] += 1
                continue
            software = software_of(device.platform)
            if software is None:
                self.log_warning(
                    f"Skipped: platform `{device.platform}` is not an OS > version platform "
                    "(expected e.g. Cisco > IOS-XE > 17.18.2).",
                    device,
                )
                totals['devices skipped'] += 1
                continue
            platforms.setdefault(device.platform, (software, []))[1].append(device.name or f'#{device.pk}')

        for platform, (software, names) in platforms.items():
            label = f"{software[0]} {software[1]} ({len(names)} device{'s' if len(names) != 1 else ''})"
            if software not in cache:
                try:
                    cache[software] = client.by_software(*software)
                except PSIRTUnknownVersion:
                    cache[software] = None
                except PSIRTError as e:
                    self.log_warning(f"Skipped: Cisco API error for {label}: {e}", platform)
                    totals['platforms skipped'] += 1
                    continue
            advisories = cache[software]
            if advisories is None:
                self.log_warning(
                    f"Skipped: Cisco does not recognise {software[0]} version `{software[1]}` "
                    f"({len(names)} device{'s' if len(names) != 1 else ''}). Check the platform name.",
                    platform,
                )
                totals['platforms skipped'] += 1
                continue

            relevant = [
                adv for adv in advisories
                if (adv.get('sir') or '').lower() in severities
                and not ((published := parse_date(adv.get('firstPublished'))) and published < cutoff)
            ]
            existing = list(
                JournalEntry.objects.filter(assigned_object_type=ct, assigned_object_id=platform.pk)
                .values_list('comments', flat=True)
            )
            created = 0
            for adv in sorted(relevant, key=lambda a: a['advisoryId']):
                if any(adv['advisoryId'] in comments for comments in existing):
                    totals['existing'] += 1
                    continue
                entry = JournalEntry(
                    assigned_object=platform,
                    kind=SEVERITY_KIND.get((adv.get('sir') or '').lower(), 'info'),
                    comments=render_entry(adv, *software),
                    created_by=user,
                )
                entry.full_clean()
                entry.save()
                created += 1
            totals['created'] += created

            if created:
                self.log_success(f"{label}: wrote {created} new advisory journal entries.", platform)
            elif relevant:
                self.log_info(f"{label}: {len(relevant)} matching advisories, all already journaled.", platform)
            else:
                self.log_info(f"{label}: no matching advisories in the selected window.", platform)

        return (
            f"{totals['created']} entries created, {totals['existing']} already recorded, "
            f"{totals['devices skipped']} devices and {totals['platforms skipped']} platforms skipped "
            "(see warnings)."
        )


script_order = (CiscoPSIRTAdvisories,)
