# netbox-scripts

A collection of [NetBox custom scripts](https://netboxlabs.com/docs/netbox/customization/custom-scripts/).
Each script lives in its own directory with a README covering what it does, its form options, any
credentials it needs and how to install it.

## Scripts

| Script | Description |
|---|---|
| [cisco-psirt-advisories](cisco-psirt-advisories/) | Journals Cisco PSIRT security advisories, enriched with CISA KEV and FIRST EPSS, on the platforms of the software versions Cisco devices run |

## Installing a script

Upload the `.py` file in the UI (Customization > Scripts > Add), or through the API:

```bash
curl -X POST -H "Authorization: Bearer $NETBOX_TOKEN" \
  -F "file=@<directory>/<script>.py" "$NETBOX_URL/api/extras/scripts/upload/"
```

Scripts read secrets from the environment of the NetBox worker process (`netbox-rq` on systemd), never
from the script form, since form inputs are stored on the Job. See each script's README for the
variables it uses.

## License

[MIT](LICENSE)
