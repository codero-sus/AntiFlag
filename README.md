# AntiFlag

Many websites flag a harmless **Wi-Fi, school, or corporate proxy** as a **VPN**.
AntiFlag assesses a connection and separates the two cases, so you can tell
them apart instead of treating every intermediary the same way.

It is a small, dependency-free Python package. The classifier is a plain
function, so it can run in a web backend, a CLI, or a test.

## Verdicts

| Verdict   | Meaning                                                                 |
|-----------|-------------------------------------------------------------------------|
| `DIRECT`  | No intermediary and no VPN or hosting network detected.                 |
| `PROXY`   | Forwarding headers from a residential or institutional network. Usually a Wi-Fi, school or corporate proxy, **not** a VPN. |
| `VPN`     | The exit address belongs to a VPN provider.                             |
| `HOSTING` | The exit address is in a datacenter. Could be a VPN, a cloud proxy, or a bot. |

Each result includes a heuristic `confidence` (0 to 1, not a probability) and the
`reasons` behind the verdict.

## How it decides

1. An exit address owned by a VPN provider is a `VPN`, regardless of headers.
2. A datacenter exit is `HOSTING`. It is not labelled a VPN, because the evidence is weaker.
3. Forwarding headers (`Via`, `X-Forwarded-For`, `Forwarded`, and some legacy
   markers) on a residential or institutional network are a `PROXY`.
4. Otherwise the connection is `DIRECT`.

The IP address that opened the connection is the authoritative signal. Forwarding
headers are client-controlled, so they are used only as hints.

## Usage

### Python

```python
from antiflag import NetworkDB, assess, headers_from_wsgi

db = NetworkDB.from_file("networks.json")

# Flask / Django / any WSGI app:
headers = headers_from_wsgi(request.environ)
result = assess(request.remote_addr, headers, lookup=db)

if result.verdict is Verdict.VPN and result.confidence >= 0.9:
    ...  # apply your policy
elif result.verdict is Verdict.PROXY:
    ...  # likely a shared Wi-Fi or school proxy: allow, or show a softer check

print(result.to_dict())
```

Plain headers work too:

```python
assess("203.0.113.7", {"Via": "1.1 hotspot-proxy"}, network=NetworkInfo(...))
```

### Command line

```bash
python -m antiflag check --ip 203.0.113.7 \
    --header "Via: 1.1 wifi-proxy" \
    --db examples/networks.example.json

python -m antiflag check --org "Mullvad VPN AB" --json
```

Install it as a command with `pip install .`, then run `antiflag check --help`.

## Network database

The database maps CIDR ranges to network facts. Longest prefix wins. Create one
from your own IP intelligence source. See `examples/networks.example.json`:

```json
{"networks": [
  {"cidr": "198.51.100.0/24", "org": "Example VPN Ltd", "asn": 64500, "kind": "vpn"}
]}
```

`kind` is one of `residential`, `institution`, `hosting`, `vpn` or `unknown`. If it
is omitted, the kind is inferred from `org` by keyword. Keyword matches are less
certain than curated entries, so they receive lower confidence.

## Keeping up to date

Three updaters pull the latest commits for whichever branch you have checked out.
They never switch branches, and they only fast-forward:

```bash
python3 updaters.py      # Linux, macOS, Windows
./updaters.sh            # Linux, macOS
updaters.bat             # Windows
```

Add `--test` to run the unit tests afterwards. Add `--allow-dirty` to update even
with local edits. Without it, a dirty tree, a detached HEAD, or diverged history
stops the update and leaves everything unchanged.

## Development

```bash
python -m unittest discover -s tests -v
```

The runtime has no dependencies and needs Python 3.10 or newer.

## Limitations

- Keyword rules and the example database are seeds. For production accuracy,
  supply a maintained database of VPN, hosting and ISP ranges.
- Confidence values are hand-tuned heuristics. They are useful for ranking and
  policy thresholds, but they are not calibrated probabilities.
- AntiFlag tells you what a connection looks like. It does not hide or alter
  any connection.
