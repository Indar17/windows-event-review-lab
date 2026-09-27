# Windows sign-in event review lab

A small, dependency-free Python example that reviews **synthetic** Windows sign-in events. It groups failed sign-ins (Event ID 4625) by account and source IP, flags five or more failures within ten minutes, and marks any later success (4624) from the same pair within fifteen minutes of the flagged burst. The sample CSV contains no real user or company data.

This is a triage aid and learning exercise, not a SIEM, compromise determination, or production incident response tool. A successful sign-in after failures can be a legitimate user correcting a password. Windows security events may have missing or misleading source fields; corroborate any finding with device, identity, and network context.

## Run

Requires Python 3.9 or newer. No packages or account required.

```bash
python3 analyze.py sample_events.csv
python3 -m unittest discover -s tests
```

Options: `--threshold 5 --window-minutes 10 --followup-minutes 15 --format json`.

Expected default output:

```text
2026-08-18T09:08:00+00:00 | FAILED_SIGNIN_BURST | alex.demo | 203.0.113.10 | 5 failures in 10 min
2026-08-18T09:11:00+00:00 | SUCCESS_AFTER_BURST | alex.demo | 203.0.113.10 | success 3 min after flagged burst
```

The address `203.0.113.10` is in a documentation-only range. Names and hostnames are fictional.

## Input contract

CSV columns: `timestamp_utc,event_id,account,source_ip,computer`. Timestamps must be timezone-aware ISO 8601 strings. Rows are sorted by timestamp before analysis. Events other than 4624 and 4625 are ignored. Malformed rows fail with a line number; unknown accounts/IPs are not silently collapsed into a shared group.

## How I would investigate a finding

1. Confirm the user, device, timestamp, and IP against identity and endpoint logs.
2. Check whether the account was locked out, password was reset, or MFA challenged.
3. Determine whether the IP is a trusted VPN, shared NAT, or documentation/test address.
4. Escalate according to the organization's runbook; record the evidence and outcome.

## Limits and next steps

The detector has no baseline, geolocation, suppression list, streaming state, or severity scoring. A source IP alone does not identify a person. Further work could ingest exported EVTX data in a separate adapter, add account-specific thresholds, and report analyst annotations. Do not upload employer logs, secrets, or client identifiers to a public repository.

**Portfolio disclosure:** This is a self-directed lab built with fictional data. It is not a paid client project.
