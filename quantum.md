### jq stream directly from tshark
### ie., list all dns queries in real-time

```bash
sudo \
  `# capture filter to JSON` \
  tshark -T json -i enp0s17 port 53 and not src 10.1.10.1 | \
  `# JSON->LDJSON conversion aids streaming` \
  sed -r '/^(\[|  ,)$/d' | \
  `# reduce to data of interest` \
  jq -c '._source.layers | {ts: .frame["frame.time"], src: .ip["ip.src"], dns: .dns.Queries | map(.["dns.qry.name"]) }' | \
  `# log to disk while tailing` \
  tee dns.log
```
