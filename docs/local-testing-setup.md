# Local Testing Setup — Splunk & Elasticsearch with Docker

This guide walks through deploying free, local Splunk and Elasticsearch instances using Docker so you can test the deploy workflow's hunt phase end-to-end.

---

## Prerequisites

- Docker and Docker Compose installed
- At least 6 GB of free RAM (Splunk ~2 GB, Elasticsearch ~2 GB, overhead ~2 GB)
- Ports 8089 (Splunk management) and 9200 (Elasticsearch) available

---

## 1. Create the Docker Compose File

Create a `docker-compose.testing.yml` in the repo root:

```yaml
services:
  splunk:
    image: splunk/splunk:latest
    container_name: splunk
    environment:
      SPLUNK_START_ARGS: --accept-license
      SPLUNK_PASSWORD: changeme123   # Min 8 chars
      SPLUNK_HEC_TOKEN: ""           # We'll use session token instead
    ports:
      - "8000:8000"   # Web UI
      - "8089:8089"   # REST API (this is what the pipeline uses)
    volumes:
      - splunk-data:/opt/splunk/var
    restart: unless-stopped

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.17.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false   # Disable HTTPS for local testing
      - ELASTIC_PASSWORD=changeme123
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "9200:9200"
    volumes:
      - elastic-data:/usr/share/elasticsearch/data
    restart: unless-stopped

volumes:
  splunk-data:
  elastic-data:
```

---

## 2. Start the Containers

```bash
docker compose -f docker-compose.testing.yml up -d
```

Wait for both services to become healthy (~60-90 seconds):

```bash
# Check Splunk is ready (returns JSON when ready)
curl -s -k -u admin:changeme123 https://localhost:8089/services/server/info?output_mode=json | head -c 200

# Check Elasticsearch is ready
curl -s -u elastic:changeme123 http://localhost:9200/_cluster/health | head -c 200
```

---

## 3. Configure Splunk

### 3.1 Create an Authentication Token

The pipeline authenticates to Splunk using a Bearer token. Create one via the REST API:

```bash
# Create a token for the admin user
curl -s -k -u admin:changeme123 \
  -X POST https://localhost:8089/services/authorization/tokens \
  -d name=admin \
  -d audience=ioc-pipeline \
  -d output_mode=json | python3 -m json.tool
```

Copy the `token` value from the response — this is your `SPLUNK_TOKEN`.

### 3.2 Ingest Sample Data

Load some test events that match the IOC field names the pipeline searches for:

```bash
# Create an index (optional — default "main" already exists)
# Ingest test events via the REST API
curl -s -k -u admin:changeme123 \
  -X POST https://localhost:8089/services/receivers/simple?index=main\&sourcetype=test \
  -d '{"src_ip": "185.220.101.34", "dest_ip": "10.0.0.5", "action": "allowed"}'

curl -s -k -u admin:changeme123 \
  -X POST https://localhost:8089/services/receivers/simple?index=main\&sourcetype=test \
  -d '{"query": "evil-domain.com", "src_ip": "10.0.0.2", "action": "dns-query"}'

curl -s -k -u admin:changeme123 \
  -X POST https://localhost:8089/services/receivers/simple?index=main\&sourcetype=test \
  -d '{"url": "http://login-secure-update.com/office365/signin.php", "src_ip": "10.0.0.3"}'

curl -s -k -u admin:changeme123 \
  -X POST https://localhost:8089/services/receivers/simple?index=main\&sourcetype=test \
  -d '{"file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hostname": "workstation-01"}'
```

### 3.3 Verify Data Is Searchable

```bash
curl -s -k -u admin:changeme123 \
  -X POST https://localhost:8089/services/search/jobs/export \
  -d 'search=search index=main | head 10' \
  -d output_mode=json
```

You should see the events you just ingested.

---

## 4. Configure Elasticsearch

### 4.1 Create an API Key

The pipeline authenticates to Elasticsearch using an API key:

```bash
# Create an API key
curl -s -u elastic:changeme123 \
  -X POST http://localhost:9200/_security/api_key \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ioc-pipeline-key",
    "role_descriptors": {
      "ioc_reader": {
        "cluster": ["monitor"],
        "index": [
          {
            "names": ["*"],
            "privileges": ["read", "view_index_metadata"]
          }
        ]
      }
    }
  }' | python3 -m json.tool
```

The response contains `id` and `api_key`. The pipeline expects the **encoded** form. Combine them:

```bash
# The "encoded" field in the response is what you need — use it directly as ELASTIC_API_KEY
# If only id + api_key are returned, encode them:
echo -n "<id>:<api_key>" | base64
```

This base64 string is your `ELASTIC_API_KEY`.

### 4.2 Create an Index and Ingest Sample Data

Use ECS-compatible field names so the hunt queries match:

```bash
# Create an index with a basic mapping
curl -s -u elastic:changeme123 \
  -X PUT http://localhost:9200/ioc-test \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": {
      "properties": {
        "@timestamp":        { "type": "date" },
        "source.ip":         { "type": "ip" },
        "destination.ip":    { "type": "ip" },
        "dns.question.name": { "type": "keyword" },
        "url.full":          { "type": "keyword" },
        "url.original":      { "type": "keyword" },
        "url.domain":        { "type": "keyword" },
        "file.hash.md5":     { "type": "keyword" },
        "file.hash.sha1":    { "type": "keyword" },
        "file.hash.sha256":  { "type": "keyword" }
      }
    }
  }'

# Ingest test events
curl -s -u elastic:changeme123 \
  -X POST http://localhost:9200/ioc-test/_doc \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "source.ip": "185.220.101.34",
    "destination.ip": "10.0.0.5",
    "event.action": "allowed"
  }'

curl -s -u elastic:changeme123 \
  -X POST http://localhost:9200/ioc-test/_doc \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "dns.question.name": "evil-domain.com",
    "source.ip": "10.0.0.2"
  }'

curl -s -u elastic:changeme123 \
  -X POST http://localhost:9200/ioc-test/_doc \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "url.full": "http://login-secure-update.com/office365/signin.php",
    "source.ip": "10.0.0.3"
  }'

curl -s -u elastic:changeme123 \
  -X POST http://localhost:9200/ioc-test/_doc \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "file.hash.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "host.name": "workstation-01"
  }'
```

### 4.3 Verify Data Is Searchable

```bash
curl -s -u elastic:changeme123 \
  'http://localhost:9200/ioc-test/_search?pretty&size=5'
```

---

## 5. Test the Pipeline Locally

Run the pipeline's publish command against your local instances:

```bash
source .venv/bin/activate

export SPLUNK_URL="https://localhost:8089"
export SPLUNK_TOKEN="<token from step 3.1>"
export SPLUNK_INDEX="main"

export ELASTIC_URL="http://localhost:9200"
export ELASTIC_API_KEY="<encoded key from step 4.1>"
export ELASTIC_INDEX="ioc-test"
export ELASTIC_VERIFY_SSL="false"

export MAX_IOC_AGE_DAYS="30"
export PUBLISHERS="splunk,elastic"

python -m src.cli publish
```

If your master inventory (`iocs/master-indicators.csv`) has IOCs that match the sample data, you should see hunt hits in the output.

---

## 6. Test via GitHub Actions (with Tunneling)

To test the full deploy workflow from GitHub Actions against your local Docker instances, you need to expose them publicly. Use a tunneling service:

### Option A: ngrok (free tier)

```bash
# Install ngrok
# https://ngrok.com/download

# Expose Splunk (HTTPS)
ngrok http https://localhost:8089

# In a separate terminal, expose Elasticsearch (HTTP)
ngrok http http://localhost:9200
```

Use the ngrok URLs as your `SPLUNK_URL` and `ELASTIC_URL` GitHub secrets.

### Option B: Cloudflare Tunnel (free)

```bash
# Install cloudflared
# https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

cloudflared tunnel --url https://localhost:8089
# In a separate terminal:
cloudflared tunnel --url http://localhost:9200
```

### Set GitHub Secrets

Go to your repo **Settings > Secrets and variables > Actions** and set:

| Secret              | Value                                   |
|---------------------|-----------------------------------------|
| `SPLUNK_URL`        | Your tunnel URL for port 8089           |
| `SPLUNK_TOKEN`      | Token from step 3.1                     |
| `ELASTIC_URL`       | Your tunnel URL for port 9200           |
| `ELASTIC_API_KEY`   | Encoded API key from step 4.1           |

Set these as **variables** (not secrets):

| Variable                     | Value      |
|------------------------------|------------|
| `SPLUNK_INDEX`               | `main`     |
| `ELASTIC_INDEX`              | `ioc-test` |
| `ELASTIC_VERIFY_SSL`         | `false`    |

Then trigger the deploy workflow by merging a PR that modifies `iocs/indicators.txt`.

---

## 7. Teardown

```bash
docker compose -f docker-compose.testing.yml down

# To also remove persisted data:
docker compose -f docker-compose.testing.yml down -v
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Splunk returns 401 | Token may have expired — regenerate it (step 3.1) |
| Elasticsearch connection refused | Wait longer for startup; check `docker logs elasticsearch` |
| No hunt results | Verify the sample data field names match the IOC types in your `master-indicators.csv` |
| Splunk SSL errors locally | Expected — the pipeline sets `ssl=False` for Splunk connections |
| Elastic `security_exception` | API key may lack permissions — recreate with the role descriptor above |
| `docker compose` not found | Use `docker-compose` (hyphenated) if on an older Docker version |

---

## Cost

Everything here is free:
- **Splunk**: The `splunk/splunk` Docker image includes a free trial license (500 MB/day indexing)
- **Elasticsearch**: The base image is free and open; security features are included in the basic license
- **ngrok/Cloudflare Tunnel**: Both have free tiers sufficient for testing
