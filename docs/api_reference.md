# VERITAS-lite API reference

Base URL: `http://localhost:8000`. Interactive OpenAPI documentation is served from `/docs`; the ReDoc view is `/redoc`.

## Health

### `GET /health`

Returns API and database health. The check succeeds when the campaign table exists, including when there are no campaign rows.

```json
{"status":"healthy","version":"0.1.0"}
```

## Campaigns

### `POST /campaigns`

Create a campaign and queue its LangGraph run. Returns HTTP `202` with `campaign_id` and `status`. The request may provide `sut_descriptor`, `threat_model`, `budget` (`max_steps`, `max_tokens`), and `human_policy`; defaults select the custom three-tool SUT.

### `GET /campaigns?page=1&limit=20`

List campaigns newest first. `page` starts at 1 and `limit` is 1–100. The response includes `campaigns`, `page`, `limit`, and `total`.

### `GET /campaigns/{campaign_id}`

Return campaign status, current phase and metrics, step count, and timestamps. Missing campaigns return `404`.

### `DELETE /campaigns/{campaign_id}`

Cancel an active campaign. Only `running` campaigns can be cancelled; missing campaigns return `404`, and other statuses return `400`.

### `POST /campaigns/{campaign_id}/resume`

Resume a campaign paused for human review. The body is `{"approved": true, "comment": "optional note"}`. Missing campaigns return `404`; campaigns that are not paused return `400`.

## Reports and traces

### `GET /campaigns/{campaign_id}/report`

Return the final `CampaignReport` and a human-readable `summary`. The campaign must be completed; otherwise the route returns `400`.

### `GET /campaigns/{campaign_id}/traces`

Return all traces for a campaign. Secret-bearing values are redacted before serialization.

### `GET /campaigns/{campaign_id}/traces/{trace_id}`

Return one redacted trace. A missing campaign or trace returns `404`.

### `GET /campaigns/{campaign_id}/ws`

WebSocket stream of `phase`, `asr_before`, `asr_after`, and `step_count`, sent every two seconds while the campaign is active. The stream stops for completed, failed, or cancelled campaigns.

## Metrics

### `GET /metrics`

Return aggregate campaign counts, mean ASR before/after, total regression test count, and applied patch count.

## Example

```bash
curl -X POST http://localhost:8000/campaigns \
  -H 'Content-Type: application/json' \
  -d '{"budget":{"max_steps":10,"max_tokens":20000}}'
```
