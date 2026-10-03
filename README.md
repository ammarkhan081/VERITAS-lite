# VERITAS-lite

**A closed-loop, multi-agent system that tests AI agents for security failures and applies defenses.**

VERITAS-lite runs attacks against a system under test (SUT), verifies behavior with deterministic gates, proposes defenses, then checks attack resistance and normal-task utility again.

## Architecture

```text
┌────────────────┐       ┌──────────────────────────┐
│ FastAPI clients │──────▶│ Campaign API + SQLite    │
└────────────────┘       └─────────────┬────────────┘
                                        │
                               ┌────────▼────────┐
                               │ LangGraph loop  │
                               │ attack → verify │
                               │ defend → confirm│
                               └───┬─────────┬───┘
                                   │         │
                         ┌─────────▼──┐ ┌────▼──────────┐
                         │ Agents     │ │ Evaluation    │
                         │ & Gates    │ │ & Environment │
                         └──────┬──────┘ └─────┬────────┘
                                │              │
                                └──────┬───────┘
                                  ┌────▼────┐
                                  │ Core    │
                                  │ Memory  │
                                  │ Schemas │
                                  └─────────┘
```

## Quick start with Docker Compose

Run these commands from the project root:

```bash
cp .env.example .env
docker compose --profile frontend up --build -d
python scripts/run_campaign.py --api-url http://localhost:8000
```

The frontend is available at [http://localhost:3000](http://localhost:3000). API docs are at [http://localhost:8000/docs](http://localhost:8000/docs).

## Local Development Setup

1. Create and activate a Python 3.12+ virtual environment:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate  # On Windows
   ```
2. Install the dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. Copy `.env.example` to `.env`, select an LLM provider, and set its API key for live campaigns.
4. Start the API server:
   ```bash
   uvicorn backend.api.main:app --reload
   ```
5. In another terminal, start the frontend (Node.js 24+):
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open [http://localhost:5173](http://localhost:5173). Vite proxies `/api` requests and campaign WebSockets to the API on port 8000.

Check dependency imports before starting with `python scripts/check_deps.py`.

## Demo

From the project root, run:

```bash
python scripts/demo.py
```

The scripted demo uses a seeded indirect-injection attack, mock tools, and a deterministic SUT mode. It makes no network or LLM calls and shows baseline utility, the attack, proposed defenses, same-attack and held-out retests, and final metrics.

For a live LLM-backed campaign, start the API and use `python scripts/run_campaign.py`. Configure the `LLM_PROVIDER` and matching API key in `.env` first.

## Tests

The project includes a comprehensive pytest suite. Run it from the project root:

```bash
pytest tests/ -v
```

Tests use deterministic adapters, isolated SQLite databases, and mocked campaign workers; they do not call external services or live LLMs.

## API reference

The live OpenAPI UI is served at `/docs`.

## Project structure

```text
backend/
├── agents/          # Multi-agent implementations (Red, Blue, Verifier, Orchestrator)
├── api/             # FastAPI application and routes
├── core/            # Configuration and common utilities
├── environment/     # SUT adapters and mock tools
├── eval/            # Normal and held-out task evaluation
├── gates/           # Deterministic security and structural gates
├── memory/          # SQLite stores for campaigns and regressions
├── orchestration/   # LangGraph StateGraph definitions
└── schemas/         # Shared Pydantic models and TypedDicts
scripts/             # Campaign CLI and deterministic demo
tests/               # Full test suite
frontend/            # React + TypeScript campaign workspace
```

## Configuration

The `.env` file supports these settings:

| Variable | Purpose |
| --- | --- |
| `LLM_PROVIDER` | `openai`, `anthropic`, or `groq` for live agent and SUT calls |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GROQ_API_KEY` | Provider credentials |
| `ORCHESTRATOR_MODEL`, `RED_TEAM_MODEL`, `BLUE_TEAM_MODEL`, `VERIFIER_LLM_MODEL` | Model per agent role |
| `DATABASE_URL` | SQLite database path |
| `ENVIRONMENT_TYPE` | `custom_sut` (default) or `agentdojo` |
| `AGENTDOJO_SUITE` | Intended suite name for the AgentDojo adapter stub |
| `NORMAL_TASK_ACCURACY_THRESHOLD` | Maximum tolerated normal-task accuracy loss |
| `DEFAULT_MAX_STEPS`, `DEFAULT_MAX_TOKENS` | Default campaign budget |
| `SECRET_PATTERNS` | Secret labels to redact from returned traces (JSON list format) |

## Limitations and non-goals

- AgentDojo is an explicit stub until its separate validation is complete.
- The custom SUT tools use mock search results, an in-memory filesystem, and an in-memory message log; they do not access real services or write to disk.
- Live campaigns depend on configured model providers. The packaged demo is deterministic and offline.
- The frontend exposes the campaign, metrics, trace, and report data available through the current API. The API does not expose patch proposal details, a global regression-test list, or a campaign event feed; the UI does not fabricate those views.

## License

MIT. See [`LICENSE`](LICENSE).
