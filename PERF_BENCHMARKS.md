# AgentGuard — Performance Benchmarks

## SLA Targets

| Operation | p50 | p95 | p99 | Sustained |
|-----------|-----|-----|-----|-----------|
| Interceptor overhead | <5ms | <20ms | <50ms | — |
| Policy evaluation | <1ms | <3ms | <5ms | — |
| DLP scan (10KB) | — | — | <50ms | — |
| Queue enqueue | — | — | <5ms | — |
| Injection Stage 1 | — | — | <5ms | — |
| Event throughput | — | — | — | 100+ events/sec |
| Dashboard load (10K events) | — | — | — | <3 seconds |

## How to Run Benchmarks

### 1. Interceptor Overhead

```bash
pytest tests/test_interceptor.py::TestInterceptorLatency -v
```

Measures 1000 on_tool_start → on_tool_end cycles.

### 2. Policy Evaluation

```bash
pytest tests/test_policy_engine.py::TestPolicyPerformance -v
```

Measures 1000 rule evaluations against 10-rule default policy.

### 3. Queue Enqueue Latency

```bash
pytest tests/test_event_store.py::TestEnqueuePerformance -v
```

Measures 1000 enqueue operations with p99 assertion.

### 4. Injection Detection Stage 1

```bash
pytest tests/test_injection_detector.py::TestInjectionPerformance -v
```

Measures 500 regex scans on 1KB input.

### 5. Sustained Throughput (Locust)

Install Locust:
```bash
pip install locust
```

Create `locustfile.py`:
```python
from locust import HttpUser, task, between

class AgentGuardUser(HttpUser):
    wait_time = between(0.01, 0.05)
    host = "http://localhost:8000"

    def on_start(self):
        resp = self.client.post("/auth/token", json={"api_key": "admin-key-dev"})
        self.token = resp.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    @task(5)
    def query_events(self):
        self.client.post("/events", json={"limit": 10}, headers=self.headers)

    @task(1)
    def health(self):
        self.client.get("/health")

    @task(1)
    def metrics(self):
        self.client.get("/metrics")

    @task(1)
    def verify_chain(self):
        self.client.get("/audit/verify", headers=self.headers)
```

Run:
```bash
# Start API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# In another terminal
locust -f locustfile.py --headless -u 50 -r 10 -t 60s --host http://localhost:8000
```

Target: 100+ events/sec sustained with p99 < 500ms.

### 6. Docker Compose Full Stack

```bash
docker compose up -d
# Wait for healthy
docker compose ps

# Run Locust against Docker stack
locust -f locustfile.py --headless -u 100 -r 20 -t 120s --host http://localhost:8000
```

## Results Template

| Test | Date | Events/sec | p50 | p95 | p99 | Pass |
|------|------|-----------|-----|-----|-----|------|
| Interceptor | — | — | — | — | — | — |
| Policy eval | — | — | — | — | — | — |
| Queue enqueue | — | — | — | — | — | — |
| Injection S1 | — | — | — | — | — | — |
| Locust (SQLite) | — | — | — | — | — | — |
| Locust (PostgreSQL) | — | — | — | — | — | — |
