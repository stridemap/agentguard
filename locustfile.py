"""Locust load test for AgentGuard API.

Simulates sustained 100+ events/sec with mixed endpoint traffic.

Run:
    # Start API first
    uvicorn api.main:app --host 0.0.0.0 --port 8000

    # Run load test
    locust -f locustfile.py --headless -u 50 -r 10 -t 60s --host http://localhost:8000

    # With web UI
    locust -f locustfile.py --host http://localhost:8000
"""

from locust import HttpUser, between, task


class AgentGuardUser(HttpUser):
    """Simulates an authenticated API consumer."""

    wait_time = between(0.01, 0.05)

    def on_start(self):
        """Authenticate on user start."""
        resp = self.client.post(
            "/auth/token",
            json={"api_key": "admin-key-dev"},
        )
        if resp.status_code == 200:
            self.token = resp.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.token = ""
            self.headers = {}

    @task(10)
    def query_events(self):
        """Most frequent: query events with small limit."""
        self.client.post(
            "/events",
            json={"limit": 10},
            headers=self.headers,
        )

    @task(5)
    def health_check(self):
        """Health endpoint (no auth)."""
        self.client.get("/health")

    @task(3)
    def metrics(self):
        """Prometheus metrics (no auth)."""
        self.client.get("/metrics")

    @task(2)
    def verify_chain(self):
        """Audit chain verification."""
        self.client.get("/audit/verify", headers=self.headers)

    @task(1)
    def list_policies(self):
        """List policy rules."""
        self.client.get("/policies", headers=self.headers)

    @task(1)
    def federation_stats(self):
        """Federation statistics."""
        self.client.get("/federation/stats", headers=self.headers)

    @task(1)
    def marketplace_packs(self):
        """List marketplace packs."""
        self.client.get("/marketplace/packs", headers=self.headers)
