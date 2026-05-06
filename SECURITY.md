# Security & Threat Model

Unincorporated Protocol provides a transparent, tamper-evident proxy that sits in front of your database (Postgres/MongoDB/S3) and generates a cryptographically verifiable audit chain for every access.

This document outlines our security policies and our explicit threat model (what we protect against, and what we don't).

## Reporting a Vulnerability

If you discover a security vulnerability in the Unincorporated Protocol, the Rust proxy, the WASM verifier, or the hosted platform, please report it privately.

**Please do not open public GitHub issues for security vulnerabilities.**

Send an email to: **uninchq@gmail.com**

We will respond within 48 hours to acknowledge receipt and coordinate a fix and disclosure timeline.

## Threat Model & Honest Limits

Any tool that claims to eliminate trust entirely is selling theatre. What happens after data reaches an admin's screen is beyond any database tool's control. Below is a breakdown of what the Unincorporated proxy catches, what it only surfaces, and what remains a genuine gap.

### 1. In Scope: Caught & Logged
*   **Admin Data Access:** Admins reading, writing, or bulk-exporting user records through the proxy (`SELECT`, `UPDATE`, `pg_dump`). Every query is logged, and users see who read what and when.
*   **Rogue DB Users:** An admin trying to avoid detection by creating a shadow user (`CREATE USER`). The creation goes through the proxy and is logged.
*   **AI Agent Actions:** Autonomous agents querying the database are logged with their exact credential label (e.g., `agent:triage-bot`). The affected user sees an entry labeled as agent traffic, not human admin.
*   **Rate Storms:** An agent in an infinite loop reading a profile 1,000 times will generate 1,000 chain entries, providing undeniable proof of the malfunction.

### 2. Partial Coverage: Visible, but Not Prevented
*   **We are the camera, not the locked door:** The proxy does not *prevent* an authorized admin or AI agent from querying the database. It guarantees that the access is undeniably recorded in a client-verifiable Merkle chain.
*   **Slow Exfiltration:** An admin script reading one user per hour for weeks. Every query is logged, but detecting the anomaly requires analyzing the chain over time.
*   **Data Handling Post-Retrieval:** Once an admin copies results to their clipboard, saves a CSV, or screenshots their monitor, the data has left the database layer. This is an access control problem, not an audit logging problem.

### 3. Out of Scope: Genuine Gaps
*   **Direct Database Access (Bypassing the Proxy):** In a self-hosted environment, if an admin connects directly to the raw DB port (e.g., `5432` on the DB host instead of the proxy), the query is not logged. *Note: In our managed 5-VM topology, the DB replicas sit on a private subnet with no public IP, and the Observer VM cross-checks the DB's native replication stream (WAL) to detect bypasses or proxy lies.*
*   **OS-Level Root Compromise (Self-Hosted):** If an attacker gains `root` access to the Docker host running the proxy and chain engine, they control everything. They can delete chain files or extract encryption keys.
*   **Backups and WAL Files:** Out-of-band backups (e.g., `pg_basebackup` to a separate bucket) never flow through the proxy. Backup storage requires its own access controls.
*   **Outbound Application HTTP Calls:** If an AI agent reads user data and then posts it to an external webhook, the database access is logged, but the outbound HTTP call leaves the app container and is invisible to the database proxy.

## Verification Architecture (Managed Tier)

For deployments using our multi-VM topology, the trust boundary does not end at the proxy. To prevent a compromised proxy from silently rewriting history:

1.  **Chain Quorum:** The proxy fans out chain writes to multiple chain-MinIO sidecars.
2.  **The Observer VM:** An independent VM subscribes directly to the upstream primitive's native replication stream (Postgres logical replication, MongoDB change streams, S3 bucket notifications) using read-only credentials issued out-of-band. It independently hashes the operations and cross-verifies them against the proxy's chain.

If the proxy is compromised and attempts to log a fabricated history, the Observer detects the mismatch from the database's actual replication output and fires an alert.