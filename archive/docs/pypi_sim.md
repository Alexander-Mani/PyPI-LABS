# Component Requirements: PyPI Simulator

### 1. Functional Requirements (Core)
* **Protocol Compliance:** Must implement **PEP 503** (Simple Repository API) to support standard `pip install`.
* **Read Endpoint (`/simple/`):**
    * **Dynamic Indexing:** Automatically generate HTML `<a>` tags for all files in the storage directory upon request.
    * **Normalization:** Map package names to normalized URLs (e.g., `Silent-Sync` -> `/simple/silentsync/`) per PEP 503 rules.
* **Write Endpoint (`/legacy/`):**
    * **Compatibility:** Accept `POST` requests from `twine` (multipart/form-data).
    * **Payload Handling:** Receive and store `.tar.gz` and `.whl` files directly to the local filesystem.

### 2. Attack Simulation Configuration
* **Typosquatting Support:**
    * **Action:** **DISABLE** name-similarity checks (Levenstein distance guards).
    * **Reason:** Allows registration of lookalike packages (e.g., `colorizer`) that legitimate repositories might otherwise auto-block, enabling detection testing.
* **Dependency Confusion Support:**
    * **Action:** **ACCEPT** arbitrary high version numbers (e.g., `99.9.9`, `2025.1.1`).
    * **Reason:** Simulates the specific "higher version wins" mechanic used in substitution attacks.
* **Credential Takeover Support:**
    * **Action:** **ENFORCE** standard versioning (Must bump version to upload, e.g., v1.0.0 -> v1.0.1).
    * **Reason:** Mimics real PyPI immutability. The "Hack" is the *content* of the new version, not the overwriting of the old file.

### 3. Non-Functional Requirements
* **Infrastructure:** Run on a dedicated **Frostbyte** VM to ensure isolation.
* **Tech Stack:** Python 3.9+ (Standard Library or lightweight Flask).
* **Data Storage:** Stateless/Flat-file storage (directory-based).
* **Network:** Bind to local interface; isolated from public PyPI.
