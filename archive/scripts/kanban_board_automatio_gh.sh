#!/bin/bash

# CONFIGURATION
ASSIGNEE="@me"

# Function to add a task with labels
add_task() {
    local title="$1"
    local body="$2"
    
    echo "Creating issue: $title..."
    
    issue_url=$(gh issue create \
        --title "$title" \
        --body "$body" \
        --assignee "$ASSIGNEE")
        
    echo "Created: $issue_url"
}

echo "Starting Granular PyPI Phase II Backlog Generation..."

# Current relavant and coresponding kanban projects for phase 2

# ---------------------------------------------------------
# SIMULATOR & STORAGE (Based on Tasks 10 & 11)
# ---------------------------------------------------------

add_task "[Task 10.1] Setup Flask App Boilerplate (main.py)" \
"**Description:** Initialize the minimal Flask application for the simulator.
**Acceptance Criteria:**
- [ ] Create \`main.py\`
- [ ] Define \`PyPISimulatorApp\` class
- [ ] Configure basic Flask routing structure
- [ ] Ensure app runs on localhost development server" "simulator"

add_task "[Task 10.2] Implement PEP 503 Routing (simple.py)" \
"**Description:** Build the /simple/ endpoints required for pip compatibility.
**Acceptance Criteria:**
- [ ] Create \`simple.py\`
- [ ] Implement \`SimpleAPI\` and \`SimpleIndexRenderer\` classes
- [ ] Implement \`ProjectIndex\` class
- [ ] Route \`/simple/\` to list all available projects
- [ ] Route \`/simple/<project>/\` to list project specific versions" "simulator"

add_task "[Task 11.1] Define SQLite Database Schema" \
"**Description:** Design and initialize the metadata database for injected packages.
**Acceptance Criteria:**
- [ ] Create SQLite schema for packages, versions, and file paths
- [ ] Write initialization script to create tables if they don't exist
- [ ] Create \`MetadataStore\` class for app integration" "database"

add_task "[Task 11.2] Build SQL API Abstraction (sql.py)" \
"**Description:** Implement the CRUD operations abstraction layer.
**Acceptance Criteria:**
- [ ] Create \`sql.py\`
- [ ] Implement secure SQL insert operations for new package uploads
- [ ] Implement select operations to feed data to \`simple.py\` renderers
- [ ] Handle database connection pooling/closing cleanly" "database"

add_task "[Task 10.3] Artifact Serving & Twine Integration" \
"**Description:** Allow the simulator to serve actual .tar.gz/.whl files and accept uploads.
**Acceptance Criteria:**
- [ ] Create endpoint to serve static distribution files
- [ ] Create basic upload endpoint for Twine compatibility
- [ ] Test upload with Twine
- [ ] Test download/install with Pip" "integration"

# ---------------------------------------------------------
# DIFFING ENGINE (Based on Tasks 13, 14, 16 & 17)
# ---------------------------------------------------------

add_task "[Task 17] Implement Centralized Logging (logger.py)" \
"**Description:** Build the log module shared between Injector and Analyzer.
**Acceptance Criteria:**
- [ ] Create \`logger.py\`
- [ ] Implement \`Logger\` class with debug, info, warning, error levels
- [ ] Configure file and console output formats" "infrastructure"

add_task "[Task 13.1] Diff Engine: Unpacking Logic (diff.py)" \
"**Description:** Implement extraction of Python distribution files.
**Acceptance Criteria:**
- [ ] Create \`diff.py\` and \`PackageExtractor\` class
- [ ] Implement extraction for \`.tar.gz\` (sdist)
- [ ] Implement extraction for \`.whl\` (bdist)
- [ ] Securely extract to temporary directories" "analyzer"

add_task "[Task 13.2] Diff Engine: Static Code Diffing (diff.py)" \
"**Description:** Compute the differences between consecutive package versions.
**Acceptance Criteria:**
- [ ] Implement \`DiffEngine\` class
- [ ] Compare extracted directories of Version A and Version B
- [ ] Generate standard diff outputs
- [ ] Implement \`DiffParser\` to normalize the diffs for downstream AI analysis" "analyzer"

add_task "[Task 13.3] Diff Engine: Artifact Filtering" \
"**Description:** Filter out noise from the diffs before sending to detection tools.
**Acceptance Criteria:**
- [ ] Filter out unchanged files
- [ ] Filter out non-code artifacts (e.g., images, compiled binaries)
- [ ] Ensure only human-readable source code changes are retained" "analyzer"

add_task "[Task 14] Unit Test Diffing Logic" \
"**Description:** Write tests to ensure diffs are accurate.
**Acceptance Criteria:**
- [ ] Create mock Version A and Version B packages
- [ ] Test that \`DiffEngine\` correctly identifies added, modified, and deleted lines
- [ ] Test that filtering correctly ignores non-code artifacts" "testing"

echo "Granular tasks generated! Check your GitHub repo."
