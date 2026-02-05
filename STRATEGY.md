```markdown
# MCPMint Strategy & Roadmap

**Status:** Strategic North Star (Living Document)  
**Goal:** Build the standard infrastructure for safe, versioned agent-to-API communication.

---

## 1. Positioning

### The "Hook" (Marketing)
**"MCPMint: The Traffic-to-MCP Compiler."**  
*Pitch:* Turn real browser traffic into safe, runnable MCP servers (Claude Desktop compatible) in seconds. No boilerplate.  
*Audience:* Developers, Indie Hackers, AI Engineers.  
*Channels:* Hacker News, X/Twitter, Reddit.

### The "Truth" (Architecture)
**"MCPMint: An Action Surface Compiler."**  
*Pitch:* A compiler that transforms raw traffic into versioned, governable tool contracts with drift detection.  
*Audience:* Platform Engineers, Security Teams, CTOs.  
*Value:* Prevents runtime tool breakage and reduces unsafe tool calls when APIs change.

---

## 2. Technical Roadmap

### Phase 1: The Viral Wedge (Weeks 1–2)
**Objective:** Solve the MCP “cold start” problem: users should be able to capture traffic and immediately run a safe tool server.

1. **Capture Engine**
   * Support HAR import: `mcpmint capture import <traffic.har> --name <capture_name>`
   * **Naming Heuristics:** Use `verb_noun` intent detection with collision handling:
     * `GET /users/{id}` → `get_user`
     * `GET /users` → `list_users`
     * `POST /users` → `create_user`
     * **Collision Strategy:** Namespace by service/host first, then fall back to counter:
       * `get_user__auth_service` or `get_user__api_example_com`
       * if still collides: `get_user__api_example_com__2`
   * **Scope Default:** `agent_safe_readonly` (conservative baseline):
     * default includes `GET` only
     * **Read-Only POST** allowed only via explicit policy exception (see Policy below)

2. **Protocol-Agnostic Core (Non-Negotiable)**
   * **Intermediate Artifact:** `manifest.json` (generic tool manifest using JSON Schema)
   * The manifest is the source of truth. Everything else is a compiler target.
   * **Adapter Pattern:** `manifest.json` → target format:
     * Target A: **MCP Server** (Python/TS) — *launch focus*
     * Target B: OpenAPI/Swagger — future
     * Target C: OpenAI tool definitions — future

3. **Data Privacy & Redaction (Crucial)**
   * **Zero-Copy HAR:** MCPMint reads the HAR and extracts normalized definitions. It does **not** copy the raw HAR into the artifact store by default.
   * **Redaction before persistence:**
     * Headers: `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`, common key/token headers
     * Query params: keys matching patterns like `token`, `key`, `auth`, `signature`, `session`
     * Bodies: default to schema inference and key sampling; avoid storing raw payloads unless explicitly enabled
   * **Artifacts:** Only normalized, redacted contracts/manifests/policies are saved.

4. **Authentication Handling**
   * **Capture-time:** credentials are stripped/redacted; never persisted into artifacts.
   * **Compile-time:** generated servers contain *placeholders* for secrets.
   * **Runtime:** credentials are injected from env/config only.
     * Example: `API_KEY = os.getenv("API_KEY")`
   * No hardcoded secrets. Ever.

5. **Compiler Target: MCP Adapter (Launch Deliverable)**
   * Command: `mcpmint compile --capture <name_or_id> --format mcp-python`
   * Output: standalone `server.py` using the MCP SDK + `httpx`.
   * **Safety baked in** at runtime:
     * allowlist enforcement (hosts and optional path patterns)
     * policy evaluation for scopes and read-only exceptions
     * confirmation requirement for state-changing calls
     * redaction on logging and persisted audit records

6. **The "Magic Moment" Demo**
   * User browses a local demo app and exports a HAR.
   * `capture` → `compile`
   * Claude Desktop can immediately call tools to read data.
   * Trust moment: a write attempt is blocked with a clear policy error.

---

### Phase 2: The Infrastructure Moat (Weeks 3–4)
**Objective:** Solve “semantic drift” with automated identity management and approval workflows.

1. **Three-Layer Identity Model**
   * **`signature_id` (Physical / Location):**
     * `sha256(method + host + normalized_path_template + sorted_param_keys)`
   * **`tool_id` (Logical / Identity):**
     * stable semantic name used by agents and humans (e.g., `get_user_profile`)
     * default via naming heuristics; override by user tag
   * **`tool_version` (Version):**
     * integer incremented on breaking schema changes
   * **`aliases`:**
     * list of previous `signature_id`s mapped to this tool identity

2. **Approval Persistence (Non-Negotiable for Teams)**
   * Store approvals/mappings in a repo-friendly lockfile:
     * `mcpmint.lock.json` (or `mcpmint.lock.yaml`)
   * The lockfile records:
     * `tool_id`, `tool_version`
     * current `signature_id`
     * `aliases`
     * timestamps and optional approver metadata (when used in CI)

3. **Automated Mapping Engine (Deterministic Similarity)**
   * When an old `signature_id` disappears and a new one appears, compute similarity.
   * **Hard rule:** method mismatch → score = 0
   * **Score formula (deterministic):**
     * Host match: `+0.20`
     * Path token overlap (Jaccard): `+0.15 * overlap`
     * Response schema key overlap: `+0.40 * overlap`
     * Request schema key overlap: `+0.15 * overlap`
     * Status code pattern match: `+0.05`
     * Content-type match: `+0.05`
   * **Thresholds:**
     * `>= 0.90`: high confidence suggestion
     * `0.75–0.90`: medium confidence suggestion (explicit “review” label)
     * `< 0.75`: treat as new tool
   * **Workflow:**
     * engine suggests: “Looks like tool moved” with score + reasons
     * user approves in CLI/CI → mapping written to lockfile
     * no manual re-tagging as a primary flow

4. **Drift Outcomes**
   * `same_tool_breaking_change`:
     * signature same, schema incompatible
     * action: increment `tool_version`, alert/fail gate (configurable)
   * `same_tool_nonbreaking_change`:
     * signature same, schema additive/compatible
     * action: update schema, no alert by default
   * `candidate_tool_move`:
     * new signature appears, similarity to existing tool meets threshold
     * action: suggest mapping, require approval
   * `new_tool`:
     * new signature, low similarity
     * action: add as new tool
   * `removed_tool`:
     * old signature disappears with no match
     * action: alert (configurable), mark removed

5. **Read-Only POST Policy (More Than Path + Content-Type)**
   * Default deny for `POST` in `agent_safe_readonly`.
   * Allow only if:
     * explicitly allowlisted by endpoint pattern **and**
     * declared as read-only in policy **and**
     * optional additional check passes:
       * GraphQL: allow only `query`, block `mutation` unless `--allow-risk`
       * Search APIs: allow only if request body matches allowlisted schema keys (policy-controlled)

---

### Phase 3: Monetization (Month 2+)
**Objective:** Convert adoption into paid controls and automation.

1. **The "Drift Gate" (CI/CD Product)**
   * GitHub Action: `mcpmint/check-drift`
   * Runs in PRs:
     * fails if a stable `tool_id` has:
       * breaking change without version bump, or
       * unmapped move (candidate move not approved), or
       * policy violations (optional)
   * Pricing:
     * free for public repos
     * paid license for private repos (final model TBD)

2. **The "Governance Gateway" (Enterprise)**
   * Sell control and auditability:
     * RBAC: which agents can call which tools
     * audit trails: who approved or executed risky actions
     * human-in-the-loop approvals (Slack, email, etc.)
     * budgets, rate limits, and “block on unknown drift”

---

## 3. Go-to-Market Execution

### Launch Post Outline
**Title:** I built a compiler that turns HAR files into safe MCP servers.

**Content:**
1. The problem: docs drift, writing schemas is boring, full API access for agents is dangerous.
2. The solution: capture traffic → compile a safe subset → run a tool server.
3. The demo: capture → compile → agent call → blocked write.
4. The senior detail: MCPMint detects likely tool moves and proposes mappings so identity stays stable after approval.

---

## 4. Key Differentiators (Why MCPMint)

| Feature | Generic Generators | MCPMint |
| :--- | :--- | :--- |
| Input | Swagger/OpenAPI (often stale) | **Real traffic** (truth) |
| Safety | “Good luck” | **Safe-by-default** + enforcement |
| Identity | Path-based | **Signature + Tool ID + Approval mapping** |
| Drift | Diff endpoints | **Risk-aware drift** + CI gating |
| Privacy | Unclear | **Redacted-by-default**, zero-copy HAR |
| Output | Manifests only | **Runnable MCP server** + generic manifest |