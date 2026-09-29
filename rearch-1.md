You are a Principal Software Architect and Staff Python Systems Engineer.

Using the codebase analysis and baseline architecture already captured in our `.kiro/` steering and project context, design and implement a full architectural modernization of this Python application. 

Do not patch existing technical debt piecemeal. Instead, refactor and restructure the application to adhere to clean, enterprise-grade architecture patterns while maximizing reusability, modularity, and operational efficiency.

Follow Kiro's Spec-Driven lifecycle: formalize the architectural specifications first (`requirements.md`, `design.md`, `tasks.md`), wait for human review at each phase gate, and execute the planned tasks in discrete, test-driven phases.

---

### Core Architectural Directives

1. **Architecture & Separation of Concerns:**
   - Enforce Clean/Hexagonal (Ports & Adapters) Architecture:
     - **Domain Layer:** Pure business logic and entity models, strictly decoupled from external libraries, frameworks, or database drivers.
     - **Application/Service Layer:** Orchestration, use-case handlers, and Unit-of-Work patterns.
     - **Infrastructure Layer:** Repositories, external clients, concrete ORM mappers, message queues, and persistence mechanics.
     - **Presentation/Transport Layer:** API routers, CLI entrypoints, or event consumers with thin, declarative handlers.
   - Adhere strictly to SOLID principles, high cohesion, low coupling, and explicit Dependency Injection (DI).

2. **Templatization, Reusability & DRY:**
   - **Generic Repositories & Base Services:** Establish type-safe, generic base classes (e.g., `BaseRepository[ModelType, CreateSchema, UpdateSchema]`, `BaseService[ModelType]`) using Python `typing.Generic` and TypeVars to eliminate boilerplate CRUD and queries.
   - **Cross-Cutting Concerns:** Templatize standardized middleware, correlation ID tracking, structured JSON logging, exception-to-HTTP mapping, and distributed tracing.
   - **Validation & Serialization:** Standardize schema contracts using modern Pydantic v2 (or domain entity dataclasses) with shared base models, audit timestamps, and field converters.
   - **Config & Environment:** Consolidate configuration into a strongly typed, environment-driven settings manager (e.g., `pydantic-settings`).

3. **Performance & Concurrency Optimization:**
   - Eliminate all blocking I/O calls within async event loops (`asyncio`).
   - Implement connection pooling, query batching, and eager-loading where needed to eliminate N+1 database queries.
   - Use idempotent retry mechanisms with exponential backoff for transient network and database failures.

4. **Reliability, Testing & Quality Gates:**
   - For every modern service/layer, include corresponding test suites (Unit, Integration, and Mock-backed tests using `pytest` and `pytest-asyncio`).
   - Introduce property-based or boundary-condition test cases to guarantee parity between legacy outputs and new modernized flows.

---

### Required Spec-Driven Artifacts

#### Phase 1: `requirements.md`
- Detail functional and non-functional requirements using **EARS notation** (`WHEN [trigger condition] THE SYSTEM SHALL [expected outcome]`).
- Define exact migration boundaries to ensure zero functional regressions.

#### Phase 2: `design.md`
- **Target Folder Structure:** Provide a clear visual tree of the new modular project layout (e.g., `src/domain/`, `src/application/`, `src/infrastructure/`, `src/presentation/`).
- **Core Interfaces & Contracts:** Define key abstract base classes (ABCs), generic repository interfaces, and dependency injection wiring.
- **Component Interaction Diagrams:** Provide updated Mermaid.js sequence and component diagrams demonstrating the modernized, decoupled execution flow.

#### Phase 3: `tasks.md`
- Break down the implementation into sequenced, dependency-ordered waves:
  - **Wave 1:** Core foundation, base classes/templates, configuration, and interfaces.
  - **Wave 2:** Infrastructure adapters, repository implementations, and data access layer.
  - **Wave 3:** Application services, domain logic migration, and use-case handlers.
  - **Wave 4:** Transport layer (API endpoints/consumers), middleware, and DI container wiring.
  - **Wave 5:** Test suite migration, linting/formatting pass, and deprecation of legacy dead code.

---

**Execution Rule:**
Generate the `requirements.md` and `design.md` first. Stop and present them for review before executing the file creation and implementation tasks in `tasks.md`.
