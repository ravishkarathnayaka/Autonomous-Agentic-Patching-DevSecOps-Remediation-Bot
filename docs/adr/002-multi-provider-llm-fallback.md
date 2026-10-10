# ADR 002: Multi-Provider LLM Fallback Architecture

## Status
Accepted

## Context
Relying on a single proprietary cloud LLM endpoint exposes the remediation pipeline to rate limiting, network partitions, and vendor lock-in. Furthermore, air-gapped enterprise environments prohibit sending code outside local boundaries.

## Decision
We architected a provider-agnostic LLM interface supporting local models (Ollama, vLLM) and commercial APIs (OpenAI, Azure) with seamless automatic fallback.

## Consequences
- **Positive**: $0 compute cost in local environments; high resilience during cloud outages.
- **Negative**: Requires maintaining prompt template compatibility across varying model context windows.
