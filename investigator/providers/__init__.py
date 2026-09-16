"""Provider adapters for the AI investigator model interface.

Each provider module exposes a class implementing the model contract:
    decide(request: ModelRequest) -> ModelDecision

Architecture Guarantee:
  Provider adapters are pure translators. They never invoke ToolRouter,
  execute Splunk queries, call subprocess, or return raw SDK objects.
  All provider output is validated into local deterministic dataclasses.
"""
