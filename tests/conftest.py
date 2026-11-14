"""Test configuration: the answer pipeline never calls a real LLM provider.

`triage.config` reads LLM_ENABLED once at import, so it is forced off here
before that import. The pool reads the variable at call time and is tested
with injected fake providers, so it is switched back on afterwards.
"""
import os

os.environ["LLM_ENABLED"] = "0"
import triage.config  # noqa: E402,F401

os.environ["LLM_ENABLED"] = "1"
