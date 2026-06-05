"""
InjectIQ v2 — Thin redirect to the new modular architecture.
The real engine lives in inject.py. This file exists for backward compatibility.
"""
from .inject import InjectIQEngine, InjectionPoint, ExtractionState

__all__ = ["InjectIQEngine", "InjectionPoint", "ExtractionState"]
