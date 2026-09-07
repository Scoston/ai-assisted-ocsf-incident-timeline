"""Read-only collection with durable pages and explicit window checkpoints."""

from .runner import collect_until, collect_window

__all__ = ["collect_window", "collect_until"]
