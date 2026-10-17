"""Text normalization stage interface."""
from gateway.contracts import NormalizeError, NormalizedText


def normalize_text(text: str) -> NormalizedText:
    """Return original, cleaned and matching representations."""
    raise NotImplementedError
