class CompassError(RuntimeError):
    """Base error raised by the COMPASS pipeline."""


class ConfigurationError(CompassError):
    """The supplied configuration is incomplete or inconsistent."""


class BackendUnavailable(CompassError):
    """A required external analysis or monitoring backend is unavailable."""


class CaptureError(CompassError):
    """Runtime or preparation capture failed."""


class AnalysisError(CompassError):
    """Binary or symbolic analysis failed."""


class SchemaError(CompassError):
    """Persisted data does not satisfy the COMPASS schema."""

