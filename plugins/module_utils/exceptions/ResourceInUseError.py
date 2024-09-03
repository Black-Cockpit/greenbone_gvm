class ResourceInUseError(Exception):
    """Exception raised for deletion or modification of resource in use."""

    def __init__(self, message):
        super().__init__(message)