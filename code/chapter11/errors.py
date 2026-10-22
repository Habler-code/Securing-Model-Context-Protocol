"""Stable validation failures; never include raw payloads in their messages."""


class ValidationFault(ValueError):
    def __init__(self, code: int, message: str, http_status: int = 400, data: dict | None = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.data = {} if data is None else data
