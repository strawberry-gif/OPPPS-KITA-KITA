class AppError(Exception):
    status_code = 400
    default_message = "Request could not be processed"

    def __init__(self, message: str | None = None):
        self.message = message or self.default_message
        super().__init__(self.message)


class ValidationError(AppError):
    status_code = 422
    default_message = "Validation failed"


class ConflictError(AppError):
    status_code = 409
    default_message = "Resource conflict"


class NotFoundError(AppError):
    status_code = 404
    default_message = "Resource not found"


class AuthenticationError(AppError):
    status_code = 401
    default_message = "Authentication failed"


class ServiceUnavailableError(AppError):
    status_code = 503
    default_message = "Service temporarily unavailable"
