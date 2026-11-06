class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }

  static badRequest(message, details) {
    return new ApiError(400, 'VALIDATION_ERROR', message, details);
  }

  static unauthorized(code, message, details) {
    return new ApiError(401, code || 'UNAUTHORIZED', message, details);
  }

  static forbidden(message, details) {
    return new ApiError(403, 'FORBIDDEN', message, details);
  }

  static notFound(message) {
    return new ApiError(404, 'RESOURCE_NOT_FOUND', message);
  }

  static conflict(message, details) {
    return new ApiError(409, 'EMAIL_TAKEN', message, details);
  }

  static tooMany(message, details) {
    return new ApiError(429, 'TOO_MANY_ATTEMPTS', message, details);
  }
}

module.exports = ApiError;
