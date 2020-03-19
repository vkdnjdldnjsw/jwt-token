export class JwtError extends Error {
  public code: number
  constructor(code: number) {
    super()
    this.code = code
  }

  static ERROR = {
    EXPIRED_JWT: 0,
    INVALID_JWT: 1,
  }
}
