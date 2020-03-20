export class JwtError extends Error {
  public code: number
  constructor(code: number) {
    super()
    this.code = code
    this.errorWrapper(code)
  }

  static ERROR = {
    EXPIRED_JWT: 0,
    INVALID_JWT: 1,
    NO_MANUALLY_CHANGED_AT: 2,
    CREATED_BEFORE_BEING_MANUALLY_CHANGED: 3,
    NO_RESULT_OF_GET_REFRESHTOKEN: 4,
  }

  errorWrapper(code: number): void {
    switch (code) {
      case JwtError.ERROR.EXPIRED_JWT:
        this.message = 'expired jwt'
        break
      case JwtError.ERROR.INVALID_JWT:
        this.message = 'inavlid jwt'
        break
      case JwtError.ERROR.NO_MANUALLY_CHANGED_AT:
        this.message = 'no manually changed at'
        break
      case JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED:
        this.message = 'token is created before being manually changed'
        break
      case JwtError.ERROR.NO_RESULT_OF_GET_REFRESHTOKEN:
        this.message = 'no result of get refreshToken'
        break
    }
  }
}
