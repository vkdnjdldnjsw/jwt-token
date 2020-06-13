import Jwt from 'jsonwebtoken'
import { JwtError } from './jwt-error'

export interface Decoded<T> {
  payload: T
  exp: number
  iat: number
}

export class JwtToken<T> {
  public token: string = ''
  public decoded: Decoded<T> = {} as Decoded<T>

  constructor(secret: string, token: string)
  constructor(secret: string, payload: T, expire: string)
  constructor(secret: string, p1: string | T, p2?: string) {
    switch (arguments.length) {
      case 2:
        this.token = p1 as string
        break
      case 3:
        this.create(secret, p1 as T, p2!)
    }
    this.verify(secret)
  }

  create(secret: string, payload: T, expire: string): void {
    this.token = Jwt.sign({ payload }, secret, {
      expiresIn: expire,
    })
  }

  verify(secret: string): void {
    try {
      this.decoded = Jwt.verify(this.token, secret) as Decoded<T>
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw new JwtError(JwtError.ERROR.EXPIRED_JWT)
      } else {
        throw new JwtError(JwtError.ERROR.INVALID_JWT)
      }
    }
  }
}
