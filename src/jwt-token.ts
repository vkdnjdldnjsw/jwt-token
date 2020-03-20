import Jwt from 'jsonwebtoken'
import { JwtError } from './jwt-error'

export interface Decoded<T> {
  payload: T
  exp: number
  iat: number
}

export interface TokenOption<T> {
  secret: string
  expire: string
}

export interface DecodeTokenOption {
  token: string
  secret: string
}

export interface CreateTokenOption<T> extends TokenOption<T> {
  payload: T
}

export class JwtToken<T> {
  public token: string = ''
  public decoded: Decoded<T> = {} as Decoded<T>

  constructor(config: DecodeTokenOption | CreateTokenOption<T>) {
    if ((config as DecodeTokenOption).token !== undefined) {
      this.token = (config as DecodeTokenOption).token
    } else {
      this.create(config as CreateTokenOption<T>)
    }
    this.verify(config.secret)
  }

  create(createTokenOption: CreateTokenOption<T>): void {
    const { payload, secret, expire } = createTokenOption

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
        console.error(err)
        throw new JwtError(JwtError.ERROR.INVALID_JWT)
      }
    }
  }
}
