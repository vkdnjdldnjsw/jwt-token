import {
  RefreshToken,
  RefreshTokenOption,
  CreateRefreshTokenOption,
  DecodeRefreshTokenOption,
} from './refresh-token'
import {
  JwtToken,
  CreateTokenOption,
  DecodeTokenOption,
  TokenOption,
} from './jwt-token'
import { JwtError } from './jwt-error'

export interface Tokens<T> {
  accessToken: JwtToken<T>
  refreshToken: RefreshToken<T>
}
export interface ResultOfGetRefreshToken {
  manuallyChangedAt: number
  refreshToken: string
}

export class Jwt {
  static async getTokenOrCreateTokens<T>(
    payload: T,
    refreshTokenOption: RefreshTokenOption<T>,
    createAccessTokenOption: CreateTokenOption<T>,
    getRefreshToken: (payload: T) => Promise<string | undefined>,
    saveRefreshToken: (refreshToken: RefreshToken<T>) => Promise<void>,
    updateRefreshToken: (refreshToken: RefreshToken<T>) => Promise<void>
  ): Promise<Tokens<T>> {
    const result = {} as Tokens<T>
    const accessToken = new JwtToken<T>({
      payload,
      ...createAccessTokenOption,
    } as CreateTokenOption<T>)
    result.accessToken = accessToken
    const savedRefreshToken = await getRefreshToken(payload)
    if (savedRefreshToken === undefined) {
      // no refresh token in db
      const refreshToken = new RefreshToken<T>({
        payload,
        ...refreshTokenOption,
      } as CreateRefreshTokenOption<T>)
      await saveRefreshToken(refreshToken)
      result.refreshToken = refreshToken
    } else {
      try {
        const refreshToken = new RefreshToken<T>({
          token: savedRefreshToken,
          ...refreshTokenOption,
        } as DecodeRefreshTokenOption)
        if (
          refreshToken.refreshRefreshTokenIfPossible({
            payload,
            ...refreshTokenOption,
          } as CreateRefreshTokenOption<T>)
        ) {
          // refreshToken is refreshed
          await updateRefreshToken(refreshToken)
        }
        result.refreshToken = refreshToken
      } catch (_) {
        const refreshToken = new RefreshToken<T>({
          payload,
          ...refreshTokenOption,
        } as CreateRefreshTokenOption<T>)
        await updateRefreshToken(refreshToken)
        result.refreshToken = refreshToken
      }
    }

    return result
  }

  static async verifyAccessToken<T>(
    decodeAccessTokenOption: DecodeTokenOption,
    getManuallyChangedAt: (accessToken: JwtToken<T>) => Promise<number>
  ): Promise<T> {
    const accessToken = new JwtToken<T>({
      ...decodeAccessTokenOption,
    } as DecodeTokenOption)
    const manuallyChangedAt = await getManuallyChangedAt(accessToken)
    if (manuallyChangedAt === undefined) {
      throw new JwtError(JwtError.ERROR.NO_MANUALLY_CHANGED_AT)
    } else if (manuallyChangedAt > accessToken.decoded.iat) {
      throw new JwtError(JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED)
    }
    return accessToken.decoded.payload
  }

  static async refresh<T>(
    refreshTokenString: string,
    refreshTokenOption: RefreshTokenOption<T>,
    accessTokenOption: TokenOption<T>,
    getRefreshToken: (
      refreshToken: RefreshToken<T>
    ) => Promise<ResultOfGetRefreshToken | undefined>,
    updateRefreshToken: (refreshToken: RefreshToken<T>) => Promise<void>
  ): Promise<Tokens<T>> {
    const result = {} as Tokens<T>
    const refreshToken = new RefreshToken<T>({
      token: refreshTokenString,
      ...refreshTokenOption,
    } as DecodeRefreshTokenOption)
    const resultOfGetRefreshToken = await getRefreshToken(refreshToken)
    if (resultOfGetRefreshToken === undefined) {
      throw new JwtError(JwtError.ERROR.NO_RESULT_OF_GET_REFRESHTOKEN)
    } else if (
      resultOfGetRefreshToken.manuallyChangedAt > refreshToken.decoded.iat
    ) {
      throw new JwtError(JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED)
    }
    const savedRefreshToken = new RefreshToken<T>({
      token: resultOfGetRefreshToken.refreshToken,
      ...refreshTokenOption,
    } as DecodeRefreshTokenOption)
    const payload = savedRefreshToken.decoded.payload
    if (
      savedRefreshToken.refreshRefreshTokenIfPossible({
        payload,
        ...refreshTokenOption,
      })
    ) {
      await updateRefreshToken(savedRefreshToken)
    }
    result.refreshToken = savedRefreshToken
    const accessToken = new JwtToken<T>({
      payload: savedRefreshToken.decoded.payload,
      ...accessTokenOption,
    } as CreateTokenOption<T>)
    result.accessToken = accessToken
    return result
  }
}
