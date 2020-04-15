import { RefreshToken } from './refresh-token'
import { JwtToken } from './jwt-token'
import { JwtError } from './jwt-error'
import dayjs from 'dayjs'

export interface Tokens<AccessTokenPayload, RefreshTokenPayload> {
  accessToken: JwtToken<AccessTokenPayload>
  refreshToken: RefreshToken<RefreshTokenPayload>
}
export interface ResultOfGetRefreshToken {
  manuallyChangedAt: number
  refreshToken: string
}

export class Jwt {
  static async getTokenOrCreateTokens<AccessTokenPayload, RefreshTokenPayload>(
    accessTokenSecret: string,
    accessTokenPayload: AccessTokenPayload,
    accessTokenExpire: string,
    refreshTokenSecret: string,
    refreshTokenPayload: RefreshTokenPayload,
    refreshTokenExpire: string,
    refreshRefreshTokenAllowedValue: number,
    refreshRefreshTokenAllowedUnit: dayjs.UnitType,
    getRefreshToken: (
      payload: RefreshTokenPayload
    ) => Promise<string | undefined>,
    saveRefreshToken: (
      refreshToken: RefreshToken<RefreshTokenPayload>
    ) => Promise<void>,
    updateRefreshToken: (
      refreshToken: RefreshToken<RefreshTokenPayload>
    ) => Promise<void>
  ): Promise<Tokens<AccessTokenPayload, RefreshTokenPayload>> {
    const result = {} as Tokens<AccessTokenPayload, RefreshTokenPayload>
    const accessToken = new JwtToken<AccessTokenPayload>(
      accessTokenSecret,
      accessTokenPayload,
      accessTokenExpire
    )
    result.accessToken = accessToken
    const savedRefreshToken = await getRefreshToken(refreshTokenPayload)
    if (savedRefreshToken === undefined) {
      // no refresh token in db
      const refreshToken = new RefreshToken<RefreshTokenPayload>(
        refreshTokenSecret,
        refreshTokenPayload,
        refreshTokenExpire
      )
      await saveRefreshToken(refreshToken)
      result.refreshToken = refreshToken
    } else {
      try {
        const refreshToken = new RefreshToken<RefreshTokenPayload>(
          refreshTokenSecret,
          savedRefreshToken
        )
        if (
          refreshToken.refreshRefreshTokenIfPossible(
            refreshTokenSecret,
            refreshTokenPayload,
            refreshTokenExpire,
            refreshRefreshTokenAllowedValue,
            refreshRefreshTokenAllowedUnit
          )
        ) {
          // refreshToken is refreshed
          await updateRefreshToken(refreshToken)
        }
        result.refreshToken = refreshToken
      } catch (_) {
        const refreshToken = new RefreshToken<RefreshTokenPayload>(
          refreshTokenSecret,
          refreshTokenPayload,
          refreshTokenExpire
        )
        await updateRefreshToken(refreshToken)
        result.refreshToken = refreshToken
      }
    }

    return result
  }

  static async verifyAccessToken<AccessTokenPayload>(
    accessTokenSecret: string,
    accessTokenString: string,
    getManuallyChangedAt: (
      accessToken: JwtToken<AccessTokenPayload>
    ) => Promise<number>
  ): Promise<AccessTokenPayload> {
    const accessToken = new JwtToken<AccessTokenPayload>(
      accessTokenSecret,
      accessTokenString
    )
    const manuallyChangedAt = await getManuallyChangedAt(accessToken)
    if (manuallyChangedAt === undefined) {
      throw new JwtError(JwtError.ERROR.NO_MANUALLY_CHANGED_AT)
    } else if (manuallyChangedAt > accessToken.decoded.iat) {
      throw new JwtError(JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED)
    }
    return accessToken.decoded.payload
  }

  static async refresh<AccessTokenPayload, RefreshTokenPayload>(
    accessTokenSecret: string,
    accessTokenPayload: AccessTokenPayload,
    accessTokenExpire: string,
    refreshTokenSecret: string,
    refreshTokenString: string,
    refreshTokenExpire: string,
    refreshRefreshTokenAllowedValue: number,
    refreshRefreshTokenAllowedUnit: dayjs.UnitType,
    getRefreshToken: (
      refreshToken: RefreshToken<RefreshTokenPayload>
    ) => Promise<ResultOfGetRefreshToken | undefined>,
    updateRefreshToken: (
      refreshToken: RefreshToken<RefreshTokenPayload>
    ) => Promise<void>
  ): Promise<Tokens<AccessTokenPayload, RefreshTokenPayload>> {
    const result = {} as Tokens<AccessTokenPayload, RefreshTokenPayload>
    const refreshToken = new RefreshToken<RefreshTokenPayload>(
      refreshTokenSecret,
      refreshTokenString
    )
    const resultOfGetRefreshToken = await getRefreshToken(refreshToken)
    if (resultOfGetRefreshToken === undefined) {
      throw new JwtError(JwtError.ERROR.NO_RESULT_OF_GET_REFRESHTOKEN)
    } else if (
      resultOfGetRefreshToken.manuallyChangedAt > refreshToken.decoded.iat
    ) {
      throw new JwtError(JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED)
    }
    const savedRefreshToken = new RefreshToken<RefreshTokenPayload>(
      refreshTokenSecret,
      resultOfGetRefreshToken.refreshToken
    )
    const payload = savedRefreshToken.decoded.payload
    if (
      savedRefreshToken.refreshRefreshTokenIfPossible(
        refreshTokenSecret,
        payload,
        refreshTokenExpire,
        refreshRefreshTokenAllowedValue,
        refreshRefreshTokenAllowedUnit
      )
    ) {
      await updateRefreshToken(savedRefreshToken)
    }
    result.refreshToken = savedRefreshToken
    const accessToken = new JwtToken<AccessTokenPayload>(
      accessTokenSecret,
      accessTokenPayload,
      accessTokenExpire
    )
    result.accessToken = accessToken
    return result
  }
}
