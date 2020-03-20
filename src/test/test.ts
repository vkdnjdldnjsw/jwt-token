import { Jwt, Tokens, JwtToken } from '../index'
import { RefreshToken } from '../refresh-token'
import { JwtError } from '../jwt-error'

interface Payload {
  userId: number
  isAdmin: boolean
}

const sleep = (ms: number) => {
  return new Promise(resolve => {
    setTimeout(resolve, ms)
  })
}
const testPaylaod: Payload = {
  userId: 1,
  isAdmin: false,
}
;(async (): Promise<void> => {
  console.log('get token with undefined saved refresh token')
  const normalGetToken = await Jwt.getTokenOrCreateTokens(
    testPaylaod,
    {
      secret: 'refresh',
      expire: '14d',
      refreshTokenOption: {
        refreshRefreshTokenAllowedUnit: 'day',
        refreshRefreshTokenAllowedValue: 3,
      },
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async (payload: Payload) => {
      return undefined
    },
    async _ => {},
    async _ => {}
  )
  console.log(normalGetToken)

  await sleep(1000)
  const shortExpireToken = await Jwt.getTokenOrCreateTokens(
    testPaylaod,
    {
      secret: 'refresh',
      expire: '1s',
      refreshTokenOption: {
        refreshRefreshTokenAllowedUnit: 'day',
        refreshRefreshTokenAllowedValue: 3,
      },
    },
    {
      expire: '1s',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async (payload: Payload) => {
      return undefined
    },
    async _ => {},
    async _ => {}
  )
  await sleep(1000)
  console.log('get token again with saved refreshToken')
  const sameRefreshDiffAccess: Tokens<Payload> = await Jwt.getTokenOrCreateTokens(
    testPaylaod,
    {
      secret: 'refresh',
      expire: '14d',
      refreshTokenOption: {
        refreshRefreshTokenAllowedUnit: 'day',
        refreshRefreshTokenAllowedValue: 3,
      },
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async (payload: Payload) => {
      return normalGetToken.refreshToken.token
    },
    async _ => {},
    async _ => {}
  )
  console.log(
    ' access : ' +
      (normalGetToken.accessToken.token !==
        sameRefreshDiffAccess.accessToken.token)
  )
  console.log(
    ' refresh : ' +
      (normalGetToken.refreshToken.token ===
        sameRefreshDiffAccess.refreshToken.token)
  )
  await sleep(1500)
  console.log('get the tokens with expired refreshToken')
  const diffTokens = await Jwt.getTokenOrCreateTokens(
    testPaylaod,
    {
      secret: 'refresh',
      expire: '1s',
      refreshTokenOption: {
        refreshRefreshTokenAllowedUnit: 'day',
        refreshRefreshTokenAllowedValue: 3,
      },
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async (payload: Payload) => {
      return shortExpireToken.refreshToken.token
    },
    async _ => {},
    async _ => {}
  )
  console.log(
    ' access : ' +
      (normalGetToken.accessToken.token !== diffTokens.accessToken.token)
  )
  console.log(
    ' refresh : ' +
      (normalGetToken.refreshToken.token !== diffTokens.refreshToken.token)
  )
  console.log('normal verify')

  const normalVerify: Payload = await Jwt.verifyAccessToken(
    {
      token: normalGetToken.accessToken.token,
      secret: 'access',
    },
    async (): Promise<number> => {
      return normalGetToken.accessToken.decoded.iat
    }
  )
  console.log(
    ' same payload : ' +
      (normalVerify.isAdmin === testPaylaod.isAdmin &&
        normalVerify.userId === testPaylaod.userId)
  )

  console.log('verify with expired token')

  await Jwt.verifyAccessToken(
    {
      token: shortExpireToken.accessToken.token,
      secret: 'access',
    },
    async (): Promise<number> => {
      return normalGetToken.accessToken.decoded.iat
    }
  ).catch(err => {
    console.log(
      ' expired : ' + ((err as JwtError).code === JwtError.ERROR.EXPIRED_JWT)
    )
  })

  console.log('verify with created before manually changed')

  await Jwt.verifyAccessToken(
    {
      token: normalGetToken.accessToken.token,
      secret: 'access',
    },
    async (): Promise<number> => {
      return shortExpireToken.accessToken.decoded.iat
    }
  ).catch(err => {
    console.log(
      ' expired : ' +
        ((err as JwtError).code ===
          JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED)
    )
  })

  await sleep(1000)
  console.log('normal refresh')
  const normalRefresh = await Jwt.refresh(
    normalGetToken.refreshToken.token,
    {
      refreshTokenOption: {
        refreshRefreshTokenAllowedValue: 1,
        refreshRefreshTokenAllowedUnit: 'day',
      },
      secret: 'refresh',
      expire: '14d',
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async () => {
      return {
        refreshToken: normalGetToken.refreshToken.token,
        manuallyChangedAt: normalGetToken.refreshToken.decoded.iat,
      }
    },
    async (token: RefreshToken<Payload>) => {}
  )
  console.log(
    ' access : ' +
      (normalGetToken.accessToken.token !== normalRefresh.accessToken.token)
  )
  console.log(
    ' refresh : ' +
      (normalGetToken.refreshToken.token === normalRefresh.refreshToken.token)
  )
  await sleep(1000)
  console.log('refresh with refreshable refresh token')
  const refreshableToken = await Jwt.getTokenOrCreateTokens(
    testPaylaod,
    {
      secret: 'refresh',
      expire: '2d',
      refreshTokenOption: {
        refreshRefreshTokenAllowedUnit: 'day',
        refreshRefreshTokenAllowedValue: 3,
      },
    },
    {
      expire: '1s',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async (payload: Payload) => {
      return undefined
    },
    async _ => {},
    async _ => {}
  )
  const refreshed = await Jwt.refresh(
    refreshableToken.refreshToken.token,
    {
      refreshTokenOption: {
        refreshRefreshTokenAllowedValue: 3,
        refreshRefreshTokenAllowedUnit: 'day',
      },
      secret: 'refresh',
      expire: '14d',
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async () => {
      return {
        refreshToken: refreshableToken.refreshToken.token,
        manuallyChangedAt: refreshableToken.refreshToken.decoded.iat,
      }
    },
    async (token: RefreshToken<Payload>) => {}
  )
  console.log(
    ' access : ' +
      (refreshableToken.accessToken.token !== refreshed.accessToken.token)
  )
  console.log(
    ' refresh : ' +
      (refreshableToken.refreshToken.token !== refreshed.refreshToken.token)
  )
  console.log('refresh with expired refresh token')
  await Jwt.refresh(
    shortExpireToken.refreshToken.token,
    {
      refreshTokenOption: {
        refreshRefreshTokenAllowedValue: 1,
        refreshRefreshTokenAllowedUnit: 'day',
      },
      secret: 'refresh',
      expire: '14d',
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async () => {
      return {
        refreshToken: shortExpireToken.refreshToken.token,
        manuallyChangedAt: shortExpireToken.refreshToken.decoded.iat,
      }
    },
    async (token: RefreshToken<Payload>) => {}
  ).catch(err => {
    console.log(
      ' expired : ' + ((err as JwtError).code === JwtError.ERROR.EXPIRED_JWT)
    )
  })

  console.log('refresh with created before being manually changed')
  await Jwt.refresh(
    normalGetToken.refreshToken.token,
    {
      refreshTokenOption: {
        refreshRefreshTokenAllowedValue: 3,
        refreshRefreshTokenAllowedUnit: 'day',
      },
      secret: 'refresh',
      expire: '14d',
    },
    {
      expire: '14d',
      payload: {
        userId: 1,
        isAdmin: false,
      },
      secret: 'access',
    },
    async () => {
      return {
        refreshToken: refreshed.refreshToken.token,
        manuallyChangedAt: refreshed.refreshToken.decoded.iat,
      }
    },
    async (token: RefreshToken<Payload>) => {}
  ).catch(err => {
    console.log(
      ' expired : ' +
        ((err as JwtError).code ===
          JwtError.ERROR.CREATED_BEFORE_BEING_MANUALLY_CHANGED)
    )
  })
})()
