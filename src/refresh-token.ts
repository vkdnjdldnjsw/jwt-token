import dayjs from 'dayjs'
import { JwtToken } from './jwt-token'

export class RefreshToken<T> extends JwtToken<T> {
  isAllowedRefresh(
    refreshRefreshTokenAllowedValue: number,
    refreshRefreshTokenAllowedUnit: dayjs.UnitType
  ): boolean {
    const refreshTokenExpireDate = dayjs.unix(this.decoded.exp)
    if (
      refreshTokenExpireDate.diff(dayjs(), refreshRefreshTokenAllowedUnit) <=
      refreshRefreshTokenAllowedValue
    ) {
      return true
    } else {
      return false
    }
  }

  refreshRefreshTokenIfPossible(
    secret: string,
    payload: T,
    expire: string,
    refreshRefreshTokenAllowedValue: number,
    refreshRefreshTokenAllowedUnit: dayjs.UnitType
  ): boolean {
    const isAllowed = this.isAllowedRefresh(
      refreshRefreshTokenAllowedValue,
      refreshRefreshTokenAllowedUnit
    )
    if (isAllowed) {
      this.create(secret, payload, expire)
    }
    return isAllowed
  }
}
