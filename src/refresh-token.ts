import dayjs from 'dayjs'
import {
  CreateTokenOption,
  DecodeTokenOption,
  JwtToken,
  TokenOption,
} from './jwt-token'

export interface RefreshOption {
  refreshRefreshTokenAllowedValue: number
  refreshRefreshTokenAllowedUnit: dayjs.UnitType
}

export interface RefreshTokenOption<T> extends TokenOption<T> {
  refreshTokenOption: RefreshOption
}

export interface DecodeRefreshTokenOption extends DecodeTokenOption {
  refreshTokenOption: RefreshOption
}

export interface CreateRefreshTokenOption<T> extends CreateTokenOption<T> {
  refreshTokenOption: RefreshOption
}

export class RefreshToken<T> extends JwtToken<T> {
  private refreshOption?: {
    allowedValue: number
    unit: dayjs.UnitType
  }

  constructor(config: DecodeRefreshTokenOption | CreateRefreshTokenOption<T>) {
    super(config)
  }

  isAllowedRefresh(refreshTokenOption: RefreshOption): boolean {
    const refreshTokenExpireDate = dayjs.unix(this.decoded.exp)
    if (
      refreshTokenExpireDate.diff(
        dayjs(),
        refreshTokenOption.refreshRefreshTokenAllowedUnit
      ) <= refreshTokenOption.refreshRefreshTokenAllowedValue
    ) {
      return true
    } else {
      return false
    }
  }

  refreshRefreshTokenIfPossible(
    CreaterefreshTokenOption: CreateRefreshTokenOption<T>
  ): boolean {
    const isAllowed = this.isAllowedRefresh(
      CreaterefreshTokenOption.refreshTokenOption
    )
    if (isAllowed) {
      this.create(CreaterefreshTokenOption)
    }
    return isAllowed
  }
}
