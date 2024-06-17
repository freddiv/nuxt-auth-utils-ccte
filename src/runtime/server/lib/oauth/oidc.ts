import type { H3Event, H3Error } from 'h3'
import { eventHandler, createError, getQuery, getRequestURL, sendRedirect } from 'h3'
import { withQuery, parsePath } from 'ufo'
import { ofetch } from 'ofetch'
import { defu } from 'defu'
import { useRuntimeConfig } from '#imports'

export interface OAuthOidcConfig {
  /**
   * WAM OAuth Client ID
   * @default process.env.NUXT_OAUTH_OIDC_CLIENT_ID
   */
  clientId?: string
  /**
   * WAM  OAuth Client Secret
   * @default process.env.NUXT_OAUTH_OIDC_CLIENT_SECRET
   */
  clientSecret?: string
  /**
   * WAM  OAuth Scope
   * @default ['openid', 'profile']
   */
  scope?: string[]
  /**
   * WAM OAuth Authorization URL
   * @default 'https://wamssostg.epa.gov:443/oauth2/rest/authorize'
   * @see https://wamssostg.epa.gov/oauth2/rest/openid-configuration
   */
  authorizationUrl?: string
  /**
   * WAM OAuth Token URL
   * @default 'https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token'
   * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
   */
  tokenURL?: string
  /**
   * WAM OAuth UserINFO URL
   * @default 'https://graph.microsoft.com/v1.0/me'
   */
  userinfoURL?: string
  /**
   * Extra authorization parameters to provide to the authorization URL
   * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
   */
  authorizationParams?: Record<string, string>
  /**
   * Redirect URL to prevent in prod prevent redirect_uri mismatch http to https
   * @default process.env.NUXT_OAUTH_OIDC_REDIRECT_URL
   * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
   */
  redirectUrl?: string
}

interface OAuthConfig {
  config?: OAuthOidcConfig
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onSuccess: (event: H3Event, result: { user: any, tokens: any }) => Promise<void> | void
  onError?: (event: H3Event, error: H3Error) => Promise<void> | void
}

export function oidcEventHandler({ config, onSuccess, onError }: OAuthConfig) {
  return eventHandler(async (event: H3Event) => {
    config = defu(config, useRuntimeConfig(event).oauth?.oidc, {
      authorizationParams: {},
    }) as OAuthOidcConfig
    const { code } = getQuery(event)

    if (!config.clientId || !config.clientSecret ) {
      const error = createError({
        statusCode: 500,
        message: 'Missing NUXT_OAUTH_OIDC_CLIENT_ID or NUXT_OAUTH_OIDC_CLIENT_SECRET env variables.',
      })
      if (!onError) throw error
      return onError(event, error)
    }

    const authorizationURL = config.authorizationURL || 'https://wamssostg.epa.gov:443/oauth2/rest/authorize'
    const tokenURL = config.tokenURL || 'https://wamssostg.epa.gov:443/oauth2/rest/token'

    const redirectUrl = config.redirectUrl || getRequestURL(event).href
    if (!code) {
      const scope = config.scope && config.scope.length > 0 ? config.scope : ['openid', 'profile']
      // Redirect to Oidc Oauth page
      return sendRedirect(
        event,
        withQuery(authorizationURL as string, {
          client_id: config.clientId,
          response_type: 'code',
          redirect_uri: redirectUrl,
          scope: scope.join(' '),
          ...config.authorizationParams,
        }),
      )
    }

    const data = new URLSearchParams()
    data.append('grant_type', 'authorization_code')
    data.append('client_id', config.clientId)
    data.append('client_secret', config.clientSecret)
    data.append('redirect_uri', parsePath(redirectUrl).pathname)
    data.append('code', String(code))

    // TODO: improve typing
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tokens: any = await ofetch(
      tokenURL as string,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: data,
      },
    ).catch((error) => {
      return { error }
    })
    if (tokens.error) {
      const error = createError({
        statusCode: 401,
        message: `Oidc login failed: ${tokens.error?.data?.error_description || 'Unknown error'}`,
        data: tokens,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    const tokenType = tokens.token_type
    const accessToken = tokens.access_token
    const userinfoURL = config.userinfoURL
    // TODO: improve typing
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const user: any = await ofetch(userinfoURL, {
      headers: {
        Authorization: `${tokenType} ${accessToken}`,
      },
    }).catch((error) => {
      return { error }
    })
    if (user.error) {
      const error = createError({
        statusCode: 401,
        message: `Oidc login failed: ${user.error || 'Unknown error'}`,
        data: user,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    return onSuccess(event, {
      tokens,
      user,
    })
  })
}
