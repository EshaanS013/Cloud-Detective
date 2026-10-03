import { User, UserManager, WebStorageStateStore } from "oidc-client-ts";

const poolId = import.meta.env.VITE_COGNITO_USER_POOL_ID as string | undefined;
const clientId = import.meta.env.VITE_COGNITO_APP_CLIENT_ID as string | undefined;
const region = (import.meta.env.VITE_AWS_REGION as string | undefined) ?? "ap-southeast-2";
const domain = import.meta.env.VITE_COGNITO_DOMAIN as string | undefined;

export const authEnabled = Boolean(poolId && clientId && domain);

const authority = poolId
  ? `https://cognito-idp.${region}.amazonaws.com/${poolId}`
  : "https://disabled.invalid";

export const userManager = new UserManager({
  authority,
  client_id: clientId ?? "local",
  redirect_uri: `${window.location.origin}/callback`,
  post_logout_redirect_uri: `${window.location.origin}/`,
  response_type: "code",
  scope: "openid email profile",
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  metadata: domain
    ? {
        issuer: authority,
        authorization_endpoint: `${domain}/oauth2/authorize`,
        token_endpoint: `${domain}/oauth2/token`,
        userinfo_endpoint: `${domain}/oauth2/userInfo`,
        end_session_endpoint: `${domain}/logout`,
        jwks_uri: `${authority}/.well-known/jwks.json`,
      }
    : undefined,
});

export async function restoreUser(): Promise<User | null> {
  if (!authEnabled) return null;
  if (window.location.pathname === "/callback" && window.location.search.includes("code=")) {
    const user = await userManager.signinRedirectCallback();
    window.history.replaceState({}, document.title, "/");
    return user;
  }
  return userManager.getUser();
}
