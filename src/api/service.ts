import {ConfigInterface, FetchInterface} from "../types/auth";
import {
    ACCESS_TOKEN_STORAGE_KEY,
    AUTHORIZE_STORAGE_KEY,
    bufferToBase64UrlEncoded,
    createQueryParams,
    createRandomString, fetchObservable, parseQueryResult,
    sha256
} from "../helpers/utilities";

export default class AuthService {
    config: ConfigInterface | null;
    isAuthenticated: boolean;

    constructor(config: ConfigInterface) {
        this.config = config || null
        this.isAuthenticated = false
    }

    public async buildAuthorizeUrl(): Promise<string> {
        const code_verifier = createRandomString();
        const code_challengeBuffer = await sha256(code_verifier);
        const code_challenge = bufferToBase64UrlEncoded(code_challengeBuffer);
        const redirect_uri = `${window.location.origin}/auth`;

        // authorize params
        const params = {
            client_id: this.config?.client_id,
            response_type: "code",
            redirect_uri: redirect_uri,
            code_challenge,
            code_challenge_method: "S256",
        };

        // generate authorize url
        const url = `${this.config?.api_endpoint}/o/authorize?${createQueryParams(params)}`;

        // save data to session storage
        const authorizeStorageParams = {
            code_verifier,
            redirect_uri: params.redirect_uri,
        };
        sessionStorage.setItem(AUTHORIZE_STORAGE_KEY, JSON.stringify(authorizeStorageParams));

        // return generated url
        return url;
    }

    public async loginWithRedirect() {
        const url = await this.buildAuthorizeUrl();
        window.location.assign(url);
    }

    logout() {
        const auth = AuthService.getAuthFromLocalStorage();
        if (!auth || !auth.authToken) {
            return undefined
        }

        const headers = new Headers({
            Authorization: `Bearer ${auth.authToken}`,
        });

        fetchObservable("POST", `${this.config?.api_endpoint}/o/logout/`, null, headers, false).then(() => {
            localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
            window.location.href = window.location.origin;
        }).catch((error) => {
            throw new Error(error.message)
        })
    }

    handleRedirectCallback() {
        // get params
        const queryStringFragments = window.location.href.split("?").slice(1);
        if (queryStringFragments.length === 0) {
            throw new Error('There are no query params available for parsing.')
        }
        const { code } = parseQueryResult(queryStringFragments.join(""));

        // get authorize data
        let authorizeData = JSON.parse(sessionStorage.getItem(AUTHORIZE_STORAGE_KEY) || '');

        // remove authorize data from session storage
        sessionStorage.removeItem(AUTHORIZE_STORAGE_KEY);

        // authorize data should have a `code_verifier` to do PKCE
        if (!authorizeData || !authorizeData.code_verifier) {
            throw new Error('Invalid state');
        }

        // get access token
        return this.getAccessToken(authorizeData.code_verifier, code)
            .then((response) => {
            return AuthService.setAuthToLocalStorage(response)
            })
            .catch((error) => {
            throw new Error (error.message)
            })
    }

    getAccessToken(code_verifier: string, code: string | undefined) {
        const body = {
            client_id: this.config?.client_id,
            grant_type: "authorization_code",
            redirect_uri: `${window.location.origin}/auth`,
            code_verifier,
            code,
        };
        return fetchObservable("POST", `${this.config?.api_endpoint}/o/token/`, JSON.stringify(body));
    }

    verifyToken() {
        const auth = AuthService.getAuthFromLocalStorage();
        if (!auth || !auth.authToken) {
            return undefined;
        }

        return this.getVerificationToken(auth)
            .then((response) => {
                if(!response){
                    this.logout()
                    return
                }

                this.isAuthenticated = true
                return response
            })
    }

    getVerificationToken(auth: FetchInterface) {
        const headers = new Headers({
            Authorization: `Bearer ${auth.authToken}`,
        });

        return fetchObservable("POST", `${this.config?.api_endpoint}/o/verify-token/`, null, headers).catch((error) => {
            let isRefreshingToken = false
            if(error instanceof Response && (error.status === 401 || error.status === 403)){
                if (!isRefreshingToken) {
                    isRefreshingToken = true;
                    this.refreshToken(auth.refreshToken)
                        .then((response) => {
                        if(response && response.authToken){
                            localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, JSON.stringify(response));
                        }

                        this.verifyToken().catch((error) => {console.error('Token verification failed: ', error.message)})
                        isRefreshingToken = false;
                    })
                }
            }
        })
    }

    refreshToken(token: string) {
        const body = {
            refresh_token: token,
            client_id: this.config?.client_id,
            grant_type: "refresh_token",
        };

        return fetchObservable("POST", `${this.config?.api_endpoint}/o/token/`, JSON.stringify(body));
    }


    private static setAuthToLocalStorage(auth: FetchInterface): boolean {
        // store auth authToken/refreshToken/expiresIn in local storage to keep user logged in between page refreshes
        if (auth && auth.authToken) {
            localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, JSON.stringify(auth));
            return true;
        }
        return false;
    }

    private static getAuthFromLocalStorage(): FetchInterface | undefined {
        try {
            const accessToken = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY)

            if(!accessToken){
                return undefined
            }

            return JSON.parse(localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY) as string);
        } catch (error) {
            console.error(error);
            return undefined;
        }
    }
}
