"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const utilities_1 = require("../helpers/utilities");
class AuthService {
    constructor() {
        this.config = null;
        this.isAuthenticated = false;
    }
    buildAuthorizeUrl() {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            const code_verifier = (0, utilities_1.createRandomString)();
            const code_challengeBuffer = yield (0, utilities_1.sha256)(code_verifier);
            const code_challenge = (0, utilities_1.bufferToBase64UrlEncoded)(code_challengeBuffer);
            const redirect_uri = `${window.location.origin}/auth`;
            // authorize params
            const params = {
                client_id: (_a = this.config) === null || _a === void 0 ? void 0 : _a.client_id,
                response_type: "code",
                redirect_uri: redirect_uri,
                code_challenge,
                code_challenge_method: "S256",
            };
            // generate authorize url
            const url = `${(_b = this.config) === null || _b === void 0 ? void 0 : _b.api_endpoint}/o/authorize?${(0, utilities_1.createQueryParams)(params)}`;
            // save data to session storage
            const authorizeStorageParams = {
                code_verifier,
                redirect_uri: params.redirect_uri,
            };
            sessionStorage.setItem(utilities_1.AUTHORIZE_STORAGE_KEY, JSON.stringify(authorizeStorageParams));
            // return generated url
            return url;
        });
    }
    loginWithRedirect() {
        return __awaiter(this, void 0, void 0, function* () {
            const url = yield this.buildAuthorizeUrl();
            window.location.assign(url);
        });
    }
    logout() {
        var _a;
        const auth = AuthService.getAuthFromLocalStorage();
        if (!auth || !auth.authToken) {
            return undefined;
        }
        const headers = new Headers({
            Authorization: `Bearer ${auth.authToken}`,
        });
        (0, utilities_1.fetchObservable)("POST", `${(_a = this.config) === null || _a === void 0 ? void 0 : _a.api_endpoint}/o/logout/`, null, headers, false).then(() => {
            localStorage.removeItem(utilities_1.ACCESS_TOKEN_STORAGE_KEY);
            window.location.href = window.location.origin;
        }).catch((error) => {
            throw new Error(error.message);
        });
    }
    handleRedirectCallback() {
        // get params
        const queryStringFragments = window.location.href.split("?").slice(1);
        if (queryStringFragments.length === 0) {
            throw new Error('There are no query params available for parsing.');
        }
        const { code } = (0, utilities_1.parseQueryResult)(queryStringFragments.join(""));
        // get authorize data
        let authorizeData = JSON.parse(sessionStorage.getItem(utilities_1.AUTHORIZE_STORAGE_KEY) || '');
        // remove authorize data from session storage
        sessionStorage.removeItem(utilities_1.AUTHORIZE_STORAGE_KEY);
        // authorize data should have a `code_verifier` to do PKCE
        if (!authorizeData || !authorizeData.code_verifier) {
            throw new Error('Invalid state');
        }
        // get access token
        return this.getAccessToken(authorizeData.code_verifier, code)
            .then((response) => {
            return AuthService.setAuthToLocalStorage(response);
        })
            .catch((error) => {
            throw new Error(error.message);
        });
    }
    getAccessToken(code_verifier, code) {
        var _a, _b;
        const body = {
            client_id: (_a = this.config) === null || _a === void 0 ? void 0 : _a.client_id,
            grant_type: "authorization_code",
            redirect_uri: `${window.location.origin}/auth`,
            code_verifier,
            code,
        };
        return (0, utilities_1.fetchObservable)("POST", `${(_b = this.config) === null || _b === void 0 ? void 0 : _b.api_endpoint}/o/token/`, JSON.stringify(body));
    }
    verifyToken() {
        const auth = AuthService.getAuthFromLocalStorage();
        if (!auth || !auth.authToken) {
            return undefined;
        }
        return this.getVerificationToken(auth)
            .then((response) => {
            if (!response) {
                this.logout();
                return;
            }
            this.isAuthenticated = true;
            return response;
        });
    }
    getVerificationToken(auth) {
        var _a;
        const headers = new Headers({
            Authorization: `Bearer ${auth.authToken}`,
        });
        return (0, utilities_1.fetchObservable)("POST", `${(_a = this.config) === null || _a === void 0 ? void 0 : _a.api_endpoint}/o/verify-token/`, null, headers).catch((error) => {
            let isRefreshingToken = false;
            if (error instanceof Response && (error.status === 401 || error.status === 403)) {
                if (!isRefreshingToken) {
                    isRefreshingToken = true;
                    this.refreshToken(auth.refreshToken)
                        .then((response) => {
                        if (response && response.authToken) {
                            localStorage.setItem(utilities_1.ACCESS_TOKEN_STORAGE_KEY, JSON.stringify(response));
                        }
                        this.verifyToken();
                        isRefreshingToken = false;
                    });
                }
            }
        });
    }
    refreshToken(token) {
        var _a, _b;
        const body = {
            refresh_token: token,
            client_id: (_a = this.config) === null || _a === void 0 ? void 0 : _a.client_id,
            grant_type: "refresh_token",
        };
        return (0, utilities_1.fetchObservable)("POST", `${(_b = this.config) === null || _b === void 0 ? void 0 : _b.api_endpoint}/o/token/`, JSON.stringify(body));
    }
    testOutput() {
        console.log('Testing the output');
    }
    static setAuthToLocalStorage(auth) {
        // store auth authToken/refreshToken/expiresIn in local storage to keep user logged in between page refreshes
        if (auth && auth.authToken) {
            localStorage.setItem(utilities_1.ACCESS_TOKEN_STORAGE_KEY, JSON.stringify(auth));
            return true;
        }
        return false;
    }
    static getAuthFromLocalStorage() {
        try {
            const accessToken = localStorage.getItem(utilities_1.ACCESS_TOKEN_STORAGE_KEY);
            if (!accessToken) {
                return undefined;
            }
            return JSON.parse(localStorage.getItem(utilities_1.ACCESS_TOKEN_STORAGE_KEY));
        }
        catch (error) {
            console.error(error);
            return undefined;
        }
    }
}
exports.default = AuthService;
