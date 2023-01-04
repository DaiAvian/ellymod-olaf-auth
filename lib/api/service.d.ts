import { ConfigInterface, FetchInterface } from "../types/auth";
export default class AuthService {
    config: ConfigInterface | null;
    isAuthenticated: boolean;
    constructor();
    buildAuthorizeUrl(): Promise<string>;
    loginWithRedirect(): Promise<void>;
    logout(): any;
    handleRedirectCallback(): Promise<boolean>;
    getAccessToken(code_verifier: string, code: string | undefined): Promise<any>;
    verifyToken(): Promise<any>;
    getVerificationToken(auth: FetchInterface): Promise<any>;
    refreshToken(token: string): Promise<any>;
    testOutput(): void;
    private static setAuthToLocalStorage;
    private static getAuthFromLocalStorage;
}
