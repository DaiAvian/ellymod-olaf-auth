import { AuthenticationInterface } from "../types/auth";
export declare const AUTHORIZE_STORAGE_KEY = "olaf.auth.o";
export declare const ACCESS_TOKEN_STORAGE_KEY = "olaf.auth.token";
export declare const parseQueryResult: (queryString: string) => AuthenticationInterface;
export declare const getCrypto: () => Crypto;
export declare const getCryptoSubtle: () => any;
export declare const createRandomString: () => string;
export declare const sha256: (s: string) => Promise<any>;
export declare const urlEncodeB64: (input: string) => string;
export declare const bufferToBase64UrlEncoded: (input: number[] | Uint8Array) => string;
export declare const createQueryParams: (params: any) => string;
export declare const fetchObservable: (method: string, url: string, body?: BodyInit | null, headers?: Headers | null, omitCredentials?: boolean) => Promise<any>;
export declare const getBaseUrl: () => any;
