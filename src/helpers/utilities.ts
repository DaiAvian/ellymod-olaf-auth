import {AuthenticationInterface} from "../types/auth";

export const AUTHORIZE_STORAGE_KEY = "olaf.auth.o";

export const ACCESS_TOKEN_STORAGE_KEY = "olaf.auth.token";

export const parseQueryResult = (queryString: string) => {
    if (queryString.indexOf("#") > -1) {
        queryString = queryString.substring(0, queryString.indexOf("#"));
    }

    const queryParams = queryString.split("&");

    const parsedQuery: any = {};
    queryParams.forEach((qp) => {
        const [key, val] = qp.split("=");
        parsedQuery[key] = decodeURIComponent(val);
    });

    return {
        ...parsedQuery,
        expires_in: parseInt(parsedQuery.expires_in),
    } as AuthenticationInterface;
};

export const getCrypto = () => {
    return (window.crypto || (window as any).msCrypto) as Crypto;
};

export const getCryptoSubtle = () => {
    const crypto = getCrypto();
    return crypto.subtle || (crypto as any).webkitSubtle;
};

export const createRandomString = () => {
    const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~.";
    let random = "";
    const randomValues = Array.from(getCrypto().getRandomValues(new Uint8Array(43)));
    randomValues.forEach((v) => (random += charset[v % charset.length]));
    return random;
};

export const sha256 = async (s: string) => {
    const digestOp: any = getCryptoSubtle().digest({ name: "SHA-256" }, new TextEncoder().encode(s));

    if ((window as any).msCrypto) {
        return new Promise((res, rej) => {
            digestOp.oncomplete = (e: any) => {
                res(e.target.result);
            };

            digestOp.onerror = (e: ErrorEvent) => {
                rej(e.error);
            };

            digestOp.onabort = () => {
                rej("The digest operation was aborted");
            };
        });
    }

    return await digestOp;
};

export const urlEncodeB64 = (input: string) => {
    const b64Chars: { [index: string]: string } = { "+": "-", "/": "_", "=": "" };
    return input.replace(/[+/=]/g, (m: string) => b64Chars[m]);
};

export const bufferToBase64UrlEncoded = (input: number[] | Uint8Array) => {
    const ie11SafeInput = new Uint8Array(input);
    return urlEncodeB64(window.btoa(String.fromCharCode(...Array.from(ie11SafeInput))));
};

export const createQueryParams = (params: any) => {
    return Object.keys(params)
        .filter((k) => typeof params[k] !== "undefined")
        .map((k) => encodeURIComponent(k) + "=" + encodeURIComponent(params[k]))
        .join("&");
};

export const fetchObservable = async (
    method: string,
    url: string,
    body?: BodyInit | null,
    headers?: Headers | null,
    omitCredentials = true
) => {
    if (headers == null) {
        headers = new Headers({
            "Content-Type": "application/json",
        });
    }

    const credentials: RequestCredentials = omitCredentials ? "omit" : "include";

    try {
        const response = await fetch(url, {
            method,
            headers,
            body,
            credentials
        })

        if(!response.ok){
            throw new Error(`Response error: ${response.statusText}`)
        }

        return response.json();
    } catch (error) {
        console.error('fetch error: ', (error as Error).message)
    }
}

export const getBaseUrl = () => {
    const result: RegExpMatchArray | null = location.origin.match(
        "http(s)?:\\/\\/(?<host>[A-Za-z0-9-.]*)((:\\d*))?(.*)?"
    );
    const groups = result ? (result as any).groups : null;
    if (groups == null || !("host" in groups)) {
        return null;
    }
    return groups["host"];
};
