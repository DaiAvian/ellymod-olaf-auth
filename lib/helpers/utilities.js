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
exports.getBaseUrl = exports.fetchObservable = exports.createQueryParams = exports.bufferToBase64UrlEncoded = exports.urlEncodeB64 = exports.sha256 = exports.createRandomString = exports.getCryptoSubtle = exports.getCrypto = exports.parseQueryResult = exports.ACCESS_TOKEN_STORAGE_KEY = exports.AUTHORIZE_STORAGE_KEY = void 0;
exports.AUTHORIZE_STORAGE_KEY = "olaf.auth.o";
exports.ACCESS_TOKEN_STORAGE_KEY = "olaf.auth.token";
const parseQueryResult = (queryString) => {
    if (queryString.indexOf("#") > -1) {
        queryString = queryString.substring(0, queryString.indexOf("#"));
    }
    const queryParams = queryString.split("&");
    const parsedQuery = {};
    queryParams.forEach((qp) => {
        const [key, val] = qp.split("=");
        parsedQuery[key] = decodeURIComponent(val);
    });
    return Object.assign(Object.assign({}, parsedQuery), { expires_in: parseInt(parsedQuery.expires_in) });
};
exports.parseQueryResult = parseQueryResult;
const getCrypto = () => {
    return (window.crypto || window.msCrypto);
};
exports.getCrypto = getCrypto;
const getCryptoSubtle = () => {
    const crypto = (0, exports.getCrypto)();
    return crypto.subtle || crypto.webkitSubtle;
};
exports.getCryptoSubtle = getCryptoSubtle;
const createRandomString = () => {
    const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~.";
    let random = "";
    const randomValues = Array.from((0, exports.getCrypto)().getRandomValues(new Uint8Array(43)));
    randomValues.forEach((v) => (random += charset[v % charset.length]));
    return random;
};
exports.createRandomString = createRandomString;
const sha256 = (s) => __awaiter(void 0, void 0, void 0, function* () {
    const digestOp = (0, exports.getCryptoSubtle)().digest({ name: "SHA-256" }, new TextEncoder().encode(s));
    if (window.msCrypto) {
        return new Promise((res, rej) => {
            digestOp.oncomplete = (e) => {
                res(e.target.result);
            };
            digestOp.onerror = (e) => {
                rej(e.error);
            };
            digestOp.onabort = () => {
                rej("The digest operation was aborted");
            };
        });
    }
    return yield digestOp;
});
exports.sha256 = sha256;
const urlEncodeB64 = (input) => {
    const b64Chars = { "+": "-", "/": "_", "=": "" };
    return input.replace(/[+/=]/g, (m) => b64Chars[m]);
};
exports.urlEncodeB64 = urlEncodeB64;
const bufferToBase64UrlEncoded = (input) => {
    const ie11SafeInput = new Uint8Array(input);
    return (0, exports.urlEncodeB64)(window.btoa(String.fromCharCode(...Array.from(ie11SafeInput))));
};
exports.bufferToBase64UrlEncoded = bufferToBase64UrlEncoded;
const createQueryParams = (params) => {
    return Object.keys(params)
        .filter((k) => typeof params[k] !== "undefined")
        .map((k) => encodeURIComponent(k) + "=" + encodeURIComponent(params[k]))
        .join("&");
};
exports.createQueryParams = createQueryParams;
const fetchObservable = (method, url, body, headers, omitCredentials = true) => __awaiter(void 0, void 0, void 0, function* () {
    if (headers == null) {
        headers = new Headers({
            "Content-Type": "application/json",
        });
    }
    const credentials = omitCredentials ? "omit" : "include";
    try {
        const response = yield fetch(url, {
            method,
            headers,
            body,
            credentials
        });
        if (!response.ok) {
            throw new Error(`Response error: ${response.statusText}`);
        }
        return response.json();
    }
    catch (error) {
        console.error('fetch error: ', error.message);
    }
});
exports.fetchObservable = fetchObservable;
const getBaseUrl = () => {
    const result = location.origin.match("http(s)?:\\/\\/(?<host>[A-Za-z0-9-.]*)((:\\d*))?(.*)?");
    const groups = result ? result.groups : null;
    if (groups == null || !("host" in groups)) {
        return null;
    }
    return groups["host"];
};
exports.getBaseUrl = getBaseUrl;
