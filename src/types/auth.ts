export interface AuthenticationInterface {
    code?: string
}

export interface FetchInterface {
    authToken: string;
    refreshToken: string;
    expiresIn: Date;
}

export interface ConfigInterface {
    account_name: string
    api_endpoint: string
    client_id: string
    account_url: string
}
