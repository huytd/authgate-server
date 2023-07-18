export const AuthGateResponse = {
    UNAUTHORIZED: 401,
    INVALID_REQUEST: 400,
    SUCCESS: 200,
}

export class AuthGateClient {
    constructor(authGateUrl) {
        this.authGateUrl = authGateUrl;
    }

    /**
     * Fetches the user profile from the auth gate server.
     *
     * @return {Promise} A promise that resolves to the user profile JSON object.
     */
    async getUserProfile() {
        const res = await fetch(`${this.authGateUrl}/profile`);
        if (res.status !== 200) {
            return AuthGateResponse.UNAUTHORIZED;
        }
        return res.json();
    }

    /**
     * Register a user with the given email, password, and optional name.
     *
     * @param {string} email - The email of the user.
     * @param {string} password - The password of the user.
     * @param {string} [name=""] - The name of the user (optional).
     * @return {Promise<AuthGateResponse>} The result of the registration process.
     */
    async registerWith(email, password, name = "") {
        const res = await fetch(`${this.authGateUrl}/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email,
                password,
                name
            })
        });
        if (res.status !== 200) {
            return AuthGateResponse.INVALID_REQUEST;
        }
        return AuthGateResponse.SUCCESS;
    }

    /**
     * Logs in a user with the provided email and password.
     *
     * @param {string} email - The user's email address.
     * @param {string} password - The user's password.
     * @return {Promise<AuthGateResponse>} The response from the authentication gate.
     */
    async loginWith(email, password) {
        const res = await fetch(`${this.authGateUrl}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email,
                password
            })
        });
        if (res.status === 400) {
            return AuthGateResponse.INVALID_REQUEST;
        }
        if (res.status === 401) {
            return AuthGateResponse.UNAUTHORIZED;
        }
        return AuthGateResponse.SUCCESS;
    }

    /**
     * Logs out the user.
     *
     * @return {Promise<AuthGateResponse>} A promise that resolves when the user has been logged out.
     */
    async logout() {
        await fetch(`${this.authGateUrl}/logout`, {
            method: "POST"
        });
        return AuthGateResponse.SUCCESS;
    }
}