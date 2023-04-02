import { NextFunction, Response, Request } from "express";
import axios from "axios";
import jwt, { TokenExpiredError } from 'jsonwebtoken';

interface IDiscordAuthOptions {
    clientId: string,
    clientSecret: string,
    tokenSecret: string,
    scope: string,
}

export interface ISessionPreAuthRequest extends Request {
    sessionDetails?: ISessionDetails,
}
export interface ISessionAuthRequest extends Request {
    sessionDetails: ISessionDetails
}

export interface ISessionDetails {
    access_token: string
    expires_in: number
    refresh_token: string
    scope: string
    token_type: string
    userId: string
    username: string
}


export default class DiscordAuth {
    static #clientId: string;
    static #clientSecret: string;
    static #tokenSecret: string;
    static #scope: string;

    static configure(options: IDiscordAuthOptions): void {
        DiscordAuth.#clientId = options.clientId;
        DiscordAuth.#clientSecret = options.clientSecret;
        DiscordAuth.#tokenSecret = options.tokenSecret;
        DiscordAuth.#scope = options.scope;
        DiscordAuth.authorize = DiscordAuth.authorize.bind(DiscordAuth);
        DiscordAuth.authCodeToJwtToken = DiscordAuth.authCodeToJwtToken.bind(DiscordAuth);
        DiscordAuth.reAuth = DiscordAuth.reAuth.bind(DiscordAuth);
        DiscordAuth.identify = DiscordAuth.identify.bind(DiscordAuth);
        DiscordAuth.logout = DiscordAuth.logout.bind(DiscordAuth);
    }

    static async authorize(
        req: Request,
        res: Response,
    ): Promise<void> {
        if(!req.query?.redirect_uri) {
            res.status(400).send('missing redirect_uri');
            return;
        }
        const urlSearchParams = {
            client_id: DiscordAuth.#clientId,
            response_type: 'code',
            scope: DiscordAuth.#scope,
            redirect_uri: req.query.redirect_uri as string,
        };

        const searchParams = new URLSearchParams(urlSearchParams).toString();

        res.redirect(`https://discord.com/api/oauth2/authorize?${searchParams.toString()}`);
    }

    static async authCodeToJwtToken(
        req: Request,
        res: Response,
    ): Promise<void> {
        const {code, redirect_uri } = req?.query ?? {};
        if(code === undefined) {
            res.status(400).send('Bad request: code missing from request');
            return;
        }
        if(redirect_uri === undefined) {
            res.status(400).send('Bad request: redirect_uri missing from request');
            return;
        }
    
        const urlSearchParams = {
            client_id: DiscordAuth.#clientId,
            client_secret: DiscordAuth.#clientSecret,
            code: code.toString(),
            grant_type: 'authorization_code',
            redirect_uri: redirect_uri as string,
            scope: DiscordAuth.#scope,
        };
    
        const tokenResponseData = await axios({
            method: 'post',
            url: 'https://discord.com/api/oauth2/token',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data: new URLSearchParams(urlSearchParams),
        });

        if(tokenResponseData.status === 401) {
            res.status(401).json({ discordResponse: tokenResponseData });
            return;
        }
    
        const data: ISessionDetails = tokenResponseData.data;
        const userData = await axios({
            method: 'get',
            url: 'https://discord.com/api/users/@me',
            headers: {
                authorization: `${data.token_type} ${data.access_token}`,
            },
        });
        const token = jwt.sign(
            {
                ...data,
                userId: userData.data.id,
                username: userData.data.username,
            },
            DiscordAuth.#tokenSecret, {expiresIn: '93d'},
        );
        res.cookie('access_token', token, { maxAge: 86400000 * 93,  path: "/", httpOnly: false ,secure: true, sameSite: 'none' });
        res.sendStatus(204);
    }

    static async reAuth(
        req: ISessionAuthRequest,
        res: Response,
        next: NextFunction,
        callback: (
            req: ISessionAuthRequest,
            res: Response, 
            next: NextFunction,
        ) => Promise<void>,
    ): Promise<void> {
        const { sessionDetails } = req;
        if(!sessionDetails) {
            res.sendStatus(401);
            return;
        }
        const urlSearchParams = {
            client_id: DiscordAuth.#clientId as string,
            client_secret: DiscordAuth.#clientSecret as string,
            grant_type: 'refresh_token',
            refresh_token: sessionDetails?.refresh_token,
            scope: DiscordAuth.#scope,
        };
        try {
            const tokenResponseData = await axios({
                method: 'post',
                url: 'https://discord.com/api/oauth2/token',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                data: new URLSearchParams(urlSearchParams),
            });
    
            if(tokenResponseData?.status === 401) {
                res.sendStatus(401);
            }
            const data: ISessionDetails = tokenResponseData.data;
            const token = jwt.sign({ ...data, userId: sessionDetails.userId, username: sessionDetails.username }, DiscordAuth.#tokenSecret, {expiresIn: '90d'});
            res.cookie('access_token', token, { maxAge: 86400000 * 93,  path: "/", httpOnly: false ,secure: true, sameSite: 'none' });
        } catch {
            res.sendStatus(401);
            return;
        }
        callback(req, res, next);
        return;
    }

    static async identify(req: ISessionAuthRequest , res: Response, next: NextFunction): Promise<void> {
        //retrieve possible tokens
        const sessionId = req.cookies['access_token'] as string;
        try {
            //check if a token exists
            if (sessionId) {
                const test = jwt.verify(sessionId, DiscordAuth.#tokenSecret);
                if(!test) {
                    throw new Error("token invalid or expired");
                }
                req.sessionDetails = test as ISessionDetails;
                next();
            } else {
                res.status(401).send("no token in request");
                return;
            }
        } catch (err) {
            res.clearCookie('access_token');
            res.status(401).send(`Authentication Failed: ${err.message}`);
        }
    }

    static async logout(req: ISessionAuthRequest , res: Response): Promise<void> {
        //retrieve possible tokens
        const sessionId = req.cookies['access_token'] as string;
        try {
            //check if a token exists
            if (sessionId) {
                const tokenData = jwt.verify(sessionId, DiscordAuth.#tokenSecret) as ISessionDetails;
                const urlParameters = {
                    client_id: DiscordAuth.#clientId,
                    client_secret: DiscordAuth.#clientSecret,

                };
                const resetToken = axios({
                    url: 'https://discord.com/api/oauth2/token/revoke',
                    method: 'post',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    data: new URLSearchParams({
                        ...urlParameters,
                        token: tokenData.access_token,
                        token_type_hint: 'access_token',
                    }),
                });
                const resetRefresh = axios({
                    url: 'https://discord.com/api/oauth2/token/revoke',
                    method: 'post',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    data: new URLSearchParams({
                        ...urlParameters,
                        token: tokenData.refresh_token,
                        token_type_hint: 'refresh_token',
                    }),
                });
                await Promise.all([resetToken, resetRefresh]);
                res.clearCookie('access_token');
                res.status(200).send('tokens revoked');
            } else {
                res.status(400).send("no token in request");
                return;
            }
        } catch (err) {
            res.clearCookie('access_token');
            if(err instanceof TokenExpiredError) {
                res.sendStatus(200);
                return;
            }
            res.status(400).send(`Authentication Failed: ${err.message}`);
        }
    }
}