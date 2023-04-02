import { Request, Response } from "express";
import mockAxios from 'jest-mock-axios';
import jwt from 'jsonwebtoken';
import DiscordAuth, { ISessionAuthRequest } from ".";
import { MockRequest, MockResponse, createRequest, createResponse } from "node-mocks-http";


const tokenSecret = 'tokenSecret';
describe('discord auth test', () => {
    let mockRequest: MockRequest<Request>;
    let mockResponse: MockResponse<Response>;
    const nextFunction = jest.fn(async () => {
        return;
    });

    beforeEach(() => {
        mockRequest = createRequest();
        mockResponse = createResponse();
        nextFunction.mockClear();
        jest.clearAllMocks();
        DiscordAuth.configure({
            clientId: 'clientId',
            clientSecret: 'clientSecret',
            tokenSecret,
            scope: 'scope',
        });
    });

    afterEach(() => {
        mockAxios.reset();
    });

    it('authorize checks redirect_uri on authorize', async () => {
        await DiscordAuth.authorize(mockRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(400);
    });

    it('authorize redirects when redirect_uri is present', async () => {
        mockRequest = createRequest({
            query: {
                redirect_uri: 'http://redirect.com/redirect',
            },
        });
        await DiscordAuth.authorize(mockRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(302);
    });

    it('authCodeToJwTToken checks if code exists', async () => {
        await DiscordAuth.authCodeToJwtToken(mockRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse._getData()).toContain('code missing from request');
    });

    it('authCodeToJwTToken checks if redirect_uri exists', async () => {
        mockRequest = createRequest({
            query: {
                code: 'code',
            },
        });
        await DiscordAuth.authCodeToJwtToken(mockRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse._getData()).toContain('redirect_uri missing from request');
    });

    it('authCodeToJwt handles bad data', async () => {
        mockRequest = createRequest({
            query: {
                code: 'code',
                redirect_uri: 'https://redirect.com/redirect',
            },
        });

        mockAxios.mockImplementation(async () => (
            {
                status: 401,
            }
        ));

        await DiscordAuth.authCodeToJwtToken(mockRequest, mockResponse);
        expect(mockAxios).toHaveBeenCalledTimes(1);
        expect(mockResponse.statusCode).toBe(401);
        expect(JSON.parse(mockResponse._getData())).toEqual({ discordResponse: { status: 401 } });
    });

    it('authCodeToJwt handles correct data', async () => {
        mockRequest = createRequest({
            query: {
                code: 'code',
                redirect_uri: 'https://redirect.com/redirect',
            },
        });
        mockAxios.mockImplementation(async (req) => {
            if(req.url === 'https://discord.com/api/oauth2/token') {
                return {
                    status: 200,
                    data: {
                        token_type: 'a',
                        access_token: 'b',
                    },
                };
            }
            return {
                status: 200,
                data: {
                    id: 'a',
                    username: 'b',
                },
            };
        });
        await DiscordAuth.authCodeToJwtToken(mockRequest, mockResponse).catch(err => console.log(err));

    
        expect(mockResponse.statusCode).toBe(204);
        expect(mockResponse.cookies).toHaveProperty('access_token');
        expect(mockAxios).toHaveBeenCalledTimes(2);
    });

    it('reAuth returns 401 without sessionDetails', async () => {
        const callBack = jest.fn();
        const next = jest.fn();
        await DiscordAuth.reAuth(mockRequest as unknown as ISessionAuthRequest, mockResponse, next,  callBack);
        expect(mockResponse.statusCode).toBe(401);
    });

    it('reAuth returns 401 with invalid token', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, tokenSecret, { expiresIn: 1 });
        mockRequest = createRequest({
            sessionDetails: fakeToken,
        });

        mockAxios.mockImplementation(() => ({
            status: 401,
        }));
        const callBack = jest.fn();
        const next = jest.fn();
        await DiscordAuth.reAuth(mockRequest as unknown as ISessionAuthRequest, mockResponse, next,  callBack);
        expect(mockResponse.statusCode).toBe(401);
    });

    it('reAuth calls callback with next', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, tokenSecret, { expiresIn: 1 });
        mockRequest = createRequest({
            sessionDetails: fakeToken,
        });

        mockAxios.mockImplementation(() => ({
            status: 200,
            data: {},
        }));
        const callBack = jest.fn();
        const next = jest.fn();
        await DiscordAuth.reAuth(mockRequest as unknown as ISessionAuthRequest, mockResponse, next,  callBack);
        expect(callBack).toHaveBeenCalledWith(mockRequest, mockResponse, next);
        expect(callBack).toHaveBeenCalledTimes(1);
    });

    it('identify returns 401 with outdated token', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, tokenSecret, { expiresIn: -10000 });
        mockRequest = createRequest({
            cookies: {
                'access_token': fakeToken,
            },
        });
        const next = jest.fn();
        await DiscordAuth.identify(mockRequest as unknown as ISessionAuthRequest, mockResponse, next);
        expect(mockResponse.statusCode).toBe(401);
        expect(mockResponse._getData()).toContain('jwt expired');
    });

    
    it('identify returns 401 with incorrect token', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, 'not the token secret', { expiresIn: -10000 });
        mockRequest = createRequest({
            cookies: {
                'access_token': fakeToken,
            },
        });
        const next = jest.fn();
        await DiscordAuth.identify(mockRequest as unknown as ISessionAuthRequest, mockResponse, next);
        expect(mockResponse.statusCode).toBe(401);
        expect(mockResponse._getData()).toContain('invalid signature');
    });

    it('identify calls next with correct token', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, tokenSecret, { expiresIn: 10000 });
        mockRequest = createRequest({
            cookies: {
                'access_token': fakeToken,
            },
        });
        const next = jest.fn();
        await DiscordAuth.identify(mockRequest as unknown as ISessionAuthRequest, mockResponse, next);
        expect(next).toBeCalledTimes(1);
        expect(mockRequest.sessionDetails).toHaveProperty('refresh_token');
    });

    it('logout throws 400 without token', async () => {
        await DiscordAuth.logout(mockRequest as unknown as ISessionAuthRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse._getData()).toContain('no token in request');
    });

    it('logout throws 200 with expired token', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, tokenSecret, { expiresIn: -10000 });
        mockRequest = createRequest({
            cookies: {
                'access_token': fakeToken,
            },
        });
        await DiscordAuth.logout(mockRequest as unknown as ISessionAuthRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(200);
    });

    it('logout throws 400 with invalid token', async () => {
        const fakeToken = jwt.sign({
            refresh_token: 'refresh_token',
        }, 'not the token secret', { expiresIn: 10000 });
        mockRequest = createRequest({
            cookies: {
                'access_token': fakeToken,
            },
        });
        await DiscordAuth.logout(mockRequest as unknown as ISessionAuthRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse._getData()).toContain('invalid signature');
    });

    it('logs out with correct tokens', async () => {
        const token = jwt.sign({
            refresh_token: 'refresh_token',
        }, tokenSecret, { expiresIn: 10000 });
        mockRequest = createRequest({
            cookies: {
                'access_token': token,
            },
        });
        await DiscordAuth.logout(mockRequest as unknown as ISessionAuthRequest, mockResponse);
        expect(mockResponse.statusCode).toBe(200);
    });
});
