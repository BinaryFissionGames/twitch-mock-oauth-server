import * as express from "express";
import {Express, NextFunction} from "express";
import * as http from "http";
import * as cookieParser from "cookie-parser";
import * as assert from "assert";
import * as createHttpError from "http-errors";
import * as crypto from "crypto";
import {addClient, addOrGetUser, validateToken} from "./programmatic_api";
import {generateToken, getUserAuthorizationForm, prisma} from "./internal";

type MockServerOptionsCommon = {
    token_url: string,
    authorize_url: string,
    validate_url: string,
    logErrors?: boolean
}

type MockServerOptionsExpressApp = {
    expressApp: Express,
} & MockServerOptionsCommon

type MockServerOptionsPort = {
    port: number
} & MockServerOptionsCommon

type MockServerOptions = MockServerOptionsPort | MockServerOptionsExpressApp

let server: http.Server;

function setUpMockAuthServer(config: MockServerOptions): Promise<void> {

    const OAUTH_URL = new URL(config.token_url);
    const OAUTH_AUTHORIZE_URL = new URL(config.authorize_url);
    const OAUTH_VALIDATE_URL = new URL(config.validate_url);

    const app = (config as MockServerOptionsExpressApp).expressApp ? (config as MockServerOptionsExpressApp).expressApp : express();

    app.use(cookieParser());

    app.post(OAUTH_URL.pathname, async (req, res, next) => {
        try {
            if (req.query.grant_type === 'authorization_code') {
                //Asking for auth token w/ code
                assert.ok(!!req.query.client_id, createHttpError(400, 'Missing client_id'));
                assert.ok(!!req.query.client_secret, createHttpError(400, 'Missing client_secret'));
                assert.ok(!!req.query.code, createHttpError(400, 'Missing code'));
                assert.ok(!!req.query.redirect_uri, createHttpError(400, 'Missing redirect_uri'));
                let token = await prisma.authToken.findMany({
                    where: {
                        issuedClient: {
                            clientId: req.query.client_id.toString(),
                            clientSecretHash: crypto.createHash('sha256').update(req.query.client_secret.toString()).digest('hex')
                        },
                        code: req.query.code.toString()
                    }
                });

                if (!token || token.length < 1) {
                    return next(createHttpError(400, "No token associated with the client/secret/code combination."));
                }

                res.json({
                    access_token: token[0].token,
                    refresh_token: token[0].refreshToken,
                    scope: token[0].scope && token[0].scope !== '' ? token[0].scope.split(' ') : [],
                    expires_in: Math.floor((token[0].expiry.getTime() - Date.now()) / 1000),
                    token_type: 'bearer'
                });

                res.end();

            } else if (req.query.grant_type === 'refresh_token') {
                //Asking for oauth token w/ refresh token
                assert.ok(!!req.query.client_id, createHttpError(400, 'Missing client_id'));
                assert.ok(!!req.query.client_secret, createHttpError(400, 'Missing client_secret'));
                assert.ok(!!req.query.refresh_token, createHttpError(400, 'Missing refresh_token'));
                let tokens = await prisma.authToken.findMany({
                    where: {
                        issuedClient: {
                            clientId: req.query.client_id.toString(),
                            clientSecretHash: crypto.createHash('sha256').update(req.query.client_secret.toString()).digest('hex')
                        },
                        refreshToken: req.query.refresh_token.toString()
                    },
                    include: {
                        issuedUser: true
                    }
                });

                if (!tokens || tokens.length < 1) {
                    return next(createHttpError(400, "No token associated with the client/secret/refresh token combination."));
                }

                let requestedScopes: string[];
                if (req.query.scope && req.query.scope !== '') {
                    requestedScopes = req.query.scope.toString().split(' ');
                } else {
                    requestedScopes = tokens[0].scope && tokens[0].scope !== '' ? tokens[0].scope.split(' ') : [];
                }

                let oldScopes: string[] = tokens[0].scope && tokens[0].scope !== '' ? tokens[0].scope.split(' ') : [];

                requestedScopes.forEach((val) => {
                    if (!oldScopes.includes(val)) {
                        return next(createHttpError(400, `Requested scope is greater than the original scopes! (${val} was not originally requested)`));
                    }
                });

                let token = await generateToken(tokens[0].issuedUser, req.query.client_id.toString(), requestedScopes.join(' '));

                res.json({
                    access_token: token.token,
                    refresh_token: token.refreshToken,
                    scope: token.scope ? token.scope : '',
                    expires_in: Math.floor((token.expiry.getTime() - Date.now()) / 1000),
                    token_type: 'bearer'
                });

                res.end();

            } else {
                return next(createHttpError(400, `Bad grant type ${req.query.grant_type}`));
            }
        } catch (e) {
            next(e);
        }
    });

    app.get(OAUTH_AUTHORIZE_URL.pathname, async (req, res, next) => {
        try {
            assert.ok(!!req.query.client_id, createHttpError(400, 'Missing client_id'));
            assert.ok(!!req.query.redirect_uri, createHttpError(400, 'Missing redirect_uri'));
            assert.ok(!!req.query.response_type, createHttpError(400, 'Missing response_type'));

            let sessId = req.cookies.oauth_session;
            if (!sessId) {
                res.send(
                    getUserAuthorizationForm(
                        req.query.client_id.toString(),
                        req.query.redirect_uri.toString(),
                        req.query.response_type.toString(),
                        req.query.state?.toString(),
                        req.query.scope?.toString())
                );
                res.end();
                return;
            }


            let user = await prisma.authUser.findOne({
                where: {
                    sessionId: sessId
                }
            });

            if (!user) {
                res.send(
                    getUserAuthorizationForm(
                        req.query.client_id.toString(),
                        req.query.redirect_uri.toString(),
                        req.query.response_type.toString(),
                        req.query.state?.toString(),
                        req.query.scope?.toString())
                );
                res.end();
                return;
            }

            let token = await generateToken(user, decodeURIComponent(req.query.client_id.toString()), decodeURIComponent(req.query.scope?.toString()));
            let url = new URL(req.query.redirect_uri.toString());
            url.searchParams.set('code', token.code);
            if (req.query.state) {
                url.searchParams.set('state', req.query.state.toString());
            }
            url.searchParams.set('scope', token.scope);
            //Always redirect; Typically the user would click a button here, but this is meant to be automated; So we assume the user presses yes
            res.redirect(307, url.href);
        } catch (e) {
            next(e);
        }
    });

    app.get('/userAuthorize', async (req, res, next) => {
        try {
            let username: string = req.query.username.toString();
            let user = await addOrGetUser(username);

            let token = await generateToken(user, req.query.client_id.toString(), req.query.scope.toString());

            let scopes: string[] = [];
            if (req.query.scope) {
                scopes = (req.query.scope.toString().trim() === '') ? [] : req.query.scope.toString().split(' ');
            }

            res.cookie('oauth_session', user.sessionId, {
                maxAge: 360000,
                httpOnly: true
            });

            let url = new URL(<string>req.query.redirect_uri);
            url.searchParams.set('code', token.code);
            if (req.query.state) {
                url.searchParams.set('state', req.query.state.toString());
            }
            url.searchParams.set('scope', JSON.stringify(scopes));
            res.redirect(307, url.href);
        } catch (e) {
            next(e);
        }

    });

    app.get(OAUTH_VALIDATE_URL.pathname, async (req, res, next) => {
        try {
            if (!req.header('Authorization')) {
                throw createHttpError(401, 'must provide token');
            }
            let response = await validateToken((<string>req.header('Authorization')).split(' ')[1]);
            res.send(JSON.stringify(response));
            res.end();
        } catch (e) {
            next(e);
        }
    });

    app.post('/addOrGetUser/:username', async (req, res, next) => {
        try {
            if (!req.params.username) {
                return next(createHttpError(400,
                    `Must specify username`
                ));
            }
            let user = await addOrGetUser(req.params.username);
            res.json(user);
            res.end();
        } catch (e) {
            next(e);
        }
    });

    app.post('/addClient/:clientId/:clientSecret', async (req, res, next) => {
        try {
            if (!req.params.clientId) {
                return next(createHttpError(400,
                    `Must specify clientId`
                ));
            }

            if (!req.params.clientSecret) {
                return next(createHttpError(400,
                    `Must specify clientSecret`
                ));
            }

            await addClient(req.params.clientId, req.params.clientSecret);
            res.end();
        } catch (e) {
            next(e);
        }
    });

    //Error handler
    app.use(function (error: Error, req: express.Request, res: express.Response, next: NextFunction) {
        console.log(error);

        if (res.headersSent) {
            return next(error);
        }

        if (config.logErrors) {
            console.error(error);
        }

        let statusCode: number;
        if ((error as createHttpError.HttpError).statusCode) {
            statusCode = (error as createHttpError.HttpError).statusCode;
        } else {
            statusCode = 500;
        }

        res.status(statusCode);

        res.json({
            status: statusCode,
            message: error.message
        });

        res.end();
    });

    if ((config as MockServerOptionsPort).port) {
        return new Promise((resolve, reject) => {
            server = app.listen((config as MockServerOptionsPort).port, resolve).on('error', reject);
        });
    }

    return Promise.resolve();
}

export {
    setUpMockAuthServer,
    MockServerOptions,
    server
}