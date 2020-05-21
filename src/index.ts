import * as express from 'express';
import * as bodyParser from 'body-parser';
import * as assert from 'assert';
import {v4 as uuidv4} from 'uuid';
import * as cookieParser from 'cookie-parser'
import * as crypto from 'crypto'
import {PrismaClient, AuthUser, AuthToken, Client} from '@prisma/client'
import {Express, NextFunction} from "express";
import * as http from 'http';
import * as createHttpError from "http-errors";

const prisma = new PrismaClient({
    datasources: {
        twitch_mock_oauth_server_ds: 'file:./twitch_mock_oauth_server_db.db' // need to specify this here.. I think? Need to look more into how this interacts with multiple datasources
    }
});

async function addClient(clientId: string, clientSecret: string): Promise<Client> {
    return await prisma.client.create({
        data: {
            clientId: clientId,
            clientSecretHash: crypto.createHash('sha256').update(clientSecret).digest('hex')
        }
    });
}

async function addOrGetUser(userName: string): Promise<AuthUser> {
    return prisma.authUser.upsert({
        create: {
            userName: userName,
            sessionId: uuidv4()
        },
        where: {
            userName: userName
        },
        update: {}
    });
}

async function clearDb(): Promise<void> {
    await prisma.authToken.deleteMany({});
    await prisma.authUser.deleteMany({});
    await prisma.client.deleteMany({});
}

//Generates a new token
async function generateToken(user: AuthUser, clientId: string, scope: string): Promise<AuthToken> {

    let client = await prisma.client.findOne({
        where: {
            clientId: clientId
        }
    });

    if (client === null) {
        throw createHttpError(400, `Cannot find client with id ${clientId}`);
    }

    let tokens = await prisma.authToken.findMany({
        where: {
            AND: [{
                issuedUser: user
            }, {
                issuedClientId: clientId
            }]
        }
    });

    if (tokens && tokens.length >= 1) {
        return prisma.authToken.update({
            where:{
              id: tokens[0].id
            },
            data: {
                token: uuidv4(),
                refreshToken: uuidv4(),
                code: uuidv4(),
                expiry: new Date(Date.now() + 3600 * 1000),
                scope: scope
            }
        });
    } else {
        return prisma.authToken.create({
            data: {
                token: uuidv4(),
                refreshToken: uuidv4(),
                issuedClient: {
                    connect: {
                        clientId: client.clientId
                    }
                },
                issuedUser: {
                    connect: {
                        id: user.id
                    }
                },
                code: uuidv4(),
                expiry: new Date(Date.now() + 3600 * 1000),
                scope: scope
            }
        });
    }
}

type MockServerOptionsCommon = {
    token_url: string,
    authorize_url: string,
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

    const app = (config as MockServerOptionsExpressApp).expressApp ? (config as MockServerOptionsExpressApp).expressApp : express();

    app.use(cookieParser());
    app.use(bodyParser.urlencoded({
        extended: false
    }));


    app.post(OAUTH_URL.pathname, async (req, res, next) => {
        try {
            let url = new URL(req.originalUrl, `http://${req.header('hostname')}`);
            if (req.body.grant_type === 'authorization_code') {
                //Asking for auth token w/ code
                assert.ok(!!req.body.client_id, createHttpError(400, 'Missing client_id'));
                assert.ok(!!req.body.client_secret, createHttpError(400, 'Missing client_secret'));
                assert.ok(!!req.body.code, createHttpError(400, 'Missing code'));
                assert.ok(!!req.body.redirect_uri, createHttpError(400, 'Missing redirect_uri'));
                assert.ok(!!req.body.scope, createHttpError(400, 'Missing scope'));
                //TODO: Verify code, send back token
                let token = await prisma.authToken.findMany({
                    where: {
                        issuedClient: {
                            clientId: req.body.client_id,
                            clientSecretHash: crypto.createHash('sha256').update(req.body.client_secret).digest('hex')
                        },
                        code: req.body.code
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

            } else if (req.body.grant_type === 'refresh_token') {
                //Asking for oauth token w/ refresh token
                assert.ok(!!req.body.client_id, createHttpError(400, 'Missing client_id'));
                assert.ok(!!req.body.client_secret, createHttpError(400, 'Missing client_secret'));
                assert.ok(!!req.body.refresh_token, createHttpError(400, 'Missing refresh_token'));
                let tokens = await prisma.authToken.findMany({
                    where: {
                        issuedClient: {
                            clientId: req.body.client_id,
                            clientSecretHash: crypto.createHash('sha256').update(req.body.client_secret).digest('hex')
                        },
                        refreshToken: req.body.refresh_token
                    },
                    include: {
                        issuedUser: true
                    }
                });

                if (!tokens || tokens.length < 1) {
                    return next(createHttpError(400, "No token associated with the client/secret/refresh token combination."));
                }

                let requestedScopes: string[];
                if (req.body.scope && req.body.scope !== '') {
                    requestedScopes = req.body.scope.split(' ');
                } else {
                    requestedScopes = tokens[0].scope && tokens[0].scope !== '' ? tokens[0].scope.split(' ') : [];
                }

                let oldScopes: string[] = tokens[0].scope && tokens[0].scope !== '' ? tokens[0].scope.split(' ') : [];

                requestedScopes.forEach((val) => {
                    if (!oldScopes.includes(val)) {
                        return next(createHttpError(400, `Requested scope is greater than the original scopes! (${val} was not originally requested)`));
                    }
                });

                let token = await generateToken(tokens[0].issuedUser, req.body.client_id, requestedScopes.join(' '));

                res.json({
                    access_token: token.token,
                    refresh_token: token.refreshToken,
                    scope: token.scope && token.scope !== '' ? token.scope.split(' ') : [],
                    expires_in: Math.floor((token.expiry.getTime() - Date.now()) / 1000),
                    token_type: 'bearer'
                });

                res.end();

            } else {
                return next(createHttpError(400, `Bad grant type ${url.searchParams.get('grant_type')}`));
            }
        } catch (e) {
            next(e);
        }
    });

    app.get(OAUTH_AUTHORIZE_URL.pathname, async (req, res, next) => {
        try {
            let sessId = req.cookies.oauth_session;
            let url = new URL(req.originalUrl, `http://${req.header('hostname')}`);
            if (!sessId) {
                return next(createHttpError(400, 'Could not find any Session ID'));
            }

            let user = await prisma.authUser.findOne({
                where: {
                    sessionId: sessId
                }
            });

            if (!user) {
                return next(createHttpError(400, `No user associated to session ${sessId}`));
            }

            assert.ok(!!req.body.client_id, createHttpError(400, 'Missing client_id'));
            assert.ok(!!req.body.redirect_uri, createHttpError(400, 'Missing redirect_uri'));
            assert.ok(!!req.body.response_type, createHttpError(400, 'Missing response_type'));

            let token = await generateToken(user, decodeURIComponent(<string>url.searchParams.get('client_id')), decodeURIComponent(<string>url.searchParams.get('scope')));

            let scopes: string[] = [];
            if (url.searchParams.get('scope')) {
                scopes = (decodeURIComponent(<string>url.searchParams.get('scope')).trim() === '') ? [] : decodeURIComponent(<string>url.searchParams.get('scope')).split(' ');
            }

            //Always redirect; Typically the user would click a button here, but this is meant to be automated; So we assume the user presses yet
            //TODO: Possibly reject in some cases? I think twitch just redirects back to the original URL, but i'd need to confirm this behaviour
            res.redirect(307, `${decodeURIComponent(<string>url.searchParams.get('redirect_uri'))}` +
                `?access_token=${encodeURIComponent(token.token)}` +
                `&refresh_token=${encodeURIComponent(token.refreshToken)}` +
                `&code=${encodeURIComponent(token.code)}` +
                (req.body.state ? `&state=${req.body.state}` : '') +
                `&expires_in=3600` +
                `&scope=${JSON.stringify(scopes)}` +
                `&token_type=bearer`);
        } catch (e) {
            next(e);
        }
    });

    app.post('/addOrGetUser/:username', async (req, res, next) => {
        try {
            if (!req.params.username) {
                return next(createHttpError(400, `Must specify username`));
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
                return next(createHttpError(400, `Must specify clientId`));
            }

            if (!req.params.clientSecret) {
                return next(createHttpError(400, `Must specify clientSecret`));
            }

            await addClient(req.params.clientId, req.params.clientSecret);
            res.end();
        } catch (e) {
            next(e);
        }
    });

    app.use(function (error: Error, req: express.Request, res: express.Response, next: NextFunction) {
        if (res.headersSent) {
            return next(error);
        }

        if (config.logErrors) {
            console.error(error);
        }
        if ((error as createHttpError.HttpError).statusCode) {
            res.status((error as createHttpError.HttpError).statusCode);
        } else {
            res.status(500);
        }

        res.json({
            status: 'error',
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

async function closeMockServer(killPrisma?: boolean): Promise<void> {
    if (killPrisma) {
        await prisma.disconnect();
    }

    if (server) {
        return new Promise((resolve, reject) => {
            server.close((err) => {
                if (err) {
                    reject(err)
                } else {
                    resolve()
                }
            });
        });
    }
}

if (require.main === module) {
    clearDb().then(() => {
        return setUpMockAuthServer({
            token_url: 'http://localhost:3080/token',
            authorize_url: 'http://localhost:3080/authorize',
            port: 3080
        });
    }).then(() => {
        console.log('Setup auth server; Listening on port 3080');
    });
}

export {
    addOrGetUser,
    addClient,
    clearDb,
    setUpMockAuthServer,
    MockServerOptions,
    closeMockServer
}