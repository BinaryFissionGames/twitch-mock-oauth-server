//Generates a new token
import {AuthToken, AuthUser, PrismaClient} from "../dist/generated/prisma/client";
import * as createHttpError from "http-errors";
import {v4 as uuidv4} from "uuid";
import * as fs from "fs";
import * as path from "path";

const prisma = new PrismaClient({
    datasources: {
        twitch_mock_oauth_server_ds: 'file:./twitch_mock_oauth_server_db.db'
    }
});


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

function getUserAuthorizationForm(client_id: string, redirect_uri: string, response_type: string, state?: string, scope?: string) : string {
    return fs.readFileSync(path.join(__dirname, '../www/index.html')).toString('utf8')
        .replace('<!--INSERTHIDDENHERE-->',
            `<input type="hidden" name="client_id" id="client_id" value="${client_id}">` +
            `<input type="hidden" name="redirect_uri" id="redirect_uri" value="${redirect_uri}">` +
            `<input type="hidden" name="response_type" id="response_type" value="${response_type}">` +
            (state ? `<input type="hidden" name="state" id="state" value="${state}">` : '') +
            (scope ? `<input type="hidden" name="scope" id="scope" value="${scope}">` : '')
        )
}

export {
    generateToken,
    getUserAuthorizationForm,
    prisma
}