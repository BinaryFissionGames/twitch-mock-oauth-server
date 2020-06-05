//Generates a new token
import {AuthToken, AuthUser, PrismaClient} from "../dist/generated/prisma/client";
import * as createHttpError from "http-errors";
import {v4 as uuidv4} from "uuid";

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

export {
    generateToken,
    prisma
}