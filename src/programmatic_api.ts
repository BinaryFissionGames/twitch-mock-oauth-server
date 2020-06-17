import {AuthUser, Client} from "../dist/generated/prisma/client";
import {v4 as uuidv4} from "uuid";
import * as crypto from "crypto";
import {server} from "./routes";
import {prisma} from "./internal";
import createHttpError = require("http-errors");

async function clearDb(): Promise<void> {
    await prisma.authToken.deleteMany({});
    await prisma.authUser.deleteMany({});
    await prisma.client.deleteMany({});
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

async function addClient(clientId: string, clientSecret: string): Promise<Client> {
    return await prisma.client.create({
        data: {
            clientId: clientId,
            clientSecretHash: crypto.createHash('sha256').update(clientSecret).digest('hex')
        }
    });
}

type ValidateResponse = {
    client_id: string
    login: string
    scopes: string[]
    user_id: string
}

async function validateToken(access_token: string): Promise<ValidateResponse> {
    let token = await prisma.authToken.findOne({
        where: {
            token: access_token
        },
        include: {
            issuedUser: true
        }
    });

    if(!token){
        throw createHttpError(401, 'invalid access token');
    }

    return {
        client_id: token.issuedClientId,
        login: token.issuedUser.userName,
        scopes: token.scope.split(' '),
        user_id: token.issuedUserId.toString()
    }
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

export {
    clearDb,
    closeMockServer,
    addOrGetUser,
    addClient,
    validateToken,

}