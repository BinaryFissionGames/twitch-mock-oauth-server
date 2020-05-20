//On install, we need to move our prisma schema to the child project.
// We'll do this by concat-ing out schema.prisma onto the child project (installers) if it exists, else
// we'll drop ours into a prisma folder
import {promisify} from 'util'
import * as fs from 'fs';
import * as path from 'path';

const mkdir = promisify(fs.mkdir);
const copyFile = promisify(fs.copyFile);

if (process.env.INIT_CWD) {
    process.chdir(process.env.INIT_CWD) // cwd -> installer projects CWD
}


async function main() {
    //Check if prisma folder exists, if not, then we'll create it
    const prismaFolder = path.join(__dirname, '../../../../prisma');
    if (!fs.existsSync(prismaFolder)) {
        await mkdir(prismaFolder);
    }

    if (fs.existsSync(path.join(prismaFolder, 'prisma.schema'))) {
        console.log('Backing up existing prisma schema file, just in case... (prisma.schema => prisma.schema.backup)');
        await copyFile(path.join(prismaFolder, 'prisma.schema'), path.join(prismaFolder, 'prisma.schema.backup'))
    }

    console.log('Appending prisma schema file to the end of existing projects schema file...');
    let installerBody = '';
    if (fs.existsSync(path.join(prismaFolder, 'schema.prisma'))) {
        installerBody = fs.readFileSync(path.join(prismaFolder, 'schema.prisma')).toString('utf8');
    }

    let childPrismaFile = fs.openSync(path.join(prismaFolder, 'schema.prisma'), 'w');
    let projectPrismaFileContents = fs.readFileSync(path.join(__dirname, '../../prisma/schema.prisma')).toString('utf8');

    projectPrismaFileContents = hasClientDefinition(installerBody) ? removeClientDefinition(projectPrismaFileContents) : projectPrismaFileContents;

    fs.writeSync(childPrismaFile, replaceOrAddCode(installerBody, projectPrismaFileContents));
    fs.closeSync(childPrismaFile);

    console.log('Appended/copied prisma schema. Copying blank database template...');

    await copyFile(path.join(__dirname, '../../prisma/twitch_mock_oauth_server_db.db'), path.join(prismaFolder, 'twitch_mock_oauth_server_db.db'));

    console.log('Install done. Please run npx prisma generate to (re)generate your schema, and confirm that the original schema is intact.');
    console.log('If you run into problems and would like to undo what this script has done, copy prisma.schema.backup => prisma.schema, and delete the database file created in the prisma folder.');
}

const clientDefRegex = /generator client {[^}]*}/m;

function hasClientDefinition(body: string) {
    return clientDefRegex.test(body);
}

function removeClientDefinition(body: string): string {
    return body.replace(clientDefRegex, '');
}

function replaceOrAddCode(body: string, code: string): string {
    let regex = /\/\/COPIED CONTENTS FROM twitch-mock-oauth-server(.|\n|\r)*\/\/END CONTENTS FROM twitch-mock-oauth-server/mg;
    let insertion = '\r\n//COPIED CONTENTS FROM twitch-mock-oauth-server - TOUCHING THIS CODE MAY BREAK THIS COMPONENT!\r\n';
    insertion += code;
    insertion += '\r\n//END CONTENTS FROM twitch-mock-oauth-server';
    if (regex.test(body)) {
        body = body.replace(regex, insertion);
    } else {
        body += insertion;
    }
    return body.replace(regex, insertion);
}

function isInstalledAsDependency(): boolean {
    return fs.existsSync(path.join(__dirname, '../../../../node_modules'))
}

if(isInstalledAsDependency()){
    main();
} else {
    console.log("Skipping post-install hook; twitch-mock-oauth-server is not installed as a module.")
}
