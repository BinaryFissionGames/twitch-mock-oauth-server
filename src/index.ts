
import {clearDb} from './programmatic_api';
import { setUpMockAuthServer, MockServerOptions } from './routes';


if (require.main === module) {
    clearDb().then(() => {
        return setUpMockAuthServer({
            token_url: 'http://localhost:5080/token',
            authorize_url: 'http://localhost:5080/authorize',
            validate_url: 'http://localhost:5080/oauth2/validate',
            port: 5080
        });
    }).then(() => {
        console.log('Setup auth server; Listening on port 5080');
    });
}

export * from './programmatic_api';

export {
    setUpMockAuthServer,
    MockServerOptions
}