# API_Notes

*For Sending and Checking Requests, Responses use PostMan App

https://www.youtube.com/watch?v=b8ZUb_Okxro&t=2241s
1. Init & Install Packages
	1. npm install -y
	2. npm install -D typescript
	3. npm install -D ts-node
	4. npm install -D nodemon  // auto-change
	5. npm i express body-praser cookie-parser compression cors
	6. npm i -D @types/express @types/body-parser @types/cookie-parser @types/compression @types/cors    // we need it for TypeScript
	7. npm install mongoose
	8. npm i -D @types/mongoose
	9. npm i lodash
	10. npm i -D @types/lodash
		
1. Create tsconfig.json

The tsconfig.json file tells the TypeScript compiler how to convert TypeScript code into regular JavaScript code. It sets various options like which version of JavaScript to target, where to put the compiled JavaScript files, and how to handle different parts of the project. It helps ensure that the TypeScript code is compiled correctly and can catch errors early...

```
	{
		"compilerOptions": {
			"module" :  "NodeNext",
			"moduleResolution": "node",
			"baseUrl": "src",
			"outDir": "dist",
			"sourceMap": true,
			"noImplicitAny": true
		},
		"include":  ['src/**/*']
		/*means include all files + 
                    folders with their files*/
	}
```

3. Create nodemon.json

Is used to monitor changes in Node.js applications and automatically restart the server when code changes are detected. For Front End, s.t. React, Vue mostly is used Webpack [Watch Later] and Parcel for monitoring.

```
{
    "watch": ["src"],
    "ext": ".ts,.js",
    "exec": "ts-node ./src/index.js"
}
```

4. Folder Structure
   
   ./scr
	1. Index.ts
	2. ./db
		1. users.ts
	3. ./helpers
		1. index.ts
	4. ./controllers
		1. authentication.ts
		2. users.ts
	5. ./router
		1. index.ts
		2. authentication.ts
		3. users.ts
	6. ./middlewares
		1. index.ts


5. To quicly start a project like [npm start] go to package.json and add to "scripts", "start" key with value "nodemon"


///////////
Index.ts

```
// IMPORTS

import express from 'express';
// Express is the main middleware for BackEnd App, quite popular for its flexebility and fast running code

import http from 'http';
// to handle http request, responses, reqlly important

import bodyParser from 'body-parser';
// Express middleware, to handle "forms" extra data

import cookieParser from 'cookie-parser';
// Express middleware, to handle cookies for flexability

import compression from 'compression';
// cool Express middleware that allow to gzip the responce to have a quicker response!

import cors from 'cors';
// It enables Cross-Origin Resource Sharing (CORS) for your server, allowing it to handle requests coming from different domains or ports.

import mongoose from 'mongoose';
// MongoDB MiddleWare

// Routers
import router from './router';
```

Cross-Origin Resource Sharing (CORS)
By default, web browsers restrict cross-origin requests due to the same-origin policy, which is a security measure. However, if the server allows cross-origin requests from specific origins, it includes the necessary CORS headers in its responses. These headers inform the browser that the request is allowed, and the browser then permits the JavaScript code in the web page to access the response data.

1. Hex Adjusting allow to make a good set string line from the generated 32 bits string

```
const app = express();

app.use(cors({
    credentials: true,
}));

// IN CORS Credentials controls whether the browser should include credentials (such as cookies, HTTP authentication, and client-side SSL certificates) in cross-origin request.

app.use(compression());
app.use(cookieParser());
app.use(bodyParser.json());

const server = http.createServer(app);

// default structure
server.listen(8080, () => {
    console.log('Server running on http://localhost:8080');
});
```

6. Create MongoDB Cluster
	1. create the DB user
	2. Add my Current IP Add
	3. Use Local Env
	4. Go to DB Dash, use Connect Btn
		1. Using Node.js copy link
		2. Plug in Code

```
const MONGO_URL = 'DB_URL_HERE'; // change to created user data

mongoose.Promise = Promise;
mongoose.connect(MONGO_URL);
mongoose.connection.on('error', (error: Error) => console.log(error));

app.use('/', router());
```


/////////////////
./db/users.ts

1. line "select: false" allows not to grab all the data set of users when fatching. Just for security not show it all up to the user
2. values can be set to be either string or anything else through (values: Record<string, any>)
3. to save data in DB just use .save() on an Model
4. to call if of an MonfoDB Model use _id
5. SessionToken is given on LogIn
6. Salt is const random value/unique hash

```
import mongoose from 'mongoose';

////////////////
// Schema/Format
const UserSchema = new mongoose.Schema({
    username: {type: String, required: true},
    email: {type: String, required: true},
    authentication: {
        password: {type: String, required: true, select: false},
        salt: {type: String, select: false},
        sessionToken: {type: String, select: false},
    },
});

////////////////////////////
// Actual DataTable with Ids
export const UserModel = mongoose.model('User', UserSchema);

///////////////////////
// SetUp Find Functions
export const getUsers = () => UserModel.find();
export const getUserByEmail = (email: string) => UserModel.findOne({email});
export const getUserBySessionToken = (sessionToken: string) => UserModel.findOne({
    'authentication.sessiontoken': sessionToken,
    // passinng as an object
});
export const getUserById = (id: string) => UserModel.findById(id);

///////////////////////////////////////////
// SetUp Create & Delete & Update Functions

// .then() allows to save submited data in createUser
export const createUser = (values: Record<string, any>) => new UserModel(values).save().then((user) => user.toObject()); 

export const deleteUserById = (id: string) => UserModel.findOneAndDelete({ _id: id });

export const updateUserById = (id: string, values: Record<string, any>) => UserModel.findByIdAndUpdate(id, values);
```


/////////////////////////
./Helpers/Index.ts
// helper for an authentication

SHA-256 (Secure Hash Algorithm 256-bit) is a widely used cryptographic hash function that belongs to the SHA-2 (Secure Hash Algorithm 2) family. It is one of the most common hash functions used for various security applications, such as data integrity verification, digital signatures, password hashing, and blockchain technology.

```
import crypto from 'crypto';

// Hidden Hashing Word
const SECRET = 'ANTONIO-REST-API';

// Hashing User
export const random = () => crypto.randomBytes(128).toString('base64');
export const authentication = (salt: string, password: string) => {
    return crypto.createHmac('sha256', [salt, password].join('/').update(SECRET).digest('hex'));
}
```


////////////////////////////////////////
./Controllers/authentication.ts

1. Async functions allows to run to the next line without waiting for the response from the function.
2. Const allow the function be a bit more secured of unpredicted changes, so we do not reassign it in a wrong way. Also, const functions should defined first before calling them.

```
import express from 'express';
import {getUserByEmail, createUser} from '../db/users';
import {random, authentication} from '../helpers';

export const login = aync (req: express.Request, res: express.Response) => {
    try {
        const {email, password} = req.body;
    
        if (!email || !password) {
            res.sendStatus(400);
        }

        const user = await getUserByEmail(email).select('+authentication.salt +authentication.password'); // allowing back select

        if (!user) {
            return res.sendStatus(400);
        }

        const exprectedHash = authentication(user.authentication.salt, password);
        
        if (user.authentication.password !== exprectedHash) {
            return res.sendStatus(403);
        }
        
        const salt = random();
        user.authentication.sessionToken = authentication(salt, user._id.toString());

        await user.save();

        res.cookie('ANTONIO-AUTH', user.authentication.sessionToken, {domain: 'localhost', path: '/'});
        
        // return logged in user
        return res.status(200).json(user).end();

    } catch (error) {
        concole.log(error);
        return res.sendStatus(400);
    }
}

export const register = async (req: express.Request, res: express.Response) => {
    try {
        const {email, password, username} = req.body;
        
        if (!email || !password || !username) {
            return res.sendStatus(400);
        }

        const existingUser = await getUserByEmail(email);

        if (existingUser) {
            return res.sendStatus(400);
        }

        const salt = random();
        const user = await createUser({
            email,
            username,
            authentication: {
                salt,
                password: authentication(salt, password),  
            },
        });
        
        // return registered in user
        return res.status(200).json(user).end(); 
   
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
}
```


////////////////////////////
./Controllers/users.ts

```
import express from 'express';
import {getUsers} from './db/users';

export const getAllUsers = async (req: express.Request, res: express.Response) => {

    try {
        const users = await getUsers();

        return res.status(200).json(users);
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }

}

export const deleteUser = async (req: express.Request, res: express.Response) => {
    try {
        const {id} = req.params;

        const deletedUser = await deleteUserById(id);
    
        // return
        return res.json(deletedUser);
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);    
    }
}

export const updateUser = 
async (req: express.Request, res: express.Response) => {
    
    try {
        const {id} = req.params;
        const {username} = req.body;
    
        if (!username) {
            res.sendStatus(400);
        }

        const user = await getUserById(id);

        user.username = username;
        await user.save();        
    
        // return
        return res.status(200).json(user).end();
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);    
    }

}
```


//////////////////////
./Router/index.ts
// SetUp the List of Routers [MAIN]

```
import express from 'express';

import authentication from './authentication';
import users from './users';

const router = express.Router();

export default (): express.Router => {
    authentication(router);
    users(router);

    return router;
};
```



HERE WE DEVIDE ROUTER FOR A STRUCTURE

/////////////////////////////////
./Router/authentication.ts
// SetUp the Router for Authentication with POST method

```
import express from 'express';
import {register, login} from '../controllers/authentication';

export default (router: express.Router) => {
    router.post('/auth/register', register);
    router.post('/auth/login', login);
}
```


///////////////////////
./Router/users.ts

```
import express from 'express';

import {getAllUsers} from '../controllers/users';
import {isAuthenticated, isOwner} from '../middlewares';


export default (router: express.Router) => {
    router.get('/users', isAuthenticated, getAllUsers);
    router.delete('/users/:id', isAuthenticated, isOwner, deleteUser)
    router.patch('/users/:id', isAuthenticated, isOwner, updateUser);
};
```


///////////////////////////////
./Middlewares/index.ts

```
import express from 'express';
import {get, merge} from 'lodash';

import {getUserBySessionToken} from '../db/users';

export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const {id} = req.params;
        const currentUserId = get(req, 'identity._id') as string;
    
        if (!currentUserId) {
            return res.sendStatus(403);
        }

        if (currentUserId.toString() !== id) {
            return res.sendStatus(403);
        }

        next();
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
}

export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction=) => {
    try {
        const sessionToken = req.cookies['ANTONIO-AUTH'];

        if (!sessionToken) {
            return res.sendStatus(403);
        }

        const existingUser = await getUserBySessionToken(sessionToken);

        if (!existingUser) {
            return res.sendStatus(403);
        }
        
        // eventually, the res should be a session that merges new objects, authenticated users, to one
        merge(res, {identity: existingUser});

        return next();
        // next passes control over the obj to the next middleware function

    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
}

```


//////////////////////////////
./Middlewares/users.ts

```
import express from 'express';

import {getAllUsers} from '../controllers/users';

export default (router: express.Router) => {
    router.get('/users', getAllUsers);
};
```


/// END
