const fs = require('fs');
const express = require('express');
const session = require('express-session');
const https = require('https')
const http = require('http')
const passport = require('passport');
const refresh = require('passport-oauth2-refresh');
const OnshapeStrategy = require('passport-onshape');
const process = require('process');
const MemoryStore = require('memorystore')(session);
const axios = require('axios');

const HTTP_PORT = 80;
const HTTPS_PORT = 443;
const DATA_DIR = "/data";
const CERTS_DIR = DATA_DIR + '/certs';
require('dotenv').config({ path: '/data/.env'});

try {
  tls_key = fs.readFileSync(CERTS_DIR + '/privkey.pem');
  tls_cert = fs.readFileSync(CERTS_DIR + '/cert.pem');
} catch {
  console.error('Cannot read TLS certificates from ${CERTS_DIR}.  Exiting.');
  process.exit(1);
}

const app = express()

// Redirect all non-secure traffic to HTTPS.
app.use((req, res, next) => {
  if (!req.secure) {
    return res.redirect(`https://${process.env.EXTERNAL_HOSTNAME}${req.url}`);
  }
  next();
});

// Initialize session ID cookie management.
app.use(session({
  secret: process.env.SESSION_ID_COOKIE_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, maxAge: 86400000, sameSite: 'none' },
  store: new MemoryStore({
    checkPeriod: 86400000 // prune expired entries every 24h
  }),
}));

// Initialize the authenticator.
app.use(passport.initialize());

// Transforms user into a value that will be stored in req.session.passport.user.
// We don't need to do anything special here because the user profile data is small
// and transient. We only need to keep it in memory for the lifetime of the server.
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Reads the user from the session cookie if there is one and stores it into req.user.
app.use(passport.session());

// Adds an authentication strategy for calling OnShape APIs and getting OnShape user information.
const onshapeStrategy = new OnshapeStrategy({
    clientID: process.env.ONSHAPE_APP_CLIENT_ID,
    clientSecret: process.env.ONSHAPE_APP_CLIENT_SECRET,
    callbackURL: '/oauth/redirect',
    authorizationURL: process.env.ONSHAPE_AUTHORIZATION_URL,
    tokenURL: process.env.ONSHAPE_TOKEN_URL,
    userProfileURL: process.env.ONSHAPE_USER_PROFILE_URL,
  },
  (accessToken, refreshToken, profile, done) => {
    let user = { accessToken, refreshToken, profile };
    return done(null, user);
  });
passport.use(onshapeStrategy);
refresh.use(onshapeStrategy);

// OnShape API accessor
const api = axios.create({
  baseURL: process.env.ONSHAPE_API_URL,
  timeout: 10000,
});

// Attaches the OnShape user access token to the request header.
api.interceptors.request.use((config) => {
    const onshapeUser = config.onshapeUser;
    if (onshapeUser) {
      config.headers.Authorization = `Bearer ${onshapeUser.accessToken}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error)
  });

// Handles authentication errors and automatically refreshes the OnShape user
// access token if needed.
api.interceptors.response.use((response) => {
  return response;
}, (error) => {
  const config = error.config;
  const onshapeUser = config.onshapeUser;
  if (!onshapeUser
      || error.response.status !== 401
      || config.onshapeAccessTokenRefreshed) {
    return Promise.reject(error);
  }

  config.onshapeAccessTokenRefreshed = true;
  return new Promise((resolve, reject) => {
    refresh.requestNewAccessToken('onshape', onshapeUser.refreshToken,
        (error, accessToken, refreshToken) => {
      if (error) {
        return reject(error);
      }
      onshapeUser.accessToken = accessToken;
      onshapeUser.refreshToken = refreshToken;
      api(config).then(resolve, reject);
    });
  });
});

// Called by OnShape when the user clicks the button to grant this application
// access to their documents. The optional 'redirectOnshapeUri' query parameter tells
// this application how to get back to OnShape once the flow has completed.
app.use('/oauth/signin',
  (req, res, next) => {
    // This call to authenticate will redirect to the OnShape access grant page.
    // Remember where to return from authentication in 'state'.
    let state = req.query.redirectOnshapeUri;
    return passport.authenticate('onshape', { state })(req, res, next);
  });

// Called by OnShape with the results of the sign-in authentication request.
app.use('/oauth/redirect',
  (req, res, next) => {
    passport.authenticate('onshape', {}, (err, user, info) => {
      let redirectUri = req.query.state;
      if (err)
        return res.redirect(redirectUri ? redirectUri : `/?authsuccess=false`);
  
      req.login(user, (err) => {
        if (err)
          return next(err); // report internal server error

        req.session.save((err) => {
          if (err)
            return next(err); // report internal server error
          return res.redirect(redirectUri ? redirectUri : `/?authsuccess=true`);
        });
      });
    })(req, res, next);
  });

// Placeholder front page.
app.get('/',
  (req, res, next) => {
    return res.send(`Please install Camel from the OnShape app store. Access the app from the right panel in a Part Studio.`);
  });

// All pages under '/view' require authentication.
app.use('/view',
  (req, res, next) => {
    if (!req.isAuthenticated()) {
      let state = req.originalUrl;
      return passport.authenticate('onshape', { state })(req, res, next);
    }
    next();
  });

app.get('/view/cam',
  (req, res, next) => {
    let context = {
      documentId: req.query.di,
      workspaceOrVersion: req.query.wv,
      workspaceOrVersionId: req.query.wvi,
      elementId: req.query.ei,
      user: req.user,
    };

    getFileIndex(context).then((fileIndex) => {
      if (fileIndex.length === 0) {
        res.send('There are no CAM files yet.');
      } else {
        getFile(context, fileIndex, fileIndex[0].fileName).then((data) => {
          res.send(`<pre>${data}</pre>`);
        }).catch(err => {
          res.send(`Error ${err}`);
        });
      }
    }).catch((err) => {
      res.send(`Error ${err}`);
    });
  });

http.createServer(app).listen(HTTP_PORT, () => {
  console.log(`Listening for HTTP connections on port ${HTTP_PORT}`);
});

https.createServer({ key: tls_key, cert: tls_cert }, app).listen(HTTPS_PORT, () => {
  console.log(`Listening for HTTPS connections on port ${HTTPS_PORT}`);
});

function getFileIndex(context) {
  // A valid response looks like this:
  // {
  //   "result": {
  //     "btType": "com.belmonttech.serialize.fsvalue.BTFSValueMap",
  //     "value": [
  //       {
  //         "btType": "BTFSValueMapEntry-2077",
  //         "value": {
  //           "btType": "com.belmonttech.serialize.fsvalue.BTFSValueString",
  //           "value": "camelFile0",
  //           "typeTag": ""
  //         },
  //         "key": {
  //           "btType": "com.belmonttech.serialize.fsvalue.BTFSValueString",
  //           "value": "CAM Demo.nc",
  //           "typeTag": ""
  //         }
  //       }
  //     ],
  //     "typeTag": ""
  //   },
  //   <lots more stuff>
  // }
  return new Promise((resolve, reject) => {
    evalFeatureScript(context, 'return getVariable(context, "camelFileIndex");').then((out) => {
      let result = out.data.result;
      if (result === null)
        return resolve([]); // There were no files

      if (result.btType !== 'com.belmonttech.serialize.fsvalue.BTFSValueMap')
        return reject(new Error('Could not get the file index from the Part Studio'));

      resolve(result.value.map((entry) => {
        return { name: entry.key.value, variable: entry.value.value };
      }));
    }).catch((err) => {
      return reject(new Error(`Could not get the file index from the Part Studio: ${err}`));
    });
  });
}

function getFile(context, fileIndex, fileName) {
  // A valid response looks like this:
  // {
  //   "result": {
  //     "btType": "com.belmonttech.serialize.fsvalue.BTFSValueString",
  //     "value": "<contents>",
  //     "typeTag": ""
  //   },
  //   <lots more stuff>
  // }
  return new Promise((resolve, reject) => {
    let entry = fileIndex.find((entry) => entry.fileName === fileName);
    if (entry === undefined)
      return reject(new Error('File not found'));

    // Guard against a possible FeatureScript injection attack and other malformed data.
    let variable = entry.variable;
    if (!/^camelFile[0-9]+$/.test(variable))
      reject(new Error('The file index is malformed'));

    evalFeatureScript(context, `return getVariable(context, "${variable}");`).then((out) => {
      let result = out.data.result;
      if (result === null)
        return reject(new Error('File not found'));

      if (result.btType !== 'com.belmonttech.serialize.fsvalue.BTFSValueString')
        return reject(new Error('The file index is malformed'));

      resolve(result.value);
    }).catch((err) => {
      return reject(new Error(`Could not get the file: ${err}`));
    });
  });
}

function evalFeatureScript(context, fn) {
  let url = `/v5/partstudios/d/${context.documentId}/${context.workspaceOrVersion}/${context.workspaceOrVersionId}/e/${context.elementId}/featurescript`;
  return api.post(url, {
    script: `function (context is Context, queries is map) { ${fn} }`,
  }, {
    onshapeUser: context.user,
  });
}
