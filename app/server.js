const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const process = require('node:process');

const express = require('express');
const session = require('express-session');
const handlebars = require('express-handlebars');
const passport = require('passport');
const refresh = require('passport-oauth2-refresh');
const OnshapeStrategy = require('passport-onshape');
const helmet = require('helmet');
const MemoryStore = require('memorystore')(session);
const axios = require('axios');
const Zip = require('adm-zip');

const HTTP_PORT = 80;
const HTTPS_PORT = 443;
const DATA_DIR = "/data";
const CERTS_DIR = DATA_DIR + '/certs';
const BASE_URL = `https://${process.env.EXTERNAL_HOSTNAME}`;

try {
  tls_key = fs.readFileSync(CERTS_DIR + '/privkey.pem');
  tls_cert = fs.readFileSync(CERTS_DIR + '/cert.pem');
} catch {
  console.error(`Cannot read TLS certificates from ${CERTS_DIR}.  Exiting.`);
  process.exit(1);
}

express.static.mime.define({'text/plain': ['nc']});

const app = express();

// Configuration various security headers.
app.disable('x-powered-by'); // don't advertise that we're using Express
app.use(helmet.contentSecurityPolicy({
  directives: {
    frameAncestors: ['self', 'https://cad.onshape.com'], // only allow embedding by OnShape
  },
}));
app.use(helmet.crossOriginEmbedderPolicy()); // only load resources from this origin
app.use(helmet.crossOriginOpenerPolicy()); // block sharing of the window object
app.use(helmet.crossOriginResourcePolicy()); // block access to our resources from other origins
app.use(helmet.hsts()); // tell user agent that we will always require HTTPS
app.use(helmet.noSniff()); // ask browser not to guess the mime type of downloaded files
app.use(helmet.referrerPolicy()); // don't send Referrer headers

// Enable the handlebars template engine.
app.engine('handlebars', handlebars.engine());
app.set('view engine', 'handlebars');

// Serve static content.
app.use(express.static('static'));

// Redirect all non-secure traffic to HTTPS.
app.use((req, res, next) => {
  if (!req.secure) {
    return res.redirect(`${BASE_URL}${req.url}`);
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
    let state = encodeState(req.query.redirectOnshapeUri);
    return passport.authenticate('onshape', { state })(req, res, next);
  });

// Called by OnShape with the results of the sign-in authentication request.
app.use('/oauth/redirect',
  (req, res, next) => {
    passport.authenticate('onshape', {}, (err, user, info) => {
      if (err || !user)
        return res.redirect(`/oauth/denied`);
  
      req.login(user, (err) => {
        if (err)
          return next(err); // report internal server error

        req.session.save((err) => {
          if (err)
            return next(err); // report internal server error

          let redirectUri = decodeState(req.query.state);
          return res.redirect(redirectUri || '/');
        });
      });
    })(req, res, next);
  });

// Called when the user denies authorization to the application.
app.get('/oauth/denied',
  (req, res, next) => {
    return res.render('oauth-denied');
  });

// Called after authentication to check whether the session cookie is valid.
// If so, it redirects back to the action that triggered authentication.
// Otherwise, it informs the user that the browser may be blocking the cookie
// and provides them with alternatives.
app.get('/oauth/session',
  (req, res, next) => {
    let actionUri = decodeState(req.query.action);
    if (!actionUri)
      return res.redirect('/'); // how did we get here?

    if (req.isAuthenticated())
      return res.redirect(actionUri);

    res.render('oauth-session-lost', { actionUri });
  });

// There's no front page since this application is meant to be embedded in OnShape.
// Redirect curious visitors to the project's home.
app.get('/',
  (req, res, next) => {
    return res.redirect(process.env.MAIN_PAGE_REDIRECT);
  });

// All pages under '/action' require authentication.
app.use('/action',
  (req, res, next) => {
    if (!req.isAuthenticated()) {
      let actionUri = req.originalUrl;
      let redirectUri = `/oauth/session?action=${encodeState(actionUri)}`;
      let state = encodeState(redirectUri.toString());
      return passport.authenticate('onshape', { state })(req, res, next);
    }
    next();
  });

// The view that is embedded as an iframe within a Part Studio right side panel.
app.get('/action/d/:documentId/:workspaceOrVersion/:workspaceOrVersionId/e/:elementId/panel',
  (req, res, next) => {
    const context = {
      documentId: req.params.documentId,
      workspaceOrVersion: req.params.workspaceOrVersion,
      workspaceOrVersionId: req.params.workspaceOrVersionId,
      elementId: req.params.elementId,
      configuration: parseConfigurationFromQuery(req.query.configuration),
      user: req.user,
    };

    getFileNames(context).then((files) => {
      res.render('panel', { files, query: encodeQuery(context.configuration) });
    }).catch((err) => {
      res.render('panel', { error: err.toString(), query: encodeQuery(context.configuration) });
    });
  });

// File download page.
app.get('/action/d/:documentId/:workspaceOrVersion/:workspaceOrVersionId/e/:elementId/f/:fileName/download',
  (req, res, next) => {
    const context = {
      documentId: req.params.documentId,
      workspaceOrVersion: req.params.workspaceOrVersion,
      workspaceOrVersionId: req.params.workspaceOrVersionId,
      elementId: req.params.elementId,
      configuration: parseConfigurationFromQuery(req.query.configuration),
      user: req.user,
    };
    const fileName = req.params.fileName;

    getFileContents(context, fileName).then((contents) => {
      res.attachment(fileName).send(contents);
    }, (error) => {
      res.status(404).send(error.toString());
    });
  });

// File viewer page.
app.get('/action/d/:documentId/:workspaceOrVersion/:workspaceOrVersionId/e/:elementId/f/:fileName/view',
  (req, res, next) => {
    const context = {
      documentId: req.params.documentId,
      workspaceOrVersion: req.params.workspaceOrVersion,
      workspaceOrVersionId: req.params.workspaceOrVersionId,
      elementId: req.params.elementId,
      configuration: parseConfigurationFromQuery(req.query.configuration),
      user: req.user,
    };
    const fileName = req.params.fileName;

    getFileContents(context, fileName).then((contents) => {
      res.render('view-file', { fileName, contents, query: encodeQuery(context.configuration) });
    }, (error) => {
      res.redirect('../../../panel');
    });
  });

// Zip file download page.
app.get('/action/d/:documentId/:workspaceOrVersion/:workspaceOrVersionId/e/:elementId/zip',
  (req, res, next) => {
    const context = {
      documentId: req.params.documentId,
      workspaceOrVersion: req.params.workspaceOrVersion,
      workspaceOrVersionId: req.params.workspaceOrVersionId,
      elementId: req.params.elementId,
      configuration: parseConfigurationFromQuery(req.query.configuration),
      user: req.user,
    };

    getAllFileContents(context).then((files) => {
      let archive = Zip();
      files.forEach(entry => {
        archive.addFile(entry[0], Buffer.from(entry[1], "utf-8"));
      });
      archive.toBuffer((buffer) => {
        res.attachment('CAM Files.zip').send(buffer);
      }, (error) => {
        res.status(500).send(error.toString());
      });
    }, (error) => {
      res.status(404).send(error.toString());
    });
  });

function getFileNames(context) {
  // A valid response looks like this:
  // {
  //   "result": {
  //     "btType": "com.belmonttech.serialize.fsvalue.BTFSValueArray",
  //     "value":[
  //       {
  //         "btType": "com.belmonttech.serialize.fsvalue.BTFSValueString",
  //         "value": "CAM Demo.nc",
  //         "typeTag": ""
  //       }
  //     ],
  //     "typeTag": ""
  //   },
  //   <lots more stuff>
  // }
  return new Promise((resolve, reject) => {
    evalFeatureScript(context, `
        try silent {
          const state = getVariable(context, "@camelState");
          return state.files is map ? keys(state.files) : [];
        }
        try silent { // old version
          const index = getVariable(context, "camelFileIndex");
          return keys(index);
        }
        return [];
      `).then((out) => {
      const result = out.data.result;
      if (result !== null
          && result.btType === 'com.belmonttech.serialize.fsvalue.BTFSValueArray') {
        return resolve(result.value.map((entry) => entry.value));
      }
      return reject(new Error('Could not get the file index'));
    }).catch((err) => {
      return reject(new Error('Could not get the file index'));
    });
  });
}

function getFileContents(context, fileName) {
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
    evalFeatureScript(context, `
        const fileName = "${escapeFeatureScriptString(fileName)}";
        try silent {
          const state = getVariable(context, "@camelState");
          if (state.files[fileName] is string) {
            return state.files[fileName];
          }
        }
        try silent { // old version
          const index = getVariable(context, "camelFileIndex");
          const content = getVariable(context, index[fileName]);
          if (content is string) {
            return content;
          }
        }
        throw "File not found";
      `).then((out) => {
      const result = out.data.result;
      if (result !== null
          && result.btType === 'com.belmonttech.serialize.fsvalue.BTFSValueString') {
        return resolve(result.value);
      }
      return reject(new Error('File not found'));
    }).catch((err) => {
      return reject(new Error('Could not download the file'));
    });
  });
}

function getAllFileContents(context) {
  return new Promise((resolve, reject) => {
    evalFeatureScript(context, `
        try silent {
          const state = getVariable(context, "@camelState");
          return state.files is map ? state.files : {};
        }
        try silent { // old version
          const index = getVariable(context, "camelFileIndex");
          var files = {};
          for (var fileName in keys(index)) {
            files[fileName] = getVariable(context, index[fileName]);
          }
          return files;
        }
        return {};
      `).then((out) => {
      const result = out.data.result;
      if (result !== null
          && result.btType === 'com.belmonttech.serialize.fsvalue.BTFSValueMap') {
        return resolve(result.value.map((entry) => [entry.key.value, entry.value.value]));
      }
      return reject(new Error('Could not download all of the files'));
    }).catch((err) => {
      return reject(new Error('Could not download all of the files'));
    });
  });
}

function escapeFeatureScriptString(str) {
  // To prevent possible FeatureScript injection attacks, we escape every character
  // in the string. This is overkill but easy and sufficient.
  let result = "";
  for (let i = 0; i < str.length; i++) {
    result += '\\u' + str.charCodeAt(i).toString(16).padStart(4, '0');
  }
  return result;
}

function evalFeatureScript(context, fn) {
  let url = `/v5/partstudios/d/${context.documentId}/${context.workspaceOrVersion}/${context.workspaceOrVersionId}/e/${context.elementId}/featurescript${encodeQuery(context.configuration)}`;
  return api.post(url, {
    script: `function (context is Context, queries is map) { ${fn} }`,
  }, {
    onshapeUser: context.user,
  });
}

function parseConfigurationFromQuery(param) {
  // Curiously, OnShape sends '{$configuration}' when there is no configuration
  // instead of sending an empty value.
  if (param === undefined || param === '{$configuration}')
    return '';
  return param;
}

function encodeQuery(configuration) {
  if (configuration) {
    return `?configuration=${encodeURIComponent(configuration)}`;
  }
  return '';
}

function encodeState(redirectUri) {
  return redirectUri ? encodeURIComponent(redirectUri) : '';
}

function decodeState(state) {
  return state ? decodeURIComponent(state) : '';
}

// Start the server
http.createServer(app).listen(HTTP_PORT, () => {
  console.log(`Listening for HTTP connections on port ${HTTP_PORT}`);
});

https.createServer({ key: tls_key, cert: tls_cert }, app).listen(HTTPS_PORT, () => {
  console.log(`Listening for HTTPS connections on port ${HTTPS_PORT}`);
});
