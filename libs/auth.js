/** Auth JS file */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fido2 = require('@simplewebauthn/server');
const base64url = require('base64url');
const cryptoJS = require('crypto-js');
const fs = require('fs');
const low = require('lowdb');

if (!fs.existsSync('./.data')) {
  fs.mkdirSync('./.data');
}

const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);

router.use(express.json());

const TIMEOUT = 30 * 1000 * 60;

/**
 * Initialize database
 */
db.defaults({
  users: [],
}).write();

/**
 * Check CSRF
 *
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
const csrfCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    return res.status(400).json({ error: 'invalid access.' });
  }

  next();
};

/**
 * Checks CSRF protection using custom header `X-Requested-With`
 * If the session doesn't contain `signed-in`, consider the user is not authenticated.
 *
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
const sessionCheck = (req, res, next) => {
  if (!req.session['signed-in']) {
    return res.status(401).json({ error: 'not signed in.' });
  }

  next();
};

/**
 * Setup origin
 *
 * @param {*} userAgent 
 * @returns 
 */
const getOrigin = (userAgent) => {
  let origin = '';

  if (userAgent.indexOf('okhttp') === 0) {
    const octArray = process.env.ANDROID_SHA256HASH.split(':').map((h) =>
      parseInt(h, 16),
    );

    const androidHash = base64url.encode(octArray);
    origin = `android:apk-key-hash:${androidHash}`;
  } else {
    origin = process.env.ORIGIN;
  }

  return origin;
}

/**
 * Check name and email, create a new account if it doesn't exist.
 * Set a `name` and `email` in the session.
 *
 * @param {*} req 
 * @param {*} res 
 */
router.post('/register/validate', (req, res) => {
  const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  const name = req.body.name;
  const email = req.body.email;

  // Validate credentials
  let invalidName = !name;
  let invalidEmail = !email || !emailRegex.test(email.toLowerCase());

  // Check input data
  if (invalidName && invalidEmail) {
    return res.status(400).send({
      error: 'Bad request',
      validations: {
        name: "Invalid name",
        email: "Invalid email address",
      }
    });
  } else if (invalidName) {
    return res.status(400).send({
      error: 'Bad request',
      validations: {
        name: "Invalid name",
        email: "",
      }
    });
  } else if (invalidEmail) {
    return res.status(400).send({
      error: 'Bad request',
      validations: {
        email: "Invalid email address",
        name: "",
      }
    });
  } else {
    // See if account already exists using email address
    let user = db.get('users').find({ email: email }).value();

    if (user) {
      return res.status(400).send({
        error: 'Bad request',
        validations: {
          email: "Email address already exist",
          name: "",
        }
      });
    }

    // Register new user
    user = {
      name: name,
      email: email,
      password: null, // set to null temporarily
      id: base64url.encode(crypto.randomBytes(32)),
      credentials: [],
    };

    db.get('users').push(user).write();

    // Set data in the session
    req.session.name = name;
    req.session.email = email;

    // If sign-in succeeded, redirect to `/home`.
    res.json(user);
  }
});

/**
 * Authenticate a registered user in login page
 *
 * @param {*} req 
 * @param {*} res 
 */
router.post('/login/validate', (req, res) => {
  const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  const email = req.body.email;

  // Validate credentials
  let invalidEmail = !email || !emailRegex.test(email.toLowerCase());

  // Check input data
  if (invalidEmail) {
    return res.status(401).json({ error: 'Failed to authenticate.' });
  } else {
    // See if account already exists
    let user = db.get('users').find({ email: email }).value();

    // Return error if account doesn't exist
    if (!user) {
      return res.status(401).json({ error: 'Failed to authenticate.' });
    }

    console.log(user);

    // Set data in the session
    req.session.name = user.name;
    req.session.email = user.email;

    // If sign-in succeeded, redirect to `/home`.
    res.json(user);
  }
});

/**
 * Verifies user credential and let the user sign-in.
 *
 * @param {*} req 
 * @param {*} res 
 */
router.post('/password', (req, res) => {
  let password = req.body.password;
  let name = req.session.name;
  let email = req.session.email;

  if (!password) {
    return res.status(401).json({ error: 'Enter at least one random letter.' });
  }

  const user = db.get('users').find({ email: email }).value();

  if (!user) {
    return res.status(401).json({ error: 'Enter email first.' });
  }

  if (user.password === null) {
    // Encrypt password then save
    let encryptedPass = cryptoJS.AES.encrypt(password, "Secret Passphrase");

    // Update password
    db.get('users')
      .find({ email: email })
      .assign({ password: encryptedPass.toString() })
      .write();

    req.session['signed-in'] = 'yes';
  } else {
    // Decrypt and check if input password is correct
    let decryptedPass = cryptoJS.AES.decrypt(user.password, "Secret Passphrase");

    if (password === decryptedPass.toString(cryptoJS.enc.Utf8)) {
      req.session['signed-in'] = 'yes';
    } else {
      return res.status(401).json({ error: 'Failed to authenticate.' });
    }
  }

  res.json(user);
});

/**
 * Logout authenticated user
 *
 * @param {*} req 
 * @param {*} res 
 */
router.get('/signout', (req, res) => {
  // Remove the session
  req.session.destroy();

  // Redirect to `/`
  res.redirect(302, '/');
});

/**
 * Returns a credential id
 *
 * @param {*} req 
 * @param {*} res 
 **/
router.post('/getKeys', csrfCheck, sessionCheck, (req, res) => {
  const user = db.get('users').find({ email: req.session.email }).value();

  res.json(user || {});
});

/**
 * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', csrfCheck, sessionCheck, (req, res) => {
  const credId = req.query.credId;
  const email = req.session.email;
  const user = db.get('users').find({ email: email }).value();

  const newCreds = user.credentials.filter((cred) => {
    // Leave credential ids that do not match
    return cred.credId !== credId;
  });

  db.get('users')
    .find({ email: email })
    .assign({ credentials: newCreds })
    .write();

  res.json({});
});

/**
 * Reset database
 *
 * @param {*} req 
 * @param {*} res 
 */
router.get('/resetDB', (req, res) => {
  db.set('users', []).write();

  const users = db.get('users').value();

  res.json(users);
});

/**
 * Respond with required information to call navigator.credential.create()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     excludeCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }```
 **/
router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const email = req.session.email;
  const user = db.get('users').find({ email: email }).value();

  try {
    const excludeCredentials = [];

    if (user.credentials.length > 0) {
      for (let cred of user.credentials) {
        excludeCredentials.push({
          id: cred.credId,
          type: 'public-key',
          transports: ['internal'],
        });
      }
    }

    const pubKeyCredParams = [];
    const params = [-7, -257];

    for (let param of params) {
      pubKeyCredParams.push({ type: 'public-key', alg: param });
    }

    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;
    let authenticatorSelection;
    let attestation = 'none';

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }

    if (rr && typeof rr == 'boolean') {
      asFlag = true;
      as.requireResidentKey = rr;
    }

    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }

    if (asFlag) {
      authenticatorSelection = as;
    }

    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      attestation = cp;
    }

    const options = fido2.generateAttestationOptions({
      rpName: process.env.APP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.name,
      timeout: TIMEOUT,
      // Prompt users for additional information about the authenticator.
      attestationType: attestation,
      // Prevent users from re-registering existing authenticators
      excludeCredentials,
      authenticatorSelection,
    });

    req.session.challenge = options.challenge;

    // Temporary hack until SimpleWebAuthn supports `pubKeyCredParams`
    options.pubKeyCredParams = [];
    for (let param of params) {
      options.pubKeyCredParams.push({ type: 'public-key', alg: param });
    }

    res.json(options);
  } catch (e) {
    res.status(400).send({ error: e });
  }
});

/**
 * Register user credential.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const email = req.session.email;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credId = req.body.id;
  const type = req.body.type;

  try {
    const { body } = req;

    const verification = await fido2.verifyAttestationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });

    const { verified, authenticatorInfo } = verification;

    if (!verified) {
      throw 'User verification failed.';
    }

    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;

    const user = db.get('users').find({ email: email }).value();

    const existingCred = user.credentials.find(
      (cred) => cred.credID === base64CredentialID,
    );

    if (!existingCred) {
      /**
       * Add the returned device to the user's list of devices
       */
      user.credentials.push({
        publicKey: base64PublicKey,
        credId: base64CredentialID,
        prevCounter: counter,
      });
    }

    db.get('users').find({ email: email }).assign(user).write();

    delete req.session.challenge;

    // Respond with user info
    res.json(user);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).send({ error: e.message });
  }
});

/**
 * Respond with required information to call navigator.credential.get()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     challenge: String,
     userVerification: ('required'|'preferred'|'discouraged'),
     allowCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...]
 * }```
 **/
router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    const user = db
      .get('users')
      .find({ email: req.session.email })
      .value();

    if (!user) {
      // Send empty response if user is not registered yet.
      return res.json({ error: 'User not found.' });
    }

    const credId = req.query.credId;
    const userVerification = req.body.userVerification || 'required';
    const allowCredentials = [];

    for (let cred of user.credentials) {
      // `credId` is specified and matches
      if (credId && cred.credId == credId) {
        allowCredentials.push({
          id: cred.credId,
          type: 'public-key',
          transports: ['internal']
        });
      }
    }

    const options = fido2.generateAssertionOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification,
    });
    req.session.challenge = options.challenge;

    res.json(options);
  } catch (e) {
    res.status(400).json({ error: e });
  }
});

/**
 * Authenticate the user.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       authenticatorData: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post('/signinResponse', csrfCheck, async (req, res) => {
  const { body } = req;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  // Query the user
  const user = db.get('users').find({ email: req.session.email }).value();

  let credential = user.credentials.find((cred) => cred.credId === req.body.id);

  try {
    if (!credential) {
      throw 'Authenticating credential not found.';
    }

    const verification = fido2.verifyAssertionResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: credential,
    });

    const { verified, authenticatorInfo } = verification;

    if (!verified) {
      throw 'User verification failed.';
    }

    credential.prevCounter = authenticatorInfo.counter;

    db.get('users').find({ email: req.session.email }).assign(user).write();

    delete req.session.challenge;
    req.session['signed-in'] = 'yes';
    res.json(user);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).json({ error: e });
  }
});

module.exports = router;
