/** Server JS file */

const express = require('express');
const session = require('express-session');
const hbs = require('hbs');
const auth = require('./libs/auth');
const app = express();

app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(express.json());
app.use(express.static('public'));
app.use(express.static('dist'));
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  }
}));

/**
 * Initialize application info
 */
app.use((req, res, next) => {
  if (process.env.PROJECT_DOMAIN) {
    process.env.HOSTNAME = process.env.PROJECT_DOMAIN;
  } else {
    process.env.HOSTNAME = req.headers.host;
  }

  const protocol = /^localhost/.test(process.env.HOSTNAME) ? 'http' : 'https';
  process.env.ORIGIN = `${protocol}://${process.env.HOSTNAME}`;

  if (
    req.get('x-forwarded-proto') &&
    req.get('x-forwarded-proto').split(',')[0] !== 'https'
  ) {
    return res.redirect(301, process.env.ORIGIN);
  }

  req.schema = 'https';

  next();
});

/**
 * Index page function
 *
 * Method: GET
 * Route: /
 *
 * @param {*} req 
 * @param {*} res 
 */
app.get('/', (req, res) => {
  // Check session
  if (req.session.email) {
    // If user is signed in, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }

  // If user is not signed in, show `index.html` with id/password form.
  res.render('index.html');
});

/**
 * Login page function
 *
 * Method: GET
 * Route: /login
 *
 * @param {*} req 
 * @param {*} res 
 */
app.get('/login', (req, res) => {
  res.render('login.html');
});

/**
 * Home page function
 *
 * Method: GET
 * Route: /home
 *
 * @param {*} req 
 * @param {*} res 
 */
app.get('/home', (req, res) => {
  if (!req.session.email || !req.session.name || req.session['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    return res.redirect(307, '/');
  }

  // `home.html` shows sign-out link
  res.render('home.html', { 
    email: req.session.email,
    name: req.session.name,
  });
});

/**
 * Reauthentication page function
 *
 * Method: GET
 * Route: /reauth
 *
 * @param {*} req 
 * @param {*} res 
 */
app.get('/reauth', (req, res) => {
  const email = req.session.email;

  if (!email) {
    return res.redirect(302, '/');
  }

  res.render('reauth.html', { email: email });
});

/**
 * Get asset links
 *
 * @param {*} req 
 * @param {*} res 
 */
app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  const relation = [
    'delegate_permission/common.handle_all_urls',
    'delegate_permission/common.get_login_creds',
  ];

  assetlinks.push({
    relation: relation,
    target: {
      namespace: 'web',
      site: process.env.ORIGIN,
    },
  });

  if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
    assetlinks.push({
      relation: relation,
      target: {
        namespace: 'android_app',
        package_name: process.env.ANDROID_PACKAGENAME,
        sha256_cert_fingerprints: [process.env.ANDROID_SHA256HASH],
      },
    });
  }

  res.json(assetlinks);
});

app.use('/auth', auth);

// listen for req :)
const port = process.env.PORT || 3000;
const listener = app.listen(port, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
