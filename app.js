/*
 Copyright 2019 IBM Corp.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const appID = require("ibmcloud-appid");
const jwt = require('jsonwebtoken');
const fs = require('fs');
const helmet = require("helmet");
const express_enforces_ssl = require("express-enforces-ssl");
const cfEnv = require("cfenv");
const cookieParser = require("cookie-parser");
const flash = require("connect-flash");
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const UnauthorizedException = appID.UnauthorizedException;
const app = express();
const userProfileManager = appID.UserProfileManager;
const PROTECTED_URL = '/protected';
const APPID_AUTH_CONTEXT = 'AppID_Auth_context';
const LINKEDINCLIENTID = "LINKEDINCLIENTID";
const LINKEDINSECRET = "LINKEDINSECRET";
const port = process.env.PORT || 4000;
const isLocal = cfEnv.getAppEnv().isLocal;
const config = {
  "clientId": "clientId",
  "oauthServerUrl": "oauthServerUrl",
  "profilesUrl": "profilesUrl",
  "secret": "secret",
  "tenantId": "tenantId",
  "version": 4,
  "preferredLocale": "en"
};

configureSecurity();

app.use(flash());

app.use(session({
	secret: "123456",
	resave: true,
	saveUninitialized: true,
	proxy: true,
	cookie: {
		httpOnly: true,
		secure: !isLocal
	}
}));

app.set('view engine', 'ejs');

// Configure express application to use passportjs
app.use(passport.initialize());
app.use(passport.session());


const tokenManager = new appID.TokenManager(config);
// Initialize the user attribute Manager
userProfileManager.init(config);

passport.use(new LinkedInStrategy({
	clientID: LINKEDINCLIENTID,
	clientSecret: LINKEDINSECRET,
	callbackURL: "http://localhost:4000/auth/linkedin/callback",
	profileFields: ["id", "first-name", "last-name", "email-address", "public-profile-url", "headline", "location:(name,country:(code))"],
}, function(accessToken, refreshToken, profile, done) {
	process.nextTick(function () {
		return done(null, { accessToken, profile});
	});
}));

// Configure passportjs with user serialization/deserialization. This is required
// for authenticated session persistence accross HTTP requests. See passportjs docs
// for additional information http://passportjs.org/docs
passport.serializeUser(function(user, cb) {
	cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
	cb(null, obj);
});

app.get('/auth/linkedin', passport.authenticate('linkedin'));

app.get('/auth/linkedin/callback', passport.authenticate('linkedin', {failureRedirect: '/'}), function(req, res, next) {
	const profile = req.session.passport.user.profile;
	let sampleToken = {
		header: {
			alg: 'RS256',
			kid: 'sample-rsa-private-key'
		},
		payload: {
			iss: profile.provider,
			sub: profile.id,
			aud: tokenManager.serviceConfig.getOAuthServerUrl().split('/')[2],
			exp: 9999999999,
			scope: 'customScope'
		}
	};
	Object.assign(sampleToken.payload, profile._json);
	delete sampleToken.payload.id;
	const generateSignedJWT = (privateKey) => {
		const { header, payload } = sampleToken;
		return jwt.sign(payload, privateKey, { header });
	};

	const privateKey = fs.readFileSync('./resources/private.pem');
	let jwsTokenString = generateSignedJWT(privateKey);

	tokenManager.getCustomIdentityTokens(jwsTokenString).then((authContext) => {
		req.session[APPID_AUTH_CONTEXT] = authContext;
		req.session[APPID_AUTH_CONTEXT].identityTokenPayload = jwt.decode(authContext.identityToken);
		req.session[APPID_AUTH_CONTEXT].accessTokenPayload = jwt.decode(authContext.accessToken);
		next();
	}).catch((error) => {
		console.log(error);
		res.redirect('/error');
	});
}, function (req, res) {
	userProfileManager.getUserInfo(req.session[APPID_AUTH_CONTEXT].accessToken).then(function (userInfo) {
		req.session[APPID_AUTH_CONTEXT].userInfo = userInfo;
		res.redirect(PROTECTED_URL);
	}).catch(function() {
		console.log(`Access token userInfo: error`);
		res.redirect(PROTECTED_URL);
	});
});

function isLoggedIn(req) {
	return req.session[APPID_AUTH_CONTEXT];
}

app.get(PROTECTED_URL, function(req, res, next) {
	if (isLoggedIn(req)) {
		next();
	} else {
		res.redirect("/");
	}
}, (req, res) => {
	res.render('token',{tokens: JSON.stringify(req.session[APPID_AUTH_CONTEXT])});
});

app.get("/logout", function(req, res, next) {
	req.logout();
	delete req.session[APPID_AUTH_CONTEXT];
	res.redirect("/");
});

app.get('/error', function(req, res) {
	let errorArray = req.flash('error');
	res.render("error.ejs",{errorMessage: errorArray[0]});
});


app.use(express.static("public", {index: null}));

app.use('/', function(req, res, next) {
	if (!isLoggedIn(req)) {
		next();
	} else {
		res.redirect(PROTECTED_URL);
	}
},function(req,res,next) {
	res.sendFile(__dirname + '/public/index.html');
});


app.use(function(err, req, res, next) {
	if (err instanceof UnauthorizedException) {
		res.redirect('/');
	} else {
		next(err);
	}
});

app.listen(port, function(){
	console.log("Listening on http://localhost:" + port);
});

function configureSecurity() {
	app.use(helmet());
	app.use(cookieParser());
	app.use(helmet.noCache());
	app.enable("trust proxy");
	if (!isLocal) {
		app.use(express_enforces_ssl());
	}
}