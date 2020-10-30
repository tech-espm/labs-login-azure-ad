import express = require("express");
import cookieParser = require("cookie-parser");
import passport = require("passport");
import appsettings = require("./appsettings");

const app = express();

app.disable("x-powered-by");
app.disable("etag");

app.use(cookieParser());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
	res.header("Cache-Control", "private, no-cache, no-store, must-revalidate");
	res.header("Expires", "-1");
	res.header("Pragma", "no-cache");
	next();
});

const OIDCStrategy = require("passport-azure-ad").OIDCStrategy;

passport.use(new OIDCStrategy({
	identityMetadata: appsettings.adAuthority + appsettings.adTenantId + appsettings.adIdMetadata,
	clientID: appsettings.adApplicationId,
	responseType: "code id_token",
	responseMode: "form_post",
	redirectUrl: appsettings.adRedirectUrl,
	allowHttpForRedirectUrl: true,
	clientSecret: appsettings.adClientSecret,
	validateIssuer: false,
	passReqToCallback: false,
    useCookieInsteadOfSession: true,
    cookieEncryptionKeys: appsettings.adCookieEncryptionKeys,
	scope: appsettings.adScopes
}, (iss: any, sub: any, profile: any, accessToken: any, refreshToken: any, params: any, done: any): any => {
	// done(err: any, user: any, info: any), executa o callback em routes\ad.ts
	return (profile.oid ? done(null, profile, accessToken) : done(new Error("Usuário do Microsoft AD sem OID."), null, null));
}));

app.use(appsettings.routePrefix, require("./routes/ad"));

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
	res.status(err.status || 500);

	res.json(err.status == 404 ? "Não encontrado" : (err.message || err.toString()));
});

const server = app.listen(parseInt(process.env.PORT) || 3010, process.env.IP || "127.0.0.1", () => {
	console.log("Express server listening on port " + server.address()["port"]);
});
