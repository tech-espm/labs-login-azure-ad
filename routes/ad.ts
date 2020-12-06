import { randomBytes } from "crypto";
import express = require("express");
import graph = require('@microsoft/microsoft-graph-client');
import passport = require("passport");
import appsettings = require("../appsettings");
import intToHex = require("../utils/intToHex");

require("isomorphic-fetch");

const router = express.Router();

class Usuario {
	public user: string;
	public nome: string;
	public email: string;
	public emailAcademico: string;
	public aluno: boolean;
}

interface Resultado {
	token: string;
	erro: string;
	dados: Usuario;
}

const maxResultados = (1 << 14), // 2 ^ 14 = 16384
	maxResultadosMask = maxResultados - 1,
	resultados: Resultado[] = new Array(maxResultados);
let ultimoResultado = 0;

const testeMaxResultados = (1 << 7), // 2 ^ 7 = 128
	testeMaxResultadosMask = testeMaxResultados - 1,
	testeResultados: Resultado[] = new Array(testeMaxResultados);
let testeUltimoResultado = 0;

function adLogin(req: express.Request, res: express.Response, next: express.NextFunction) {
	// https://www.npmjs.com/package/passport-azure-ad
	// https://docs.microsoft.com/en-us/graph/tutorials/node
	passport.authenticate("azuread-openidconnect", { session: false }, async (err: any, user: any, info: any) => {
		let erro: string = null;
		let dados: Usuario = null;

		try {
			if (err) {
				erro = (err.message || err.toString());
			} else {
				// https://www.npmjs.com/package/@microsoft/microsoft-graph-client
				// https://github.com/microsoftgraph/msgraph-sdk-javascript
				// https://github.com/microsoftgraph/msgraph-training-nodeexpressapp/blob/main/tutorial/04-add-aad-auth.md

				// info é o accessToken, enviado pelo callback em app.ts
				const client = graph.Client.init({ authProvider: (done) => { done(null, info); } });
				const user = await client.api("/me").get();

				dados = new Usuario();
				dados.nome = (user.displayName as string || "").trim() || (user.givenName as string || "").trim();
				if (!dados.nome) {
					erro = "Informações sobre o nome do usuário faltantes no AD";
					dados = null;
				} else {
					dados.user = (user.userPrincipalName as string || "").trim().toLowerCase();
					if (!dados.user || (!dados.user.endsWith("@espm.br") && !dados.user.endsWith("@acad.espm.br"))) {
						dados.user = (user.mail || "").trim();
						if (!dados.user || (!dados.user.endsWith("@espm.br") && !dados.user.endsWith("@acad.espm.br"))) {
							erro = "Informações sobre o login do usuário faltantes no AD";
							dados = null;
						} else {
							dados.email = (user.userPrincipalName as string || "").trim().toLowerCase();
						}
					} else {
						dados.email = (user.mail as string || "").trim().toLowerCase();
					}
					if (dados) {
						dados.emailAcademico = dados.user;
						if (!dados.email)
							dados.email = dados.user;
						dados.aluno = dados.user.endsWith("@acad.espm.br");
						dados.user = dados.user.substring(0, dados.user.lastIndexOf("@"));
						if (!dados.user) {
							erro = "E-mail de login do usuário está inválido no AD";
							dados = null;
						}
					}
				}
			}
		} catch (ex) {
			erro = ex.message || ex.toString();
			dados = null;
		}

		const callback = req.cookies[appsettings.cookieName] as string;
		res.cookie(appsettings.cookieName, "", { expires: new Date(0), httpOnly: true, path: "/", secure: false });
		if (!callback) {
			res.status(400).json("Parâmetro callback faltando!");
		} else {
			ultimoResultado++;
			ultimoResultado &= maxResultadosMask;
			const resultado: Resultado = {
				token: intToHex(ultimoResultado ^ appsettings.hashId) + randomBytes(16).toString("hex"),
				erro: erro,
				dados: dados
			};
			resultados[ultimoResultado] = resultado;
			res.redirect(callback + ((callback.indexOf("?") >= 0) ? "&token=" : "?token=") + resultado.token);
		}
	})(req, res, next);
}

// Alguns iPhones redirecionam apenas para /ad, e não para /ad/login...
router.all("/", adLogin);

router.all("/login", adLogin);

router.all("/redir", (req: express.Request, res: express.Response) => {
	const callback = req.query["callback"] as string;
	if (!callback) {
		res.status(400).json("Parâmetro callback faltando!");
		return;
	}
	res.cookie(appsettings.cookieName, callback, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, path: "/", secure: false });
	res.redirect(appsettings.adRedirectUrl);
});

router.get("/token/:token", (req: express.Request, res: express.Response) => {
	const token = req.params["token"] as string;
	let id: number;
	if (!token ||
		token.length !== 40 ||
		isNaN(id = parseInt(token.substr(0, 8), 16)) ||
		(id = (id ^ appsettings.hashId)) < 0 ||
		id >= maxResultados) {
		res.json({ token: null, erro: "Token inválido", dados: null });
		return;
	}
	const resultado = resultados[id];
	if (!resultado) {
		res.json({ token: null, erro: "Dados nulos para o token requisitado", dados: null });
		return;
	}
	if (resultado.token !== token) {
		res.json({ token: null, erro: "Token não confere", dados: null });
		return;
	}
	resultados[id] = null;
	res.json(resultado);
});

router.all("/teste-redir", (req: express.Request, res: express.Response) => {
	const callback = req.query["callback"] as string;
	if (!callback) {
		res.status(400).json("Parâmetro callback faltando!");
		return;
	}
	if (req.body && req.body.nome && req.body.user) {
		const nome = (req.body.nome as string).normalize().trim(),
			user = (req.body.user as string).normalize().trim().toLowerCase();
		if (nome && user) {
			if (nome.length > 50 || user.length > 30) {
				res.status(400).json("Nome/login muito longo!");
			} else {
				testeUltimoResultado++;
				testeUltimoResultado &= testeMaxResultadosMask;
				const dados = new Usuario();
				dados.aluno = !!req.body.aluno;
				dados.email = user + (dados.aluno ? "@acad.espm.br" : "@espm.br");
				dados.emailAcademico = dados.email;
				dados.nome = nome;
				dados.user = user;
				const resultado: Resultado = {
					token: intToHex(testeUltimoResultado ^ appsettings.hashId) + randomBytes(16).toString("hex"),
					erro: null,
					dados: dados
				};
				testeResultados[testeUltimoResultado] = resultado;
				res.redirect(callback + ((callback.indexOf("?") >= 0) ? "&token=" : "?token=") + resultado.token);
			}
			return;
		}
	}
	res.send(`<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="pt-BR">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Teste de Integração</title>
</head>
<body>
	<form method="POST">
		<p>Forneça um nome de usuário (login) qualquer, como joão.silva, e diga se esse usuário deve ser entendido ou não como aluno.</p>
		<p>O login forncecido aqui não precisa existir no Azure real, <b>pois as informações fornecidas aqui são utilizadas apenas para fins de teste de integração, e não têm qualquer tipo de ligação com o Azure real</b>.</p>
		<p><input type="text" spellcheck="false" id="nome" name="nome" size="30" maxlength="50" placeholder="Nome (como João da Silva)" /></p>
		<p><input type="text" spellcheck="false" id="user" name="user" size="30" maxlength="30" placeholder="Login (como joão.silva)" /></p>
		<p><label><input type="checkbox" id="aluno" name="aluno" /> Considerar como aluno?</label></p>
		<p><button type="submit">Enviar</button></p>
	</form>
</body>
</html>`);
});

router.get("/teste-token/:token", (req: express.Request, res: express.Response) => {
	const token = req.params["token"] as string;
	let id: number;
	if (!token ||
		token.length !== 40 ||
		isNaN(id = parseInt(token.substr(0, 8), 16)) ||
		(id = (id ^ appsettings.hashId)) < 0 ||
		id >= testeMaxResultados) {
		res.json({ token: null, erro: "Token inválido", dados: null });
		return;
	}
	const resultado = testeResultados[id];
	if (!resultado) {
		res.json({ token: null, erro: "Dados nulos para o token requisitado", dados: null });
		return;
	}
	if (resultado.token !== token) {
		res.json({ token: null, erro: "Token não confere", dados: null });
		return;
	}
	testeResultados[id] = null;
	res.json(resultado);
});

export = router;
