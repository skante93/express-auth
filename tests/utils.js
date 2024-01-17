
const express = require('express');
const ExpressAuth = require('../index');
const fs = require('fs');
const jwktopem = require('jwk-to-pem');
const jose = require('node-jose');
const Path = require('path');
const http = require('http');
exports.buildGenericExpressApp = function(...expressAuthArguments){
	let server = express();
	// server.get('/', (req, res, next)=>{ res.json({ response: "Wellcome Home" }) })
	server.get('/foo', (req, res, next)=>{ 
		res.json({ response: "What's up foo?!" }) 
	})
	server.get('/bar', ExpressAuth(...expressAuthArguments), (req, res, next)=>{ 
		res.json({ response: "Wait, fish or social gathering?" }) 
	})
	server.use('*', (err, req, res, next)=>{
		// console.log('err', err);
		let message = err.body || err;
		message = message instanceof Error ? message.message : message;

		res.status(err.statusCode || err.status || 500).json({ message });
	})

	return server;
}

exports.buildGenericExpressAppWithJWKSEndpoint = function(...expressAuthArguments){
	let server = exports.buildGenericExpressApp(...expressAuthArguments);

	const keyStore = jose.JWK.createKeyStore();

	return keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig', kid: "set1" })
	.then(() => keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig', kid: "set2" }))
	.then(()=>{
		fs.writeFileSync(Path.join(__dirname, '../keys.json'), JSON.stringify(keyStore.toJSON(true), null, '  ') );
		let keys = keyStore.all({ use: 'sig' });;
		let certs = keys.map(k=>[k.kid, jwktopem(k.toJSON(true), { private: true })])
		certs = Object.fromEntries(certs);

		let jwkServer = express();
		jwkServer.get('/jwks', (req, res, next) => {
			res.json({ keys: keys.map(k=>k.toJSON()) });
		});
		jwkServer = http.createServer(jwkServer);
		// jwkServer.listen(3000);
		return { server, jwkServer, certs };
	});
}

exports.cleanUpBasicAuth = (done) => {
	let knownPaths = ['basic.auth.json', 'test-custom-path-authlist.json', 'settings']
	for (var p of knownPaths){
		if (!fs.existsSync(p)) continue;
		if (fs.statSync(p).isDirectory()){
			fs.rmSync(p, {recursive:true});
		} else {
			fs.unlinkSync(p);
		}
	}
	
	typeof done === 'function' && done();
}

const BASIC_AUTH_LIST = [
	{id: "abc", email: 'foo@example.com', password: "foo1234"},
	{id: "def", email: 'bar@example.com', password: "bar1234"}
]

exports.BASIC_AUTH_LIST = BASIC_AUTH_LIST;

exports.makeBaiscSettingsFile = (kind = 1) => {
	
	let file = kind == 1 ? 'basic.auth.json' : kind == 2 ? 'settings/basic.auth.json' : 'test-custom-path-authlist.json'
	if (kind == 2 && !fs.existsSync('settings')) fs.mkdirSync('settings', {recursive:true});

	fs.writeFileSync(file, JSON.stringify(BASIC_AUTH_LIST), 'utf8')
	// typeof done === 'function' && done();
}


// exports.buildGenericExpressAppWithJWKSEndpoint({ method: "bearer", jwks: { serverURL: 'http://localhost:3000/jwks'} }).then(s=>{
// 	s.server.listen(3000, ()=>{ console.log("Running"); });
// 	setTimeout(()=>{
// 		s.server.close(()=>{
// 			console.log('closed successfully');
// 		})
// 	}, 3000)
// });