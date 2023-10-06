
const axios = require('axios'), fs = require('fs');
const jsonwebtoken = require('jsonwebtoken');

const CachedVAR = function(value, ms){ 
	
	let id = `${Math.floor(Math.random()*10**4).toString().padStart(4, "0")}.${Date.now()}`
	
	if (CACHE[id] && CACHE[id].expiresAt < Date.now() ){
		delete CACHE[id];
	}

	if (!CACHE[id]) {
		CACHE[id] = { expiresAt: Date.now() + ms }
	}

	CACHE[id].value = value || CACHE[id].value;

	return {
		get val(){ return CACHE[id].value },
		set val(v){ CACHE[id].value = v },
	} 
}

/**
 * @typedef LoginObject
 * @property {string} username
 * @property {string} password
 * 
 * @param {object} options 
 * @param {LoginObject[]} options.authList 
 * @param {string} options.authFile 
 * @return { (req: Express.Request, res: Express.Response, next: function) => void }
 */
const basicAuth = async (options) => {
	// 
	let { authList, authFile } = options;
	if (!authList && !authFile) throw new Error(`options missing both fields "authList" and "authFile"`);

	let isAuthData = (d) => d && typeof d.username === 'string' && typeof d.password === 'string';

	let loadAuthDataFromFile = (src) =>{
		let data = JSON.parse(fs.readFileSync(src, 'utf8'));
		if ( !(data instanceof Array) ) throw new Error(`AuthFile should contain an array`)
		data.forEach( (d, i) => {
			if ( !isAuthData(d) ) {
				throw new Error(
					`AuthFile at index ${i}: must be valid BasicAuthEntryObjects `+
					`(i.e. format: {"username": "string", "password": "string"})`
				);
			}
		});
		return data;
		// return new CachedVAR(data, 25000); // CACHED FOR 25 SECS
	}

	authList = authFile ? loadAuthDataFromFile(authFile) : authList;
	
	authList.forEach( (data, i) => {
		if ( !isAuthData(data) ) {
			throw new Error(
				`AuthFile at index ${i}: must be valid BasicAuthEntryObjects `+
				`(i.e. format: {"username": "string", "password": "string"})`
			);
		}
	});

	return (req, res, next)=>{

		let b64;
		if (
			!(req.headers.authorization||'').startsWith(/^basic /i)  ||
			!(b64 = req.headers.authorization.replace(/^basic /i, '').trim())
		) {
			res.setHeader('WWW-Authenticate', 'Basic');
			return next(options.required === true ? {statusCode: 401} : null);
		}

		let [ username, password ] = Buffer.from(b64, 'base64').toString().split(':'); 
		if (!username || !password) {
			res.setHeader('WWW-Authenticate', 'Basic');
			return next(options.required === true ? {statusCode: 401} : null);
		}

		let data = authFile ? loadAuthDataFromFile(authFile) : authList, user;
		if (!(user = data.find(d=>d.username == username && d.password == password))) {
			res.setHeader('WWW-Authenticate', 'Basic');
			return next(options.required === true ? {statusCode: 401} : null);
		}

		req._user = user;
		next()
	}
}

/**
 * @typedef LoginObject
 * @property {string} username
 * @property {string} password
 * 
 * @param {object} options 
 * @param {"bearer"|"apiKey"|"customScheme"|"customHeader"} options.type 
 * @param {"base64"|"jwt"} options.format 
 * @param {"base64"|"jwt"} options.format 
 * @param { (token: string, cb: (err, user) => void ) => void } options.processToken 
 * @return { (req: Express.Request, res: Express.Response, next: function) => void }
 */
 const authorizationSchemaAuth = async (options) => {
	// 
	let { bearer, apiKey, customAuthorizationSchema, customHeader } = options;


	options.processToken("tok", ())
	return (req, res, next)=>{

		let b64;
		if (
			!(req.headers.authorization||'').startsWith(/^basic /i)  ||
			!(b64 = req.headers.authorization.replace(/^basic /i, '').trim())
		) {
			res.setHeader('WWW-Authenticate', 'Basic');
			return next(options.required === true ? {statusCode: 401} : null);
		}

		let [ username, password ] = Buffer.from(b64, 'base64').toString().split(':'); 
		if (!username || !password) {
			res.setHeader('WWW-Authenticate', 'Basic');
			return next(options.required === true ? {statusCode: 401} : null);
		}

		let data = authFile ? loadAuthDataFromFile(authFile) : authList, user;
		if (!(user = data.find(d=>d.username == username && d.password == password))) {
			res.setHeader('WWW-Authenticate', 'Basic');
			return next(options.required === true ? {statusCode: 401} : null);
		}

		req._user = user;
		next()
	}
}

function AuthMiddleware(){

}

module.exports = AuthMiddleware;