
const axios = require('axios'), fs = require('fs');
const jsonwebtoken = require('jsonwebtoken');
const debug = require('debug');

const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'x-auth-cookie';

// [Begin Utils]

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

const isJSON = (o) => !!o && (
	Object.getPrototypeOf(o) == null || 
	o.constructor.prototype === ({}).constructor.prototype
)

const isURL = (url) => {
	try {new URL(url); return true } catch(e){ return false }
}

/**
 * 
 * @param {string} str 
 */
 const objectToInterpolatedString = (shape, obj) => {
	let str = shape, interpolations = [...shape.matchAll(/\$\{[^\}]*\}/g)];
	if (interpolations.length==0) return shape;

	let getObjectSubpath = (o, p)=>{
		let res = o;
		for (var i of p.split('.')){
			if ( !isJSON(res) ) res = null;
			if (res == null) break;
			res = res[i];
		}
		if (res == null) {
			debug('EXPRESS-AUTH:Interpolation:warning')(`path "${p}"'s interpolation is actually null`)
		}
		if ( res instanceof Array || isJSON(res) ) {
			debug('EXPRESS-AUTH:Interpolation:warning')(`path "${p}"'s interpolation is actually an ${res instanceof Array ? 'array' : 'object'}`)
		}
		return res;
	}
	for (var segment of interpolations){
		let match = segment[0].substring(2, segment[0].length-1).trim().replace(/^%?\.?/,'');
		str = str.replace(segment[0], getObjectSubpath(obj, match));
	}
	debug('EXPRESS-AUTH:Interpolation:info')(`Interpolated string = <em>${str}</em>`);
	return str;

	// let txt = '{"email":"${%.profile.email}","password":"${%.ghost.password}"}', 
	//     obj = { profile: { email:"user@domain.com" }, secret: "Only known to me 8)" };
	// // Produces
	// // ``` (Env DEBUG=EXPRESS-AUTH:Interpolation:info)
	// //   EXPRESS-AUTH:Interpolation:info Interpolated string = <em>{"email":"user@domain.com","password":"null"}</em> +0ms
	// // {"email":"user@domain.com","password":"null"}
	// // ```
	// console.log(objectToInterpolatedString(txt, obj)) 
}

/**
 * @typedef CustomMethods
 * @property {"AuthorizationScheme"|"CustomHeader"} type
 * @property {string} name
 * 
 * @param {"Bearer"|"ApiKey"|"OAuth2"|CustomMethods} spec
 * @param {object} spec.type
 * @param {Express.Request} req 
 */
const findTokenInHeader = (spec, req) => {
	if (!spec) return new Error(`param "spec" required`)
	if (!req) return new Error(`param "req" required`)

	let token = '';

	if (typeof spec === 'string'){
		switch(spec.toLocaleLowerCase()){
			case 'bearer':
			case 'oauth2':
				if ( !req.headers.authorization ) return new Error(`missing header "Authorization"`);
				let t = req.headers.authorization.split(' ');
				if ( (t[0]||'').toLocaleLowerCase().trim() != "bearer" ) {
					return new Error(`no token found, is the "Authorization" header shaped like this: "Bearer <JWT>"?`)
				}
				token = t[1];
				break;
			case 'apikey':
				if ( !(token = req.headers['x-api-key']) ) return new Error(`missing header "X-API-KEY"`)
				break;
			default:
				return new Error(`method "${spec}" not supported`);
		}
	} else if (!isJSON(spec)){
		return new Error(`param "spec" must either be a string or an object`)
	} else {
		if ( !spec.type || typeof spec.type !== 'string' || ['authorizationscheme', 'customheader'].indexOf(spec.type.toLocaleLowerCase())<0 ) {
			return new Error(`param "spec.type" must be an enumerated string taking values in: ["AuthorizationScheme", "CustomHeader"]`)
		}
		if (!spec.name || typeof spec.name !== 'string') {
			return new Error(`param "spec.name" is required and must be string`)
		} else if (spec.name.includes(' ')){
			return new Error(`param "spec.name" cannot include any spaces`)
		}

		switch(spec.type.toLocaleLowerCase()){
			case 'authorizationscheme':
				if ( !req.headers.authorization ) return new Error(`missing header "Authorization"`);
				let t = req.headers.authorization.split(' ');
				if ( (t[0]||'').toLocaleLowerCase().trim() != spec.name.toLocaleLowerCase() ) {
					return new Error(`no token found, is the "Authorization" header shaped like this: "${spec.name} <Token>"?`)
				}
				token = t[1];
				break;
			case 'customheader':
				if ( !(token = req.headers[spec.name]) ) return new Error(`missing header "${spec.name}"`)
				break;
			default:
				return new Error(`method "${spec}" not supported`);
		}
	}
	return token;
}

/**
 * @typedef {object} BasicAuthRecord
 * @property {string} username 
 * @property {string} password
 *  
 * @param {BasicAuthRecord[]} authList 
 * @param {object} options 
 * @param {boolean} options.required 
 * @returns 
 */
let BasicAuthAuthenticator = function(authList, options = {}) {
	//
	let checkParam = (arr) => {
		if ( !(arr instanceof Array) ) return new Error('expected array');
		arr = arr.filter(e=>e);
		if ( arr.length == 0 ) return new Error('expected non-empty array');
		for (var entry of arr){
			if ( !(entry && isJSON(entry) && entry.username && typeof entry.username === 'string') ){
				return new Error(`at index "${arr.indexOf(entry)}", field "username" is a required string`)
			}
			if ( !(entry && isJSON(entry) && entry.password && typeof entry.password === 'string') ){
				return new Error(`at index "${arr.indexOf(entry)}", field "password" is a required string`)
			}
		}
	} 
	if (typeof authList === 'string'){
		if ( !fs.existsSync(authList) ) return new Error(`Basic auth record file "${authList}" not found`);

		let data = fs.readFileSync(authList, 'utf8');
		try { authList = JSON.parse(data) } catch (error){ return new Error(`Basic auth record file "${authList}" not a valid JSON`) }
	}

	let valid = checkParam(authList);
	if (valid instanceof Error) throw valid;

	this.authList = authList;
	this.opts = options || {};
}

/**
 * 
 * @param {Express.Request} req 
 * @param {Express.Response} res 
 * @param {(err: Error) => void} next 
 * @returns {void}
 */
BasicAuthAuthenticator.prototype.auth = function (req, res, next){	
	let b64, user;

	let authTokenReceived = (req.headers.authorization||'').startsWith(/^basic /i) &&
	                        (b64 = req.headers.authorization.replace(/^basic /i, '').trim());
	if (!authTokenReceived) {
		res.setHeader('WWW-Authenticate', 'Basic');
		return next(this.opts.required !== true? null : {
			statusCode: 401, 
			body: new Error(`Either missing "Authorization" header or it is ` +
			    `not formatted as "Basic <Base64-encoded 'username:password'>"`
			)
		});
	}
	
	let [ username, password ] = Buffer.from(b64, 'base64').toString().split(':'); 
	if (!username || !password) {
		res.setHeader('WWW-Authenticate', 'Basic');
		return next({
			statusCode: 401, body: new Error(`Could not find "username" and/or "password" in "Athorization" header`)
		});
	}

	if ( !(user = this.authList.find(u => u.username == username && u.password == password)) ) {
		res.setHeader('WWW-Authenticate', 'Basic');
		return next({
			statusCode: 401, 
			body: new Error(`[BasicAuthFailed] wrong username and/or password`)
		});
	}

	req._token = b64;
	req._user = user;
	next()
}

/**
 * 
 * @param {object} validation 
 * @param {string} validation.secret 
 * @param {object} validation.jwks 
 * @param {object} options 
 * @param {boolean} options.required 
 */
let JWTAuthenticator = function(validation, options = {}){
	// 
	this.secret = validation && validation.secret || process.env.ACCESS_TOKEN_SECRET;
	this.jwks = validation.jwks;

	if ( this.secret && typeof this.secret !== 'string' ){
		throw new Error(`JWT auth secret must be string`);
	}

	if ( this.jwks && (typeof this.jwks !== 'string' || !isURL(jwks)) ){
		throw new Error(`JWT auth param JWKS must be valid URL`);	
	}

	if (!this.secret && !this.jwks) throw new Error(`Both fields "secret" and "jwks" cannot be missing`)

	this.opts = options;
}

/**
 * @returns {Promise<string>} 
 */
JWTAuthenticator.prototype.fetchSecret = function(){
	if (!this.jwks) return Promise.resolve(this.secret);
	return axios.get(this.jwks).then( ({data}) => data.keys[0] )
}

/**
 * 
 * @param {Express.Request} req 
 * @param {Express.Response} res 
 * @param {(err: Error) => void} next 
 * @returns {void}
 */
JWTAuthenticator.prototype.auth = function(req, res, next){
	let token = findTokenInHeader("Bearer", req);

	if (token instanceof Error) {
		return next (this.opts.required !== true ? null : {code: 401, body: token});
	}

	this.fetchSecret()
		.then(secret => jsonwebtoken.verify(token, secret))
		.then(user => {
			req._token = token;
			req._user = user;
			next();
		}).catch(err){
			if (err instanceof axios.AxiosError && err.response){
				next(new Error(`could not retrieve JWKS server (HTTP ${err.response.status})`))				
			} else {
				next(new Error(`could not retrieve JWKS server (${err.code ? `[${err.code}] `:''}${err.message})`));	
			}
		}
}


// [/End Utils]

// [Begin JS Doc types]

/**
 * @typedef BALoginObject
 * @property {string} username
 * @property {string} password
 */

/**
 * 
 * 
 * @typedef {object} HttpBackend
 * @property {"http"} type 
 * @property {string} url
 * @property {object} headers
 * @property {string} bodyTemplate
 * @property {boolean} rejectUnauthorized
 * 
 * @typedef {object} MongoBackend
 * @property {"mongo"} type 
 * @property {string} url
 * @property {string} username
 * @property {string} password
 * @property {string} db
 * @property {string} collection
 * 
 * @typedef {HttpBackend|MongoBackend} AuthBackend 
 *
 * @typedef {object} AuthSpecObject
 * @property {"Bearer"|"ApiKey"|"CustomScheme"|"CustomHeader"|"OAuth2"} type
 * @property {"Base64"|"JWT"} tokenFormat
 * @property { (token: string) => Promise<reshapedToken: object> } reshapeToken
 * @property { (reshapedToken: object) => Promise<user: object> | AuthBackend } backend
 *  
 * @typedef APIKeyAuthObject
 * @extends AuthSpecObject
 * @property {"ApiKey"} type
 * 
 */
// [END JS Doc types]


function main(spec){

	if (!(isJSON(spec) && spec.type && typeof spec.type === 'string')){
		throw new Error(`Express Auth expects an object as arugment with a required string field "type"`);
	} else if (["basic", "apikey", "bearer", "oauth2", "authorizationscheme", "customheader"].indexOf(spec.type.toLocaleLowerCase())<0){

	}
	
	let authenticator;

	switch(spec.type){
		case 'basic':
			authenticator = new BasicAuthAuthenticator(spec, {});
		case 'bearer':
			authenticator = new JWTAuthenticator(spec, {});
		default:
			new Error(`not yet implemented`);
	}

	return authenticator.auth.bind(authenticator);
}

module.exports = main;