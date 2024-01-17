const { isJSON, isURL, findTokenInHeader } = require("./common");
const {Request, Response, NextFunction } = require('express');
const jsonwebtoken = require('jsonwebtoken');
const jwktopem = require('jwk-to-pem')

const axios = require('axios');


const isJWKSObject = (o) => {
	// 
	if ( !isJSON(o) ) return new Error(`must be an object`);
	if ( ! (o.serverURL && typeof o.serverURL === 'string') ) return new Error(`field "serverURL" is required and must be string`);
	if ( ! (isURL(o.serverURL) && /^https?:\/\//.test(o.serverURL)) ) return new Error(`field "serverURL" is required and must be a valid HTTP(S) URL`);
	if ( o.kid && typeof o.kid != 'string' ) return new Error(`field "kid" must be string`);
}

/**
 * @param {object} authSpec
 * @param {string} authSpec.secret
 * @param {string} authSpec.jwks
 * @param {object} options 
 * @param {boolean} options.required 
 * @param {boolean} options.userField 
 * @param {boolean} options.passwordField 
 */
 let JWTAuthenticator = function(authSpec, options = {}){
	// 
	this.secret = authSpec && authSpec.secret || process.env.ACCESS_TOKEN_SECRET;
	this.jwks = authSpec.jwks;

	if ( this.secret && typeof this.secret !== 'string' ){
		throw new Error(`JWT auth param "secret" must be string`);
	}

	let err = this.jwks && isJWKSObject(this.jwks);
	if ( err instanceof Error ){
		err.message = `JWT auth param "jwks": ${err.message}`
		throw err;
	}

	if (!this.secret && !this.jwks) throw new Error(`Both fields "secret" and "jwks" cannot be missing`)

	this.opts = options;
}

/**
 * @returns {Promise<string>} 
 */
JWTAuthenticator.prototype.fetchSecret = function(){
	return !this.jwks ? 
		Promise.resolve(this.secret) :
		axios.get(this.jwks.serverURL).then( ({data}) => {
			let keys = data instanceof Array ? data : data.keys;
			if ( !(keys instanceof Array) ) throw new Error(`JWKS server response expected to be an array of of JWKS of an object with field "keys" returning that array`);
			
			let key = keys.find((e,i) => this.jwks.kid ? e.kid == this.jwks.kid : i==0 );
			return jwktopem(key);
		})
}

/**
 * 
 * @param {Request} req 
 * @param {Response} res 
 * @param {NextFunction} next 
 * @returns {void}
 */
JWTAuthenticator.prototype.auth = function(req, res, next){
	let token = findTokenInHeader({ method: "Bearer" }, req);

	if (token instanceof Error) {
		return next (this.opts.required !== true ? null : {statusCode: 401, body: token});
	}

	this.fetchSecret()
		.then(secret => {
			// console.log('secret:', secret);
			return jsonwebtoken.verify(token, secret)
		})
		.then(user => {
			req._token = token;
			req._user = user;
			next();
		}).catch(err => {
			// console.log(err);
			if (err instanceof axios.AxiosError && err.response){
				next({
					statusCode: 401, 
					body: new Error(`could either not retrieve JWKS from server or verify JWT: HTTP ${err.response.status}${err.response.message ? `: ${err.response.message}` : ''}`)
				});
			} else {
				next({
					statusCode: 401, 
					body: new Error(`could either not retrieve JWKS from server or verify JWT: ${err.code ? `[${err.code}] `:''}${err.message}`)
				});
			}
		});
}

module.exports = JWTAuthenticator;