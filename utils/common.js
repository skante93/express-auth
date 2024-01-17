
const { Request } = require("express");

const isJSON = (o) => !!o && (
	Object.getPrototypeOf(o) == null || 
	o.constructor.prototype === ({}).constructor.prototype
)

const isURL = (url) => {
	try {new URL(url); return true } catch(e){ return false }
}


/**
 * @typedef {object} BearerAuthSpec
 * @property { "Bearer" } method
 * 
 * @typedef {object} OAuth2AuthSpec
 * @property { "OAuth2" } method
 *  
 * @typedef {object} SchemeAuthSpec
 * @property { "Scheme" } method
 * @property { string } scheme
 *  
 * @typedef {object} APIKeyAuthSpec
 * @property { "ApiKey" } method
 *  
 * @typedef {object} HeaderAuthSpec
 * @property { "Header" } method
 * @property { string } header
 *  
 * @param { BearerAuthSpec | OAuth2AuthSpec | SchemeAuthSpec | APIKeyAuthSpec | HeaderAuthSpec } authSpec
 * @param { Request } req 
 */
 const findTokenInHeader = (authSpec, req) => {
	if (!isJSON(authSpec)) return new Error(`param "authSpec" required and must be JSON object`)
	if (!(authSpec.method && typeof authSpec.method == "string")){
		return new Error(`in param "authSpec", field "method" required and must be string`)
	}
	if (!req) return new Error(`param "req" required`)

	let method = authSpec.method.toLocaleLowerCase();

	switch(method){
		case 'bearer':
		// case 'oauth2':
		case 'scheme':
			let s = method == 'scheme' ? authSpec.scheme : 'bearer';

			if ( !req.headers.authorization ) {
				return new Error(`missing "Authorization" header`);
			}
			let [scheme, token] = req.headers.authorization.trim().split(' ');
			if (scheme.toLowerCase() != s || !token) {
				return new Error(`no token found, is the "Authorization" header shaped like this: "Bearer <JWT>"?`)
			}
			return token
		case 'apikey':
		case 'header':
			/**@type {string} */
			let h = method == "apikey" ? 'x-api-key' : authSpec.header;
			if (!h || h.includes(' ')) return new Error(`for method "${method}", expected field "name" in authSpec with non-empty and space-free value`)
			return req.headers[h] || new Error(`missing header "${h.toUpperCase()}"`)			
		default:
			return new Error(`method ${method} no supported`)
	}
}

/**
 * 
 * @param {*} obj 
 * @param {string | string[] } fields 
 */
const getObjectSerializedField = (obj, fields) =>{
	if (obj == null) return null;

	fields = fields instanceof Array ? fields : fields.split('.').filter(e=>e);
	let f0 = fields.shift();

	return f0 == null ? obj : getObjectSerializedField(obj [ f0 ], fields) 
}

const loadAuthBase = (authSpec, options) => {
	// 
	if (!isJSON(authSpec)) return new Error(`param "authSpec" required and must be JSON object`)
	if (!(authSpec.method && typeof authSpec.method == "string")){
		return new Error(`in param "authSpec", field "method" required and must be string`)
	}
}

module.exports = {
	isJSON, isURL, findTokenInHeader, getObjectSerializedField
}