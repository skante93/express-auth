const BasicAuthAuthenticator = require('./utils/basic');
const JWTAuthenticator = require('./utils/jwt');
const { isJSON } = require('./utils/common');

const SUPPORTED_METHODS = ["basic", "apikey", "bearer", "oauth2", "scheme", "header"]
function ExpressAuth(authSpec, options = {}){

	if (!(isJSON(authSpec) && authSpec.method && typeof authSpec.method === 'string')){
		throw new Error(`Express Auth expects an object as arugment with a required string field "method"`);
	} else if (SUPPORTED_METHODS.indexOf(authSpec.method.toLocaleLowerCase()) < 0){
		throw new Error(`Unexpected value "${authSpec.method}, Field method must be one of the following: "${SUPPORTED_METHODS.join('", "')}"`);
	}
	
	let authenticator;

	switch(authSpec.method){
		case 'basic':
			authenticator = new BasicAuthAuthenticator(authSpec, options);
			break;
		case 'bearer':
			authenticator = new JWTAuthenticator(authSpec, options);
			break;
		default:
			new Error(`Authenticator "${authSpec.method}"not yet implemented`);
	}

	return authenticator.auth.bind(authenticator);
}

module.exports = ExpressAuth;