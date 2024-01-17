const fs = require('fs');
const { isJSON, getObjectSerializedField } = require("./common");
const { Request, Response, NextFunction } = require('express');

/**
 * @param {object} authSpec
 * @param {string} authSpec.credentialsFile
 * @param {object[]} authSpec.credentialsList
 * @param {object} options 
 * @param {boolean} options.required 
 * @param {boolean} options.userField 
 * @param {boolean} options.passwordField 
 */
 let BasicAuthAuthenticator = function(authSpec, options = {}) {
	//
	this.opts = options || {};
	this.opts.userField = this.opts.userField || 'email'
	this.opts.passwordField = this.opts.passwordField || 'password'

	// this.authSpec = authSpec;
	let { credentialsFile, credentialsList } = authSpec
	if (!credentialsList){
		if (credentialsFile && !fs.existsSync(credentialsFile)){
			throw new Error(`specified credentialsFile does not exist`);
		} else if (!credentialsFile && fs.existsSync(process.cwd()+'/basic.auth.json')){
			credentialsFile = process.cwd()+'/basic.auth.json'
		} else if (!credentialsFile && fs.existsSync(process.cwd()+'/settings/basic.auth.json')){
			credentialsFile = process.cwd()+'/settings/basic.auth.json'
		} else if (!credentialsFile) {
			throw new Error(`neither credentialsList nor credentialsFile specified, at least one has to be secified`);
		}

		credentialsList = fs.readFileSync(credentialsFile, 'utf8');
		try { 
			credentialsList = JSON.parse(credentialsList);
		} catch (error){ 
			throw new Error(`Basic auth credentials file "${credentialsFile}" not a valid JSON`) 
		}
		if ( !(credentialsList instanceof Array) ) {
			throw new Error(`Basic auth credentials file "${credentialsFile}" expected to ba an array`) 
		}
	}

	this.credentialsList = credentialsList;
	
	for (var entry of this.credentialsList){
		let valid = this.isWellFormatted(entry);
		if (valid instanceof Error) throw valid;
	}
}

BasicAuthAuthenticator.prototype.isWellFormatted = function(authEntry){
	if ( !(authEntry && isJSON(authEntry)) ){
		return new Error(`entry must be a json object`);
	}

	let uf = getObjectSerializedField(authEntry, this.opts.userField);
	let pf = getObjectSerializedField(authEntry, this.opts.passwordField);

	if ( !(uf && typeof uf === 'string') ){
		return new Error(`entry should have string field "${this.opts.userField}"`)
	}
	if ( !(pf && typeof pf === 'string') ){
		return new Error(`entry should have string field "${this.opts.passwordField}"`)
	}

	authEntry._id = authEntry._id || authEntry.id;
	delete authEntry.id;
	
	if ( !(authEntry._id && typeof authEntry._id === 'string') ){
		return new Error(`entry must have a string Id`);
	}
	
	return true;
}

/**
 * 
 * @param {Request} req 
 * @param {Response} res 
 * @param {NextFunction} next 
 * @returns {void}
 */
BasicAuthAuthenticator.prototype.auth = function (req, res, next){	

	let authTokenReceived = '';
	if ( /^basic /i.test(req.headers.authorization||'') ) {
		authTokenReceived = req.headers.authorization.replace(/^basic /i, '').trim();
	}
	let [ user, pass ] = Buffer.from(authTokenReceived, 'base64').toString().split(':'); 

	if ( !(authTokenReceived && user && pass) ) {
		if (this.opts.required === true){
			res.setHeader('WWW-Authenticate', 'Basic');
			return next({
				statusCode: 401, 
				body: new Error(`Either missing "Authorization" header or it is ` +
					`not formatted as "Basic <Base64-encoded('username:password')>"`)
			});
		}
		return next();
	}

	user = this.credentialsList.find(u => {
		return getObjectSerializedField(u, this.opts.userField) == user &&
			getObjectSerializedField(u, this.opts.passwordField) == pass ;
	})

	if ( !user ) {
		res.setHeader('WWW-Authenticate', 'Basic');
		return next({
			statusCode: 401, 
			body: new Error(`[BasicAuthFailed] wrong username and/or password`)
		});
	}

	req._token = authTokenReceived;
	req._user = user;
	next()
}

module.exports = BasicAuthAuthenticator