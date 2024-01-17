

const chai = require('chai');
const chaiHttp = require('chai-http');

const fs = require('fs')
const jsonwebtoken = require('jsonwebtoken');
const express = require('express'); 
const should = chai.should();
const expect = chai.expect;



chai.use(chaiHttp);
const ExpressAuth = require('../index');
const { 
	buildGenericExpressApp, 
	buildGenericExpressAppWithJWKSEndpoint,
	cleanUpBasicAuth, 
	makeBaiscSettingsFile, 
	BASIC_AUTH_LIST 
} = require('./utils');



describe('Express Auth', ()=>{
	describe('Basic Authenticator', ()=>{
		before(cleanUpBasicAuth)
		after(cleanUpBasicAuth)

		describe('Middleware parameters checks', () => {
			
			it('should fail because insufficient parameters to Express Auth', done =>{
				let fn = () => ExpressAuth({ method: "basic" });
				expect(fn).to.throw('neither credentialsList nor credentialsFile specified');
				done()
			})

			it('should not fail to launch because "credentialsFile" specified (1)', done =>{
				makeBaiscSettingsFile(3);
				let fn = () => ExpressAuth({ method: "basic", credentialsFile: 'test-custom-path-authlist.json' });
				
				expect(fn).to.not.throw();
				let obj = fn();
				console.log(obj.credentialsList);
				
				cleanUpBasicAuth(done)
			})

			it('should not fail to launch because "credentialsFile" specified (2)', done =>{
				makeBaiscSettingsFile(1)
				let fn = () => ExpressAuth({ method: "basic" });
				expect(fn).to.not.throw();
				cleanUpBasicAuth(done)
			})

			it('should not fail to launch because "credentialsFile" specified (3)', done =>{
				makeBaiscSettingsFile(2)
				let fn = () => ExpressAuth({ method: "basic" });
				expect(fn).to.not.throw();
				cleanUpBasicAuth(done)
			})
		})

		describe('Middleware Auth checks', () => {
			/**
			 * @type {express.Express}
			 */
			let server ;
			before(done =>{
				makeBaiscSettingsFile(1);
				server = buildGenericExpressApp({ method: "basic" }, {required:true});
				done();
			});
			after(cleanUpBasicAuth)

			it('should be able to access unprotected url path', done => {
				chai.request(server)
					.get('/foo')
					.end((err, res) => {
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						res.body.response.should.be.eql("What's up foo?!");
						done();
					});
			});

			it('should not be able to access protected url path without basic auth header', done => {
				chai.request(server)
					.get('/bar')
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});

			it('should not be able to access protected url path without right credientials (1: no scheme)', done => {
				chai.request(server)
					.get('/bar')
					.set('Authorization', `abc`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});
			
			it('should not be able to access protected url path without right credientials (2: not base64-encoded)', done => {
				let {email: u, password: p} = BASIC_AUTH_LIST[0];
				chai.request(server)
					.get('/bar')
					.set('Authorization', `Basic ${u + ':' + p}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});

			it('should work with correct header (1)', done => {
				let {email: u, password: p} = BASIC_AUTH_LIST[0];
				chai.request(server)
					.get('/bar')
					.set('Authorization', `Basic ${Buffer.from(u + ':' + p).toString('base64')}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						// res.body.response.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});
			it('should work with correct header (2)', done => {
				let {email: u, password: p} = BASIC_AUTH_LIST[1];
				chai.request(server)
					.get('/bar')
					.set('Authorization', `Basic ${Buffer.from(u + ':' + p).toString('base64')}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						// res.body.response.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});
		})

		describe('Settings auth file works?', () => {
			/**
			 * @type {express.Express}
			 */
			 let server ;
			before(done =>{
				cleanUpBasicAuth();
				makeBaiscSettingsFile(2);

				server = buildGenericExpressApp({ method: "basic" }, {required:true});
				done();
			});
			after(cleanUpBasicAuth)

			it('should not be able to access protected url path without right credientials', done => {
				chai.request(server)
					.get('/bar')
					.set('Authorization', `abc`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});

			it('should work with correct header (1)', done => {
				let {email: u, password: p} = BASIC_AUTH_LIST[0];
				chai.request(server)
					.get('/bar')
					.set('Authorization', `Basic ${Buffer.from(u + ':' + p).toString('base64')}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						// res.body.response.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});
		})

		describe('credentialsList option works?', () => {
			/**
			 * @type {express.Express}
			 */
			 let server ;
			before(done =>{
				cleanUpBasicAuth();

				server = buildGenericExpressApp({ method: "basic", credentialsList: BASIC_AUTH_LIST }, {required:true});
				done();
			});

			it('should not be able to access protected url path without right credientials', done => {
				chai.request(server)
					.get('/bar')
					.set('Authorization', `abc`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});
			it('should work with correct header (1)', done => {
				let {email: u, password: p} = BASIC_AUTH_LIST[0];
				chai.request(server)
					.get('/bar')
					.set('Authorization', `Basic ${Buffer.from(u + ':' + p).toString('base64')}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						// res.body.response.should.be.eql('Either missing "Authorization" header or it is not formatted as "Basic <Base64-encoded(\'username:password\')>"');
						done();
					});
			});
		})
	})

	describe('Bearer Authenticator', ()=>{
		
		describe('Middleware parameters checks', () => {
			
			it('should fail because insufficient parameters to Express Auth', done =>{
				let fn = () => ExpressAuth({ method: "bearer" });
				expect(fn).to.throw('Both fields "secret" and "jwks" cannot be missing');
				done()
			})

			it('should fail because empty secret', done =>{
				let fn = () => ExpressAuth({ method: "bearer", secret: '' });
				expect(fn).to.throw('Both fields "secret" and "jwks" cannot be missing');
				done()
			})

			it('should fail because jwks is not an object', done =>{
				let fn = () => ExpressAuth({ method: "bearer", jwks: 'wrong' });
				expect(fn).to.throw('JWT auth param "jwks": must be an object');
				done()
			})

			it('should fail because jwks.serverURL was not specified', done =>{
				let fn = () => ExpressAuth({ method: "bearer", jwks: {} });
				expect(fn).to.throw('JWT auth param "jwks": field "serverURL" is required and must be string');
				done()
			})

			it('should fail because jwks.serverURL was not valid url', done =>{
				let fn = () => ExpressAuth({ method: "bearer", jwks: { serverURL: 'xyz' } });
				expect(fn).to.throw('JWT auth param "jwks": field "serverURL" is required and must be a valid HTTP(S) URL');
				done()
			})

			it('should fail because jwks.serverURL was not valid HTTP(s) url', done =>{
				let fn = () => ExpressAuth({ method: "bearer", jwks: { serverURL: 'proto://xyz' } });
				expect(fn).to.throw('JWT auth param "jwks": field "serverURL" is required and must be a valid HTTP(S) URL');
				done()
			})

			it('should fail because jwks.kid was not string', done =>{
				let fn = () => ExpressAuth({ method: "bearer", jwks: { serverURL: 'https://xyz', kid: new Date() } });
				expect(fn).to.throw('JWT auth param "jwks": field "kid" must be string');
				done()
			})

			it('should work since proper now', done =>{
				let fn = () => ExpressAuth({ method: "bearer", jwks: { serverURL: 'https://xyz' } });
				expect(fn).to.not.throw();
				done()
			})
		});

		describe('Testing "secret" option', ()=>{
			/**
			 * @type {express.Express}
			 */
			 let server ;
			before(done => {
				server = buildGenericExpressApp({ method: "bearer", secret: "stealthy as a ninja!" }, {required:true});
				done();
			})

			it('should fail because no auth header', done =>{
				chai.request(server)
					.get('/bar')
					// .set('Authorization', `abc`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('missing "Authorization" header');
						done();
					});
			})

			it('should fail because no bearer in auth header', done =>{
				chai.request(server)
					.get('/bar')
					.set('Authorization', `abc`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('no token found, is the "Authorization" header shaped like this: "Bearer <JWT>"?');
						done();
					});
			})

			it('should fail because token is no legit jwt', done =>{
				// let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], 'wrong secret', { algorithm: 'HS256' })
				chai.request(server)
					.get('/bar')
					.set('Authorization', `bearer randomstuff`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: jwt malformed');
						done();
					});
			})

			it('should fail because token generated with wrong secret', done =>{
				let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], 'wrong secret', { algorithm: 'HS256' })
				chai.request(server)
					.get('/bar')
					.set('Authorization', `bearer ${token}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
						done();
					});
			})

			it('should work because token generated with right secret', done =>{
				let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], 'stealthy as a ninja!', { algorithm: 'HS256' })
				chai.request(server)
					.get('/bar')
					.set('Authorization', `bearer ${token}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						// res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
						done();
					});
			})
		})

		describe('Testing "secret" option via environment variable', ()=>{
			/**
			 * @type {express.Express}
			 */
			 let server ;
			before(done => {
				process.env.ACCESS_TOKEN_SECRET = "stealthy as a ninja!";

				server = buildGenericExpressApp({ method: "bearer" }, {required:true});
				done();
			})

			it('should fail because token generated with wrong secret', done =>{
				let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], 'wrong secret', { algorithm: 'HS256' })
				chai.request(server)
					.get('/bar')
					.set('Authorization', `bearer ${token}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(401);
						res.body.should.be.a('object');
						res.body.message.should.be.a('string');
						res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
						done();
					});
			})

			it('should work because token generated with right secret', done =>{
				let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], 'stealthy as a ninja!', { algorithm: 'HS256' })
				chai.request(server)
					.get('/bar')
					.set('Authorization', `bearer ${token}`)
					.end((err, res) => {
						// console.log("body", typeof res.body, res.body);
						res.should.have.status(200);
						res.body.should.be.a('object');
						res.body.response.should.be.a('string');
						// res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
						done();
					});
			})
		})

		describe('Testing "jwks" option', ()=>{
			
			after(done=>{
				let k = process.cwd()+'/keys.json';
				if (fs.existsSync(k)) fs.unlink(k, done);
			})
			describe('Without "kid" field', ()=>{
				let server, srv, certs;

				before(done => {
					let opts = { 
						method: "bearer", 
						jwks: {
							serverURL: 'http://localhost:3000/jwks'
						}
					}
					buildGenericExpressAppWithJWKSEndpoint(opts, {required:true}).then(result=>{						
						certs = result.certs;
						server = result.server;
						srv = result.jwkServer;
						srv.listen(3000, done);
					});
				})

				after(done => srv.close(done));

				it('should fail because token generated with 2nd jwk', done =>{
					let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], certs.set2, { algorithm: 'RS256' })
					chai.request(server)
						.get('/bar')
						.set('Authorization', `bearer ${token}`)
						.end((err, res) => {
							// console.log("body", typeof res.body, res.body);
							res.should.have.status(401);
							res.body.should.be.a('object');
							res.body.message.should.be.a('string');
							res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
							done();
						});
				})

				it('should work because token generated with 1st jwk', done =>{
					let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], certs.set1, { algorithm: 'RS256' })
					chai.request(server)
						.get('/bar')
						.set('Authorization', `bearer ${token}`)
						.end((err, res) => {
							// console.log("body", typeof res.body, res.body);
							res.should.have.status(200);
							res.body.should.be.a('object');
							res.body.response.should.be.a('string');
							// res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
							done();
						});
				})
			});

			describe('With "kid" field', ()=>{
				let server, srv, certs;

				before(done => {
					let opts = { 
						method: "bearer", 
						jwks: {
							serverURL: 'http://localhost:3000/jwks',
							kid: "set2"
						}
					}
					buildGenericExpressAppWithJWKSEndpoint(opts, {required:true}).then(result=>{						
						certs = result.certs;
						server = result.server;
						srv = result.jwkServer;
						srv.listen(3000, done);
					});
				})

				after(done => srv.close(done));

				it('should fail because token generated with 1st jwk', done =>{
					let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], certs.set1, { algorithm: 'RS256' })
					chai.request(server)
						.get('/bar')
						.set('Authorization', `bearer ${token}`)
						.end((err, res) => {
							// console.log("body", typeof res.body, res.body);
							res.should.have.status(401);
							res.body.should.be.a('object');
							res.body.message.should.be.a('string');
							res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
							done();
						});
				})

				it('should work because token generated with 2nd jwk', done =>{
					let token = jsonwebtoken.sign(BASIC_AUTH_LIST[0], certs.set2, { algorithm: 'RS256' })
					chai.request(server)
						.get('/bar')
						.set('Authorization', `bearer ${token}`)
						.end((err, res) => {
							// console.log("body", typeof res.body, res.body);
							res.should.have.status(200);
							res.body.should.be.a('object');
							res.body.response.should.be.a('string');
							// res.body.message.should.be.eql('could either not retrieve JWKS from server or verify JWT: invalid signature');
							done();
						});
				})
			})
		})
	})
})