const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const morgan = require('morgan');

const sslCertificate = require('get-ssl-certificate');
const CryptoJS = require('crypto-js');
const { generateKeyPair } = require('crypto');

app.set('view engine','ejs')

app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
morgan.token('body', function(req, res) { return JSON.stringify( req.body ) })
app.use(morgan(':method :url :status :res[content-length] - :response-time ms :body'));

// get routes
app.get('/', (req, res) => {
	res.redirect('/certi');
});

app.get('/certi', (req, res) => {
	sslCertificate.get('google.com').then( function (certificate) {
		// issuers and infoAccess not working object Prototype null
		const included = [ 'valid_from', 'valid_to',
			 'fingerprint' , 'fingerprint256', 'serialNumber', 'pemEncoded'];
		let arr = {};
		for( let i of Object.keys(certificate) ) {
			if( included.includes(i) ) {
				if( typeof(i) === "object" ) arr[i] = (JSON.stringify(certificate[i]));
				else arr[i] = certificate[i]
			}
		}
		// console.log(arr);
		res.render('home', { elements:  arr, title: 'google.com'});
	});
});

app.get('/ende', (req, res) => {
	res.render('ende', { plainText: '', key: '', cipherText: '', plainText1: '', key1: '', cipherText1: ''});
});

app.get('/hash', (req, res) => {
	res.render('hash', { message: '', hash: ''});
});

app.get('/keypairs', (req, res) => {
	let result = generateKeyPair('rsa', {
		modulusLength: 4096,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem',
			
		},
		privateKeyEncoding: {
			type: 'pkcs8',
			format: 'pem',
			cipher: 'aes-256-cbc',
			passphrase: 'top secret'
		}
	}, (err, publicKey, privateKey) => {
		console.log(err);
		res.render('key', { privateKey: privateKey, publicKey: publicKey});
	});

	console.log(result);
});

// post routes
app.post('/certi', (req, res) => {
	const body = req.body;
	
	sslCertificate.get(body.site)
		.then( certificate => {
			const included = [ 'valid_from', 'valid_to',
				'fingerprint' , 'fingerprint256', 'serialNumber', 'pemEncoded'];
			let arr = {};
			for( let i of Object.keys(certificate) ) {
				if( included.includes(i) ) {
					if( typeof(i) === "object" ) arr[i] = (JSON.stringify(certificate[i]));
					else arr[i] = certificate[i]
				}
			}
			// console.log(arr);
			res.render('home', { elements:  arr, title: body.site});
		}).catch( error => {
			console.log(err);
			res.status(400).end();
		});

});

app.post('/encrypt', (req, res) => {
	const body = req.body;
	let cipherText = CryptoJS.AES.encrypt(body.en_txt, body.key).toString();
	res.render('ende', { plainText: body.en_txt, key: body.key, cipherText: cipherText, plainText1: '', key1: '', cipherText1: ''});
});

app.post('/decrypt', (req, res) => {
	const body = req.body;
	let cipherText = CryptoJS.AES.decrypt(body.en_txt, body.key).toString(CryptoJS.enc.Utf8);
	res.render('ende', { plainText1: body.en_txt, key1: body.key, cipherText1: cipherText, plainText: '', key: '', cipherText: ''});
});

app.post('/hash', (req, res) => {
	const body = req.body;
	let hashed = CryptoJS.SHA256(body.message).toString();
	console.log(hashed);
	res.render('hash', { message: body.message, hash: hashed});
})

const PORT = 8000;
app.listen(PORT, () => {
	console.log(`Service running on port ${PORT}`);
})