// https://www.npmjs.com/package/crypto-js
const hmacSha256 = require('crypto-js/hmac-sha256');

//https://www.npmjs.com/package/base64url
const base64url = require('base64url');

//https://www.npmjs.com/package/node-rsa
const nodeRSA = require('node-rsa');



////// Base64 //////

// funkcja kodująca za pomocą base64
function base64UrlEncode(item) {
    return base64url.encode(JSON.stringify(item));
};

// funkcja dekodująca base64
function base64UrlDecode(item) {
    // TODO:1 funkcja powinna zwracać wynik dekodowania
    return base64url.decode(JSON.stringify(item)).toString();
};

// sprawdzenie poprawności działania funkcji kodującej i dekodującej base64
const testBase64 = "Test Base64"
const testBase64Encoded = base64UrlEncode(testBase64);
const testBase64Decoded = base64UrlDecode(testBase64Encoded).toString();

console.log("Base64 Test: ", testBase64 === testBase64Decoded, testBase64Encoded, testBase64Decoded);



////// RSA512 //////

// funckcja tworząca klucz publiczny i prywatny
function generateRSAPairKeys() {
    const key = new nodeRSA({ b: 512 });
    const publicDer = key.exportKey('pkcs1-public'); // TODO:2 użycie funkcji zwracajacej klucz publiczny
    const privateDer = key.exportKey('pkcs1-private');
    console.log(publicDer, privateDer)

    return { private: privateDer, public: publicDer }   
}


const keys = generateRSAPairKeys();

const privateKey = new nodeRSA();
privateKey.importKey(keys.private);

const publicKey = new nodeRSA();
publicKey.importKey(keys.public);


// sprawdzenie poprawności działania funkcji kodującej i dekodującej RSA512
const testRSA512 = "Test RSA512"
// stworzenie podpisu za pomocą klucza prywatnego (tylko klucz prywatny jest w stanie wygenerować podpis, 
// który jest możliwy do zdekodowania za pomocą klucza publicznego - co za tym idzie nie ma możliwości ukrycia danych za pomocą podpisu)
const testRSA512Encrypted = privateKey.encryptPrivate(testRSA512, 'base64'); 

const testRSA512Decrypted = publicKey.decryptPublic(testRSA512Encrypted, 'utf8');

console.log("RSA512 Test: ", testRSA512 === testRSA512Decrypted);

////// JWT //////

// funkcja tworząca token
// key: klucz dla hmacSha256 lub klucz prywatny dla RSA256
function createJWT(algorithm, payload, key) {

    if (algorithm === "HS256" || algorithm === "RSA512") {

        // stworzenie header'a
        const header = {
            typ: 'JWT',
            alg: algorithm
        };

        // stworzenie tokena 
        const jwtToken = base64UrlEncode(header) + '.' + base64UrlEncode(payload);

        var signature = "";

        if (algorithm === "HS256") {
            // stworzenie sygnatury za pomocą hmacSha256
            signature = base64url.encode(hmacSha256(jwtToken, key).toString());
        }
        else {
            const privateKey = new nodeRSA();
            privateKey.importKey(key);
            // stworzenie sygnatury za pomocą RSA512
            signature = privateKey.encryptPrivate(jwtToken, 'base64');
        }

        // zwrócenie tokenu wraz z sygnatura 
        const jwtSignedToken = jwtToken + '.' + signature;

        return jwtSignedToken;
    }
    else {
        throw Error("Only HS256 and RSA256 are available");
    }
}

// funkcja dekodujaca header i payload
function decodeJWT(token) {

    const tokenData = token.split(".")

    const headerEncoded = tokenData[0];
    const payloadEncoded = tokenData[1];

    const headerDecoded = base64UrlDecode(headerEncoded);
    const payloadDecoded = base64UrlDecode(payloadEncoded); // TODO:4 użycie funkcji dekodującej base64

    return { header: headerDecoded, payload: payloadDecoded }

}

// funkcja weryfikująca token na podstawie klucza dla hmacSha256 lub klucz publicznego dla RSA256
function verifyJWT(jwtSignedToken, key) {
    const jwtSignedTokenData = jwtSignedToken.split(".")

    const headerEncoded = jwtSignedTokenData[0];
    const payloadEncoded = jwtSignedTokenData[1];
    const signatureEncoded = jwtSignedTokenData[2];

    const headerDecoded = base64UrlDecode(headerEncoded);

    if (headerDecoded.alg === "HS256") {
        const jwtToken = base64UrlEncode(header) + "." + base64UrlEncode(payload) + "." + base64UrlEncode(signatureEncoded);
        decodeJWT(jwtToken)
        // TODO:5 sprawdzenie czy sygnatura zgadza się z zakodowanym połączonym header'em i payload'em - 
        // nie da się zdekodować sygnatury trzeba ponownie zakodowac dane i porównać obie sygantury
        return false; 
    }

    const payloadDecoded = base64UrlDecode(payloadEncoded);

    // TODO:6 Stworzenia klucza publicznego RSA z danych wejsciowych do funkcji 
    key = new nodeRSA();
    const publicKey = key.importKey('pkcs1-public');

    // TODO:7 zdekodowanie sygantury
    const signatureDecoded = base64UrlDecode(signatureEncoded);

    const signatureDecodedData = signatureDecoded.split(".")
    const headerFromDecodingSignature = base64UrlDecode(signatureDecodedData[0])
    const payloadFromDecodingSignature = base64UrlDecode(signatureDecodedData[1])

    return JSON.stringify(headerFromDecodingSignature) ===  JSON.stringify(headerDecoded) && 
            JSON.stringify(payloadFromDecodingSignature) === JSON.stringify(payloadDecoded);
}



// sprawdzenie poprawności działania JWT
const testKeyForHS256 = "testKeyForHS256"
const testPayload = { userId: 2, userName: "Test23" };

const tokenHS256 = createJWT("HS256", testPayload, testKeyForHS256);
console.log("JWT HS256 verify: ", verifyJWT(tokenHS256, testKeyForHS256));


const tokenRSA512 = createJWT("RSA512", testPayload, keys.private);
console.log("JWT RSA512 verify: ", verifyJWT(tokenRSA512, keys.public));


// wyswietlenie zdekodowanego header'a i payload'u
console.log("JWT RSA512 decoded: ", decodeJWT(tokenRSA512));
console.log("JWT HS256 decoded: ", decodeJWT(tokenHS256));
