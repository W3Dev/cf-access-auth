const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const fetch = require('node-fetch')

module.exports = class CFAccessAuth {

    static AUTH_DOMAIN;
    static AUDIENCE_TAG;
    static CERTS_URL;
    static KID;
    
    static JwksClient;

    constructor({
        AuthDomain,
        AudienceTag = ''
    }) {
        this.AUTH_DOMAIN = AuthDomain
        this.CERTS_URL = `${AuthDomain}/cdn-cgi/access/certs`
        this.AUDIENCE_TAG = AudienceTag
        this.setKID()
        this.JwksClient = jwksClient({
            jwksUri: this.CERTS_URL,
        });
    }

    setKID(cb) {

        return fetch(this.CERTS_URL).then(r => r.json()).then(d => {
            try {
                let kid = d.public_cert.kid;
                this.KID = kid;
                if (cb) cb(null, kid)

            } catch (e) {
                this.KID = null
                console.error("Error Initializing cf-access-auth")
                console.error("If you think this is an issue with the library, oepn a issue here: https://github.com/W3Dev/cf-access-auth/issues")
                if (cb) cb(e, null)
            }
        })

    }

    /**
     * Authenticate the Request using Cookie value
     * @param {string} cookieValue - Cloudflare Authencation Cookie Value, 'CF_Authorization'
     * @param {requestCallback} callback - The callback that handles the response.
     */
    Authenticate(cookieValue, callback) {
        if (this.KID) {
            const token = cookieValue
            this.JwksClient.getSigningKey(this.KID, (err, key) => {
                if (err) return callback(err, null)
                const signingKey = key.getPublicKey();
                // console.log("SigningKey:", signingKey)
                try {
                    let UserData = jwt.verify(token, signingKey, {
                        audience: this.AUDIENCE_TAG,
                    });
                    if (callback) callback(null, { UserData })

                } catch (e) {

                    if (callback) callback(e, null)

                }

            })

        } else {
            this.setKID((err, d) => {
                if (!err) return this.Authenticate(cookieValue, cb)
            })
        }
    }
}

/**
 * @typedef {Object} AuthenticatedUser
 * @param {string} email - Email of the Logged in User
 * @param {number} exp - Unix timestamp for expiration of the session 
 * @param {string} iss - Cloudflare Authencation Domain 
 * @param {string} type - Defaults to 'app'
 * @param {string} identity_nonce - Unique identifier for the Logged in User
 * @param {string} country - ISO-2 Country Code
 * @param {Array.<string>} aud - Aud Tag by Cloudflare
 * 
 * */

/**
 * @callback requestCallback 
 * @param {Error} err Exception object
 * @param {AuthenticatedUser} data.UserData Authenticated User Data
*/