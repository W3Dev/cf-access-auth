const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const fetch = require('node-fetch')


const AUTH_DOMAIN = 'https://w3dev.cloudflareaccess.com'


class CfAccessAuth {
    
    static AUTH_DOMAIN;
    static AUDIENCE_TAG;
    static CERTS_URL;
    static KID;

    static JwksClient;

    constructor({
        AuthDomain,
        AudienceTag
    }){
        this.AUTH_DOMAIN = AuthDomain
        this.CERTS_URL = `${AuthDomain}/cdn-cgi/access/certs`
        this.AUDIENCE_TAG = AudienceTag
        this.setKID()
        this.JwksClient = jwksClient({
            jwksUri: this.CERTS_URL,
        });
    }

    setKID(cb){
  
        return fetch(this.CERTS_URL).then(r=>r.json()).then(d=>{
            try{
                let kid = d.public_cert.kid;
                this.KID = kid;
                console.log("Initialization Complete")
                if(cb) cb(null, kid)

            }catch(e){
                this.KID = null
                console.error("Error Initializing cf-access-auth")
                if(cb) cb(e, null)
            }
        })
        
    }

    Authenticate(cookieValue, cb){
        if(this.KID){
            const token = cookieValue
            this.JwksClient.getSigningKey(this.KID, (err, key)=>{
                if(err) return cb(err, null)
                const signingKey = key.getPublicKey();
                // console.log("SigningKey:", signingKey)
                try {
                    let UserData = jwt.verify(token, signingKey, {
                        audience: this.AUDIENCE_TAG,
                    });
                    if(cb) cb(null, {UserData})

                } catch (e) {

                    if(cb) cb(e, null)

                }
                
            })

        }else{
            this.setKID((err, d)=>{
                if(!err) return this.Authenticate(cookieValue, cb)
            })
        }
    }
}


new CfAccessAuth({AuthDomain:AUTH_DOMAIN, AudienceTag:''}).Authenticate('asas', (err, data)=>{
    if(err) return console.error('Error:', err.message)
    console.log("Auth Data:", data)
})

module.exports = {
    CfAccessAuth
}