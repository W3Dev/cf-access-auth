
const express = require('express')
const app = express()
const port = process.env.port || 3000
const cookieParser = require('cookie-parser')

const CFAccessAuth = require('cf-access-auth')
const cfAuthenticator = new CFAccessAuth({
    AuthDomain:'https://XXXX.cloudflareaccess.com',
})

app.use(cookieParser())

// Middleware to protect the Express Route
const protectedRoute = (req, res, next) => {
    const cfCookieValue = req.cookies['CF_Authorization'];
    cfAuthenticator.Authenticate(cfCookieValue, (err, data)=>{
        
        if(err) {
            console.error('Cloudflare Access Error:', err)
            return res.status(403).send("Login Required")
        }

        // const isLoginExpired = Math.floor(+new Date()/1000) >= data.UserData?.exp;
        // console.log({isLoginExpired})
    
        if(data && data.UserData && data.UserData.email){
            req.UserData = data.UserData
            next();
        }
    })
}

app.get("/private", protectedRoute, (req, res)=>[
    res.send('Private Route via Cloudflare Access')
])

// Public Route
app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
