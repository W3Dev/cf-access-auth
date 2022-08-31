# Cloudflare Access Authenticator 

Get User Email in your application protected via Cloudflare access and validate the user login.

## How to use
1. Create a New Application on Cloudflare Teams Dashboard.
2. Configure your application to be protected with Cloudflare access
3. Visit your Protected Application 
4. You will get the Auth Domain now which looks like `https://XXXX.cloudflareaccess.com`

<br>

## Express JS Example
```javascript

const cookieParser = require('cookie-parser')

const CFAccessAuth = require('cf-access-auth')
const cfAuthenticator = new CFAccessAuth({
    AuthDomain:'https://XXXX.cloudflareaccess.com',
})

const protectedRoute = (req, res, next) => {
    const cfCookieValue = req.cookies['CF_Authorization'];
    cfAuthenticator.Authenticate(cfCookieValue, (err, data)=>{
        
        if(err) {
            console.error('Cloudflare Access Error:', err)
            return res.status(403).send("Login Required")
        }

        if(data && data.UserData && data.UserData.email){
            req.UserData = data.UserData
            next();
        }
    })
}

// Private Route
app.get("/private", protectedRoute, (req, res)=>{
    const loggedInUser = req.UserData.email;
    res.send(`Private Route accessed by ${loggedInUser}`)
})

// Public Route
app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
```