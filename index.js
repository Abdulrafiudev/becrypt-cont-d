import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"
import session from "express-session"
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv"
import GoogleStrategy from "passport-google-oauth2"

const app = express();
const port = 3000;
let salt_rounds = 10
env.config()

const db = new pg.Client({
  user: process.env.DB_USER,
  host: "localhost",
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.PORT,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge: 1000 * 60 * 60 * 24
  }
}))

// This must come directly after your session creation 
app.use(passport.initialize())
app.use(passport.session())



app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get(`/secrets`, async (req, res) => {
 
  if (req.isAuthenticated){
    try{
      let response = await db.query(`SELECT secret_text FROM users WHERE users.usernaame = $1`, [req.user.usernaame])
      let result = response.rows[0].secret_text
      
      if (result){
        res.render(`secrets.ejs`, {secrets: result})
      }
      else{
        
        res.render(`secrets.ejs`, {secrets: `Jack Bauer is my hero.`})
      }
      
    }
    catch(error){
      console.error(error)
  }


  }
  else{
    res.render(`login.ejs`)
  }
})

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(`/auth/google/secrets`, passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}))

app.get(`/submit`, (req, res) => {
  if (req.isAuthenticated()){
    res.render((`submit.ejs`))
  }
  else{
    res.redirect(`/login`)
  }
 
})


app.post(`/submit`, async (req, res) => {
  let secret_text = req.body.secret
  try{

    await db.query(`UPDATE users SET secret_text = $1 WHERE users.usernaame = $2`, [secret_text, req.user.usernaame])
    res.redirect(`/secrets`)
  
  }
  catch(error){
    console.error(error)
  }

})

app.get(`/logout`, (req, res) => {
  req.logout((error) => {
    if (error){
      console.error(`error logging out`)
    }
    else{
      res.redirect(`/`)
    }
  })
})




// logic to register on the web app

app.post("/register", async (req, res) => {
  let user_name = req.body.username
  let password = req.body.password

  try{
    let response = await db.query('SELECT * FROM users WHERE users.usernaame = $1', [user_name])
    let result = response.rows

    if (result.length > 0){
      console.log(`User already exist. Kindly go to the login page`)
    }
    else {
      // password hashing
      bcrypt.hash(password, salt_rounds, async (err, hash) => {
        if(err){
          console.error(`Error hashing passwords`)
        }
        else{
          console.log(hash)
          let response = await db.query('INSERT INTO users (usernaame, password ) VALUES ($1, $2) RETURNING *', [user_name, hash])
          let user = response.rows[0]
          req.login(user, (error) => {
            console.log(user)
            res.redirect(`/secrets`)
          })

        }
      })
      
   
    }
  }
  catch(error){
     console.error(`Failed to make request`)
  }
});


app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);


// managing sessions when loggin in and logic to login back into the web app
passport.use(`local`, new Strategy(async function verify(username, password, cb){
  console.log(username)
  try{
    // Comparing the passwords

    let response = await db.query('SELECT * FROM users WHERE users.usernaame = $1', [username])
    let user = response.rows[0]
    console.log(user)

    if(response.rows.length > 0){
      let stored_password = user.password
      console.log(stored_password)
      

      bcrypt.compare(password, stored_password, (err, result) => {
        if(err){
          return cb(err)
        }
        else{
          console.log(result)
          //passed password check
          if (result){
            console.log(user)
            return cb(null, user)
          }
          //Did not pass password check
          else{
            //This means there is no error but they also wasnt any user found
            return cb(null, false)
            
          }
        }
      })
      
     
    }
    else{
      return cb(`Kindly register as a user`)
      
    }

  }
  catch(err){
    return cb(err)
  }
}))

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL:"http://www.googleapis.com/oauth2/v3/userinfo"

}, async function(accessToken, refreshToken, profile, cb){
  console.log(profile)
  try{
    let response = await db.query(`SELECT * FROM users WHERE usernaame = $1`, [profile.email])
    let result = response.rows
    console.log(result)
    if (result.length === 0){
      let new_user = await db.query(`INSERT INTO users(usernaame, password) VALUES($1, $2) RETURNING *`, [profile.email, "google"])
      cb(null, new_user.rows[0])
    }
    else{
      cb(null, result[0])
    }
  }
  catch(error){
    cb(error)
  }
}))

passport.serializeUser((user, cb) => {
  cb(null, user)

})
passport.deserializeUser((user, cb) => {
  cb(null, user)
 
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
