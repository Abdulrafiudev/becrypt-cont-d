import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"
import session from "express-session"
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv"

const app = express();
const port = 3000;
let salt_rounds = 10
env.config()

const db = new pg.Client({
  user: "postgres",
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

app.get(`/secrets`, (req, res) => {
  console.log(req.user)
  if (req.isAuthenticated){
    res.render(`secrets.ejs`)
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

// managing sessions when loggin in
passport.use(new Strategy(async function verify(username, password, cb){
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

passport.serializeUser((user, cb) => {
  cb(null, user)

})
passport.deserializeUser((user, cb) => {
  cb(null, user)
 
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
