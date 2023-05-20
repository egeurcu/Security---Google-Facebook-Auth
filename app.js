require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const app = express();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
    secret: "Our litte secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

main().catch(err => console.log(err));
async function main() {
  await mongoose.connect('mongodb://127.0.0.1:27017/userDB');
}

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
  done(null, user.id);
}); 
passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.displayName, facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.route("/")
.get((req, res) => {

    res.render("home");

});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));


app.get("/auth/google/secrets",
    passport.authenticate("google", {failureRedirect: "/login"}),
    (req, res) => {
        res.redirect("/secrets");
    }
);

app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/secrets');
});

app.route("/login")
.get((req, res) => {

    res.render("login");

})
.post((req, res) => {

    const user = new User({
        username:req.body.username,
        password:req.body.password
      })
   
    req.login(user,function(err){
   
        if (err) { 
          console.log(err);
          res.redirect("/login");
        } else {
          passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
          })          
        }
       
    });

});

app.route("/register")
.get((req, res) => {

    res.render("register");

})
.post((req, res) => {

    User.register({email: req.body.username}, req.body.password, function(err, user) {
        if (err) { 
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
          });
          
        }
       
    });
});

app.route("/submit")
.get((req, res) => {

  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }

})
.post((req, res) => {

  User.findById(req.user)
      .then(foundUser => {
        if (foundUser) {
          foundUser.secret = req.body.secret;
          return foundUser.save();
        }
        return null;
      })
      .then(() => {
        res.redirect("/secrets");
      })
      .catch(err => {
        console.log(err);
      });

});

app.route("/secrets")
.get((req, res) => {

  User.find({"secret":{$ne:null}})
    .then(function (foundUsers) {
      res.render("secrets",{usersWithSecrets:foundUsers});
      })
    .catch(function (err) {
      console.log(err);
      })

});

app.route("/logout")
.get((req,res) => {

    req.logOut((err) => {
        if (err) {
            res.send(err);
        } else {
            res.redirect("/");
        }
    });

})

app.listen(3000, (req, res) => {

    console.log("Server started on port 3000.")

});