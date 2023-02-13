require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET_TEXT,
//   encryptedFields: ["password"],
// });
// const saltRounds = 10;

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })
  .post((req, res) => {
    User.register(
      { username: req.body.username },
      req.body.password,
      (err, user) => {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, () => {
            res.redirect("/secrets");
          });
        }
      }
    );
    // bcrypt.hash(req.body.password, saltRounds, (err, hashedPassword) => {
    //   if (!err) {
    //     const user = new User({
    //       email: req.body.username,
    //       password: hashedPassword,
    //     });
    //     user.save((err) => {
    //       if (!err) {
    //         res.render("secrets");
    //       } else {
    //         console.log(err);
    //       }
    //     });
    //   } else {
    //     res.render(err);
    //   }
    // });
  });

app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post((req, res) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    });
    // const username = req.body.username;
    // const password = req.body.password;
    // User.findOne({ email: username }, (err, foundUser) => {
    //   if (!err) {
    //     if (foundUser) {
    //       bcrypt.compare(password, foundUser.password, (err, result) => {
    //         if (!err) {
    //           if (result === true) {
    //             res.render("secrets");
    //           } else {
    //             res.send("Wrong Password");
    //           }
    //         } else {
    //           console.log(err);
    //         }
    //       });
    //     } else {
    //       res.send("User not found");
    //     }
    //   } else {
    //     console.log(err);
    //   }
    // });
  });

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUsers) => {
    if (!err) {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    } else {
      console.log(err);
    }
  });
});

app
  .route("/submit")
  .get((req, res) => {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post((req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, foundUser) => {
      if (!err) {
        if (foundUser) {
          foundUser.secret = submittedSecret;
          foundUser.save((err) => {
            res.redirect("/secrets");
          });
        }
      } else {
        console.log(err);
      }
    });
  });

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});
app.listen(3000, () => {
  console.log("Server started at port 3000");
});
