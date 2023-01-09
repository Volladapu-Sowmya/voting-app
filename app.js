//importing all important modules
const express = require("express");
const app = express();
const csrf = require("tiny-csrf");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const flash = require("connect-flash");
const LocalStratergy = require("passport-local");
const saltRounds = 10;
//models
const { ModelAdmin, model_election, model_questions, model_option, model_voter } = require("./models");
//using the view engine ejs
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
//using all the modules mentioned above
app.set("views", path.join(__dirname, "views"));
app.use(flash());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("This is some secret string"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));

//used for creating a session
app.use(
  session({
    secret: "my-super-secret-key-2837428907583420",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use((request, response, next) => {
  response.locals.messages = request.flash();
  next();
});

app.use(passport.initialize());
app.use(passport.session());

//voter authentication
// passport.use(
//   "voter_local",
//   new LocalStratergy(
//     {
//       usernameField: "voter_id",
//       passwordField: "password",
//     },
//     function (username, password, done) {
//       model_voter.findOne({ where: { voter_id: username } })
//         .then(async (user) => {
//           const results = await bcrypt.compare(password, user.password);
//           if (results) {
//             return done(null, user);
//           } else {
//             return done(null, false, { message: "Please Enter Correct Password" });
//           }
//         })
//         .catch((error) => {
//           return done(null, false, { message: "Please Enter Correct Voter ID" });
//         });
//     }
//   )
// );

//admin authentication
passport.use(
  "admin_local",
  new LocalStratergy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (username, password, done) {
      ModelAdmin.findOne({ where: { email: username } })
        .then(async (user) => {
          const results = await bcrypt.compare(password, user.password);
          if (results) {
            return done(null, user);
          } else {
            done(null, false, { message: "Please Enter Correct Password" });
          }
        })
        .catch((error) => {
          console.log(error);
          return done(null, false, { message: "Please Enter Correct Email Address" });
        });
    }
  )
);



passport.serializeUser((user, done) => {
  done(null, { id: user.id, role: user.role });
});
passport.deserializeUser((id, done) => {
  if (id.role === "admin") {
    ModelAdmin.findByPk(id.id)
      .then((user1) => {
        done(null, user1);
      })
      .catch((error1) => {
        done(error1, null);
      });
  } else if (id.role === "voter") {
    model_voter.findByPk(id.id)
      .then((user1) => {
        done(null, user1);
      })
      .catch((error1) => {
        done(error1, null);
      });
  }
});



//first (or) main Page
app.get("/", async function(req, res){
  if (req.user) {
    console.log(req.user);
    if (req.user.role === "admin") {
      return res.redirect("/elections");
    } else if (req.user.role === "voter") {
      req.logout((err1) => {
        if (err1) {
          return res.json(err1);
        }
        res.redirect("/");
      });
    }
  } else {
    res.render("index", {
      title: "Online Voting Platform",
      csrfToken: req.csrfToken(),
    });
  }
});

//main page for elections to perform admin operations
app.get("/elections",
  connectEnsureLogin.ensureLoggedIn(),async function (request1, response1) {
    if (request1.user.role === "admin") {
      let loggedInUser = request1.user.first_name + " " + request1.user.last_name;
      try {
        const elections = await model_election.getelections(request1.user.id);
        if (request1.accepts("html")) {
          response1.render("elections", {
            title: "Online E-Voting Platform",userName: loggedInUser,elections,
          });
        } else {
          return response1.json({elections,});
        }
      } catch (error3) {
        console.log(error3);
        return response1.status(422).json(error3);
      }
    } else if (request1.user.role === "voter") {
      return response1.redirect("/");
    }
  }
);

//SignUp
app.get("/signup", function(request2, response2) {
  response2.render("signup", {title: "create an admin account",csrfToken: request2.csrfToken(),});
});

//page used to create admin account
app.post("/admin", async function(req, res) {
  if (!req.body.firstName) {
    req.flash("error", "First Name is Missing !");
    return res.redirect("/signup");
  }
  if (!req.body.email) {
    req.flash("error", "Email ID is Missing !");
    return res.redirect("/signup");
  }
  if (!req.body.password) {
    req.flash("error", "Password is Missing !");
    return res.redirect("/signup"); 
  }
  if (req.body.password.length < 8) {
    req.flash("error", "Weak Password !! enter atleast 8 characters");
    return res.redirect("/signup");
  }
  const hashedPassword1 = await bcrypt.hash(req.body.password, saltRounds);
  try {
    const user = await ModelAdmin.create_a_new_admin({
      first_name: req.body.firstName,
      last_name: req.body.lastName,
      email: req.body.email,
      password: hashedPassword1,
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
        res.redirect("/");
      } else {
        res.redirect("/elections");
      }
    });
  } catch (error12) {
    req.flash("error", "Email Id not available please use other one !");
    return res.redirect("/signup");
  }
});

//admin login
app.get("/login", async function (request3, response3){
  if (request3.user) {
    return response3.redirect("/elections");
  }
  response3.render("login_page", {title: "Login to your account",csrfToken: request3.csrfToken(),});
});

//voter login
// app.get("/e/:url/voter", async function (request4, response4) {
//   response4.render("login_voter", {title: "Login in as Voter",url: request4.params.url,
//     csrfToken: request4.csrfToken(),
//   });
// });

//starting the session for admin
app.post("/session",
  passport.authenticate("admin_local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (request1, response1) => {
    response1.redirect("/elections");
  }
);


//New Election Being Created
app.post("/elections",connectEnsureLogin.ensureLoggedIn(),
  async function (request11, response11) {
    if (request11.user.role === "admin") {
      if (request11.body.electionName.length < 5) {
        request11.flash("error", "Ensure that election name length is greater than or equal to 5 characters!");
        return response11.redirect("/elections/create");
      }
      if (request11.body.url.length < 3) {
        request11.flash("error", "Ensure that length of url is greater than or equal to 3 characters");
        return response11.redirect("/elections/create");
      }
      if (
        request11.body.url.includes(" ") ||
        request11.body.url.includes("\t") ||
        request11.body.url.includes("\n")
      ) {
        request11.flash("error", "url must not contaion escape characters or spaces");
        return response11.redirect("/elections/create");
      }
      try {
        await model_election.addAnElection({
          election_name: request11.body.electionName,
          url: request11.body.url,
          admin_id: request11.user.id,
        });
        return response11.redirect("/elections");
      } catch (error) {
        request11.flash("error", "URL not available use any other one");
        return response11.redirect("/elections/create");
      }
    } else if (request11.user.role === "voter") {
      return response11.redirect("/");
    }
  }
);


//creating New election
app.get("/elections/create",
  connectEnsureLogin.ensureLoggedIn(),async function(request9, response9) {
    if (request9.user.role === "admin") {
      return response9.render("new_election_page", {
        title: "create an election",
        csrfToken: request9.csrfToken(),
      });
    } else if (request9.user.role === "voter") {
      return response9.redirect("/");
    }
  }
);

//signout route
app.get("/signout", function (request6, response6, next){
  request6.logout((err1) => {
    if (err1) {
      return next(err1);
    }
    response6.redirect("/");
  });
});


module.exports = app;