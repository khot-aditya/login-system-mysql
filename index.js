const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const bcrypt = require("bcrypt");
const saltRounds = 10;

const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    key: "userId",
    secret: "some_very_long_secret_text",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);
const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "aditya6838",
  database: "react-node-mysql-jwt-login-system",
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});

const verifyJWT = (req, res, next) => {
  const token = req.headers["x-access-token"];

  if (!token) res.send("need a token");
  else {
    jwt.verify(token, "json_web_token_long_secret", (err, decoded) => {
      if (err) res.json({ auth: false, message: "failed to authenticate" });
      else {
        require.userId = decoded.id;
        next();
      }
    });
  }
};
app.get("/isUserAuth", verifyJWT, (req, res) => {
  res.send("Authenticated");
});

app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  db.query(
    "SELECT * FROM users WHERE username = ?",
    username,
    (err, result) => {
      if (err) res.send(err);

      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (error, response) => {
          if (response) {
            const id = result[0].id;

            const token = jwt.sign({ id }, "json_web_token_long_secret", {
              expiresIn: 300,
            });

            req.session.user = result;
            res.json({ auth: true, token: token, result: result });
          } else {
            res.json({ auth: false, message: "Wrong username or password." });
          }
        });
      } else {
        res.json({ auth: false, message: "User not found." });
      }
    }
  );
});

app.post("/register", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  bcrypt.hash(password, saltRounds, function (error, hash) {
    if (error) console.log(error);
    // --------
    db.query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hash],
      (err, result) => {
        console.log(err);
      }
    );
  });
});

app.listen(3001, () => {
  console.log("listening on http://localhost:3001");
});
