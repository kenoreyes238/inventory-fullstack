const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001; 

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
})

const corsOptions = {
   origin: '*', 
   credentials: true,  
   'access-control-allow-credentials': true,
   optionSuccessStatus: 200,
}

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use(async (req, res, next) => {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (err) {
    console.log(err)
    if (req.db) req.db.release();
    throw err;
  }
});

app.post('/register', async function (req, res) {
  try {
    const { password, email } = req.body;
    // const isAdmin = userIsAdmin ? 1 : 0
    const hashedPassword = await bcrypt.hash(password, 10);
    const [user] = await req.db.query(
      `INSERT INTO users (email, password)
      VALUES (:email, :hashedPassword);`,
      { username, hashedPassword, userIsAdmin: isAdmin });
    const jwtEncodedUser = jwt.sign(
      { userId: email.insertId, ...req.body },
      process.env.JWT_KEY
    );
    res.json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    console.log('error', err);
    res.json({ err, success: false });
  }
});

app.post('/login', async function (req, res) {
  try {
    const { email, password: userEnteredPassword } = req.body;
    const [[user]] = await req.db.query(`SELECT * FROM user WHERE email = :email`, { email });
    if (!user) res.json('Username not found');
    const hashedPassword = `${user.password}`
    const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);
    if (passwordMatches) {
      const payload = {
        userId: user.id,
        email: user.email,
        // userIsAdmin: user.admin_flag
      }   
      const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);
      res.json({ jwt: jwtEncodedUser, success: true });
    } else {
      res.json({ err: 'Password is wrong', success: false });
    }
  } catch (err) {
    console.log('Error in /authenticate', err);
  }
});

// app.use(async function verifyJwt(req, res, next) {
//   const { authorization: authHeader } = req.headers;
//   if (!authHeader) res.json('Invalid authorization, no authorization headers');
//   const [scheme, jwtToken] = authHeader.split(' ');
//   if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');
//   try {
//     const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);
//     req.user = decodedJwtObject;
//   } catch (err) {
//     console.log(err);
//     if (
//       err.message && 
//       (err.message.toUpperCase() === 'INVALID TOKEN' || 
//       err.message.toUpperCase() === 'JWT EXPIRED')
//     ) {
//       req.status = err.status || 500;
//       req.body = err.message;
//       req.app.emit('jwt-error', err, req);
//     } else {
//       throw((err.status || 500), err.message);
//     }
//   }

//   await next();
// });

