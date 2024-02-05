if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

// import
const express = require("express")
const app = express()
const mysql = require('mysql')
const passport = require('passport')
const path = require('path')
const bcrypt = require('bcrypt')
const flash = require('express-flash')
const session = require('express-session')
const LocalStrategy = require('passport-local').Strategy
const nodemailer = require('nodemailer')
const jwt = require('jsonwebtoken')

// make connection
const connection = mysql.createConnection({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE
})

app.set('view-engine', 'ejs')

app.use(express.static('public'))
app.use(express.static(path.join(__dirname, 'public'))) // get files

app.use(express.static(path.join(__dirname, 'jsForm'))) // get files

app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(express.urlencoded({ extended: false }))

// email verify START

function emailVerify(userEmail) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.AUTH_USER,
            pass: process.env.AUTH_PASS
        }
    })

    const token = jwt.sign({ email: userEmail }, process.env.TOKEN_SECRET, { expiresIn: '20m' })
    // JEV - Janari Email Verification 
    const mailConfig = {
        from: process.env.BOT_EMAIL,
        to: userEmail,
        subject: 'Verify your email address',
        html: `
        <p>Verification for LINK account. Link expires in 20 minutes.<p>
        <p>Please verify you account by clicking on this <a href='https://pollux-tsjp.onrender.com/verify/${token}'>link</a></p><br>

        <p>Thank you!</p>
        `
    }

    transporter.sendMail(mailConfig, (err, res) => {
        if (err) { console.log(err) }
        console.log('email sent')
        console.log(res)
    })
}
// email verify END


// // // // // // // // // // // // // // // // // // //
// // // // // // // // // // // // // // // // // // //

const verifyCall = async (email, password, done) => {
    try {
        // yhendus andmebaas, kus email on v6rdeline x-ga
        connection.query('SELECT * FROM userinfo WHERE email = ?', [email], async (err, res) => {
            // kui pikkus pole null
            if (res.length) {
                let user = {
                    id: res[0].id,
                    name: res[0].name,
                    email: res[0].email,
                    password: res[0].password,
                    verified: res[0].verified
                }
                // kui salas6nad on v6rdsed, muidu 2ra lase sisse logida
                if (await bcrypt.compare(password, user.password) && user.verified == 1) {
                        return done(null, user)
                } else {
                    return done(null, false, { message: 'wrong password or account not verified' })
                }
            } else {
                return done(null, false, { message: 'user not found' })
            }
        })
    } catch(err) {
        return done(err)
    }
}
const strategy = new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password'
}, verifyCall)
passport.use(strategy)

passport.serializeUser((user, done) => {
    console.log('inside serialize')
    done(null, user.id)
})

passport.deserializeUser((userId, done) => {
    console.log('inside deserialize ' + userId)
    connection.query('SELECT * FROM userinfo WHERE id = ?', [userId], (err, res) => {
        done(null, res[0])
    })
})

// // // // // // // // // // // // // // // // // // //
// // // // // // // // // // // // // // // // // // //

app.get('/verify/:token', (req, res) => {
    const {token} = req.params
    jwt.verify(token, process.env.TOKEN_SECRET, (err, decoded) => {
        if (err) {
            console.log(err)
            res.send('Email verification failed!')
        } else {
            const userEmail = decoded.email

            connection.query('UPDATE userinfo SET verified = TRUE WHERE email = ?', [userEmail], (error, result) => {
                if (error) { console.log(error) } 
                else {
                    console.log('User marked as verified')
                    res.send('Success! You can now login.')
                }
            });

        }
    })
})

app.get('/', (req, res) => {
    res.render('frontPage.ejs')
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/login',
    failureFlash: true
}))

app.post('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) {
            return next(err)
        }
        res.redirect('/login')
    })
})

app.get('/home', checkAuthenticated, (req, res) => {
    res.render('home.ejs', { name: req.user.name })
})

app.get('/register', checkNotAuthenticated, (req, res) => {
    const messageText = req.flash('message')
    res.render('register.ejs', { message: messageText })
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
        try {
            console.log('database connected')
            const cryptedPas = await bcrypt.hash(req.body.password, 10)
            let sql = `INSERT INTO userinfo (name, email, password, verified) VALUES (?, ?, ?, ?)`
            let values = [req.body.name, req.body.email, cryptedPas, false]

            connection.query('SELECT * FROM userinfo WHERE name = ?', [req.body.name], (err, result) => {
                if (result.length < 1) {
                    connection.query(sql, values, (err, dat) => {
                        if (err) { console.log(err) }
                        req.flash('message', 'verification email has been sent!')
                        emailVerify(req.body.email)
                        console.log('User data inserted')
                        res.redirect('/register')
                        // connection.end()
                    })
                } else { 
                    req.flash('message', 'user already exists')
                    res.redirect('/register')
                 }
            })
        } catch(err) {
            req.flash('message', 'error')
        }

})

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
       return res.redirect('/home')
    }
    next()
}

let mainP = process.env.PORT || 3000

app.listen(mainP)