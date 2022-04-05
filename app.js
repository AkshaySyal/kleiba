require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()


app.use(bodyParser.json())
app.use(cookieParser())

mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true });
const userSchema = { emailID: String, username: String, password: String, refreshtoken: { type: String, default: "" }, level: { type: Number, default: 1 } }
const User = mongoose.model('User', userSchema)

app.post('/register', (req, res) => {



    User.find({ username: req.body.username }, function (err, founduser) {

        if (err) {
            res.send(err);
        }
        else if (founduser.length) {

            res.send(`User with username: ${founduser[0].username} already exist.`)
        } else {

            User.find({ emailID: req.body.emailID }, function (err1, founduser1) {
                if (err1) {
                    res.send(err1)
                } else if (founduser1.length) {

                    res.send(`User with Email ID: ${founduser1[0].emailID} already exist.`)
                } else {
                    var pass = req.body.password
                    bcrypt.hash(pass, 10, function (hasherr, hash) {

                        if (hasherr) {
                            console.log(hasherr)
                        } else {
                            const user = new User(req.body)
                            user.password = hash

                            user.save();
                            res.send('User registered. Please login.')
                        }


                    });

                }
            })

        }
    });


})

app.post('/login', (req, res) => {


    User.find({ emailID: req.body.emailID }, function (err, founduser) {
        if (err) {
            res.send(err)
        } else if (founduser.length == 0) {
            res.send(`No user with Email ID: ${req.body.emailID} exist. Please register.`)
        } else {

            bcrypt.compare(req.body.password, founduser[0].password, function (hasherr, result) {

                if (hasherr) {
                    console.log(hasherr)
                } else {


                    if (result) {

                        const payload = {
                            email: founduser[0].emailID,
                            username: founduser[0].username,
                            level: founduser[0].level
                        }

                        jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '7d' }, (refreshtokenerr, refreshtoken) => {

                            if (refreshtokenerr) {
                                console.log(refreshtokenerr)
                            } else {
                                //updating refresh token in DB

                                User.findOneAndUpdate({ emailID: founduser[0].emailID }, { refreshtoken: refreshtoken }, function (rtuerr, doc) {
                                    if (rtuerr) {
                                        console.log(rtuerr)
                                    }

                                })

                            }
                        })

                        jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '10s' }, (accesstokenerr, accesstoken) => {

                            if (accesstokenerr) {
                                res.send(accesstokenerr)
                            } else {

                                res.cookie("jwt", accesstoken, { httpOnly: true })
                                res.send('Login successful')
                            }

                        })




                    } else {

                        res.send('Wrong password entered.')
                    }
                }
            });
        }
    })
})

// Middleware

function verify(req, res, next) {
    var accesstoken = req.cookies.jwt


    if (!accesstoken) {
        return res.status(403).send('No access token')
    }

    jwt.verify(accesstoken, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            if (err.name == "TokenExpiredError") {
                res.redirect('/refresh')
            } else {
                res.send(err)
            }

        } else {

            req.user = user
            next()
        }
    })


}

app.get("/protected", verify, (req, res) => {

    res.send(req.user)
})

// Issuing new access tokens

app.get("/refresh", (req, res) => {
    var accesstoken = req.cookies.jwt

    if (!accesstoken) {
        return res.status(403).send("No access token")
    }



    jwt.verify(accesstoken, process.env.SECRET_KEY, { ignoreExpiration: true }, (err, user) => {
        if (err) {
            res.send(err)
        } else {
            // getting refresh token from DB
            var email = user.email

            User.find({ emailID: email }, function (err1, founduser) {
                if (err1) {
                    res.send(err1)
                }

                var refreshtoken = founduser[0].refreshtoken

                // Verifying refresh token

                jwt.verify(refreshtoken, process.env.SECRET_KEY, (refreshtokenerr, user1) => {
                    if (refreshtokenerr) {
                        if (refreshtokenerr.name == "TokenExpiredError") {
                            res.send("Refresh token expired. Please login again.")
                        } else {
                            res.send(refreshtokenerr)
                        }

                    }

                    // Refresh token verified. Now issuing new access token

                    const payload = {
                        email: founduser[0].emailID,
                        username: founduser[0].username,
                        level: founduser[0].level
                    }

                    jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '10s' }, (accesstokenerr, newaccesstoken) => {

                        if (accesstokenerr) {
                            res.send(accesstokenerr)
                        } else {

                            console.log("Sending refreshed access token")

                            res.cookie("jwt", newaccesstoken, { httpOnly: true })
                            res.redirect('/protected')
                        }

                    })


                })
            })

        }
    })


})





app.listen(process.env.PORT || 3000, () => {
    console.log('Server has started...')
})