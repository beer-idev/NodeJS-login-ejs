//ระบบ Login on NodeJS
require('dotenv').config()
const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const {body, validationResult} = require('express-validator');

// Create express
const app = express();
app.use(express.urlencoded({extended: false}))

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000 //1hr
}))

//Delaring Custom Middleware
const ifNotLoggedIn = (req, res, next) =>{
     if(!req.session.isLoggedIn){
         return res.render('login-regist');
     }
     next();
}

const ifLoggedIn = (req, res, next) => {
    if(req.session.isLoggedIn){
        return res.redirect('/home');
    }
    next();
}
//root page
app.get('/', ifNotLoggedIn, (req, res, next) => {
    dbConnection.execute("select username from accounts where id = ?", [req.session.userID])
    .then(([rows]) => {
        res.render('home', {
            name: rows[0].username
        })
    })
}) 

//Register Page
app.post('/register', ifLoggedIn, [
    //check use email
    body('user_email', 'Invalid Email Address').isEmail().custom((value) => {
        return dbConnection.execute('select email from accounts where email = ?', [value])
        .then(([rows]) => {
            //check email in database
            if(rows.length > 0){
                return Promise.reject('This email already in use!');
            }
            return true;
        })
    }),
    
    body('user_name', 'username is empty!').trim().not().isEmpty(),
    body('user_pass', 'The password must be of minimun length 6 characters').trim().isLength({min:6}),
],
    (req, res, next) => {
        const validation_result = validationResult(req);
        const {user_name, user_email, user_pass} = req.body;

        if(validation_result.isEmpty()){
            bcrypt.hash(user_pass, 12).then((hash_pass) => {
                dbConnection.execute("INSERT INTO accounts (`username`, `email`, `password`) VALUES (?, ?, ?)", [user_name, user_email, hash_pass])
                .then(result => {
                    res.send('Your account has been creacted successfully, Now you can <a href="/">Login</a>');
                }).catch(err => {
                    if(err) throw err;
                })
            }).catch(err => {
                if(err) throw err;
            })
        } else {
            let allErrors = validation_result.errors.map((error) => {
                return error.msg;
            })
            res.render('login-regist', {
                register_error: allErrors,
                old_data: req.body
            })
        }
    })

//Login Page
app.post('/', ifLoggedIn, [
    body('user_email').custom((value) => {
        return dbConnection.execute("SELECT email FROM accounts WHERE email = ?", [value])
        .then(([rows]) => {
            if(rows.length == 1){
                return true;
            }
            return Promise.reject('Invalid Email Address!')
        });
    }),
    body('user_pass', 'Password is empty').trim().not().isEmpty(),
], (req,res) => { 
    const validdation_result = validationResult(req);
    const {user_pass, user_email} = req.body;
    if(validdation_result.isEmpty()){
        dbConnection.execute("SELECT * FROM accounts WHERE email = ?", [user_email])
        .then(([rows]) => {
            bcrypt.compare(user_pass,rows[0].password).then(compare_result => {
                if(compare_result === true) {
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;
                    req.session.usernames = rows[0].usernames;
                    res.redirect('/');
                }else{
                    res.render('login-regist', {
                        login_error: ['Invalid Password']
                    })
                }
            }).catch(err => {
                if(err) throw err;
            })
        }).catch(err => {
            if(err) throw err;
        })
    }else{
        let allErrors = validdation_result.errors.map((error) => {
            return error.msg;
        })
        res.render('login-regist', {
            login_error: allErrors
        })
    }
})

//Log out
app.get('/logout', (req, res) => {
    //session destory
    req.session = null;
    res.redirect('/');
})
//Page 404
app.use('/', (req, res) => {
    res.status(404).send('<h1>404 Page not found!</h1>')
})

app.listen(process.env.PORT,() => console.log(`Server is running on ${process.env.PORT}`))