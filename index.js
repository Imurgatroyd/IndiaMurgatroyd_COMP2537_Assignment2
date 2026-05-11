require('dotenv').config();

//Loading in installed packages
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 12;

app.set('view engine', 'ejs');

//MongoDB connection
const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true`;

const { MongoClient } = require('mongodb');
const client = new MongoClient(mongoUri, {
    serverApi: {
        version: '1',
        strict: true,
        deprecationErrors: true,
    }
});
let userCollection;

//Conects to the Atlas database and gets the user's collection
async function connectDB() {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    userCollection = db.collection('users');
    console.log('Connected to mongoDB');
}
connectDB();


//Allows server to read form data from signup/login
app.use(express.urlencoded({ extended: false }));

//Serves the images
app.use(express.static('public'));


//Setting up sessions
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    store: MongoStore.create({
        mongoUrl: mongoUri,
        collectionName: 'sessions',
        secret: process.env.MONGODB_SESSION_SECRET,
        autoRemove: 'native'
    }),
    cookie: { maxAge: 60 * 60 * 1000 }
}));


//Checking if a user is logged in
function isLoggedIn(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    next();
}


//Checking if user is admin
function isAdmin(req, res, next) {
    if (req.session.user.user_type !== 'admin') {
        return res.status(403).send(`
            <h1>403 - Not Authorized</h1>
            <p>You do not have permission to view this page</p>
            <a href="/">Go Home</a>
            `);
    }

    next();
}


//Home page route
app.get('/', (req, res) => {

    //Change
    res.render('index', { user: req.session.user || null });
});


//Signup page 
app.get('/signup', (req, res) => {
    res.render('signup');
})

//Signup Submit logic
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    //Validating with JOI
    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate({ name, email, password });

    //Making sure all required fields have inputs
    if (!name) {
        return res.send(`<p>Name is required.</p><a href="/signup">Try again</a>`);
    }
    if (!email) {
        return res.send(`<p>Please provide an email address.</p><a href="/signup">Try again</a>`);
    }
    if (!password) {
        return res.send(`<p>Password is required.</p><a href="/signup">Try again</a>`);
    }
    if (error) {
        return res.send(`<p>Invalid input.</p><a href="/signup">Try again</a>`);
    }

    //Hashing passwords and making user profile
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    //Change: made type user for each new sign up
    await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });

    //Assign the new user to the current user and redirect
    //Change
    req.session.user = { name, email, user_type: 'user'  };
    res.redirect('/members');
});


//Login page
app.get('/login', (req, res) => {
    //Change
    res.render('login');
});


//Login submit logic
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    //Validate with JOI
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate({ email, password });
    if (error) {
        return res.send(`<p>Invalid input.</p><a href="/login">Try again</a>`);
    }

    //Check if user exists and password matches
    const user = await userCollection.findOne({ email });
    if (!user) {
        return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
    }

    //Set current user as logged in user and redirect
    //Change
    req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
    res.redirect('/members');
})


//Members page
app.get('/members', isLoggedIn, (req, res) => {
    //Bring in images and *Change* display all 3 
    const images = ['ChamonixMountain.jpg', 'WhistlerMountain.jpg', 'VancouverMountain.jpg'];

    //Hello message with images
    //Change
    res.render('members', {
        user: req.session.user,
        images: images
    });
});


//Admin *new*
app.get('/admin', isLoggedIn, isAdmin, async (req , res) => {

    //if user is admin, render the admin page
    const users = await userCollection.find().toArray();
    res.render('admin', { users: users });
});


//Promote user *new*
app.post('/promoteUser', isLoggedIn, async (req, res) => {

    //Validate with Joi
    const schema = Joi.object({ email: Joi.string().email().required() });
    const { error } = schema.validate({ email: req.body.email });
    if (error) return res.status(400).send('Invalid input');

    //upgrade user to admin
    await userCollection.updateOne(
        { email: req.body.email },
        { $set: { user_type: 'admin' } }
    );

    res.redirect('/admin');
});


//Demote user *new*
app.post('/demoteUser', isLoggedIn, async (req, res) => {

    //Validate with Joi
    const schema = Joi.object({ email: Joi.string().email().required() });
    const { error } = schema.validate({ email: req.body.email });
    if (error) return res.status(400).send('Invalid input');

    //Downgrade user to user
    await userCollection.updateOne(
        { email: req.body.email },
        { $set: { user_type: 'user' } }
    );

    res.redirect('/admin');
})


//Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


//404 page
app.get('*', (req, res) => {
    //Change
    res.status(404).render('404');
});
 
 
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});