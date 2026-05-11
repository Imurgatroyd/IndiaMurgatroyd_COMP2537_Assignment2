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

app.set('view engine', 'ejs');


//Home page route
app.get('/', (req, res) => {

    //If user is logged in
    if (req.session.user) {
        res.send(`
            <h1>Hello, ${req.session.user.name}!</h1>
            <a href="members"><button>Go to Members Area</button></a>
            <a href="/logout"><button>Logout</button>
        `);

    //If user not logged in 
    } else {
        res.send(`
            <h1>Home</h1>
            <a href="/signup"><button>Sign up</button></a>
            <a href="/login"><button>Log in</button></a>
        `);   
    }
});


//Signup page 
app.get('/signup', (req, res) => {
    res.send(`
        <h2>create user</h2>
        <form action="/signupSubmit" method="POST">
          <input name="name" placeholder="name" /><br>
          <input name="email" placeholder="email" /><br>
          <input name="password" type="password" placeholder="password" /><br>
          <button type="submit">Submit</button>
        </form>
    `);
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
    await userCollection.insertOne({ name, email, password: hashedPassword });

    //Assign the new user to the current user and redirect
    req.session.user = { name, email };
    res.redirect('/members');
});


//Login page
app.get('/login', (req, res) => {
    res.send(`
        <form action="/loginSubmit" method="POST">
          <input name="email" placeholder="email" /><br>
          <input name="password" type="password" placeholder="password" /><br>
          <button type="submit">Submit</button>
        </form>
    `);
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
    req.session.user = { name: user.name, email: user.email };
    res.redirect('/members');
})


//Members page
app.get('/members', (req, res) => {

    //If no user logged in, redirect to home
    if (!req.session.user) {
        return res.redirect('/');
    }

    //Bring in images and randomize
    const images = ['ChamonixMountain.jpg', 'WhistlerMountain.jpg', 'VancouverMountain.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    //Hello message with random image
    res.send(`
        <h1>Hello, ${req.session.user.name}.</h1>
        <img src="/${randomImage}" width="300" /><br><br>
        <a href="/logout"><button>Sign out</button></a>
    `);
});


//Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


//404 page
app.get('*', (req, res) => {
    res.status(404).send('<h1>Page not found - 404</h1>');
});
 
 
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});