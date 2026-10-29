// Run with:  FLUXER_CLIENT_ID=... FLUXER_CLIENT_SECRET=... node examples/express.js
// Register http://localhost:3000/auth/fluxer/callback as a redirect URI on your Fluxer application.
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy: FluxerStrategy } = require('passport-fluxer'); // or '../src' inside this repo

passport.use(
  new FluxerStrategy(
    {
      clientID: process.env.FLUXER_CLIENT_ID,
      clientSecret: process.env.FLUXER_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/fluxer/callback',
      scope: ['identify', 'email'],
      // instanceURL: 'https://my-fluxer.example.com', // for a self-hosted instance
    },
    async (accessToken, refreshToken, profile, done) => {
      // Find or create the user in your own database here.
      // Fluxer IDs are strings (snowflakes): never convert them to Number.
      done(null, { id: profile.id, name: profile.displayName, email: profile.email });
    },
  ),
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const app = express();
app.use(session({ secret: 'change-me', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => res.send(req.user ? `Hello ${req.user.name}` : '<a href="/auth/fluxer">Login with Fluxer</a>'));
app.get('/auth/fluxer', passport.authenticate('fluxer'));
app.get('/auth/fluxer/callback', passport.authenticate('fluxer', { failureRedirect: '/', successRedirect: '/' }));

app.listen(3000, () => console.log('http://localhost:3000'));
