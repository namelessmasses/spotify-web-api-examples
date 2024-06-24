/**
 * This is an example of a basic node.js script that performs
 * the Authorization Code oAuth2 flow to authenticate against
 * the Spotify Accounts.
 *
 * For more information, read
 * {@link https://developer.spotify.com/documentation/web-api/tutorials/code-flow}
 */

require('dotenv').config();
var express = require('express');
var request = require('request');
var crypto = require('crypto');
var cors = require('cors');
var querystring = require('querystring');
var cookieParser = require('cookie-parser');

var client_id = process.env.CLIENT_ID; // your clientId
var client_secret = process.env.CLIENT_SECRET; // Your secret
var redirect_uri = 'http://localhost:8888/callback'; // Your redirect uri

/**
 * Generates a random string of the specified length.
 *
 * @param {number} length - The length of the random string to generate.
 * @returns {string} The generated random string.
 */
const generateRandomString = (length) => {
  return crypto
    .randomBytes(60)
    .toString('hex')
    .slice(0, length);
}

var stateKey = 'spotify_auth_state';

var app = express();

app.use(express.static(__dirname + '/public'))
  .use(cors())
  .use(cookieParser());

/**
 * Handles the login route and initiates the Spotify authorization process.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 */
app.get('/login', function (req, res) {

  var state = generateRandomString(16);
  res.cookie(stateKey, state);

  // your application requests authorization
  var scope = 'user-read-private user-read-email playlist-read-private playlist-modify-private';
  res.redirect('https://accounts.spotify.com/authorize?' +
    querystring.stringify({
      response_type: 'code',
      client_id: client_id,
      scope: scope,
      redirect_uri: redirect_uri,
      state: state
    }));
});

/**
 * Handles the callback route and exchanges the authorization code for access and refresh tokens.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 */
app.get('/callback', function (req, res) {

  // your application requests refresh and access tokens
  // after checking the state parameter

  var code = req.query.code || null;
  var state = req.query.state || null;
  var storedState = req.cookies ? req.cookies[stateKey] : null;

  if (state === null || state !== storedState) {
    res.redirect('/#' +
      querystring.stringify({
        error: 'state_mismatch'
      }));
  } else {
    res.clearCookie(stateKey);
    var authOptions = {
      url: 'https://accounts.spotify.com/api/token',
      form: {
        code: code,
        redirect_uri: redirect_uri,
        grant_type: 'authorization_code'
      },
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + (new Buffer.from(client_id + ':' + client_secret).toString('base64'))
      },
      json: true
    };

    request.post(authOptions, function (error, response, body) {
      if (!error && response.statusCode === 200) {

        var access_token = body.access_token,
          refresh_token = body.refresh_token;

        res.cookie('access_token', access_token);
        res.cookie('refresh_token', refresh_token);

        var options = {
          url: 'https://api.spotify.com/v1/me',
          headers: { 'Authorization': 'Bearer ' + access_token },
          json: true
        };

        // use the access token to access the Spotify Web API
        request.get(options, function (error, response, body) {
          console.log(body);
        });

        // we can also pass the token to the browser to make requests from there
        res.redirect('/#' +
          querystring.stringify({
            access_token: access_token,
            refresh_token: refresh_token
          }));
      } else {
        res.redirect('/#' +
          querystring.stringify({
            error: 'invalid_token'
          }));
      }
    });
  }
});

/**
 * Handles the refresh_token route and exchanges the refresh token for a new access token.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 */
app.get('/refresh_token', function (req, res) {

  var refresh_token = req.query.refresh_token;
  var authOptions = {
    url: 'https://accounts.spotify.com/api/token',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + (new Buffer.from(client_id + ':' + client_secret).toString('base64'))
    },
    form: {
      grant_type: 'refresh_token',
      refresh_token: refresh_token
    },
    json: true
  };

  request.post(authOptions, function (error, response, body) {
    if (!error && response.statusCode === 200) {
      var access_token = body.access_token,
        refresh_token = body.refresh_token;
      res.send({
        'access_token': access_token,
        'refresh_token': refresh_token
      });
    }
  });
});

/**
 * Handles the getplaylists route and retrieves the user's playlists.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 */
app.get('/getplaylists', function (req, res) {

  var access_token = req.cookies['access_token'];

  var options = {
    url: 'https://api.spotify.com/v1/me/playlists',
    headers: { 'Authorization': 'Bearer ' + access_token },
    json: true
  };

  request.get(options, function (error, response, body) {
    console.log(body.items);
    res.json(body.items);
  });

});

app.get('/getplaylist', function (req, res) {
  
    var access_token = req.cookies['access_token'];
    var playlist_id = req.query.id;
  
    var options = {
      url: 'https://api.spotify.com/v1/playlists/' + playlist_id + '/tracks',
      headers: { 'Authorization': 'Bearer ' + access_token },
      json: true
    };
  
    request.get(options, function (error, response, body) {
      // iterate through body.items to get the track info
      body.items.forEach(function(item) {
        console.log(item.track);
      });
      res.json(body.items);
    });
});

console.log('Listening on 8888');
app.listen(8888);
