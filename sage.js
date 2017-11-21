var oauthSignature = require('oauth-signature');
var crypto = require('crypto');
var request = require('request');

Sage.BASE_URL = "https://api.sageone.com/accounts/v1/";

/* Constructor */
function Sage(clientId, clientSecret, signingSecret, redirectUri, subscriptionKey, oauth) {
  this.clientId = clientId;
  this.clientSecret = clientSecret;
  this.signingSecret = signingSecret;
  this.redirectUri = redirectUri;
  this.subscriptionKey = subscriptionKey;
  this.oauth = oauth;
}

/* Helper Functions */
function getNonce(nonceLength) {
  return crypto.randomBytes(Math.ceil(nonceLength * 3 / 4)).toString('base64').slice(0, nonceLength).replace(/\+/g, '0').replace(/\//g, '0');
}

function SageOAuthSignature(httpMethod, url, parameters, nonce, signingSecret, accessToken, options) {
  var signatureBaseString = new oauthSignature.SignatureBaseString(httpMethod, url, parameters).generate() + '&' + nonce;
  var encodeSignature = true;
  if (options) encodeSignature = options.encodeSignature;

  return new oauthSignature.HmacSha1Signature(signatureBaseString, signingSecret, accessToken).generate(encodeSignature);
};

module.makeRequest = function (context, httpMethod, url, parameters, callback) {
  // console.log('context:', context);
  var isTokenRequest = (url === "https://api.sageone.com/oauth2/token");

  if (!isTokenRequest) {
    var nonce = getNonce(32);
    var signingSecret = context.signingSecret;
    var accessToken = context.oauth.token.access_token;
    var OAuthSignature = SageOAuthSignature(httpMethod, url, parameters, nonce, signingSecret, accessToken, { encodeSignature: false });
  }

  var options = {
    method: httpMethod,
    url: url,
    // qs: { config_setting: "foo" },
    headers: isTokenRequest ?
      { 'Content-Type': 'application/x-www-form-urlencoded' } :
      {
        'Authorization': 'Bearer ' + accessToken,
        'X-Signature': OAuthSignature,
        'X-Nonce': nonce,
        'Accept': '*/*',
        'Content-Type': 'application/json',
        'User-Agent': 'sage_nodejs',
        'X-Site' : context.oauth.token.resource_owner_id,
        'ocp-apim-subscription-key' : context.subscriptionKey
      },
    form: parameters
  };

  // Making HTTP Request
  request(options, function (error, response, body) {
    if (response.statusCode == 200 || response.statusCode == 201) {
      callback(null, JSON.parse(body));
    } else {
      // console.log('response code:', response.statusCode);
      // console.log(body);
      if (!error) error = { message: 'Error Occured', statusCode: response.statusCode }      
      callback(error, JSON.parse(body))
    }
    // console.log(response.request.uri)
    // console.log(response.request.headers);
    // console.log(response.request.body);
  });
}

/* Public Functions */
Sage.prototype.query = function (httpMethod, url, parameters, callback) {
  url = Sage.BASE_URL + url;
  var self = this;

  // Authorization is required, check if auth is valid
  this.checkAuth(function (err, isValid, token, auth) {
    if (isValid) {
      module.makeRequest(self, httpMethod, url, parameters, callback)
    } else {
      // Auth is not valid, return a custom error
      callback(new Error('No valid authentication found, please set either a token request code, or a valid refresh token'), null);
    }
  });

};

Sage.prototype.setBaseUrl = function (url) {
  Sage.BASE_URL = url;
}

Sage.prototype.setAuthCode = function (code) {
  this.oauth.requestCode = code;
}

Sage.prototype.getAuthUrl = function () {
  return "https://www.sageone.com/oauth2/auth?response_type=code&client_id=" + this.clientId
    + "&redirect_uri=" + this.redirectUri + "&scope=full_access"
};

Sage.prototype.token = function (code, grantType, callback) {
  var data = {
    grant_type: grantType,
    client_id: this.clientId,
    client_secret: this.clientSecret,
  }

  switch (grantType) {
    case 'authorization_code':
      data.code = code;
      data.redirect_uri = this.redirectUri;
      break;

    case 'refresh_token':
      data.refresh_token = code;
      break;
  }

  module.makeRequest(this, 'POST', 'https://api.sageone.com/oauth2/token', data, callback);
};

Sage.prototype.checkAuth = function (cb) {
  var self = this;

  function authorize(code, callback) {
    self.token(code, 'authorization_code', function (err, token) {
      self.oauth.authorized = true;
      self.oauth.token = token;
      self.oauth.refreshToken = token.refresh_token;
      self.oauth.expires = Date.now() + (parseInt(token.expires_in) * 1000);
      callback(err, token);
    });
  };

  function refreshToken(callback) {
    self.token(self.oauth.refreshToken, 'refresh_token', function (err, token) {
      self.oauth.authorized = true;
      self.oauth.token = token;
      self.oauth.refreshToken = token.refresh_token;
      self.oauth.expires = Date.now() + (parseInt(token.expires_in) * 1000);
      console.log('callback inside self.token :', callback.toString());
      callback(err, token);
    });
  };

  if (this.oauth.authorized && this.oauth.expires > Date.now()) {
    // Client is authorized and token is still valid
    cb(null, true, this.oauth.token, this.auth);

  } else if ((this.oauth.authorized && this.oauth.expires < Date.now()) || (!this.oauth.authorized && this.oauth.refreshToken)) {
    // Either the token has expired, or the client is not authorized but has a refresh token
    // With this info a new token can be requested
    refreshToken(function (err, token) {
      cb(err, true, token, this.auth);
    });

  } else if (this.oauth.requestCode) {
    // If no token or refresh token exists, but a request code does, authorize the client
    authorize(this.oauth.requestCode, function (err, token) {
      cb(err, true, token, this.auth);
    });

  } else {
    // No token, refresh token or request code found, this client is in no way authenticated
    cb(null, false, null, null);
  }
};

module.exports = Sage;