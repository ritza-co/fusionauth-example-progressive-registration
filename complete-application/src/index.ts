//tag::top[]
import FusionAuthClient from "@fusionauth/typescript-client";
import express from 'express';
import bodyParser from "body-parser";
import cookieParser from 'cookie-parser';
import pkceChallenge from 'pkce-challenge';
import { GetPublicKeyOrSecret, verify } from 'jsonwebtoken';
import jwksClient, { RsaSigningKey } from 'jwks-rsa';
import * as path from 'path';

// Add environment variables
import * as dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 8080; // default port to listen

if (!process.env.clientId) {
  console.error('Missing clientId from .env');
  process.exit();
}
if (!process.env.clientSecret) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
if (!process.env.fusionAuthURL) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const fusionAuthURL = process.env.fusionAuthURL;

// Validate the token signature, make sure it wasn't expired
const validateUser = async (userTokenCookie: { access_token: string }) => {
  // Make sure the user is authenticated.
  if (!userTokenCookie || !userTokenCookie?.access_token) {
    return false;
  }
  try {
    let decodedFromJwt;
    await verify(userTokenCookie.access_token, await getKey, undefined, (err, decoded) => {
      decodedFromJwt = decoded;
    });
    return decodedFromJwt;
  } catch (err) {
    console.error(err);
    return false;
  }
}


const getKey: GetPublicKeyOrSecret = async (header, callback) => {
  const jwks = jwksClient({
    jwksUri: `${fusionAuthURL}/.well-known/jwks.json`
  });
  const key = await jwks.getSigningKey(header.kid) as RsaSigningKey;
  var signingKey = key?.getPublicKey() || key?.rsaPublicKey;
  callback(null, signingKey);
}

//Cookies
const userSession = 'userSession';
const userToken = 'userToken';
const userDetails = 'userDetails'; //Non Http-Only with user info (not trusted)

const client = new FusionAuthClient('33052c8a-c283-4e96-9d2a-eb1215c69f8f-not-for-prod', fusionAuthURL);

app.use(cookieParser());
/** Decode Form URL Encoded data */
app.use(express.urlencoded());
app.use(bodyParser.json());

//end::top[]

// Static Files
//tag::static[]
app.use('/static', express.static(path.join(__dirname, '../static/')));
//end::static[]

//tag::homepage[]
app.get("/", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (await validateUser(userTokenCookie)) {
    res.redirect(302, '/account');
  } else {
    const stateValue = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const pkcePair = await pkceChallenge();
    res.cookie(userSession, { stateValue, verifier: pkcePair.code_verifier, challenge: pkcePair.code_challenge }, { httpOnly: true });

    res.sendFile(path.join(__dirname, '../templates/home.html'));
  }
});
//end::homepage[]

//tag::login[]
app.get('/login', (req, res, next) => {
  const userSessionCookie = req.cookies[userSession];

  // Cookie was cleared, just send back (hacky way)
  if (!userSessionCookie?.stateValue || !userSessionCookie?.challenge) {
    res.redirect(302, '/');
  }

  res.redirect(302, `${fusionAuthURL}/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=http://localhost:${port}/oauth-redirect?source=login&state=${userSessionCookie?.stateValue}&code_challenge=${userSessionCookie?.challenge}&code_challenge_method=S256`)
});
//end::login[]

app.get('/register', (req, res, next) => {
  const userSessionCookie = req.cookies[userSession];
  
  // Cookie was cleared, just send back (hacky way)
  if (!userSessionCookie?.stateValue || !userSessionCookie?.challenge) {
    res.redirect(302, '/');
  }
  
  res.redirect(302, `${fusionAuthURL}/oauth2/register?client_id=${clientId}&response_type=code&redirect_uri=http://localhost:${port}/oauth-redirect?source=register&state=${userSessionCookie?.stateValue}&code_challenge=${userSessionCookie?.challenge}&code_challenge_method=S256&source=register`)
 });

//tag::oauth-redirect[]
app.get('/oauth-redirect', async (req, res, next) => {
  // Capture query params
  const stateFromFusionAuth = `${req.query?.state}`;
  const authCode = `${req.query?.code}`;
  const source = `${req.query?.source}`;

  // Validate cookie state matches FusionAuth's returned state
  const userSessionCookie = req.cookies[userSession];
  if (stateFromFusionAuth !== userSessionCookie?.stateValue) {
    console.log("State doesn't match. uh-oh.");
    console.log("Saw: " + stateFromFusionAuth + ", but expected: " + userSessionCookie?.stateValue);
    res.redirect(302, '/');
    return;
  }

  try {
    // Exchange Auth Code and Verifier for Access Token
    const accessToken = (await client.exchangeOAuthCodeForAccessTokenUsingPKCE(authCode,
      clientId,
      clientSecret,
      `http://localhost:${port}/oauth-redirect?source=${source}`,
      userSessionCookie.verifier)).response;

    if (!accessToken.access_token) {
      console.error('Failed to get Access Token')
      return;
    }
    res.cookie(userToken, accessToken, { httpOnly: true })

    // Exchange Access Token for User
    const userResponse = (await client.retrieveUserUsingJWT(accessToken.access_token)).response;
    if (!userResponse?.user) {
      console.error('Failed to get User from access token, redirecting home.');
      res.redirect(302, '/');
    }
    res.cookie(userDetails, userResponse.user);

    if (source === 'register') {
      res.redirect(302, '/set-address');
    } else {
      res.redirect(302, '/account');
    }
  } catch (err: any) {
    console.error(err);
    res.status(err?.statusCode || 500).json(JSON.stringify({
      error: err
    }))
  }
});
//end::oauth-redirect[]

app.get("/set-address", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/set-address.html'));
  }
});


app.post("/set-address", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  let error;

  try {
    const address = req.body.address;
    const retrievedUserDetails = req.cookies[userDetails];
    if (!retrievedUserDetails) {
      throw new Error('No user details found in cookie');
    }
    const userId = retrievedUserDetails.id;
    if (!userId) {
      throw new Error('No user id found in cookie');
    }

    // Update the user's address
    await client.patchUser(userId, {
      user: {
        email: retrievedUserDetails.email,
        data: {
          address: address
        }
      }
    });

    res.status(200).json(JSON.stringify({
      error,
      message: 'Address updated successfully'
    }))

  } catch (ex: any) {
    console.error(ex);
    error = `There was a problem updating the address. ${ex.exeception.fieldErrors}`;
    res.json(JSON.stringify({
      error,
    }))
  }

});



//tag::account[]
app.get("/account", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/account.html'));
  }
});
//end::account[]

//tag::make-change[]
app.get("/make-change", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/make-change.html'));
  }
});

app.post("/make-change", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  let error;
  let message;

  var coins = {
    quarters: 0.25,
    dimes: 0.1,
    nickels: 0.05,
    pennies: 0.01,
  };

  try {
    message = 'We can make change for';
    let remainingAmount = +req.body.amount;
    for (const [name, nominal] of Object.entries(coins)) {
      let count = Math.floor(remainingAmount / nominal);
      remainingAmount =
        Math.round((remainingAmount - count * nominal) * 100) / 100;

      message = `${message} ${count} ${name}`;
    }
    `${message}!`;
  } catch (ex: any) {
    error = `There was a problem converting the amount submitted. ${ex.message}`;
  }
  res.json(JSON.stringify({
    error,
    message
  }))

});
//end::make-change[]

//tag::logout[]
app.get('/logout', (req, res, next) => {
  res.redirect(302, `${fusionAuthURL}/oauth2/logout?client_id=${clientId}`);
});
//end::logout[]

//tag::oauth-logout[]
app.get('/oauth2/logout', (req, res, next) => {
  console.log('Logging out...')
  res.clearCookie(userSession);
  res.clearCookie(userToken);
  res.clearCookie(userDetails);

  res.redirect(302, '/')
});
//end::oauth-logout[]


/**
 * Register a new user.
 * POST /register
 * Request Body: { email: string, password: string }
 */
app.post("/api/register", async (req: any, res: any) => {
  const { email } = req.body;
  const { password } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    const response: any = await client.register("", {
      disableDomainBlock: false,
      sendSetPasswordEmail: false,
      skipVerification: false,
      registration: {
        applicationId: clientId,
      },
      user: {
        email,
        password,
      },
    });
    res.status(201).json({
        registrationId: response.response?.registration?.id,
        user: response.response?.user
    });
  } catch (error: any) {
    console.error("Error during user registration:", error);
    res.status(error.statusCode || 500).json({ error: error.message });
  }
});


/**
 * Update user registration.
 * PATCH /register/:userId
 * Request Body: { address: { street: string, city: string, state: string, zipCode: string } }
 */
app.patch("/api/register/:userId", async (req: any, res: any) => {
  const { userId } = req.params;
  const { address } = req.body;

  if (!userId || !address) {
    return res.status(400).json({ error: "User ID and address are required" });
  }

  try {
    const response: any = await client.patchRegistration(userId, {
        registration: {
          applicationId: clientId,
          data: {
            address,
          }
        },
    });

    res.status(200).json({response});
  } catch (error: any) {
    console.error("Error during user registration update:", error);
    res.status(error.statusCode || 500).json({ error: error.exception?.fieldErrors });
  }
});


// start the Express server
//tag::app[]
app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});
//end::app[]
