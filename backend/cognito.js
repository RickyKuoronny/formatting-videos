const { loadSecrets } = require('./secrets');
const { 
  CognitoIdentityProviderClient, 
  SignUpCommand, 
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { CognitoJwtVerifier } = require('aws-jwt-verify');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;

let initialized = false;
let cognitoClient;
let clientId, clientSecret, userPoolId, region;
let idTokenVerifier;

// Helper to lazy-initialize
async function init() {
  if (initialized) return;
  await loadSecrets();

  // Cloudinary config
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });

  region = process.env.REGION;
  clientId = process.env.COGNITO_CLIENT_ID;
  clientSecret = process.env.COGNITO_CLIENT_SECRET;
  userPoolId = process.env.COGNITO_USER_POOL_ID;

  cognitoClient = new CognitoIdentityProviderClient({ region });

  idTokenVerifier = CognitoJwtVerifier.create({
    userPoolId,
    clientId,
    tokenUse: 'id'
  });

  initialized = true;
}

// Wrap any function to ensure init is called first
function withInit(fn) {
  return async (...args) => {
    await init();
    return fn(...args);
  };
}

// --- Cognito helpers ---
function secretHash(username) {
  if (!clientSecret) return undefined;
  const hasher = crypto.createHmac('sha256', clientSecret);
  hasher.update(`${username}${clientId}`);
  return hasher.digest('base64');
}

async function _signUpUser({ username, password, email }) {
  const params = { ClientId: clientId, Username: username, Password: password, UserAttributes: [{ Name: 'email', Value: email }] };
  const hash = secretHash(username);
  if (hash) params.SecretHash = hash;
  return cognitoClient.send(new SignUpCommand(params));
}

async function _confirmUser({ username, confirmationCode }) {
  const params = { ClientId: clientId, Username: username, ConfirmationCode: confirmationCode };
  const hash = secretHash(username);
  if (hash) params.SecretHash = hash;
  return cognitoClient.send(new ConfirmSignUpCommand(params));
}

async function _initiateAuthFlow({ username, password }) {
  const authParams = { USERNAME: username, PASSWORD: password };
  const hash = secretHash(username);
  if (hash) authParams.SECRET_HASH = hash;

  return cognitoClient.send(new InitiateAuthCommand({
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: clientId,
    AuthParameters: authParams
  }));
}

async function _respondToChallenge({ username, session, challengeName, otp }) {
  const challengeResponses = { USERNAME: username };
  const hash = secretHash(username);
  if (hash) challengeResponses.SECRET_HASH = hash;

  switch (challengeName) {
    case 'SMS_MFA': challengeResponses.SMS_MFA_CODE = otp; break;
    case 'SOFTWARE_TOKEN_MFA': challengeResponses.SOFTWARE_TOKEN_MFA_CODE = otp; break;
    case 'EMAIL_OTP_MULTI_FACTOR_AUTH': challengeResponses.EMAIL_OTP_CODE = otp; break;
    default: challengeResponses.ANSWER = otp; break;
  }

  return cognitoClient.send(new RespondToAuthChallengeCommand({
    ChallengeName: challengeName,
    ClientId: clientId,
    Session: session,
    ChallengeResponses: challengeResponses
  }));
}

async function _verifyIdToken(token) {
  return idTokenVerifier.verify(token);
}

// Export functions wrapped with init
module.exports = {
  signUpUser: withInit(_signUpUser),
  confirmUser: withInit(_confirmUser),
  initiateAuthFlow: withInit(_initiateAuthFlow),
  respondToChallenge: withInit(_respondToChallenge),
  verifyIdToken: withInit(_verifyIdToken),
  secretHash: withInit(secretHash) // optional, rarely used outside
};
