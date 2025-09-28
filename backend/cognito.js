const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { CognitoJwtVerifier } = require('aws-jwt-verify');
const crypto = require('crypto');

const region = process.env.REGION;
const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const userPoolId = process.env.COGNITO_USER_POOL_ID;

const cognitoClient = new CognitoIdentityProviderClient({ region });

function secretHash(username) {
  if (!clientSecret) return undefined;
  const hasher = crypto.createHmac('sha256', clientSecret);
  hasher.update(`${username}${clientId}`);
  return hasher.digest('base64');
}

async function signUpUser({ username, password, email }) {
  const params = {
    ClientId: clientId,
    Username: username,
    Password: password,
    UserAttributes: [{ Name: 'email', Value: email }]
  };

  const hash = secretHash(username);
  if (hash) {
    params.SecretHash = hash;
  }

  return cognitoClient.send(new SignUpCommand(params));
}

async function confirmUser({ username, confirmationCode }) {
  const params = {
    ClientId: clientId,
    Username: username,
    ConfirmationCode: confirmationCode
  };

  const hash = secretHash(username);
  if (hash) {
    params.SecretHash = hash;
  }

  return cognitoClient.send(new ConfirmSignUpCommand(params));
}

async function initiateAuthFlow({ username, password }) {
  const authParameters = {
    USERNAME: username,
    PASSWORD: password
  };

  const hash = secretHash(username);
  if (hash) {
    authParameters.SECRET_HASH = hash;
  }

  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: clientId,
    AuthParameters: authParameters
  };

  return cognitoClient.send(new InitiateAuthCommand(params));
}

async function respondToChallenge({ username, session, challengeName, otp }) {
  const challengeResponses = {
    USERNAME: username
  };

  const hash = secretHash(username);
  if (hash) {
    challengeResponses.SECRET_HASH = hash;
  }

  switch (challengeName) {
    case 'SMS_MFA':
      challengeResponses.SMS_MFA_CODE = otp;
      break;
    case 'SOFTWARE_TOKEN_MFA':
      challengeResponses.SOFTWARE_TOKEN_MFA_CODE = otp;
      break;
    case 'EMAIL_OTP':
      challengeResponses.ANSWER = otp;
      break;
    case 'CUSTOM_CHALLENGE':
      challengeResponses.ANSWER = otp;
      break;
    default:
      challengeResponses.ANSWER = otp;
      break;
  }

  return cognitoClient.send(new RespondToAuthChallengeCommand({
    ChallengeName: challengeName,
    ClientId: clientId,
    Session: session,
    ChallengeResponses: challengeResponses
  }));
}

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId,
  clientId,
  tokenUse: 'id'
});

async function verifyIdToken(token) {
  return idTokenVerifier.verify(token);
}

module.exports = {
  signUpUser,
  confirmUser,
  initiateAuthFlow,
  respondToChallenge,
  verifyIdToken,
  secretHash,
  cognitoClientConfig: {
    region,
    clientId,
    clientSecret,
    userPoolId
  }
};
