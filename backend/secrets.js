const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");

async function loadSecrets() {
  const client = new SecretsManagerClient({ region: "ap-southeast-2" }); // match your secret's region
  const command = new GetSecretValueCommand({ SecretId: "n10666630-a2" }); // replace with your secret name
  const response = await client.send(command);

  if (!response.SecretString) throw new Error("Secret is empty!");

  const secrets = JSON.parse(response.SecretString);

  // Inject into process.env so the rest of your app can use them
  Object.assign(process.env, secrets);

  return secrets;
}

module.exports = { loadSecrets };
