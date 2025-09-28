const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");

const client = new SSMClient({ region: "ap-southeast-2" });

async function loadAppConfig() {
  try {
    const response = await client.send(
      new GetParameterCommand({
        Name: "/n10666630/base_url",
        WithDecryption: false
      })
    );
    process.env.APP_URL = response.Parameter.Value;
    console.log("Loaded APP_URL from Parameter Store:", process.env.APP_URL);
  } catch (err) {
    console.error("Failed to load APP_URL from Parameter Store:", err);
  }
}

module.exports = { loadAppConfig };
