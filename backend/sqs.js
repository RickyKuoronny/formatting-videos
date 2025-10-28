const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");
const { loadAppConfig } = require('./paramStore');

let sqsClient;
let config;

async function getSqsClient() {
  if (!sqsClient) {
    config = await loadAppConfig();
    sqsClient = new SQSClient({ region: config.region || process.env.AWS_REGION });
  }
  return sqsClient;
}

async function sendMessage(queueUrl, messageBody) {
  const client = await getSqsClient();
  const command = new SendMessageCommand({
    QueueUrl: queueUrl,
    MessageBody: JSON.stringify(messageBody),
  });

  try {
    const data = await client.send(command);
    console.log("Success, message sent. MessageID:", data.MessageId);
    return data;
  } catch (error) {
    console.error("Error sending message to SQS:", error);
    throw error;
  }
}

module.exports = { sendMessage };
