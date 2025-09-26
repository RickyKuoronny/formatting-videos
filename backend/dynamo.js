require('dotenv').config();
const { DynamoDBClient, CreateTableCommand, DescribeTableCommand } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand } = require("@aws-sdk/lib-dynamodb");

const ddbClient = new DynamoDBClient({ region: 'ap-southeast-2' });
const docClient = DynamoDBDocumentClient.from(ddbClient);

const TABLE_NAME = "a2-n10666630";
const qutUsername = "n10666630@qut.edu.au";

// --- Cache flag ---
let tableEnsured = false;

async function ensureTable() {
  if (tableEnsured) return; // already checked

  try {
    await ddbClient.send(new DescribeTableCommand({ TableName: TABLE_NAME }));
    console.log(`✅ DynamoDB table "${TABLE_NAME}" already exists.`);
    tableEnsured = true;
  } catch (err) {
    if (err.name === "ResourceNotFoundException") {
      console.log(`ℹ️ Table "${TABLE_NAME}" not found. Creating...`);
      const command = new CreateTableCommand({
        TableName: TABLE_NAME,
        AttributeDefinitions: [
          { AttributeName: "qut-username", AttributeType: "S" },
          { AttributeName: "filename", AttributeType: "S" },
        ],
        KeySchema: [
          { AttributeName: "qut-username", KeyType: "HASH" },
          { AttributeName: "filename", KeyType: "RANGE" },
        ],
        ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 },
      });

      await ddbClient.send(command);
      console.log(`✅ Table "${TABLE_NAME}" created.`);
      // You might need a short wait until it's ACTIVE
    } else {
      console.error("❌ Error describing/creating table:", err);
      throw err;
    }
  }

  tableEnsured = true;
}

async function saveMetadata(filename, metadata) {
  await ensureTable(); // only first call does work

  const command = new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      "qut-username": qutUsername,
      filename: filename,
      ...metadata,
    },
  });

  return await docClient.send(command);
}

module.exports = { saveMetadata };
