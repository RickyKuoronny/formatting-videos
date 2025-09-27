require('dotenv').config();
const { 
  DynamoDBClient, 
  CreateTableCommand, 
  waitUntilTableExists 
} = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand } = require("@aws-sdk/lib-dynamodb");

const ddbClient = new DynamoDBClient({ region: 'ap-southeast-2' });
const docClient = DynamoDBDocumentClient.from(ddbClient);

const TABLE_NAME = "a2-n10666630";
const qutUsername = "n10666630@qut.edu.au";

// --- Cache flag ---
let tableEnsured = false;

async function ensureTable() {
  if (tableEnsured) return; 

  try {
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

    console.log(`Checking table "${TABLE_NAME}"...`);
    await ddbClient.send(command);
    console.log(`Table "${TABLE_NAME}" created. Waiting until ACTIVE...`);

    await waitUntilTableExists(
      { client: ddbClient, maxWaitTime: 30 },
      { TableName: TABLE_NAME }
    );
    console.log(`Table "${TABLE_NAME}" is ACTIVE.`);
  } catch (err) {
    if (err.name === "ResourceInUseException") {
      console.log(`Table "${TABLE_NAME}" already exists.`);
    } else {
      console.error("Error ensuring table:", err);
      throw err;
    }
  }

  tableEnsured = true;
}

async function saveMetadata(filename, metadata) {
  await ensureTable(); // make sure table is ready before inserting

  const command = new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      "qut-username": qutUsername,
      filename,
      ...metadata,
    },
  });

  return await docClient.send(command);
}

// --- Save conversion log ---
async function saveLog(log) {
  await ensureTable();
  const command = new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      "qut-username": qutUsername,
      filename: `log-${Date.now()}`, // unique key
      ...log,
    },
  });
  return await docClient.send(command);
}

// --- Fetch all logs ---
async function getLogs() {
  await ensureTable();
  const command = new ScanCommand({ TableName: TABLE_NAME });
  const result = await docClient.send(command);
  // filter out only log entries
  return result.Items.filter(item => item.output && item.startedAt);
}

module.exports = { saveMetadata, saveLog, getLogs };
