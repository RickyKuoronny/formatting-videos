// s3.js
require('dotenv').config();
const fs = require('fs');
const { 
    S3Client, 
    PutObjectCommand, 
    GetObjectCommand, 
    CreateBucketCommand, 
    HeadBucketCommand, 
    PutBucketTaggingCommand 
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Configure S3 client
const s3Client = new S3Client({ region: 'ap-southeast-2' });
const bucketName = 'a2-n10666630';  // Change to your unique bucket name
const qutUsername = 'n10666630@qut.edu.au';
const purpose = 'assessment-2';

// Cache bucket existence to avoid repeated checks
let bucketEnsured = false;

// Ensure bucket exists and is tagged
async function ensureBucket() {
    if (bucketEnsured) return;

    try {
        await s3Client.send(new HeadBucketCommand({ Bucket: bucketName }));
        console.log('Bucket exists:', bucketName);
    } catch (err) {
        if (err.$metadata?.httpStatusCode === 404) {
            await s3Client.send(new CreateBucketCommand({ Bucket: bucketName }));
            console.log('Bucket created:', bucketName);

            // Tag the bucket
            const tagCommand = new PutBucketTaggingCommand({
                Bucket: bucketName,
                Tagging: {
                    TagSet: [
                        { Key: 'qut-username', Value: qutUsername },
                        { Key: 'purpose', Value: purpose }
                    ]
                }
            });
            try {
                const response = await s3Client.send(tagCommand);
                console.log('Bucket tagged:', response);
            } catch (tagErr) {
                console.error('Failed to tag bucket:', tagErr);
            }
        } else {
            throw err;
        }
    }

    bucketEnsured = true;
}

// Upload a local file to S3
async function uploadFile(key, filePath, contentType) {
    await ensureBucket(); // Make sure bucket exists
    const fileStream = fs.createReadStream(filePath);

    await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: key,
        Body: fileStream,
        ContentType: contentType
    }));

    console.log(`File uploaded to S3: ${key}`);
    return key;
}

// Get a pre-signed URL for a file in S3
async function getPresignedUrl(key, expiresIn = 3600) {
    await ensureBucket(); // Ensure bucket exists
    const command = new GetObjectCommand({ Bucket: bucketName, Key: key });
    return await getSignedUrl(s3Client, command, { expiresIn });
}

module.exports = { uploadFile, getPresignedUrl };
