// s3.js
require('dotenv').config();
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const fs = require('fs');

const s3Client = new S3Client({ region: 'ap-southeast-2' });
const bucketName = 'n10666630-video-processor';

async function uploadFile(key, filePath, contentType) {
    const fileStream = fs.createReadStream(filePath);
    await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: key,
        Body: fileStream,
        ContentType: contentType
    }));
    return key;
}

async function getPresignedUrl(key) {
    const command = new GetObjectCommand({ Bucket: bucketName, Key: key });
    return await getSignedUrl(s3Client, command, { expiresIn: 3600 });
}

module.exports = { uploadFile, getPresignedUrl };
