// s3.js
require('dotenv').config();
const { S3Client, PutObjectCommand, GetObjectCommand, CreateBucketCommand, HeadBucketCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const fs = require('fs');

const s3Client = new S3Client({ region: 'ap-southeast-2' });
const bucketName = 'n10666630-video-processor';


async function ensureBucket() {
    try {
        await s3Client.send(new HeadBucketCommand({ Bucket: bucketName }));
        console.log('Bucket exists:', bucketName);
    } catch (err) {
        if (err.name === 'NotFound') {
            await s3Client.send(new CreateBucketCommand({ Bucket: bucketName }));
            console.log('Bucket created:', bucketName);
        } else {
            throw err;
        }
    }
}

async function uploadFile(key, filePath, contentType) {
    await ensureBucket(); // Ensure bucket exists before uploading
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
    return await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: bucketName, Key: key }), { expiresIn: 3600 });
}

module.exports = { uploadFile, getPresignedUrl };
