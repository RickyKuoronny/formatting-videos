Assignment 2 - Cloud Services Exercises - Response to Criteria
================================================

Instructions
------------------------------------------------
- Keep this file named A2_response_to_criteria.md, do not change the name
- Upload this file along with your code in the root directory of your project
- Upload this file in the current Markdown format (.md extension)
- Do not delete or rearrange sections.  If you did not attempt a criterion, leave it blank
- Text inside [ ] like [eg. S3 ] are examples and should be removed


Overview
------------------------------------------------

- **Name:** Ricky Kuoronny
- **Student number:** n10666630
- **Partner name (if applicable):** Shang-Zhe Lin
- **Application name:** Video Processing
- **Two line description:** A web platform where users can upload videos, resize, and convert them to different formats.  
Users can also retrieve processed videos via a REST API.
- **EC2 instance name or ID:** ricky_ec2

------------------------------------------------

### Core - First data persistence service

- **AWS service name:**  S3
- **What data is being stored?:** video files
- **Why is this service suited to this data?:** S3 is highly durable, scalable, and designed for large binary objects like video. It supports streaming uploads and downloads, which fits the stateless FFmpeg pipeline.
- **Why is are the other services used not suitable for this data?:** DynamoDB is not efficient for storing large binary files. Storing video directly in DynamoDB would be expensive and slow.
- **Bucket/instance/table name:** a2-n10666630
- **Video timestamp:**
- **Relevant files:**
    - server.js
    - /backend/s3.js

### Core - Second data persistence service

- **AWS service name:**  DynamoDB
- **What data is being stored?:** Video metadata (filename, codec, bitrate, resolution, timestamps, and user info)
- **Why is this service suited to this data?:** DynamoDB is a fast, scalable NoSQL database that is ideal for structured, queryable metadata. It allows quick lookups and sorting by keys (like filenames or users).
- **Why is are the other services used not suitable for this data?:** S3 is optimized for object storage, not structured metadata queries. Storing metadata in S3 would require downloading and parsing objects, which is inefficient.
- **Bucket/instance/table name:** a2-n10666630
- **Video timestamp:**
- **Relevant files:**
    - server.js
    - /backend/dynamo.js

### Third data service

- **AWS service name:**
- **What data is being stored?:** 
- **Why is this service suited to this data?:** 
- **Why is are the other services used not suitable for this data?:** 
- **Bucket/instance/table name:**
- **Video timestamp:**
- **Relevant files:**
    -

### S3 Pre-signed URLs

- **S3 Bucket names:**
- **Video timestamp:**
- **Relevant files:**
    -

### In-memory cache

- **ElastiCache instance name:**
- **What data is being cached?:** 
- **Why is this data likely to be accessed frequently?:** 
- **Video timestamp:**
- **Relevant files:**
    -

### Core - Statelessness

- **What data is stored within your application that is not stored in cloud data services?:** Nothing is written to disk. All intermediate data exists only in memory during processing.
- **Why is this data not considered persistent state?:**
- **How does your application ensure data consistency if the app suddenly stops?:** All uploads and conversion outputs are stored directly in S3 via streaming. Temporary in-memory data (uploaded file buffers and FFmpeg streams) are discarded if the server stops, but the original uploaded file in S3 remains intact. Logs and metadata are written only after successful S3 uploads. Therefore, if the application crashes, no permanent data is lost, and conversion can be safely retried from the S3-stored source file.
- **Relevant files:**
    - server.js
    - /backend/s3.js
    - /public/index.html 


### Graceful handling of persistent connections

- **Type of persistent connection and use:**
- **Method for handling lost connections:** 
- **Relevant files:**
    -


### Core - Authentication with Cognito

- **User pool name:**
- **How are authentication tokens handled by the client?:** [eg. Response to login request sets a cookie containing the token.]
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito multi-factor authentication

- **What factors are used for authentication:** [eg. password, SMS code]
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito federated identities

- **Identity providers used:**
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito groups

- **How are groups used to set permissions?:** [eg. 'admin' users can delete and ban other users]
- **Video timestamp:**
- **Relevant files:**
    -

### Core - DNS with Route53

- **Subdomain**: http://a2-n10666630.cab432.com
- **Video timestamp:**

### Parameter store

- **Parameter names:** 
- **Video timestamp:**
- **Relevant files:**
    -

### Secrets manager

- **Secrets names:** 
- **Video timestamp:**
- **Relevant files:**
    -

### Infrastructure as code

- **Technology used:**
- **Services deployed:**
- **Video timestamp:**
- **Relevant files:**
    -

### Other (with prior approval only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -

### Other (with prior permission only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -