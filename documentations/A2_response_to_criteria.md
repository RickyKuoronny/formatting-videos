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
- **Partner name (if applicable):** ShangZhe Lin
- **Partner number:** n11036583
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
- **Video timestamp:** 00:00:56
- **Relevant files:**
    - server.js
    - /backend/s3.js

### Core - Second data persistence service

- **AWS service name:**  DynamoDB
- **What data is being stored?:** Video metadata (filename, codec, bitrate, resolution, timestamps, and user info)
- **Why is this service suited to this data?:** DynamoDB is a fast, scalable NoSQL database that is ideal for structured, queryable metadata. It allows quick lookups and sorting by keys (like filenames or users).
- **Why is are the other services used not suitable for this data?:** S3 is optimized for object storage, not structured metadata queries. Storing metadata in S3 would require downloading and parsing objects, which is inefficient.
- **Bucket/instance/table name:** a2-n10666630
- **Video timestamp:** 00:01:45
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

- **S3 Bucket names:** a2-n10666630
- **Video timestamp:** 00:01:30
- **Relevant files:**
    - /backend/s3.js
    - server.js

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

- **User pool name:** A2_n11036583_userpool 
- **How are authentication tokens handled by the client?:** Tokens are returned in the response to login requests and stored in sessionStorage. The client includes the idToken as a Bearer token in the Authorization header for subsequent API requests.
- **Video timestamp:** 00:02:50
- **Relevant files:**
    - /backend/cognito.js
    - server.js 
    - /public/index.html

### Cognito multi-factor authentication

- **What factors are used for authentication:** Email One Time Code, and Password
- **Video timestamp:** 00:00:08
- **Relevant files:**
    - /backend/cognito.js
    - server.js 
    - /public/index.html

### Cognito federated identities

- **Identity providers used:** Google
- **Video timestamp:** 00:03:32
- **Relevant files:**
    - /backend/cognito.js
    - server.js 
    - /public/index.html

### Cognito groups

- **How are groups used to set permissions?:** Users in the user group can upload and convert videos, whereas users in the admin group can view conversion logs and CPU usage. Group membership is checked in JWT payload after login.
- **Video timestamp:** 00:03:57
- **Relevant files:**
    - /backend/cognito.js
    - server.js 
    - /public/index.html

### Core - DNS with Route53

- **Subdomain**: http://a2-n10666630.cab432.com
- **Video timestamp:** 00:04:55

### Parameter store

- **Parameter names:** /n10666630/base_url
- **Video timestamp:** 00:06:11
- **Relevant files:**
    - paramStore.js
    - server.js

### Secrets manager

- **Secrets names:** CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, JWT_SECRET, PORT, REGION, COGNITO_ISSUER COGNITO_REDIRECT_URI, COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET,COGNITO_DOMAIN
- **Video timestamp:** 00:06:43
- **Relevant files:**
    - secrets.js
    - server.js

### Auto scaling

- **Scaling metric used:** SQS Queue Depth (custom metric)
- **Why this metric is better than CPU:** Queue depth is a leading indicator that detects load spikes before they cause job timeouts. It scales proactively based on pending work rather than reactively based on CPU utilization. This prevents queue buildup and provides faster response to traffic changes.
- **Scaling range:** 1 to 3 instances
- **Target value:** 5 messages per instance (dynamically calculated)
- **Instance type:** t2.micro with unlimited credit specification
- **Video timestamp:** 
- **Relevant files:**
    - backend/worker.js
    - Dockerfile.worker
    - worker.service
    - start-worker.sh
    - AUTOSCALING_SETUP.md

### Serverless functions

- **Lambda function name:** video-worker-autoscaler
- **Purpose:** Custom autoscaling - monitors SQS queue depth every minute and adjusts worker ASG capacity accordingly
- **Why Lambda is appropriate:** Lightweight monitoring task that runs on schedule (every minute), event-driven, stateless, and cost-effective for periodic checks
- **Trigger:** CloudWatch Events (EventBridge) - scheduled every 1 minute
- **Video timestamp:**
- **Relevant files:**
    - lambda/customAutoscaler.js
    - lambda/package.json

### Custom scaling metric

- **Metric used:** SQS Queue Depth (ApproximateNumberOfMessages + ApproximateNumberOfMessagesNotVisible)
- **Why it's appropriate:** Queue depth directly represents pending work, providing immediate visibility into load. It prevents job timeouts and queue buildup by scaling before workers become overwhelmed.
- **Improvement over CPU:** CPU utilization is a lagging indicator - by the time CPU is high, jobs are already queued. Queue depth is a leading indicator that scales proactively, resulting in faster response times and no job timeouts.
- **Scalability:** Works equally well with 1 or 100+ instances - calculation is simple: desiredInstances = ceil(queueDepth / messagesPerInstance)
- **Video timestamp:**
- **Relevant files:**
    - lambda/customAutoscaler.js
    - AUTOSCALING_SETUP.md

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