Assignment 1 - REST API Project - Response to Criteria
================================================

Instructions:

- Don't use this file. Use the clean template from Canvas
- This file is a sample showing the kinds and amount of detail that we
    would like to see
- Video timestamp refers to the time in your video where the functionality 
    is demonstrated. The user login and user dependent functionality
    will likely contribute to demonstrating the web client.
- Relevant files are filename and line number(s) where the functionality is implemented.
    You can also refer to an entire directory or leave off the line number if 
    the whole directory/file is relevant.

Overview
------------------------------------------------

- **Name:** Ricky Kuoronny
- **Student number:** n10666630
- **Application name:** Video Resizer / Processor
- **Two line description:** A web platform where users can upload videos, resize, and convert them to different formats.  
Users can also retrieve processed videos via a REST API.

Core criteria
------------------------------------------------

### Containerise the app

- **ECR Repository name:** n10666630-repo 
- **Video timestamp:** 00:06:25 
- **Relevant files:**  
  - Dockerfile  
  - package.json  

### Deploy the container

- **EC2 instance ID:** i-047dc7c6b94d1bd6e
- **Video timestamp:** 00:00:00

### User login

- **One line description:** JWT-based authentication for video upload and access to processed videos.  
- **Video timestamp:** 00:16:08
- **Relevant files:**  
  - server.js 
  - public/index.html

### REST API

- **One line description:** Endpoints for uploading, converting, and retrieving logs.  
- **Video timestamp:** 00:29:24  
- **Relevant files:**  
  - server.js 
  - public/index.html

### Data types

- **One line description:** Handles both structured metadata and unstructured video files.  
- **Video timestamp:** 00:40:25  
- **Relevant files:**  
  - server.js 
  - public/index.html

#### First kind

- **One line description:** Raw uploaded video files.  
- **Type:** Unstructured  
- **Rationale:** Users upload videos of any format to be converted/resized.  
- **Video timestamp:** 00:40:25  
- **Relevant files:**  
  - outputs/  

#### Second kind

- **One line description:** Video metadata (format, resolution, duration, bitrate, codec).  
- **Type:** Structured  
- **Rationale:** Allows filtering, sorting, and querying of processed videos.  
- **Video timestamp:** 00:51:26
- **Relevant files:**  
  - metadata.json

### CPU intensive task

- **One line description:** Video resizing and format conversion using FFmpeg.  
- **Video timestamp:** 02:07:27
- **Relevant files:**  
  - server.js 
  - public/index.html 

### CPU load testing

- **One line description:** Manual Testing done on web client  
- **Video timestamp:** 02:07:27  
- **Relevant files:**  
  - server.js 
  - public/index.html 

Additional criteria
------------------------------------------------

### Extensive REST API features

- **One line description:** Endpoints support file upload, conversion options, filtering by format/resolution on logs, and status checks.  
- **Video timestamp:** 01:21:25
- **Relevant files:**  
  - server.js 
  - public/index.html
  - metadata.json
  - conversion_logs.json

### External API(s)

- **One line description:** Utilised ClCloudinary for extra metadata
- **Video timestamp:** 00:51:26
- **Relevant files:**  
  - server.js 
  - public/index.html

### Additional types of data

- **One line description:** Logs of conversions
- **Video timestamp:** 01:13:28  
- **Relevant files:**  
  - conversion_logs.json 

### Web client

- **One line description:** Browser interface for uploading videos, monitoring conversion progress, and downloading processed videos.  
- **Video timestamp:** 01:41:09 
- **Relevant files:**  
  - server.js 
  - public/index.html
  - public/styles.css

