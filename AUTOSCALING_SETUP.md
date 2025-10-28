# Worker Autoscaling Setup Guide

This guide explains how to set up EC2 worker autoscaling with a custom SQS-based scaling metric.

## Overview

The architecture uses:
- **EC2 Workers** (t2.micro with unlimited credit) to process video conversion jobs
- **SQS Queue** to distribute jobs to workers
- **Lambda Function** to monitor queue depth and adjust worker count
- **CloudWatch Events** to trigger Lambda every minute
- **Custom CloudWatch Metrics** for monitoring

## Why This Approach?

### Custom Scaling Metric (SQS Queue Depth)
✅ **Better than CPU utilization** for async job processing:
- **Leading indicator**: Scales before jobs pile up (CPU is lagging)
- **Predictable**: Clear relationship between queue size and needed capacity
- **Fast response**: Detects load spikes immediately
- **Job-aware**: Accounts for varying job complexity
- **Prevents timeouts**: Scales before jobs timeout in queue

### Lambda for Autoscaling
✅ **Appropriate use of serverless**:
- Lightweight monitoring task (runs every minute)
- Event-driven (CloudWatch Events trigger)
- No persistent state needed
- Cost-effective (minimal execution time)
- Responds to queue events

## Setup Steps

### 1. Create Worker AMI

SSH into your EC2 instance:

```bash
# Install Node.js if not already installed
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.nvm/nvm.sh
nvm install 22

# Clone your repository
cd ~
git clone <your-repo-url> formatvideo
cd formatvideo

# Install dependencies
npm install --production

# Install ffmpeg
sudo apt-get update
sudo apt-get install -y ffmpeg

# Set up the worker service
chmod +x start-worker.sh
sudo cp worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable worker
sudo systemctl start worker
sudo systemctl status worker

# Test the worker
# (send a test job to SQS and verify it processes)

# Reboot to ensure it starts on boot
sudo reboot
```

After reboot, verify worker is running:
```bash
sudo systemctl status worker
journalctl -u worker -f
```

Create AMI from AWS Console:
1. Go to EC2 → Instances
2. Select your worker instance
3. Actions → Image and templates → Create image
4. Name: `video-worker-v1`
5. Create image

### 2. Create Launch Template

1. EC2 → Launch Templates → Create launch template
2. **Name**: `video-worker-template`
3. **AMI**: Select your worker AMI
4. **Instance type**: t2.micro
5. **Key pair**: Select your key
6. **Security group**: Select your security group (needs SQS, S3, DynamoDB access)
7. **IAM instance profile**: Create/select role with:
   - `AmazonSQSFullAccess`
   - `AmazonS3FullAccess`
   - `AmazonDynamoDBFullAccess`
   - `SecretsManagerReadWrite`
   - `AmazonSSMReadOnlyAccess`
8. **Advanced details**:
   - **Credit specification**: Unlimited
   - **Detailed CloudWatch monitoring**: Enable
   - **User data** (optional, if not using systemd):
   ```bash
   #!/bin/bash
   cd /home/ubuntu/formatvideo
   sudo -u ubuntu node backend/worker.js > /var/log/worker.log 2>&1 &
   ```
9. Create launch template

### 3. Create Auto Scaling Group

1. EC2 → Auto Scaling Groups → Create Auto Scaling group
2. **Name**: `video-worker-asg`
3. **Launch template**: Select `video-worker-template`
4. **VPC**: Select your VPC
5. **Subnets**: Select 2-3 availability zones
6. **Load balancing**: None (workers poll SQS directly)
7. **Health checks**: EC2 (turn off ELB)
8. **Group size**:
   - Desired: 1
   - Minimum: 1
   - Maximum: 3
9. **Scaling policies**: None (Lambda will manage)
10. **Instance warmup**: 60 seconds
11. **Tags**: 
    - `Name`: `video-worker`
    - `qut-username`: `n10666630@qut.edu.au`
    - `purpose`: `assignment`
12. Create Auto Scaling group

### 4. Deploy Lambda Function

Package the Lambda:
```bash
cd lambda
npm install
zip -r autoscaler.zip .
```

Create Lambda function in AWS Console:
1. Lambda → Create function
2. **Name**: `video-worker-autoscaler`
3. **Runtime**: Node.js 22.x
4. **Architecture**: arm64
5. **Permissions**: Create new role with:
   - `AWSLambdaBasicExecutionRole`
   - `AutoScalingFullAccess`
   - `AmazonSQSReadOnlyAccess`
   - `CloudWatchFullAccess`
6. Upload `autoscaler.zip`
7. **Handler**: `customAutoscaler.handler`
8. **Timeout**: 30 seconds
9. **Environment variables**:
   - `AUTO_SCALING_GROUP_NAME`: `video-worker-asg`
   - `SQS_QUEUE_URL`: `<your-queue-url>`
   - `AWS_REGION`: `ap-southeast-2`
10. Save

### 5. Create CloudWatch Events Rule

1. CloudWatch → Events → Rules → Create rule
2. **Event Source**: Schedule
3. **Fixed rate**: 1 minute
4. **Targets**: Add target → Lambda function
5. **Function**: `video-worker-autoscaler`
6. Create rule

## Testing

### Test Scale-Out (1 → 3 instances)

```bash
# Run the load test to queue many jobs
node loadtest.js
```

Monitor:
1. CloudWatch → Metrics → VideoProcessing/CustomMetrics
   - Watch `QueueDepth` increase
   - Watch `WorkerInstances` scale from 1 → 2 → 3
2. EC2 → Auto Scaling Groups → video-worker-asg
   - Watch desired capacity increase
3. Lambda → video-worker-autoscaler → Monitor
   - View logs to see scaling decisions

### Test Scale-In (3 → 1 instances)

```bash
# Stop the load test
# Wait for queue to drain
```

After 5-10 minutes:
- Queue depth drops to 0
- Lambda scales down to 1 instance
- Excess instances terminate

### Verify CPU Utilization

While processing:
1. CloudWatch → EC2 → Per-Instance Metrics
2. Check CPU utilization of workers
3. Should see 70-90% CPU during video processing

## CloudWatch Dashboard

Create dashboard to monitor:
- SQS Queue Depth
- Worker Instance Count  
- Messages Per Instance
- CPU Utilization (per worker)
- Processing Rate (jobs/minute)

## Troubleshooting

**Workers not processing jobs:**
```bash
# SSH to worker instance
sudo systemctl status worker
journalctl -u worker -f
```

**Lambda not scaling:**
```bash
# Check Lambda logs in CloudWatch
# Verify IAM permissions
# Check environment variables
```

**Autoscaling too slow:**
- Reduce Lambda schedule from 1min to 30sec
- Adjust `MESSAGES_PER_INSTANCE` threshold
- Disable cooldown period in SetDesiredCapacity

## Cost Optimization

- Lambda: ~$0.20/month (executes every minute)
- Workers: Only pay for 1-3 t2.micro instances when active
- Scales to 1 when idle (minimal cost)

## Assignment Demonstration

**Video should show:**
1. Initial state: 1 worker instance running
2. Start loadtest.js
3. CloudWatch showing queue depth increasing
4. Lambda logs showing scale-up decisions
5. ASG scaling to 2, then 3 instances
6. CPU utilization around 70%+ during processing
7. Stop loadtest
8. Queue draining
9. Lambda logs showing scale-down decision
10. ASG scaling back to 1 instance

**Custom Metric Justification:**
- Queue depth is superior to CPU for async workloads
- Prevents job timeouts and queue buildup
- Scales proactively rather than reactively
- Works regardless of job complexity
