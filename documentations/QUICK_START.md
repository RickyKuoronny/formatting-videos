# Quick Start - Autoscaling Setup

## TL;DR - 30 Minute Setup

### Prerequisites
- ✅ Working API server on EC2
- ✅ SQS queue created
- ✅ S3 bucket configured
- ✅ DynamoDB table ready

### Step 1: Prepare Worker (10 min)

SSH to your API server:
```bash
ssh -i your-key.pem ubuntu@your-ec2-ip

cd ~/formatvideo

# Make worker script executable
chmod +x start-worker.sh

# Install worker service
sudo cp worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable worker
sudo systemctl start worker

# Verify it's running
sudo systemctl status worker
journalctl -u worker -f  # Ctrl+C to exit

# Test: Send a job via API, watch worker logs process it

# Create AMI
# AWS Console → EC2 → Your Instance → Actions → Create Image
# Name: video-worker-v1
```

### Step 2: Create Launch Template (5 min)

AWS Console → EC2 → Launch Templates → Create:

```yaml
Name: video-worker-template
AMI: video-worker-v1 (from Step 1)
Instance Type: t2.micro
Key Pair: your-keypair
Security Group: your-security-group
IAM Role: (needs SQS, S3, DynamoDB, Secrets Manager access)

Advanced Details:
  Credit Specification: Unlimited
  Detailed Monitoring: Enable
```

### Step 3: Create Auto Scaling Group (5 min)

AWS Console → EC2 → Auto Scaling Groups → Create:

```yaml
Name: video-worker-asg
Launch Template: video-worker-template
VPC: your-vpc
Subnets: Select 2-3 AZs
Load Balancing: None
Health Checks: EC2 only

Group Size:
  Desired: 1
  Min: 1
  Max: 3

Scaling Policies: None (Lambda will manage)
Instance Warmup: 60 seconds

Tags:
  Name: video-worker
  qut-username: n10666630@qut.edu.au
  purpose: assignment
```

### Step 4: Deploy Lambda (7 min)

```bash
cd lambda
npm install
zip -r autoscaler.zip .
```

AWS Console → Lambda → Create Function:

```yaml
Name: video-worker-autoscaler
Runtime: Node.js 22.x
Architecture: arm64
Permissions: Create new role with:
  - AWSLambdaBasicExecutionRole
  - AutoScalingFullAccess
  - AmazonSQSReadOnlyAccess  
  - CloudWatchFullAccess

Upload: autoscaler.zip
Handler: customAutoscaler.handler
Timeout: 30 seconds

Environment Variables:
  AUTO_SCALING_GROUP_NAME: video-worker-asg
  SQS_QUEUE_URL: https://sqs.ap-southeast-2.amazonaws.com/.../your-queue
  AWS_REGION: ap-southeast-2
```

### Step 5: Schedule Lambda (3 min)

AWS Console → CloudWatch → Events → Rules → Create:

```yaml
Name: trigger-autoscaler
Event Source: Schedule
Rate: 1 minute
Target: Lambda function → video-worker-autoscaler
```

### Step 6: Test! (5 min)

```bash
# On your local machine
cd formatting-videos
node loadtest.js
```

Watch in AWS Console:
1. SQS → Queue messages increase
2. Lambda → Logs show "Scaling UP"
3. ASG → Instances launch (1 → 2 → 3)
4. CloudWatch → CPU at 70%+
5. Wait 5 min → Scales back to 1

## Verification Commands

```bash
# Check worker is running
ssh ubuntu@worker-ip 'sudo systemctl status worker'

# Test Lambda manually
aws lambda invoke \
  --function-name video-worker-autoscaler \
  --region ap-southeast-2 \
  /tmp/result.json
cat /tmp/result.json

# Check ASG status
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names video-worker-asg \
  --region ap-southeast-2 \
  --query 'AutoScalingGroups[0].[DesiredCapacity,Instances[].InstanceId]'

# Check queue
aws sqs get-queue-attributes \
  --queue-url YOUR_QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages \
  --region ap-southeast-2
```

## Common Issues

**Worker not starting:**
```bash
sudo journalctl -u worker -n 50
# Check for missing environment variables
# Verify secrets are accessible
```

**Lambda not scaling:**
- Check environment variables are set
- Verify IAM permissions
- Check CloudWatch Logs for errors

**ASG not launching instances:**
- Verify Launch Template AMI exists
- Check instance limits in AWS account
- Review ASG Activity History for errors

## Success Criteria

✅ 1 worker running initially  
✅ Load test sends 100+ jobs  
✅ Queue builds to 30+ messages  
✅ Lambda scales to 3 workers  
✅ Workers show 70%+ CPU  
✅ Queue drains  
✅ Scales back to 1 worker  

## Files You Need

From your repo:
- `backend/worker.js` ✅ (already exists)
- `worker.service` ✅ (new)
- `start-worker.sh` ✅ (new)
- `lambda/customAutoscaler.js` ✅ (new)
- `lambda/package.json` ✅ (new)
- `loadtest.js` ✅ (already configured)

Documentation:
- `AUTOSCALING_SETUP.md` - Detailed guide
- `DEMO_GUIDE.md` - Demo script
- `ARCHITECTURE.md` - Architecture explanation
- `QUICK_START.md` - This file

## Time Estimate

- Setup: 30 minutes
- Testing: 15 minutes
- Demo recording: 10 minutes
- **Total: ~1 hour**

## Help

See detailed guides:
- Setup problems → `AUTOSCALING_SETUP.md`
- Demo preparation → `DEMO_GUIDE.md`
- Architecture questions → `ARCHITECTURE.md`

Run pre-flight check:
```bash
bash preflight-check.sh
```
