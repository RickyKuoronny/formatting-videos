# Quick Demo Guide - Autoscaling

## Pre-Demo Checklist

- [ ] 1 worker instance running in ASG
- [ ] Lambda function deployed and scheduled (1 min)
- [ ] CloudWatch dashboard created
- [ ] SQS queue empty
- [ ] Load test script ready

## Demo Script (5-7 minutes)

### 1. Show Initial State (30 sec)
```
AWS Console → Auto Scaling Groups → video-worker-asg
- Desired capacity: 1
- Running instances: 1
- Activity history: stable
```

### 2. Show Empty Queue (15 sec)
```
AWS Console → SQS → your-queue
- Messages available: 0
```

### 3. Start Load Test (15 sec)
```bash
cd formatting-videos
node loadtest.js
# Should show: "Starting load test... ✓ Authenticated"
```

### 4. Show Queue Building Up (1 min)
```
Refresh SQS console
- Messages available: 10... 20... 30... (increasing)

CloudWatch → Metrics → VideoProcessing/CustomMetrics
- QueueDepth chart shows spike
```

### 5. Show Lambda Scaling Decision (1 min)
```
Lambda → video-worker-autoscaler → Monitor → View logs
Recent log entries show:
  "Scaling UP: 1 → 2 (queue depth: 25)"
  "Scaling UP: 2 → 3 (queue depth: 40)"
```

### 6. Show ASG Scaling Out (1 min)
```
Auto Scaling Groups → video-worker-asg → Activity
- "Launching new instance..." (x2)

Instance management tab
- Shows 2-3 instances launching/running
```

### 7. Show Worker CPU Utilization (30 sec)
```
CloudWatch → EC2 → Per-Instance Metrics → CPUUtilization
- Each worker showing 70-90% CPU
- "This is the CPU intensive video processing"
```

### 8. Stop Load Test (15 sec)
```bash
# Ctrl+C to stop loadtest.js
# Or let it finish the 100 requests
```

### 9. Show Queue Draining (1 min)
```
SQS console
- Messages available: decreasing... 5... 3... 0

CloudWatch → VideoProcessing/CustomMetrics
- QueueDepth returning to 0
- WorkerInstances still at 3
```

### 10. Show Scale-In Decision (1-2 min)
```
Wait for next Lambda execution...

Lambda logs:
  "Scaling DOWN: 3 → 1 (queue depth: 0)"

ASG Activity:
  "Terminating instance..."
  
Final state: 1 worker instance
```

## Key Points to Explain

### Custom Metric Advantage
"We're using **queue depth** instead of CPU because:
- ✅ **Faster**: Sees load spike immediately (leading indicator)
- ✅ **Prevents timeouts**: Scales before jobs get stuck
- ✅ **Predictable**: Clear math (queue_depth / 5 = needed workers)
- ❌ CPU is lagging: Only reacts after jobs start processing"

### Lambda Justification
"Lambda is perfect for this because:
- ✅ Lightweight monitoring (runs every minute)
- ✅ Event-driven by CloudWatch schedule
- ✅ No persistent state needed
- ✅ Cost-effective ($0.20/month)
- ❌ NOT used for video processing (that's CPU intensive)"

### EC2 Configuration
"Workers are t2.micro because:
- ✅ Single CPU (Node.js is single-threaded)
- ✅ Unlimited credit (no burst limitations)
- ✅ Detailed monitoring (1-min intervals)"

## Backup: Manual Trigger

If Lambda doesn't auto-scale fast enough:

```bash
# Manually invoke Lambda
aws lambda invoke \
  --function-name video-worker-autoscaler \
  --region ap-southeast-2 \
  /tmp/output.json

cat /tmp/output.json
```

## CloudWatch Dashboard Layout

```
Row 1: Queue Metrics
- [QueueDepth] [MessagesPerInstance]

Row 2: Worker Metrics  
- [WorkerInstances] [CPU Utilization]

Row 3: Activity
- [ASG Activity] [Lambda Invocations]
```

## Common Issues

**Queue not filling fast enough:**
- Edit loadtest.js: reduce `delayBetweenRequests` to 500ms
- Increase `numberOfRequests` to 500

**Scaling too slow:**
- Manually invoke Lambda (see backup above)
- Check Lambda has correct permissions

**Workers not processing:**
```bash
# SSH to worker
ssh -i your-key.pem ubuntu@<worker-ip>
sudo systemctl status worker
journalctl -u worker -f
```

**Lambda errors:**
- Check environment variables are set
- Verify IAM role has AutoScaling permissions
- Check CloudWatch Logs for error details

## Success Criteria

✅ Demonstrated 1 → 3 scale-out  
✅ CPU utilization 70%+ during processing  
✅ No service interruptions  
✅ Demonstrated 3 → 1 scale-in  
✅ Custom metric explained clearly  
✅ Lambda purpose justified  

## Timing Tips

- Queue fills in ~30 seconds
- First Lambda check at 1 minute mark
- New instances launch in ~60 seconds
- Total scale-out demo: ~3 minutes
- Scale-in takes 2-3 minutes after queue empty
