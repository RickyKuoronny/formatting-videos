#!/bin/bash

# Pre-flight check script for autoscaling setup
# Run this before your demo to ensure everything is configured correctly

set -e

echo "==================================="
echo "Autoscaling Pre-Flight Check"
echo "==================================="
echo ""

# Configuration
ASG_NAME="video-worker-asg"
LAMBDA_NAME="video-worker-autoscaler"
QUEUE_NAME="your-queue-name"  # UPDATE THIS
REGION="ap-southeast-2"

check_mark="✅"
cross_mark="❌"

# Check 1: Auto Scaling Group exists
echo -n "1. Checking Auto Scaling Group exists... "
if aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --region "$REGION" \
    --query 'AutoScalingGroups[0].AutoScalingGroupName' \
    --output text 2>/dev/null | grep -q "$ASG_NAME"; then
    echo "$check_mark"
    
    # Get current state
    ASG_INFO=$(aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$ASG_NAME" \
        --region "$REGION" \
        --query 'AutoScalingGroups[0].[DesiredCapacity,MinSize,MaxSize,Instances[?LifecycleState==`InService`]|length(@)]' \
        --output text)
    
    read DESIRED MIN MAX RUNNING <<< "$ASG_INFO"
    echo "   - Desired: $DESIRED, Min: $MIN, Max: $MAX, Running: $RUNNING"
    
    if [ "$DESIRED" -ne 1 ]; then
        echo "   $cross_mark Warning: Desired capacity should be 1 for demo start"
    fi
else
    echo "$cross_mark NOT FOUND"
    echo "   Create ASG first! See AUTOSCALING_SETUP.md"
    exit 1
fi

# Check 2: Lambda function exists
echo -n "2. Checking Lambda function exists... "
if aws lambda get-function \
    --function-name "$LAMBDA_NAME" \
    --region "$REGION" \
    --query 'Configuration.FunctionName' \
    --output text 2>/dev/null | grep -q "$LAMBDA_NAME"; then
    echo "$check_mark"
    
    # Check environment variables
    ENV_VARS=$(aws lambda get-function-configuration \
        --function-name "$LAMBDA_NAME" \
        --region "$REGION" \
        --query 'Environment.Variables' \
        --output json 2>/dev/null)
    
    echo "   Environment variables:"
    echo "$ENV_VARS" | jq -r 'to_entries[] | "     - \(.key): \(.value)"'
else
    echo "$cross_mark NOT FOUND"
    echo "   Deploy Lambda function! See AUTOSCALING_SETUP.md"
    exit 1
fi

# Check 3: CloudWatch Events Rule
echo -n "3. Checking CloudWatch Events Rule... "
RULE_NAME=$(aws events list-rules \
    --region "$REGION" \
    --query "Rules[?contains(Targets[0].Arn, '$LAMBDA_NAME')].Name" \
    --output text 2>/dev/null)

if [ -n "$RULE_NAME" ]; then
    echo "$check_mark"
    echo "   - Rule: $RULE_NAME"
    
    SCHEDULE=$(aws events describe-rule \
        --name "$RULE_NAME" \
        --region "$REGION" \
        --query 'ScheduleExpression' \
        --output text 2>/dev/null)
    echo "   - Schedule: $SCHEDULE"
else
    echo "$cross_mark NOT FOUND"
    echo "   Create CloudWatch Events Rule to trigger Lambda!"
    exit 1
fi

# Check 4: SQS Queue
echo -n "4. Checking SQS Queue... "
QUEUE_URL=$(aws sqs list-queues \
    --region "$REGION" \
    --query "QueueUrls[?contains(@, '$QUEUE_NAME')]|[0]" \
    --output text 2>/dev/null)

if [ -n "$QUEUE_URL" ] && [ "$QUEUE_URL" != "None" ]; then
    echo "$check_mark"
    echo "   - URL: $QUEUE_URL"
    
    QUEUE_ATTRS=$(aws sqs get-queue-attributes \
        --queue-url "$QUEUE_URL" \
        --attribute-names ApproximateNumberOfMessages \
        --region "$REGION" \
        --query 'Attributes.ApproximateNumberOfMessages' \
        --output text 2>/dev/null)
    
    echo "   - Messages in queue: $QUEUE_ATTRS"
    
    if [ "$QUEUE_ATTRS" -gt 0 ]; then
        echo "   $cross_mark Warning: Queue should be empty for demo start"
    fi
else
    echo "$cross_mark NOT FOUND"
    echo "   Check QUEUE_NAME variable in this script"
fi

# Check 5: IAM Permissions
echo -n "5. Checking Lambda IAM permissions... "
LAMBDA_ROLE=$(aws lambda get-function \
    --function-name "$LAMBDA_NAME" \
    --region "$REGION" \
    --query 'Configuration.Role' \
    --output text 2>/dev/null)

ROLE_NAME=$(basename "$LAMBDA_ROLE")

# Check if role has AutoScaling policy
if aws iam list-attached-role-policies \
    --role-name "$ROLE_NAME" \
    --query "AttachedPolicies[?contains(PolicyName, 'AutoScaling')]" \
    --output text 2>/dev/null | grep -q .; then
    echo "$check_mark"
    echo "   - Role: $ROLE_NAME"
else
    echo "$cross_mark Missing AutoScaling permissions"
    echo "   Attach AutoScalingFullAccess policy to Lambda role"
fi

# Check 6: Worker Instance IAM Role
echo -n "6. Checking worker instance permissions... "
LAUNCH_TEMPLATE=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --region "$REGION" \
    --query 'AutoScalingGroups[0].LaunchTemplate.LaunchTemplateName' \
    --output text 2>/dev/null)

if [ -n "$LAUNCH_TEMPLATE" ] && [ "$LAUNCH_TEMPLATE" != "None" ]; then
    echo "$check_mark"
    echo "   - Launch template: $LAUNCH_TEMPLATE"
    
    # Note: Checking instance profile requires running instance
    echo "   - Note: Verify instance has SQS, S3, DynamoDB access"
else
    echo "$cross_mark Launch template not found"
fi

# Check 7: CloudWatch Custom Metrics
echo -n "7. Checking CloudWatch custom metrics... "
METRICS=$(aws cloudwatch list-metrics \
    --namespace "VideoProcessing/CustomMetrics" \
    --region "$REGION" \
    --query 'Metrics[].MetricName' \
    --output text 2>/dev/null)

if [ -n "$METRICS" ]; then
    echo "$check_mark"
    echo "   - Metrics: $METRICS"
else
    echo "⚠️  No metrics yet (will appear after first Lambda run)"
fi

# Check 8: Test connectivity
echo -n "8. Testing API endpoint... "
API_ENDPOINT="https://maple.web.cab432.com/health"
if curl -s -o /dev/null -w "%{http_code}" "$API_ENDPOINT" | grep -q "200"; then
    echo "$check_mark"
else
    echo "$cross_mark Cannot reach API"
fi

echo ""
echo "==================================="
echo "Summary"
echo "==================================="
echo ""

if [ "$DESIRED" -eq 1 ] && [ "$RUNNING" -eq 1 ] && [ "${QUEUE_ATTRS:-0}" -eq 0 ]; then
    echo "$check_mark All checks passed! Ready for demo."
    echo ""
    echo "Next steps:"
    echo "  1. Open AWS Console to Auto Scaling Groups page"
    echo "  2. Open CloudWatch Metrics dashboard"
    echo "  3. Run: node loadtest.js"
    echo "  4. Watch the magic happen!"
else
    echo "⚠️  Some warnings detected. Review above."
    echo ""
    echo "To reset for demo:"
    echo "  - Set ASG desired capacity to 1"
    echo "  - Purge SQS queue"
    echo "  - Wait 2 minutes for stabilization"
fi

echo ""
