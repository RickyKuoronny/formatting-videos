const { AutoScalingClient, SetDesiredCapacityCommand, DescribeAutoScalingGroupsCommand } = require('@aws-sdk/client-auto-scaling');
const { SQSClient, GetQueueAttributesCommand } = require('@aws-sdk/client-sqs');
const { CloudWatchClient, PutMetricDataCommand } = require('@aws-sdk/client-cloudwatch');

const autoScalingClient = new AutoScalingClient({ region: 'ap-southeast-2' });
const sqsClient = new SQSClient({ region: 'ap-southeast-2' });
const cloudWatchClient = new CloudWatchClient({ region: 'ap-southeast-2' });

const AUTO_SCALING_GROUP_NAME = "n11036583-web-auto";
const QUEUE_URL = "https://sqs.ap-southeast-2.amazonaws.com/901444280953/a3-group41-queue";

// Configuration
const MESSAGES_PER_INSTANCE = 5; // Target: 5 messages per worker instance
const MIN_INSTANCES = 1;
const MAX_INSTANCES = 3;
const SCALE_UP_THRESHOLD = 10; // Scale up if queue has more than this
const SCALE_DOWN_THRESHOLD = 2; // Scale down if queue has less than this

/**
 * Lambda function to implement custom autoscaling based on SQS queue depth
 * This is more appropriate than CPU utilization for async job processing
 * 
 * Why this is better than CPU-based scaling:
 * - Queue depth is a leading indicator (CPU is lagging)
 * - Prevents queue buildup during traffic spikes
 * - More predictable scaling behavior
 * - Works regardless of job complexity/duration
 */
exports.handler = async (event) => {
  console.log('Custom autoscaling check triggered');

  try {
    // 1. Get current queue depth
    const queueAttributes = await sqsClient.send(new GetQueueAttributesCommand({
      QueueUrl: QUEUE_URL,
      AttributeNames: ['ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible']
    }));

    const messagesAvailable = parseInt(queueAttributes.Attributes.ApproximateNumberOfMessages || '0');
    const messagesInFlight = parseInt(queueAttributes.Attributes.ApproximateNumberOfMessagesNotVisible || '0');
    const totalMessages = messagesAvailable + messagesInFlight;

    console.log(`Queue status: ${messagesAvailable} available, ${messagesInFlight} in-flight, ${totalMessages} total`);

    // 2. Get current ASG status
    const asgResponse = await autoScalingClient.send(new DescribeAutoScalingGroupsCommand({
      AutoScalingGroupNames: [AUTO_SCALING_GROUP_NAME]
    }));

    const asg = asgResponse.AutoScalingGroups[0];
    if (!asg) {
      throw new Error(`Auto Scaling Group ${AUTO_SCALING_GROUP_NAME} not found`);
    }

    const currentCapacity = asg.DesiredCapacity;
    const inServiceInstances = asg.Instances.filter(i => i.LifecycleState === 'InService').length;

    console.log(`ASG status: desired=${currentCapacity}, in-service=${inServiceInstances}, min=${MIN_INSTANCES}, max=${MAX_INSTANCES}`);

    // 3. Calculate desired capacity based on queue depth
    let desiredCapacity = Math.ceil(totalMessages / MESSAGES_PER_INSTANCE);
    
    // Apply constraints
    desiredCapacity = Math.max(MIN_INSTANCES, Math.min(MAX_INSTANCES, desiredCapacity));

    // Add hysteresis to prevent flapping
    if (desiredCapacity === currentCapacity) {
      console.log('Desired capacity matches current capacity. No scaling needed.');
    } else if (desiredCapacity > currentCapacity && totalMessages > SCALE_UP_THRESHOLD) {
      console.log(`Scaling UP: ${currentCapacity} → ${desiredCapacity} (queue depth: ${totalMessages})`);
      await autoScalingClient.send(new SetDesiredCapacityCommand({
        AutoScalingGroupName: AUTO_SCALING_GROUP_NAME,
        DesiredCapacity: desiredCapacity,
        HonorCooldown: false
      }));
    } else if (desiredCapacity < currentCapacity && totalMessages < SCALE_DOWN_THRESHOLD) {
      console.log(`Scaling DOWN: ${currentCapacity} → ${desiredCapacity} (queue depth: ${totalMessages})`);
      await autoScalingClient.send(new SetDesiredCapacityCommand({
        AutoScalingGroupName: AUTO_SCALING_GROUP_NAME,
        DesiredCapacity: desiredCapacity,
        HonorCooldown: true // Respect cooldown when scaling down
      }));
    } else {
      console.log(`Hysteresis: not scaling (current=${currentCapacity}, calculated=${desiredCapacity}, messages=${totalMessages})`);
    }

    // 4. Publish custom metric to CloudWatch for monitoring
    await cloudWatchClient.send(new PutMetricDataCommand({
      Namespace: 'VideoProcessing/CustomMetrics',
      MetricData: [
        {
          MetricName: 'QueueDepth',
          Value: totalMessages,
          Unit: 'Count',
          Timestamp: new Date()
        },
        {
          MetricName: 'MessagesPerInstance',
          Value: inServiceInstances > 0 ? totalMessages / inServiceInstances : 0,
          Unit: 'Count',
          Timestamp: new Date()
        },
        {
          MetricName: 'WorkerInstances',
          Value: inServiceInstances,
          Unit: 'Count',
          Timestamp: new Date()
        }
      ]
    }));

    return {
      statusCode: 200,
      body: JSON.stringify({
        queueDepth: totalMessages,
        currentCapacity,
        desiredCapacity,
        messagesPerInstance: inServiceInstances > 0 ? (totalMessages / inServiceInstances).toFixed(2) : 0
      })
    };

  } catch (error) {
    console.error('Error in custom autoscaling:', error);
    throw error;
  }
};
