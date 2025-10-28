const endpoint = "https://maple.web.cab432.com";
const convertEndpoint = `${endpoint}/convert`;
const numberOfRequests = 100; // Reduced for gradual scaling
const targetResponseTime = 1800;
const targetTimeHysteresis = 1.2;
const minTargetConcurrentRequests = 1; // Start with just 1
const maxTargetConcurrentRequests = 3; // Max 3 to trigger gradual scale-out
const rollingAveragePastWeight = 0.95;
const scaleoutTime = 30000; // Wait 30s between scaling decisions (increased from 10s)
const testResolution = "640x360"; // 360p for testing
const delayBetweenRequests = 2000; // 2 second delay between each request

// Bypass key authentication
let authToken = 'ricky-is-awesome';

// Generate a small test video buffer (minimal MP4)
function generateTestVideoBuffer() {
   // Minimal valid MP4 file header (ftyp + mdat boxes)
   const ftypBox = new Uint8Array([
      0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, // ftyp box
      0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00, 0x02, 0x00,
      0x69, 0x73, 0x6F, 0x6D, 0x69, 0x73, 0x6F, 0x32,
      0x61, 0x76, 0x63, 0x31, 0x6D, 0x70, 0x34, 0x31,
   ]);
   const mdatBox = new Uint8Array([
      0x00, 0x00, 0x00, 0x08, 0x6D, 0x64, 0x61, 0x74 // minimal mdat box
   ]);
   
   const buffer = new Uint8Array(ftypBox.length + mdatBox.length);
   buffer.set(ftypBox, 0);
   buffer.set(mdatBox, ftypBox.length);
   
   return new Blob([buffer], { type: 'video/mp4' });
}

const rollingAverageCurrentWeight = 1 - rollingAveragePastWeight;
var currentRequests = 0;
var targetConcurrentRequests = minTargetConcurrentRequests;
var rollingAverage = targetResponseTime;
var lastScaleoutTime = performance.now();

// Helper function to pause for a time but keep the event loop free to do other things
function sleep(ms) {
   return new Promise((resolve) => {
      setTimeout(resolve, ms);
   });
}

// Authenticate using bypass key
async function authenticate() {
   try {
      const response = await fetch(`${endpoint}/auth/key-login`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ key: 'ricky-is-awesome' })
      });
      
      if (!response.ok) {
         throw new Error(`Authentication failed: ${response.status}`);
      }
      
      const data = await response.json();
      authToken = data.tokens.idToken;
      console.log('✓ Authenticated successfully with bypass key');
      return true;
   } catch (error) {
      console.error('✗ Authentication failed:', error.message);
      return false;
   }
}

// Helper function to create a non-blocking fetch request which reports timing
function makeRequest(requestNumber) {
   currentRequests += 1;
   return new Promise((res) => {
      console.log(`Request ${requestNumber} started, currently ${currentRequests} outstanding, target ${targetConcurrentRequests} requests.`);
      const startTime = performance.now();
      
      // Create FormData with test video
      const formData = new FormData();
      const testVideo = generateTestVideoBuffer();
      formData.append('video', testVideo, `test-video-${requestNumber}.mp4`);
      formData.append('resolution', testResolution);
      
      const headers = {
         method: "POST",
         headers: { 'Authorization': `Bearer ${authToken}` },
         body: formData
      };
      
      fetch(convertEndpoint, headers).then((res) => {
         if (!res.ok) {
            console.error(
               `Request ${requestNumber} failed with status: ${res.status}`
            );
            currentRequests -= 1;
            return;
         }
         
         // Calculate a rolling average, weighted towards the most recent requests
         const responseTime = performance.now() - startTime;
         rollingAverage = rollingAverage * rollingAveragePastWeight + responseTime * rollingAverageCurrentWeight;
         
         // Print out some status information
         console.log(
            `Request ${requestNumber} completed in ${responseTime.toFixed(2)}ms, rolling average ${rollingAverage.toFixed(2)}ms.`
         );
         
         // Scale the target number of concurrent requests to keep the rolling average close to the target response time
         // Limit how quickly we scale
         if (performance.now() > scaleoutTime + lastScaleoutTime) {
            // Reduce concurrent requests if rolling average is too big
            if (currentRequests <= targetConcurrentRequests && rollingAverage > targetResponseTime * targetTimeHysteresis) {
               targetConcurrentRequests -= 1;
               lastScaleoutTime = performance.now();
               if (targetConcurrentRequests < minTargetConcurrentRequests) {
                  targetConcurrentRequests = minTargetConcurrentRequests;
               }
            // Increase concurrent requests if rolling average is too low
            } else if (currentRequests >= targetConcurrentRequests && rollingAverage < targetResponseTime  / targetTimeHysteresis) {
               targetConcurrentRequests += 1;
               lastScaleoutTime = performance.now();
               if (targetConcurrentRequests > maxTargetConcurrentRequests) {
                  targetConcurrentRequests = maxTargetConcurrentRequests;
               }            
            }
         }

         currentRequests -= 1;

      }).catch((error) => {
         console.error(`Request ${requestNumber} network error:`, error.message);
         currentRequests -= 1;
      });
   });
}

// Make a bunch of non-blocking requests, up to the target number of concurrent requests
async function loadTest() {
   console.log('Starting load test...');
   
   // Authenticate first
   const authenticated = await authenticate();
   if (!authenticated) {
      console.error('Failed to authenticate. Aborting load test.');
      return;
   }
   
   console.log(`Sending ${numberOfRequests} video conversion requests to ${convertEndpoint}`);
   console.log(`Test resolution: ${testResolution}`);
   console.log(`Fixed delay between requests: ${delayBetweenRequests}ms`);
   console.log(`Max concurrent: ${maxTargetConcurrentRequests}`);
   
   for (let i = 0; i < numberOfRequests; i++) {
      makeRequest(i);
      
      // Add a fixed delay between each request to slow down the rate
      await sleep(delayBetweenRequests);

      while (currentRequests >= targetConcurrentRequests ) {
	      await sleep(10);
      }
   }
   
   console.log('All requests initiated. Waiting for completion...');
}

loadTest();