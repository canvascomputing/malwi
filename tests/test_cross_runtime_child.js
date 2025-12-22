// Child script for cross-runtime test
// Called by Python to demonstrate cross-runtime tracing

const fs = require('fs');

// A traced JavaScript function
function traced_js_entry(message) {
    console.log('JS: ' + message);
    return nested_js_call();
}

function nested_js_call() {
    // This will trigger native fs calls that can also be traced
    // Use /etc/passwd which exists on all Unix systems
    const content = fs.readFileSync('/etc/passwd', 'utf8').split('\n')[0];
    console.log('JS: Read first line of /etc/passwd');
    return content;
}

// Entry point
const arg = process.argv[2] || 'default';
console.log('JS child started with arg:', arg);
traced_js_entry('Hello from nested JS: ' + arg);
console.log('JS child complete');
