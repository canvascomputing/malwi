// Test script for V8 Stack Parser
//
// This tests the stack parser's ability to detect JavaScript parameter types
// by reading directly from V8 stack frames using the Isolate's ThreadLocalTop.

const addon = require('./build/Release/v8_introspect.node');

console.log('=== V8 Stack Parser Test ===\n');

// Test function that calls the stack parser and logs results
function testWithArgs(...args) {
    const result = addon.testStackParser();
    return result;
}

// Helper to format BigInt values for display
function formatResult(result) {
    const formatted = { ...result };
    if (result.isolate) {
        formatted.isolate = '0x' + result.isolate.toString(16);
    }
    if (result.framePointer) {
        formatted.framePointer = '0x' + result.framePointer.toString(16);
    }
    return formatted;
}

// Test 1: No arguments
console.log('Test 1: No arguments');
let result = testWithArgs();
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 2: Single integer
console.log('Test 2: Single integer (42)');
result = testWithArgs(42);
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 3: String argument
console.log('Test 3: String argument');
result = testWithArgs("hello");
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 4: Multiple arguments of different types
console.log('Test 4: Multiple arguments (42, "hello", true, null, {}, [])');
result = testWithArgs(42, "hello", true, null, {}, []);
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 5: Nested function call
console.log('Test 5: Nested function call');
function outerFunc(a, b, c) {
    return addon.testStackParser();
}
result = outerFunc(1, "two", { three: 3 });
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 6: Array and Object
console.log('Test 6: Array and Object');
result = testWithArgs([1, 2, 3], { key: "value" });
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 7: BigInt (if supported)
console.log('Test 7: BigInt');
try {
    result = testWithArgs(BigInt(9007199254740991));
    console.log('Result:', JSON.stringify(formatResult(result), null, 2));
} catch (e) {
    console.log('BigInt test skipped:', e.message);
}
console.log();

// Test 8: undefined
console.log('Test 8: undefined');
result = testWithArgs(undefined);
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Test 9: Function argument
console.log('Test 9: Function argument');
result = testWithArgs(function myFunc() {});
console.log('Result:', JSON.stringify(formatResult(result), null, 2));
console.log();

// Summary
console.log('=== Test Complete ===');
console.log('Platform:', result.platform);
