// Test file for V8 JavaScript function tracing
// Run with: malwi x -c "js:*" node test_v8.js

// Simple function
function simpleFunction() {
    return 42;
}

// Nested function calls
function outerFunction() {
    return innerFunction();
}

function innerFunction() {
    return deepFunction();
}

function deepFunction() {
    return "deep";
}

// Recursive function
function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// Async function
async function asyncFunction() {
    return new Promise(resolve => {
        setTimeout(() => resolve("async result"), 10);
    });
}

// Arrow functions
const arrowFunction = () => "arrow";
const arrowWithArgs = (a, b) => a + b;

// Class with methods
class TestClass {
    constructor(value) {
        this.value = value;
    }

    getValue() {
        return this.value;
    }

    static staticMethod() {
        return "static";
    }
}

// Generator function
function* generatorFunction() {
    yield 1;
    yield 2;
    yield 3;
}

// Higher-order function
function higherOrder(fn) {
    return fn();
}

// Closure
function createCounter() {
    let count = 0;
    return function increment() {
        return ++count;
    };
}

// Main execution
function main() {
    console.log("Starting V8 tracing test...");

    // Test simple function
    simpleFunction();

    // Test nested calls
    outerFunction();

    // Test recursive calls
    factorial(5);

    // Test arrow functions
    arrowFunction();
    arrowWithArgs(1, 2);

    // Test class
    const obj = new TestClass(100);
    obj.getValue();
    TestClass.staticMethod();

    // Test generator
    const gen = generatorFunction();
    gen.next();
    gen.next();
    gen.next();

    // Test higher-order
    higherOrder(() => "callback");

    // Test closure
    const counter = createCounter();
    counter();
    counter();

    console.log("V8 tracing test completed.");
}

main();
