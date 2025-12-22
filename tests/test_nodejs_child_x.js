// Test file for V8 tracing with child process spawning
// Verifies that we can trace binaries spawned by Node.js using different methods
//
// Run with: malwi x -c "js:*" -c simple_target_marker node test_v8_child_spawn.js

const { spawnSync, execSync, execFileSync } = require('child_process');
const path = require('path');

// Get path to simple_target in the same directory
const TARGET_PATH = path.join(__dirname, 'simple_target');

// Test 1: spawnSync - most common method, uses posix_spawn on macOS
function testSpawnSync() {
    console.log('=== Testing spawnSync ===');

    const result = spawnSync(TARGET_PATH, ['from_spawnSync'], {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
    });

    if (result.error) {
        console.error('spawnSync error:', result.error.message);
        return false;
    }

    console.log('spawnSync stdout:', result.stdout.trim());
    console.log('spawnSync exit code:', result.status);
    return result.status === 0;
}

// Test 2: execFileSync - direct execution without shell
function testExecFileSync() {
    console.log('=== Testing execFileSync ===');

    try {
        const stdout = execFileSync(TARGET_PATH, ['from_execFileSync'], {
            encoding: 'utf8'
        });
        console.log('execFileSync stdout:', stdout.trim());
        return true;
    } catch (err) {
        console.error('execFileSync error:', err.message);
        return false;
    }
}

// Test 3: execSync - shell-based execution (wraps in /bin/sh -c)
function testExecSync() {
    console.log('=== Testing execSync ===');

    try {
        // Note: execSync runs through shell, so we need to quote the path
        const stdout = execSync(`"${TARGET_PATH}" from_execSync`, {
            encoding: 'utf8'
        });
        console.log('execSync stdout:', stdout.trim());
        return true;
    } catch (err) {
        console.error('execSync error:', err.message);
        return false;
    }
}

// Main test runner
function runAllTests() {
    console.log('V8 child spawn test starting...');
    console.log('Target binary:', TARGET_PATH);
    console.log('');

    const results = {
        spawnSync: testSpawnSync(),
        execFileSync: testExecFileSync(),
        execSync: testExecSync()
    };

    console.log('');
    console.log('=== Test Results ===');
    for (const [method, passed] of Object.entries(results)) {
        console.log(`${method}: ${passed ? 'PASSED' : 'FAILED'}`);
    }

    const allPassed = Object.values(results).every(r => r);
    console.log('');
    console.log(allPassed ? 'All tests passed!' : 'Some tests failed!');

    return allPassed;
}

// Entry point
function main() {
    const success = runAllTests();
    process.exit(success ? 0 : 1);
}

main();
