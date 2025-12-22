/**
 * HTTP library test script for malwi integration tests.
 *
 * Each function makes one HTTP request using a specific library.
 * The target URL is passed as the first argument.
 *
 * Usage: node test_http.js <url> <library>
 *   library: http | https | axios | got | node-fetch
 */

const url = process.argv[2];
const library = process.argv[3];

if (!url || !library) {
  console.log('Usage: node test_http.js <url> <library>');
  process.exit(1);
}

function testHttp(targetUrl) {
  return new Promise((resolve, reject) => {
    const http = require('http');
    http.get(targetUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        console.log('http:', res.statusCode);
        resolve();
      });
    }).on('error', reject);
  });
}

function testHttps(targetUrl) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    https.get(targetUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        console.log('https:', res.statusCode);
        resolve();
      });
    }).on('error', reject);
  });
}

async function testAxios(targetUrl) {
  const axios = require('axios');
  const resp = await axios.get(targetUrl);
  console.log('axios:', resp.status);
}

async function testGot(targetUrl) {
  const got = require('got');
  const resp = await got(targetUrl);
  console.log('got:', resp.statusCode);
}

async function testNodeFetch(targetUrl) {
  const fetch = require('node-fetch');
  const resp = await fetch(targetUrl);
  console.log('node-fetch:', resp.status);
}

const dispatch = {
  'http': testHttp,
  'https': testHttps,
  'axios': testAxios,
  'got': testGot,
  'node-fetch': testNodeFetch,
};

const fn = dispatch[library];
if (!fn) {
  console.log('Unknown library:', library);
  process.exit(1);
}

fn(url).catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
