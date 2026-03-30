// V8 Introspection Addon — Minimal N-API Entry Point
//
// This addon provides V8 stack parsing and value introspection functions
// accessed via dlopen/dlsym from the Rust agent. The actual tracing is
// handled by frida-gum hooks, not N-API wrapping.
//
// The N-API Init function is required by node-gyp but does not export
// any JavaScript-callable functions. All useful symbols are extern "C"
// functions in stack_parser.cc, resolved via dlsym at runtime.

#include <node_api.h>

static napi_value Init(napi_env env, napi_value exports) {
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
