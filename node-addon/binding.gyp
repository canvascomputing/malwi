{
  "targets": [{
    "target_name": "v8_introspect",
    "sources": [
      "src/binding.cc",
      "src/v8-internal/stack_parser.cc"
    ],
    "include_dirs": ["src"],
    "cflags!": ["-fno-exceptions"],
    "cflags_cc!": ["-fno-exceptions"],
    "cflags_cc": ["-std=c++20"],
    "conditions": [
      ["OS=='mac'", {
        "cflags_cc": ["-std=c++20", "-stdlib=libc++"],
        "xcode_settings": {
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
          "CLANG_CXX_LIBRARY": "libc++",
          "CLANG_CXX_LANGUAGE_STANDARD": "c++20",
          "MACOSX_DEPLOYMENT_TARGET": "10.15",
          "OTHER_CPLUSPLUSFLAGS": [
            "-stdlib=libc++",
            "-cxx-isystem",
            "<!@(xcrun --show-sdk-path)/usr/include/c++/v1"
          ],
          "OTHER_LDFLAGS": [
            "-stdlib=libc++",
            "-Wl,-no_weak_imports"
          ]
        }
      }],
      ["OS=='linux'", {
        "cflags_cc": ["-std=c++20"],
        "libraries": [
          "-lpthread", "-ldl"
        ]
      }]
    ]
  }]
}
