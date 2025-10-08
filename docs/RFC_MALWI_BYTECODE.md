# RFC: Malwi Bytecode Standard

**Status:** Living Standard
**Version:** 1.0
**Last Updated:** 2025-10-08

---

## Table of Contents

1. [Abstract](#abstract)
2. [Motivation](#motivation)
3. [Design Goals](#design-goals)
4. [Specification](#specification)
   - [OpCode Enumeration](#opcode-enumeration)
   - [Instruction Format](#instruction-format)
   - [Argument Mapping](#argument-mapping)
5. [OpCode Reference](#opcode-reference)
6. [Code Object Model](#code-object-model)
7. [String Tokenization](#string-tokenization)

---

## Abstract

Malwi Bytecode is a **language-independent intermediate representation** for code analysis. It normalizes source code from multiple programming languages into a unified bytecode format with standardized instructions and argument mappings.

---

## Motivation

### Problem Statement

Source code analysis across multiple programming languages faces several challenges:

1. **Language Diversity**: Code appears in multiple programming languages with different syntaxes
2. **Syntactic Variation**: Identical logic can be expressed in countless syntactic forms
3. **Obfuscation**: Variable renaming and structural transformations obscure semantic meaning
4. **Context Loss**: Token-based approaches lose critical semantic information from program structure

### Solution: Malwi Bytecode

Malwi Bytecode addresses these challenges through:

- **Language Unification**: Single intermediate representation for multiple source languages
- **Semantic Preservation**: Structure-aware compilation retains program organization and control flow
- **Normalization**: Consistent representation of equivalent operations across languages

---

## Design Goals

1. **Language Independence**: Support multiple source languages through unified bytecode
2. **Semantic Richness**: Preserve control flow, data structures, and function semantics
3. **Human Readability**: Maintain debuggability through readable instruction format
4. **Extensibility**: Support new opcodes and languages without breaking compatibility

---

## Specification

### OpCode Enumeration

The bytecode standard defines **71+ operations** grouped into functional categories:

#### Load/Store Operations (13 opcodes)
Operations for loading and storing values in different scopes:

```
LOAD_CONST       # Load constant value
LOAD_NAME        # Load variable by name
LOAD_GLOBAL      # Load global variable
LOAD_PARAM       # Load function parameter
LOAD_ATTR        # Load attribute
LOAD_FAST        # Load local variable
LOAD_DEREF       # Load closure variable
LOAD_BUILD_CLASS # Load class builder
STORE_NAME       # Store value in variable
STORE_GLOBAL     # Store value in global variable
STORE_ATTR       # Store attribute
STORE_SUBSCR     # Store subscript
STORE_FAST       # Store local variable
STORE_DEREF      # Store closure variable
```

**Design Rationale:**
- Distinguishes between local, global, parameter, and closure scopes
- Enables scope-specific pattern analysis

#### Binary Operations (6 opcodes)
```
BINARY_ADD                 # Addition
BINARY_UNSIGNED_RSHIFT     # Unsigned right shift
BINARY_NULLISH_COALESCING  # Nullish coalescing
BINARY_SUBSCR              # Subscript access
BINARY_OP                  # Generic binary operation with argument
BINARY_OPERATION           # Generic binary operation placeholder
```

**BINARY_OP Numeric Arguments:**
The `BINARY_OP` opcode uses numeric arguments to represent operator types:
- 0: Addition
- 1: Bitwise AND
- 2: Subtraction
- 3: Matrix multiplication
- 4: Bitwise OR
- 5: Multiplication
- 6: Remainder
- 7: Bitwise XOR
- 8: Power
- 9: Left shift
- 10: Right shift
- 11: True division
- 12: Floor division

#### Comparison Operations (11 opcodes)
```
COMPARE_OP           # Generic comparison
COMPARE_LESS         # Less than
COMPARE_GREATER      # Greater than
COMPARE_EQUAL        # Equal
COMPARE_NOT_EQUAL    # Not equal
COMPARE_LESS_EQUAL   # Less than or equal
COMPARE_GREATER_EQUAL# Greater than or equal
COMPARE_IN           # Membership test
COMPARE_NOT_IN       # Not in membership test
COMPARE_IS           # Identity test
COMPARE_IS_NOT       # Not identity test
COMPARE_INSTANCEOF   # Instance check
```

#### Logical Operations (3 opcodes)
```
LOGICAL_AND  # Logical AND
LOGICAL_OR   # Logical OR
LOGICAL_NOT  # Logical NOT
```

#### Unary Operations (3 opcodes)
```
UNARY_NEGATIVE  # Unary negation
UNARY_POSITIVE  # Unary plus
UNARY_INVERT    # Bitwise NOT
```

#### Control Flow Operations (10 opcodes)
```
POP_JUMP_IF_FALSE  # Conditional jump if false
POP_JUMP_IF_TRUE   # Conditional jump if true
JUMP_FORWARD       # Unconditional forward jump
JUMP_BACKWARD      # Unconditional backward jump
FOR_ITER           # Iterator for loop
GET_ITER           # Get iterator from iterable
END_FOR            # End of for loop cleanup
RETURN_VALUE       # Return from function
RETURN_CONST       # Return constant value
YIELD_VALUE        # Yield value from generator
```

#### Data Structure Operations (9 opcodes)
```
BUILD_LIST       # Create list from stack items
BUILD_TUPLE      # Create tuple from stack items
BUILD_SET        # Create set from stack items
BUILD_MAP        # Create dictionary from stack items
BUILD_STRING     # Build formatted string
LIST_APPEND      # Append to list
SET_ADD          # Add to set
MAP_ADD          # Add key-value to map
UNPACK_SEQUENCE  # Unpack sequence
```

#### Function/Class Operations (7 opcodes)
```
CALL              # Call function
MAKE_FUNCTION     # Create function object
MAKE_CLASS        # Create class object
ASYNC_FUNCTION    # Create async function
GENERATOR_FUNCTION# Create generator function
KW_NAMES          # Keyword argument names
FORMAT_VALUE      # Format value
```

#### Import/Export Operations (4 opcodes)
```
IMPORT_NAME     # Import module
IMPORT_FROM     # Import from module
EXPORT_DEFAULT  # Export default
EXPORT_NAMED    # Export named
```

#### Stack Manipulation Operations (3 opcodes)
```
POP_TOP    # Remove top of stack
COPY       # Copy stack item
PUSH_NULL  # Push null onto stack
```

#### Exception Handling Operations (4 opcodes)
```
PUSH_EXC_INFO   # Push exception info
POP_EXCEPT      # Pop exception block
RERAISE         # Re-raise exception
CHECK_EXC_MATCH # Check exception match
```

#### Context Manager Operations (2 opcodes)
```
BEFORE_WITH        # Setup context manager
WITH_EXCEPT_START  # Context manager exception handling
```

#### Other Operations (8 opcodes)
```
TYPEOF_OPERATOR  # Type query operator
VOID_OPERATOR    # Void operator
DELETE_OPERATOR  # Delete operator
AWAIT_EXPRESSION # Await expression
DELETE_NAME      # Delete variable
DELETE_SUBSCR    # Delete subscript
NOP              # No operation
RESUME           # Resume execution
```

---

### Instruction Format

Each instruction consists of:

```
opcode: OpCode    # Operation code
arg: Any          # Optional argument
language: str     # Source language identifier
```

**String Representation:**
```
{OpCode.name} {mapped_argument}
```

**Examples:**
```
LOAD_CONST INTEGER
STORE_NAME __HTTP_CLIENT__
CALL 2
COMPARE_EQUAL
BINARY_OP 0
```

---

### Argument Mapping

Arguments are normalized through multi-stage processing:

1. **Data Type Normalization**
2. **Function/Import Recognition**
3. **Pattern Detection**
4. **String Analysis**

#### Data Type Normalization

**Basic Types:**
```
LOAD_CONST <boolean>    → LOAD_CONST BOOLEAN
LOAD_CONST <integer>    → LOAD_CONST INTEGER
LOAD_CONST <float>      → LOAD_CONST FLOAT
LOAD_CONST <null>       → LOAD_CONST None
```

**Collections:**
```
LOAD_CONST <tuple>      → LOAD_CONST LIST
LOAD_CONST <tuple[str]> → LOAD_CONST <element1> <element2> ...
```

**Collection Mapping Strategy:**
- Extract string content from collections
- Map individual elements to semantic tokens
- Fallback to `LIST` token if no meaningful content

#### Function/Import Recognition

**Function Mapping:**
Maps common function names to semantic tokens:
```
STORE_NAME exec         → STORE_NAME __EXEC__
LOAD_NAME eval          → LOAD_NAME __EVAL__
STORE_NAME compile      → STORE_NAME __COMPILE__
LOAD_NAME os            → LOAD_NAME __OS__
```

**Import Mapping:**
Maps import names to normalized tokens:
```
IMPORT_NAME requests     → IMPORT_NAME __HTTP_CLIENT__
IMPORT_FROM urllib       → IMPORT_FROM __HTTP_CLIENT__
IMPORT_NAME cryptography → IMPORT_NAME __CRYPTO__
```

#### Pattern Detection

The mapper detects **14+ patterns**:

**1. IP Addresses:**
```
LOAD_CONST "192.168.1.1" → LOAD_CONST STRING_IP
```

**2. URLs:**
```
LOAD_CONST <url> → LOAD_CONST STRING_URL
```

**3. URLs in Strings:**
```
LOAD_CONST <text containing url> → LOAD_CONST STRING_CONTAINS_URL
```

**4. Localhost:**
```
LOAD_CONST "localhost"   → LOAD_CONST STRING_LOCALHOST
LOAD_CONST "127.0.0.1"   → LOAD_CONST STRING_LOCALHOST
```

**5. File Paths:**
```
LOAD_CONST <file path> → LOAD_CONST STRING_FILE_PATH
```

**6. Sensitive Paths:**
```
LOAD_CONST <sensitive path> → LOAD_CONST STRING_SENSITIVE_FILE_PATH
```

**7. Encoding Names:**
```
LOAD_CONST "utf-8"       → LOAD_CONST STRING_ENCODING
LOAD_CONST "base64"      → LOAD_CONST STRING_ENCODING
```

**8. Version Strings:**
```
LOAD_CONST "1.2.3"       → LOAD_CONST STRING_VERSION
LOAD_CONST "v2.0.1"      → LOAD_CONST STRING_VERSION
```

**9. Base64:**
```
LOAD_CONST <base64 encoded> → LOAD_CONST STRING_BASE64
```

**10. Hex Strings:**
```
LOAD_CONST <hex string> → LOAD_CONST STRING_HEX
```

**11. Bash Code:**
```
LOAD_CONST <shell command> → LOAD_CONST STRING_BASH
```

**12. SQL Code:**
```
LOAD_CONST <sql query> → LOAD_CONST STRING_SQL
```

**13. Generic Code:**
```
LOAD_CONST <code snippet> → LOAD_CONST STRING_CODE
```

**14. Long Strings with Size Buckets:**
```
LOAD_CONST <short string>     → LOAD_CONST <string>        # ≤20 chars
LOAD_CONST <medium string>    → LOAD_CONST STRING_LEN_M    # 21-50 chars
LOAD_CONST <long string>      → LOAD_CONST STRING_LEN_L    # 51-200 chars
LOAD_CONST <very long string> → LOAD_CONST STRING_LEN_XL   # 201-1000 chars
LOAD_CONST <huge string>      → LOAD_CONST STRING_LEN_XXL  # 1000+ chars
```

**Size Buckets:**
- **STRING_LEN_M** (Medium): 21-50 characters
- **STRING_LEN_L** (Large): 51-200 characters
- **STRING_LEN_XL** (Extra Large): 201-1000 characters
- **STRING_LEN_XXL** (Huge): 1000+ characters

**Combined Tokens:**
Long strings may receive multiple tokens:
```
LOAD_CONST STRING_BASE64 STRING_LEN_M
LOAD_CONST STRING_URL STRING_LEN_L
```

#### KW_NAMES Splitting

The `KW_NAMES` opcode uses a splitting strategy for keyword arguments:

**Before splitting:**
```
KW_NAMES arg1 arg2 arg3
```

**After splitting:**
```
KW_NAMES arg1
KW_NAMES arg2
KW_NAMES arg3
```

**Rationale:**
1. Finer-grained pattern recognition
2. Better context preservation
3. Improved generalization

---

## OpCode Reference

### Load/Store Operations

#### LOAD_CONST
**Description:** Load a constant value onto the stack
**Arguments:** Constant value (integer, float, boolean, string, collection, null)

#### LOAD_NAME / LOAD_GLOBAL / LOAD_FAST
**Description:** Load variable from different scopes
**Scope Distinction:**
- `LOAD_NAME`: Module-level or undefined scope
- `LOAD_GLOBAL`: Explicitly declared global variables
- `LOAD_FAST`: Local variables within functions

#### LOAD_PARAM
**Description:** Load function parameter
**Distinction:** Separate from LOAD_FAST to identify parameter usage patterns

#### LOAD_ATTR
**Description:** Load object attribute
**Note:** Attribute chains are split into individual LOAD_ATTR opcodes

**Rationale:** Splitting attribute chains creates more unique samples and enables better generalization.

#### STORE_NAME / STORE_GLOBAL / STORE_FAST
**Description:** Store value in different scopes

#### STORE_ATTR / STORE_SUBSCR
**Description:** Store attribute or subscript

### Binary Operations

#### BINARY_OP
**Description:** Unified binary operation with numeric argument
**Arguments:** Numeric code indicating operator type (see enumeration above)

#### BINARY_UNSIGNED_RSHIFT
**Description:** Unsigned right shift operator

#### BINARY_NULLISH_COALESCING
**Description:** Nullish coalescing operator

#### BINARY_SUBSCR
**Description:** Subscript access

### Comparison Operations

#### COMPARE_EQUAL / COMPARE_NOT_EQUAL
**Description:** Equality and inequality comparison

#### COMPARE_LESS / COMPARE_GREATER / COMPARE_LESS_EQUAL / COMPARE_GREATER_EQUAL
**Description:** Relational comparison operators

#### COMPARE_IN / COMPARE_NOT_IN
**Description:** Membership testing

#### COMPARE_IS / COMPARE_IS_NOT
**Description:** Identity testing

#### COMPARE_INSTANCEOF
**Description:** Instance checking

### Control Flow Operations

#### POP_JUMP_IF_FALSE / POP_JUMP_IF_TRUE
**Description:** Conditional jumps for control flow
**Usage:** Conditional statements, loops, ternary expressions
**Mapping:** No argument (jump target removed)

#### JUMP_FORWARD / JUMP_BACKWARD
**Description:** Unconditional jumps
**Usage:** Loop continuation, break statements

#### FOR_ITER / GET_ITER
**Description:** Iteration operations
**Usage:** for loops, comprehensions

#### RETURN_VALUE / RETURN_CONST
**Description:** Function return
**Distinction:**
- `RETURN_VALUE`: Returns value from stack
- `RETURN_CONST`: Returns constant value directly

#### YIELD_VALUE
**Description:** Generator yield

### Data Structure Operations

#### BUILD_LIST / BUILD_TUPLE / BUILD_SET
**Description:** Construct collections
**Argument:** Number of items

#### BUILD_MAP
**Description:** Construct dictionary
**Argument:** Number of key-value pairs

#### BUILD_STRING
**Description:** Construct formatted string
**Argument:** Number of string parts

#### LIST_APPEND / SET_ADD / MAP_ADD
**Description:** Comprehension operations
**Usage:** List/set/dict comprehensions

#### UNPACK_SEQUENCE
**Description:** Sequence unpacking
**Argument:** Number of targets

### Function/Class Operations

#### CALL
**Description:** Function call
**Argument:** Number of positional arguments

#### MAKE_FUNCTION
**Description:** Create function object
**Followed By:** Function bytecode in separate code object

#### MAKE_CLASS
**Description:** Create class object
**Followed By:** Class bytecode in separate code object

#### ASYNC_FUNCTION / GENERATOR_FUNCTION
**Description:** Special function types

#### KW_NAMES
**Description:** Keyword argument names
**Argument:** Keyword names
**Implementation:** Split into individual tokens

#### FORMAT_VALUE
**Description:** Format value in formatted string

### Import/Export Operations

#### IMPORT_NAME / IMPORT_FROM
**Description:** Module import
**Argument:** Module/member name
**Mapping:** Normalized to semantic tokens

#### EXPORT_DEFAULT / EXPORT_NAMED
**Description:** Module exports

---

## Code Object Model

Malwi Bytecode generates **multiple code objects** per source file:

### Code Object Structure

```
name: str                          # Object name (module, function name, class name)
language: str                      # Source language identifier
file_path: str                     # Source file path
file_source_code: str              # Complete file source code
byte_code: List[Instruction]       # Compiled bytecode instructions
source_code: Optional[str]         # Specific source for this object
location: Optional[Tuple[int,int]] # (start_line, end_line)
warnings: List[str]                # Compilation warnings
```

### Object Types

#### 1. Root Module Object
- **Contains:** Module-level code (imports, global assignments, top-level statements)
- **Location:** Entire file
- **Special:** Includes `RESUME` opcode at start, `RETURN_CONST` at end

#### 2. Function Objects
- **Contains:** Function body bytecode
- **Location:** Function definition lines
- **Special:** Tracks function parameters via `LOAD_PARAM`

#### 3. Class Objects
- **Contains:** Class body bytecode
- **Location:** Class definition lines
- **Special:** Nested methods become separate code objects

### Object Hierarchy

Source files are decomposed into hierarchical code objects:

**Module Object:**
```
RESUME 0
IMPORT_NAME __OS__
MAKE_FUNCTION <function_name>
MAKE_CLASS <class_name>
RETURN_CONST None
```

**Function Object:**
```
RESUME 0
LOAD_GLOBAL __OS__
LOAD_ATTR system
LOAD_CONST STRING_BASH
CALL 1
RETURN_CONST None
```

---

## String Tokenization

String tokenization normalizes string constants into standardized tokens.

### Tokenization Pipeline

1. **Whitespace Normalization:** Reduce multiple whitespace to single space
2. **Newline Removal:** Remove newline characters
3. **String Literal Cleaning:** Remove quotes
4. **Length Check:** Compare to `STRING_MAX_LENGTH` (20 characters)
5. **Pattern Detection:** If long, check for patterns (IP, URL, base64, etc.)
6. **Size Bucketing:** If long and no pattern, assign size bucket token

### Short String Handling (≤20 chars)

**Preserved As-Is:**
```
LOAD_CONST "identifier"  → LOAD_CONST identifier
LOAD_CONST "variable"    → LOAD_CONST variable
```

**Rationale:**
- Preserves semantic information for common identifiers
- Avoids vocabulary explosion

### Long String Handling (>20 chars)

**Pattern Detection (Priority Order):**
1. **Bash Code** → `STRING_BASH`
2. **SQL Code** → `STRING_SQL`
3. **Generic Code** → `STRING_CODE`
4. **Hex** → `STRING_HEX`
5. **Base64** → `STRING_BASE64`
6. **Default** → `STRING` + size bucket

**Size Bucket Assignment:**
```
Length 21-50:     STRING_LEN_M
Length 51-200:    STRING_LEN_L
Length 201-1000:  STRING_LEN_XL
Length 1000+:     STRING_LEN_XXL
```

**Combined Tokens:**
```
LOAD_CONST <long base64> → LOAD_CONST STRING_BASE64 STRING_LEN_L
```

### STRING_MAX_LENGTH Parameter

The `STRING_MAX_LENGTH` parameter is set to **20 characters**.

**Rationale:**
- Strings ≤20 chars are preserved as-is
- Strings >20 chars are analyzed for semantic patterns
- Size bucketing provides length awareness without vocabulary explosion

---

## Appendix A: Complete OpCode List

| OpCode | Category | Description |
|--------|----------|-------------|
| `LOAD_CONST` | Load/Store | Load constant value |
| `LOAD_NAME` | Load/Store | Load variable by name |
| `LOAD_GLOBAL` | Load/Store | Load global variable |
| `LOAD_PARAM` | Load/Store | Load function parameter |
| `LOAD_ATTR` | Load/Store | Load attribute |
| `LOAD_FAST` | Load/Store | Load local variable |
| `LOAD_DEREF` | Load/Store | Load closure variable |
| `LOAD_BUILD_CLASS` | Load/Store | Load class builder |
| `STORE_NAME` | Load/Store | Store variable |
| `STORE_GLOBAL` | Load/Store | Store global variable |
| `STORE_ATTR` | Load/Store | Store attribute |
| `STORE_SUBSCR` | Load/Store | Store subscript |
| `STORE_FAST` | Load/Store | Store local variable |
| `STORE_DEREF` | Load/Store | Store closure variable |
| `BINARY_ADD` | Binary | Addition |
| `BINARY_UNSIGNED_RSHIFT` | Binary | Unsigned right shift |
| `BINARY_NULLISH_COALESCING` | Binary | Nullish coalescing |
| `BINARY_SUBSCR` | Binary | Subscript access |
| `BINARY_OP` | Binary | Generic binary op |
| `BINARY_OPERATION` | Binary | Generic binary op placeholder |
| `COMPARE_OP` | Comparison | Generic comparison |
| `COMPARE_LESS` | Comparison | Less than |
| `COMPARE_GREATER` | Comparison | Greater than |
| `COMPARE_EQUAL` | Comparison | Equal |
| `COMPARE_NOT_EQUAL` | Comparison | Not equal |
| `COMPARE_LESS_EQUAL` | Comparison | Less or equal |
| `COMPARE_GREATER_EQUAL` | Comparison | Greater or equal |
| `COMPARE_IN` | Comparison | Membership test |
| `COMPARE_NOT_IN` | Comparison | Not in |
| `COMPARE_IS` | Comparison | Identity test |
| `COMPARE_IS_NOT` | Comparison | Not identity |
| `COMPARE_INSTANCEOF` | Comparison | instanceof |
| `LOGICAL_AND` | Logical | Logical AND |
| `LOGICAL_OR` | Logical | Logical OR |
| `LOGICAL_NOT` | Logical | Logical NOT |
| `UNARY_NEGATIVE` | Unary | Unary negation |
| `UNARY_POSITIVE` | Unary | Unary plus |
| `UNARY_INVERT` | Unary | Bitwise NOT |
| `POP_JUMP_IF_FALSE` | Control Flow | Conditional jump |
| `POP_JUMP_IF_TRUE` | Control Flow | Conditional jump |
| `JUMP_FORWARD` | Control Flow | Forward jump |
| `JUMP_BACKWARD` | Control Flow | Backward jump |
| `FOR_ITER` | Control Flow | For iteration |
| `GET_ITER` | Control Flow | Get iterator |
| `END_FOR` | Control Flow | End for loop |
| `RETURN_VALUE` | Control Flow | Return value |
| `RETURN_CONST` | Control Flow | Return constant |
| `YIELD_VALUE` | Control Flow | Yield value |
| `BUILD_LIST` | Data Structure | Create list |
| `BUILD_TUPLE` | Data Structure | Create tuple |
| `BUILD_SET` | Data Structure | Create set |
| `BUILD_MAP` | Data Structure | Create dict |
| `BUILD_STRING` | Data Structure | Build string |
| `LIST_APPEND` | Data Structure | Append to list |
| `SET_ADD` | Data Structure | Add to set |
| `MAP_ADD` | Data Structure | Add to dict |
| `UNPACK_SEQUENCE` | Data Structure | Unpack sequence |
| `CALL` | Function/Class | Call function |
| `MAKE_FUNCTION` | Function/Class | Create function |
| `MAKE_CLASS` | Function/Class | Create class |
| `ASYNC_FUNCTION` | Function/Class | Create async function |
| `GENERATOR_FUNCTION` | Function/Class | Create generator |
| `KW_NAMES` | Function/Class | Keyword argument names |
| `FORMAT_VALUE` | Function/Class | Format value |
| `IMPORT_NAME` | Import/Export | Import module |
| `IMPORT_FROM` | Import/Export | Import from |
| `EXPORT_DEFAULT` | Import/Export | Export default |
| `EXPORT_NAMED` | Import/Export | Export named |
| `POP_TOP` | Stack | Pop stack top |
| `COPY` | Stack | Copy stack item |
| `PUSH_NULL` | Stack | Push null |
| `PUSH_EXC_INFO` | Exception | Push exception info |
| `POP_EXCEPT` | Exception | Pop exception |
| `RERAISE` | Exception | Re-raise exception |
| `CHECK_EXC_MATCH` | Exception | Check exception match |
| `BEFORE_WITH` | Context Manager | Setup context manager |
| `WITH_EXCEPT_START` | Context Manager | Context manager exception |
| `TYPEOF_OPERATOR` | Other | Type query operator |
| `VOID_OPERATOR` | Other | Void operator |
| `DELETE_OPERATOR` | Other | Delete operator |
| `AWAIT_EXPRESSION` | Other | Await expression |
| `DELETE_NAME` | Delete | Delete variable |
| `DELETE_SUBSCR` | Delete | Delete subscript |
| `NOP` | Other | No operation |
| `RESUME` | Other | Resume execution |

---

## Appendix B: Tokenization Examples

### Example 1: Short String (Preserved)

**Input:**
```
LOAD_CONST "identifier"
```

**Output:**
```
LOAD_CONST identifier
```

**Reason:** Length ≤ 20 characters, preserved as-is.

### Example 2: IP Address Detection

**Input:**
```
LOAD_CONST "192.168.1.100"
```

**Output:**
```
LOAD_CONST STRING_IP
```

**Reason:** Matches IP address pattern.

### Example 3: Long String with Size Bucket

**Input:**
```
LOAD_CONST <long identifier>
```

**Output:**
```
LOAD_CONST STRING STRING_LEN_L
```

**Reason:** Length > 20, no special pattern detected, assigned size bucket.

### Example 4: Base64 with Size Bucket

**Input:**
```
LOAD_CONST <base64 encoded string>
```

**Output:**
```
LOAD_CONST STRING_BASE64 STRING_LEN_L
```

**Reason:** Detected as base64, length 51-200 characters.

### Example 5: Sensitive File Path

**Input:**
```
LOAD_CONST "/etc/shadow"
```

**Output:**
```
LOAD_CONST STRING_SENSITIVE_FILE_PATH
```

**Reason:** Matches sensitive path list.

---

## Appendix C: Semantic Token Mappings

### Function Semantic Tokens

```
"exec"          → "__EXEC__"
"eval"          → "__EVAL__"
"compile"       → "__COMPILE__"
"os"            → "__OS__"
"subprocess"    → "__SUBPROCESS__"
"socket"        → "__SOCKET__"
"requests"      → "__HTTP_CLIENT__"
"urllib"        → "__HTTP_CLIENT__"
"cryptography"  → "__CRYPTO__"
"base64"        → "__ENCODING__"
```

### Import Semantic Tokens

```
"fs"            → "__FILESYSTEM__"
"child_process" → "__SUBPROCESS__"
"net"           → "__SOCKET__"
"http"          → "__HTTP_CLIENT__"
"https"         → "__HTTP_CLIENT__"
"axios"         → "__HTTP_CLIENT__"
"crypto"        → "__CRYPTO__"
```

---

**End of RFC**
