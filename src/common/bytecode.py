import logging
from enum import Enum, auto
from pathlib import Path
from tree_sitter import Node
from typing import Optional, Any, List

from tree_sitter import Parser, Language
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_rust as tsrust

from .mapping import (
    FUNCTION_MAPPING,
    IMPORT_MAPPING,
    reduce_whitespace,
    remove_newlines,
    SpecialCases,
    clean_string_literal,
    is_valid_encoding_name,
    is_valid_ip,
    is_base64,
    is_hex,
    is_valid_url,
    is_version,
    is_file_path,
    contains_url,
    is_localhost,
    is_bash_code,
    is_sql,
    is_code,
    get_string_size_bucket,
    SENSITIVE_PATHS,
)
from .config import STRING_MAX_LENGTH
from .malwi_object import MalwiObject


class OpCode(Enum):
    """
    Defines the set of all possible bytecode operations for Malwicode.

    Operations are grouped by category:
    - Load/Store operations
    - Binary operations
    - Comparison operations
    - Logical operations
    - Control flow operations
    - Data structure operations
    - Function/Class operations
    - Import/Export operations
    - Special operations
    """

    # === Load/Store Operations ===
    LOAD_CONST = auto()  # Load constant value onto stack
    LOAD_NAME = auto()  # Load variable by name
    LOAD_GLOBAL = auto()  # Load global variable
    LOAD_PARAM = auto()  # Load function parameter
    LOAD_ATTR = auto()  # Load attribute (obj.attr)
    LOAD_FAST = auto()  # Load local variable (fast access)
    LOAD_DEREF = auto()  # Load closure variable
    LOAD_BUILD_CLASS = auto()  # Load __build_class__ function
    STORE_NAME = auto()  # Store value in variable
    STORE_GLOBAL = auto()  # Store value in global variable
    STORE_ATTR = auto()  # Store attribute (obj.attr = value)
    STORE_SUBSCR = auto()  # Store subscript (obj[key] = value)
    STORE_FAST = auto()  # Store local variable (fast access)
    STORE_DEREF = auto()  # Store closure variable

    # === Binary Arithmetic Operations ===
    BINARY_ADD = auto()  # Addition (+) - still used in some places

    # === Binary Bitwise Operations ===
    BINARY_UNSIGNED_RSHIFT = auto()  # Unsigned right shift (>>>) - JavaScript

    # === Binary Special Operations ===
    BINARY_NULLISH_COALESCING = auto()  # Nullish coalescing (??) - JavaScript
    BINARY_SUBSCR = auto()  # Subscript access (obj[key])
    BINARY_OP = auto()  # Generic binary operation with argument (Python 3.11+)
    BINARY_OPERATION = auto()  # Generic binary operation placeholder

    # === Comparison Operations ===
    COMPARE_OP = auto()  # Generic comparison
    COMPARE_LESS = auto()  # Less than (<)
    COMPARE_GREATER = auto()  # Greater than (>)
    COMPARE_EQUAL = auto()  # Equal (==, ===)
    COMPARE_NOT_EQUAL = auto()  # Not equal (!=, !==)
    COMPARE_LESS_EQUAL = auto()  # Less than or equal (<=)
    COMPARE_GREATER_EQUAL = auto()  # Greater than or equal (>=)
    COMPARE_IN = auto()  # Membership test (in)
    COMPARE_NOT_IN = auto()  # Not in membership test (not in)
    COMPARE_IS = auto()  # Identity test (is)
    COMPARE_IS_NOT = auto()  # Not identity test (is not)
    COMPARE_INSTANCEOF = auto()  # Instance check (instanceof) - JavaScript

    # === Logical Operations ===
    LOGICAL_AND = auto()  # Logical AND (and, &&)
    LOGICAL_OR = auto()  # Logical OR (or, ||)
    LOGICAL_NOT = auto()  # Logical NOT (not, !)

    # === Unary Operations ===
    UNARY_NEGATIVE = auto()  # Unary negation (-)
    UNARY_POSITIVE = auto()  # Unary plus (+)
    UNARY_INVERT = auto()  # Bitwise NOT (~)

    # === Control Flow Operations ===
    POP_JUMP_IF_FALSE = auto()  # Conditional jump if false
    POP_JUMP_IF_TRUE = auto()  # Conditional jump if true
    JUMP_FORWARD = auto()  # Unconditional forward jump
    JUMP_BACKWARD = auto()  # Unconditional backward jump
    FOR_ITER = auto()  # Iterator for loop
    GET_ITER = auto()  # Get iterator from iterable
    END_FOR = auto()  # End of for loop cleanup
    RETURN_VALUE = auto()  # Return from function
    RETURN_CONST = auto()  # Return constant value
    YIELD_VALUE = auto()  # Yield value from generator

    # === Data Structure Operations ===
    BUILD_LIST = auto()  # Create list from stack items
    BUILD_TUPLE = auto()  # Create tuple from stack items
    BUILD_SET = auto()  # Create set from stack items
    BUILD_MAP = auto()  # Create dictionary from stack items
    BUILD_STRING = auto()  # Build string (f-strings)
    LIST_APPEND = auto()  # Append to list (comprehensions)
    SET_ADD = auto()  # Add to set (comprehensions)
    MAP_ADD = auto()  # Add key-value to map (dict comprehensions)
    UNPACK_SEQUENCE = auto()  # Unpack sequence (a, b = x)

    # === Function/Class Operations ===
    CALL = auto()  # Call function (Python 3.11+)
    MAKE_FUNCTION = auto()  # Create function object
    MAKE_CLASS = auto()  # Create class object
    ASYNC_FUNCTION = auto()  # Create async function
    GENERATOR_FUNCTION = auto()  # Create generator function
    KW_NAMES = auto()  # Keyword argument names
    FORMAT_VALUE = auto()  # Format value (f-strings)

    # === Import/Export Operations ===
    IMPORT_NAME = auto()  # Import module
    IMPORT_FROM = auto()  # Import from module
    EXPORT_DEFAULT = auto()  # Export default - JavaScript
    EXPORT_NAMED = auto()  # Export named - JavaScript

    # === Stack Manipulation Operations ===
    POP_TOP = auto()  # Remove top of stack
    COPY = auto()  # Copy stack item
    PUSH_NULL = auto()  # Push null onto stack

    # === Exception Handling Operations ===
    PUSH_EXC_INFO = auto()  # Push exception info
    POP_EXCEPT = auto()  # Pop exception block
    RERAISE = auto()  # Re-raise exception
    CHECK_EXC_MATCH = auto()  # Check exception match

    # === Context Manager Operations ===
    BEFORE_WITH = auto()  # Setup with statement
    WITH_EXCEPT_START = auto()  # With statement exception handling

    # === JavaScript-specific Operations ===
    TYPEOF_OPERATOR = auto()  # typeof operator - JavaScript
    VOID_OPERATOR = auto()  # void operator - JavaScript
    DELETE_OPERATOR = auto()  # delete operator - JavaScript
    AWAIT_EXPRESSION = auto()  # await expression

    # === Delete Operations ===
    DELETE_NAME = auto()  # Delete variable (del x)
    DELETE_SUBSCR = auto()  # Delete subscript (del obj[key])

    # === Other Operations ===
    NOP = auto()  # No operation
    RESUME = auto()  # Resume execution (Python 3.11+)


# ============================================================================
# Operator Mappings
# ============================================================================
# These mappings define how source code operators are translated to opcodes.
# Python 3.11+ uses unified BINARY_OP with numeric arguments for efficiency.
# JavaScript-specific operators are mapped to their own opcodes.
# ============================================================================

# Binary operator mappings - maps operator symbols to OpCode and optional argument
BINARY_OPERATOR_MAPPING = {
    # === Arithmetic Operators ===
    # Python 3.11+ uses BINARY_OP with numeric arguments for arithmetic
    "+": (OpCode.BINARY_OP, 0),  # BINARY_OP 0 = add
    "-": (OpCode.BINARY_OP, 2),  # BINARY_OP 2 = subtract
    "*": (OpCode.BINARY_OP, 5),  # BINARY_OP 5 = multiply
    "/": (OpCode.BINARY_OP, 11),  # BINARY_OP 11 = true_divide
    "%": (OpCode.BINARY_OP, 6),  # BINARY_OP 6 = remainder
    "**": (OpCode.BINARY_OP, 8),  # BINARY_OP 8 = power
    "//": (OpCode.BINARY_OP, 12),  # BINARY_OP 12 = floor_divide
    "@": (OpCode.BINARY_OP, 3),  # BINARY_OP 3 = matmul
    # === Bitwise Operators ===
    "&": (OpCode.BINARY_OP, 1),  # BINARY_OP 1 = and
    "|": (OpCode.BINARY_OP, 4),  # BINARY_OP 4 = or
    "^": (OpCode.BINARY_OP, 7),  # BINARY_OP 7 = xor
    "<<": (OpCode.BINARY_OP, 9),  # BINARY_OP 9 = lshift
    ">>": (OpCode.BINARY_OP, 10),  # BINARY_OP 10 = rshift
    # === JavaScript-specific Binary Operators ===
    ">>>": OpCode.BINARY_UNSIGNED_RSHIFT,  # JavaScript unsigned right shift
    "??": OpCode.BINARY_NULLISH_COALESCING,  # JavaScript nullish coalescing
    # === Comparison Operators ===
    "<": OpCode.COMPARE_LESS,
    ">": OpCode.COMPARE_GREATER,
    "==": OpCode.COMPARE_EQUAL,
    "===": OpCode.COMPARE_EQUAL,  # JavaScript strict equality
    "!=": OpCode.COMPARE_NOT_EQUAL,
    "!==": OpCode.COMPARE_NOT_EQUAL,  # JavaScript strict inequality
    "<=": OpCode.COMPARE_LESS_EQUAL,
    ">=": OpCode.COMPARE_GREATER_EQUAL,
    "in": OpCode.COMPARE_IN,
    "not in": OpCode.COMPARE_NOT_IN,
    "is": OpCode.COMPARE_IS,
    "is not": OpCode.COMPARE_IS_NOT,
    "instanceof": OpCode.COMPARE_INSTANCEOF,  # JavaScript
    # === Logical Operators ===
    "and": OpCode.LOGICAL_AND,  # Python
    "or": OpCode.LOGICAL_OR,  # Python
    "&&": OpCode.LOGICAL_AND,  # JavaScript
    "||": OpCode.LOGICAL_OR,  # JavaScript
}

# Unary operator mappings - maps unary operator symbols to OpCode
UNARY_OPERATOR_MAPPING = {
    # === Arithmetic Unary Operators ===
    "-": OpCode.UNARY_NEGATIVE,  # Unary negation
    "+": OpCode.UNARY_POSITIVE,  # Unary plus
    # === Bitwise Unary Operators ===
    "~": OpCode.UNARY_INVERT,  # Bitwise NOT
    # === Logical Unary Operators ===
    "not": OpCode.LOGICAL_NOT,  # Python logical NOT
    "!": OpCode.LOGICAL_NOT,  # JavaScript logical NOT
    # === JavaScript-specific Unary Operators ===
    "typeof": OpCode.TYPEOF_OPERATOR,  # JavaScript typeof
    "void": OpCode.VOID_OPERATOR,  # JavaScript void
    "delete": OpCode.DELETE_OPERATOR,  # JavaScript delete
}


class Instruction:
    """
    Represents a single bytecode instruction with opcode and argument.
    Provides flexible string formatting for different output modes.
    """

    def __init__(self, opcode: "OpCode", arg: Any = None, language: str = "python"):
        self.opcode = opcode
        self.arg = arg
        self.language = language

    def __repr__(self) -> str:
        return f"Instruction({self.opcode.name}, {self.arg})"

    @classmethod
    def map_argument(
        cls, op_code: OpCode, arg: Any, language: str, for_hashing: bool = False
    ) -> str:
        """
        Maps opcode arguments to normalized tokens for machine learning model training.

        This is the most critical function for training! The mapping was optimized
        through hundreds of iterations to maximize the F1 score of the malware
        detection model.

        Args:
            op_code: The operation code (e.g., LOAD_CONST, STORE_NAME, CALL)
            arg: The argument value to be mapped (string, number, identifier, etc.)
            language: Programming language context ("python", "javascript", or "rust")
            for_hashing: If True, removes variable parts to create stable hashes
                        for deduplication of similar code patterns

        Returns:
            Normalized token string in format: "{opcode_name} {mapped_argument}"
            Examples:
            - "LOAD_CONST STRING_LEN_M_ENT_HIGH" (for long strings)
            - "STORE_NAME requests" (for known function names)
            - "LOAD_CONST BOOLEAN" (for boolean values)
            - "CALL 2" (for function calls with arg count)

        Mapping Strategy:
        1. **Data Type Normalization**: Converts literals (bool, int, float) to type tokens
        2. **Function/Import Recognition**: Maps known functions/imports using predefined dictionaries
        3. **Security Pattern Detection**: Identifies IPs, URLs, file paths, sensitive patterns
        4. **String Analysis**: For long strings, analyzes length, entropy, and encoding type

        Performance Learnings:
        - String length (STRING_MAX_LENGTH=20) has huge impact on model performance
          Shorter strings led to worse performance due to loss of context
        - Import mapping provides ~20% improvement in F1 score by reducing name variations
        - LOAD_ATTR_CHAIN was removed: chained attribute access like obj.prop1.func1
          decreased model performance, now generates individual LOAD_ATTR operations
          and creating more unique training samples for better generalization
        - Tokenization granularity is critical - splitting instructions can destroy
          context understanding and hurt model performance
        - Without function mapping the performance is around 85% (F1)

        Hashing Mode:
        When for_hashing=True, removes variable content (actual string values, numbers)
        to create stable hashes for similar code structures. This enables:
        - Deduplication of functionally identical code samples
        - Better training data quality by focusing on behavioral patterns
        - Consistent hash generation across different variable names/values
        """

        function_mapping = FUNCTION_MAPPING.get(language, {})
        import_mapping = IMPORT_MAPPING.get(language, {})

        if not arg:
            return op_code.name

        argval = clean_string_literal(reduce_whitespace(remove_newlines(str(arg))))

        # Map basic data types
        if op_code == OpCode.LOAD_CONST and isinstance(arg, bool):
            return f"{op_code.name} {SpecialCases.BOOLEAN.value}"
        elif op_code == OpCode.LOAD_CONST and isinstance(arg, int):
            return f"{op_code.name} {SpecialCases.INTEGER.value}"
        elif op_code == OpCode.LOAD_CONST and isinstance(arg, float):
            return f"{op_code.name} {SpecialCases.FLOAT.value}"
        elif op_code == OpCode.LOAD_CONST and isinstance(arg, tuple):
            # Handle tuples by extracting string content and mapping individual elements
            # This is especially important for marshal operations and import tuples
            from .mapping import map_tuple_arg

            tuple_mapping = map_tuple_arg(arg, str(arg))
            if tuple_mapping:
                return f"{op_code.name} {tuple_mapping}"
            else:
                # Fallback to LIST token if no meaningful content found
                return f"{op_code.name} LIST"
        # Map jumps for conditional logic
        elif op_code in (
            OpCode.POP_JUMP_IF_FALSE,
            OpCode.POP_JUMP_IF_TRUE,
            OpCode.JUMP_FORWARD,
        ):
            return f"{op_code.name}"
        elif op_code in [OpCode.MAKE_CLASS, OpCode.MAKE_FUNCTION]:
            return f"{op_code.name}"
        elif (
            op_code in [OpCode.IMPORT_FROM, OpCode.IMPORT_NAME]
            and argval in import_mapping
        ):
            return f"{op_code.name} {import_mapping.get(argval)}"
        # The function can be fully replaced by a single token
        elif (
            op_code
            in [
                OpCode.STORE_NAME,
                OpCode.LOAD_NAME,
                OpCode.STORE_GLOBAL,
                OpCode.LOAD_GLOBAL,
            ]
            and argval in function_mapping
        ):
            return f"{op_code.name} {function_mapping.get(argval)}"
        elif op_code in [OpCode.CALL]:
            return f"{op_code.name} {argval}"
        elif op_code in [OpCode.POP_TOP]:
            # POP_TOP discards top of stack, no argument needed
            return f"{op_code.name}"
        elif op_code in [OpCode.PUSH_NULL]:
            # PUSH_NULL pushes NULL value to stack, no argument needed
            return f"{op_code.name}"
        elif op_code in [OpCode.COPY]:
            # COPY duplicates stack values, argument indicates copy depth
            return f"{op_code.name} {argval if argval is not None else '1'}"
        elif op_code == OpCode.KW_NAMES:
            # Handle keyword argument names tuple - join with spaces
            if isinstance(arg, tuple):
                kw_names_str = " ".join(str(name) for name in arg)
                return f"{op_code.name} {kw_names_str}"
            else:
                return f"{op_code.name} {argval}"
        elif argval in SENSITIVE_PATHS:
            return f"{op_code.name} {SpecialCases.STRING_SENSITIVE_FILE_PATH.value}"
        elif is_localhost(argval):
            return f"{op_code.name} {SpecialCases.STRING_LOCALHOST.value}"
        elif is_valid_ip(argval):
            return f"{op_code.name} {SpecialCases.STRING_IP.value}"
        elif is_valid_url(argval):
            return f"{op_code.name} {SpecialCases.STRING_URL.value}"
        elif contains_url(argval):
            # String contains a URL but isn't a URL itself
            return f"{op_code.name} {SpecialCases.STRING_CONTAINS_URL.value}"
        elif is_version(argval):
            return f"{op_code.name} {SpecialCases.STRING_VERSION.value}"
        elif is_valid_encoding_name(argval):
            return f"{op_code.name} {SpecialCases.STRING_ENCODING.value}"
        elif is_file_path(argval):
            return f"{op_code.name} {SpecialCases.STRING_FILE_PATH.value}"

        # Cut strings when too long - check this BEFORE other detections
        # This preserves short identifiers like "Optional", "some_var" as-is
        elif len(argval) <= STRING_MAX_LENGTH:
            return f"{op_code.name} {argval}"
        # Long strings - check for specific patterns with early exit
        # Generate main classification token first
        main_token = ""
        if is_bash_code(argval):
            main_token = f"{op_code.name} {SpecialCases.STRING_BASH.value}"
        elif is_sql(argval):
            main_token = f"{op_code.name} {SpecialCases.STRING_SQL.value}"
        elif is_code(argval):
            main_token = f"{op_code.name} {SpecialCases.STRING_CODE.value}"
        elif is_hex(argval):
            main_token = f"{op_code.name} {SpecialCases.STRING_HEX.value}"
        elif is_base64(argval):
            main_token = f"{op_code.name} {SpecialCases.STRING_BASE64.value}"
        else:
            # Default case for long strings
            main_token = f"{op_code.name} {SpecialCases.STRING.value}"

        # Add size bucket token for strings >20 chars
        size_bucket = get_string_size_bucket(argval)
        if size_bucket:
            return f"{main_token} {size_bucket}"
        else:
            return main_token

    def to_string(self, mapped: bool, for_hashing: bool = False) -> str:
        if mapped and for_hashing:
            return Instruction.map_argument(
                op_code=self.opcode,
                arg=self.arg,
                language=self.language,
                for_hashing=True,
            )
        elif mapped:
            return Instruction.map_argument(
                op_code=self.opcode,
                arg=self.arg,
                language=self.language,
                for_hashing=for_hashing,
            )
        else:
            return f"{self.opcode.name} {self.arg}"


def emit(opcode: "OpCode", arg: Any = None, language: str = "python") -> Instruction:
    """Helper function to create Instruction objects."""
    return Instruction(opcode, arg, language)


class ASTCompiler:
    """
    Compiles a tree-sitter AST from Python, JavaScript or Rust into "Malwicode".
    An instance of the compiler is tied to a specific language.
    """

    # Language definitions are now a class property
    SUPPORTED_LANGUAGES = {
        "python": tspython.language(),
        "javascript": tsjavascript.language(),
        "rust": tsrust.language(),
    }

    def __init__(self, language: str):
        """
        Initializes the compiler for a specific language.
        """
        self.language_name = language
        language_object = self.SUPPORTED_LANGUAGES.get(language)

        if language_object is None:
            raise ValueError(f"Language '{language}' is not supported.")

        # Adapted to use the requested Parser API
        self.parser = Parser(Language(language_object))

        # Track function parameters for LOAD_PARAM vs LOAD_NAME distinction
        self.current_function_params = set()
        # Track global variables for LOAD_GLOBAL/STORE_GLOBAL distinction
        self.global_variables = set()
        # Track whether we're currently inside a function scope
        self._in_function_scope = False
        # Track comprehension variables for LOAD_FAST/STORE_FAST distinction
        self.comprehension_variables = set()
        # Track nonlocal variables for STORE_DEREF/LOAD_DEREF distinction
        self.nonlocal_variables = set()
        # Track nesting depth: 0 = module level, 1+ = nested
        self._nesting_depth = 0
        # Collection to store all MalwiObjects (root, functions, classes)
        self.code_objects = []
        # Counter for generating unique reference names
        self._next_ref_id = 0

    def _extract_module_level_source(
        self, source_code: str, code_objects: List[MalwiObject]
    ) -> str:
        """
        Extract module-level source code by removing lines that are covered by code objects.
        This is stateless and takes the source code and code objects as parameters.
        """
        if not code_objects:
            return source_code.strip()

        lines = source_code.split("\n")
        covered_lines = set()

        # Collect all lines covered by code objects
        for code_obj in code_objects:
            if hasattr(code_obj, "location") and code_obj.location:
                start_line, end_line = code_obj.location
                # Add all lines from start to end (inclusive)
                for line_num in range(start_line, end_line + 1):
                    if 1 <= line_num <= len(lines):
                        covered_lines.add(line_num - 1)  # Convert to 0-based indexing

        # Build result by including only non-empty uncovered lines
        result_lines = []
        for i, line in enumerate(lines):
            if i not in covered_lines and line.strip():
                result_lines.append(line)

        return "\n".join(result_lines).strip()

    def treesitter_to_bytecode(
        self, root_node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[MalwiObject]:
        """
        Public method to initiate the compilation of an AST to multiple MalwiObjects.
        Returns a list with the root MalwiObject first, followed by function and class MalwiObjects.
        """
        # Reset collections for each compilation
        self.code_objects = []
        self._next_ref_id = 0

        # First pass: Collect all variables that are declared global anywhere in the module
        self.global_variables = self._collect_global_variables(
            root_node, source_code_bytes
        )

        source_code = source_code_bytes.decode("utf-8", errors="replace")
        location = (root_node.start_point[0] + 1, root_node.end_point[0] + 1)

        # Generate bytecode with RESUME at start and RETURN_CONST at end
        bytecode = []
        # Add RESUME instruction at the start (for Python 3.11+ compatibility)
        bytecode.append(emit(OpCode.RESUME, 0))

        # Generate main bytecode
        module_bytecode = self._generate_bytecode(
            root_node, source_code_bytes, file_path
        )
        bytecode.extend(module_bytecode)

        # Add RETURN_CONST at the end instead of leaving it open
        bytecode.append(emit(OpCode.RETURN_CONST, None))

        # Extract module-level source (excluding function/class bodies)
        module_level_source = self._extract_module_level_source(
            source_code, self.code_objects
        )

        # Create root MalwiObject
        root_code_obj = MalwiObject(
            name="<module>",
            language=self.language_name,
            file_path=str(file_path),
            file_source_code=source_code,
            byte_code=bytecode,
            source_code=module_level_source,
            location=location,
        )

        # Return root MalwiObject first, followed by function/class MalwiObjects
        return [root_code_obj] + self.code_objects

    def _generate_ref_name(self, base_name: str) -> str:
        """Generate a unique reference name for a MalwiObject."""
        ref_name = f"{base_name}_ref_{self._next_ref_id}"
        self._next_ref_id += 1
        return ref_name

    def _get_node_text(self, node: Node, source_code_bytes: bytes) -> str:
        """Helper to extract text from a node."""
        return source_code_bytes[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _contains_yield(self, node: Node, source_code_bytes: bytes) -> bool:
        """Check if a node contains yield expressions (indicating a generator function)."""
        if node.type in ["yield", "yield_expression", "yield_from_expression"]:
            return True

        for child in node.children:
            if self._contains_yield(child, source_code_bytes):
                return True

        return False

    def _extract_function_parameters(self, node: Node, source_code_bytes: bytes) -> set:
        """Extract parameter names from function definition node."""
        params = set()

        # Handle different function types
        if node.type == "arrow_function":
            params.update(self._extract_arrow_function_params(node, source_code_bytes))
        elif node.type in ["lambda"]:
            params.update(self._extract_lambda_params(node, source_code_bytes))
        else:
            # Regular function definitions
            params.update(
                self._extract_regular_function_params(node, source_code_bytes)
            )

        return params

    def _extract_arrow_function_params(
        self, node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameters from JavaScript arrow functions."""
        params = set()

        # Check for parameter/parameters field
        param_node = node.child_by_field_name("parameter") or node.child_by_field_name(
            "parameters"
        )
        if param_node:
            if param_node.type == "identifier":
                # Single parameter: x => x * 2
                param_name = self._get_node_text(param_node, source_code_bytes)
                params.add(param_name)
            elif param_node.type == "formal_parameters":
                # Multiple parameters: (x, y) => x + y
                params.update(
                    self._extract_from_formal_parameters(param_node, source_code_bytes)
                )

        # Fallback: check direct children for single identifier
        for child in node.named_children:
            if child.type == "identifier":
                param_name = self._get_node_text(child, source_code_bytes)
                params.add(param_name)

        return params

    def _extract_lambda_params(self, node: Node, source_code_bytes: bytes) -> set:
        """Extract parameters from Python lambda functions."""
        params = set()

        # Look for parameters in lambda
        for child in node.named_children:
            if child.type in ["parameters", "lambda_parameters"]:
                if child.type == "lambda_parameters":
                    # Lambda uses lambda_parameters, extract identifiers directly
                    for param_child in child.named_children:
                        if param_child.type == "identifier":
                            param_name = self._get_node_text(
                                param_child, source_code_bytes
                            )
                            params.add(param_name)
                else:
                    params.update(
                        self._extract_from_parameters(child, source_code_bytes)
                    )
            elif child.type == "identifier":
                # Single parameter lambda
                param_name = self._get_node_text(child, source_code_bytes)
                params.add(param_name)

        return params

    def _extract_regular_function_params(
        self, node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameters from regular function definitions."""
        params = set()

        for child in node.named_children:
            if child.type in ["parameters", "formal_parameters"]:
                if child.type == "parameters":
                    params.update(
                        self._extract_from_parameters(child, source_code_bytes)
                    )
                else:  # formal_parameters
                    params.update(
                        self._extract_from_formal_parameters(child, source_code_bytes)
                    )

        return params

    def _extract_from_parameters(
        self, params_node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameter names from Python parameters node."""
        params = set()

        for param_child in params_node.named_children:
            param_name = self._extract_single_parameter_name(
                param_child, source_code_bytes
            )
            if param_name:
                params.add(param_name)

        return params

    def _extract_from_formal_parameters(
        self, params_node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameter names from JavaScript formal_parameters node."""
        params = set()

        for param_child in params_node.named_children:
            if param_child.type == "identifier":
                param_name = self._get_node_text(param_child, source_code_bytes)
                params.add(param_name)

        return params

    def _extract_single_parameter_name(
        self, param_node: Node, source_code_bytes: bytes
    ) -> str:
        """Extract parameter name from a single parameter node (Python)."""
        if param_node.type == "identifier":
            # Simple parameter: def func(param):
            return self._get_node_text(param_node, source_code_bytes)

        elif param_node.type in [
            "parameter",
            "required_parameter",
            "optional_parameter",
        ]:
            # Python typed parameters: def func(param: int):
            for child in param_node.named_children:
                if child.type == "identifier":
                    return self._get_node_text(child, source_code_bytes)

        elif param_node.type in [
            "default_parameter",
            "typed_parameter",
            "typed_default_parameter",
        ]:
            # Parameters with defaults/types: def func(param: int = 1):
            name_node = param_node.child_by_field_name("name")
            if name_node:
                return self._get_node_text(name_node, source_code_bytes)

        elif param_node.type in ["list_splat_pattern", "dictionary_splat_pattern"]:
            # Handle *args, **kwargs
            for child in param_node.named_children:
                if child.type == "identifier":
                    return self._get_node_text(child, source_code_bytes)

        # Fallback: try to get any identifier in the parameter node
        for child in param_node.named_children:
            if child.type == "identifier":
                return self._get_node_text(child, source_code_bytes)

        return None

    def _emit(self, opcode: "OpCode", arg: Any = None) -> Instruction:
        """Helper method to create Instruction objects with the compiler's language."""
        return emit(opcode, arg, self.language_name)

    def _collect_global_variables(self, node: Node, source_code_bytes: bytes) -> set:
        """
        First pass: collect all variables that are declared global anywhere in the module.
        This mimics Python's two-pass compilation where global declarations affect
        the entire module scope.
        """
        global_vars = set()

        def _traverse_for_globals(n: Node):
            if n.type == "global_statement":
                for child in n.named_children:
                    if child.type == "identifier":
                        var_name = self._get_node_text(child, source_code_bytes)
                        global_vars.add(var_name)

            # Recursively traverse all children
            for child in n.children:
                _traverse_for_globals(child)

        _traverse_for_globals(node)
        return global_vars

    def _emit_store(self, var_name: str) -> Instruction:
        """Helper method to emit appropriate store instruction based on variable scope."""
        if var_name in self.nonlocal_variables:
            # Nonlocal variables use STORE_DEREF for closure access
            return emit(OpCode.STORE_DEREF, var_name, self.language_name)
        elif var_name in self.global_variables:
            # Global variables use STORE_GLOBAL
            return emit(OpCode.STORE_GLOBAL, var_name, self.language_name)
        elif hasattr(self, "_in_function_scope") and self._in_function_scope:
            # Inside a function: other variables use STORE_GLOBAL for malware analysis consistency
            return emit(OpCode.STORE_GLOBAL, var_name, self.language_name)
        else:
            # Module level: other variables use STORE_NAME
            return emit(OpCode.STORE_NAME, var_name, self.language_name)

    def _emit_load(self, var_name: str) -> Instruction:
        """Helper method to emit appropriate load instruction based on variable scope."""
        # Check if this identifier is a comprehension variable first
        if var_name in self.comprehension_variables:
            return emit(OpCode.LOAD_FAST, var_name, self.language_name)
        # Check if this identifier is a nonlocal variable
        elif var_name in self.nonlocal_variables:
            return emit(OpCode.LOAD_DEREF, var_name, self.language_name)
        # Check if this identifier is a function parameter
        elif var_name in self.current_function_params:
            return emit(OpCode.LOAD_PARAM, var_name, self.language_name)
        elif var_name in self.global_variables:
            # Global variables use LOAD_GLOBAL
            return emit(OpCode.LOAD_GLOBAL, var_name, self.language_name)
        elif hasattr(self, "_in_function_scope") and self._in_function_scope:
            # Inside a function: other variables use LOAD_GLOBAL for malware analysis consistency
            return emit(OpCode.LOAD_GLOBAL, var_name, self.language_name)
        else:
            # Module level: other variables use LOAD_NAME
            return emit(OpCode.LOAD_NAME, var_name, self.language_name)

    def _handle_numeric_literal(
        self, node: Node, source_code_bytes: bytes
    ) -> List[Instruction]:
        """Handle numeric literals (integers, floats, complex numbers, BigInts)."""
        bytecode = []
        text = self._get_node_text(node, source_code_bytes)
        try:
            # Handle complex numbers (Python) and BigInt (JavaScript)
            if text.endswith("j") or text.endswith("J"):
                # Python complex number - convert to float representation
                # For malware analysis, we just need numeric representation
                numeric_part = text[:-1]
                if numeric_part:
                    value = float(numeric_part)
                else:
                    value = 1.0  # 'j' alone represents 1j
            elif text.endswith("n"):
                # JavaScript BigInt - strip the 'n' and convert to float
                value = float(text[:-1])
            else:
                # Regular integer or float
                value = float(text)
            bytecode.append(emit(OpCode.LOAD_CONST, value))
        except ValueError:
            # Fallback: treat as string if conversion fails
            bytecode.append(emit(OpCode.LOAD_CONST, text))
        return bytecode

    def _handle_simple_literals(
        self, node: Node, source_code_bytes: bytes
    ) -> List[Instruction]:
        """Handle simple literals (booleans, None/null, ellipsis)."""
        bytecode = []
        node_type = node.type

        if node_type in ["true", "false"]:
            bytecode.append(emit(OpCode.LOAD_CONST, node_type == "true"))
        elif node_type in ["none", "null"]:
            bytecode.append(emit(OpCode.LOAD_CONST, None))
        elif node_type == "ellipsis":
            bytecode.append(emit(OpCode.LOAD_CONST, "..."))

        return bytecode

    def _handle_identifier(
        self, node: Node, source_code_bytes: bytes
    ) -> List[Instruction]:
        """Handle identifier references."""
        bytecode = []
        identifier_name = self._get_node_text(node, source_code_bytes)
        bytecode.append(self._emit_load(identifier_name))
        return bytecode

    def _handle_list_or_array(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle list/array construction."""
        bytecode = []
        element_count = 0
        for element in node.children:
            if element.type not in ["[", "]", ","]:
                bytecode.extend(
                    self._generate_bytecode(element, source_code_bytes, file_path)
                )
                element_count += 1
        bytecode.append(emit(OpCode.BUILD_LIST, element_count))
        return bytecode

    def _handle_tuple(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle tuple construction."""
        bytecode = []
        element_count = 0
        for element in node.children:
            if element.type not in ["(", ")", ","]:
                bytecode.extend(
                    self._generate_bytecode(element, source_code_bytes, file_path)
                )
                element_count += 1
        bytecode.append(emit(OpCode.BUILD_TUPLE, element_count))
        return bytecode

    def _handle_set(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle set construction."""
        bytecode = []
        element_count = 0
        for element in node.children:
            if element.type not in ["{", "}", ","]:
                bytecode.extend(
                    self._generate_bytecode(element, source_code_bytes, file_path)
                )
                element_count += 1
        bytecode.append(emit(OpCode.BUILD_SET, element_count))
        return bytecode

    def _handle_dictionary_or_object(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle dictionary/object construction."""
        bytecode = []
        pair_count = 0
        for pair in node.children:
            if pair.type in [
                "pair",
                "property_identifier",
            ]:  # JS uses property_identifier for {key: val} shorthand
                key_node = pair.child_by_field_name("key") or (
                    pair if pair.type == "property_identifier" else None
                )
                value_node = pair.child_by_field_name("value") or key_node

                if key_node:
                    bytecode.extend(
                        self._generate_bytecode(
                            key_node,
                            source_code_bytes,
                            file_path,
                        )
                    )
                    bytecode.extend(
                        self._generate_bytecode(
                            value_node,
                            source_code_bytes,
                            file_path,
                        )
                    )
                    pair_count += 1
        bytecode.append(emit(OpCode.BUILD_MAP, pair_count))
        return bytecode

    def _handle_binary_operator(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle binary operators like +, -, *, /, etc."""
        bytecode = []
        binary_operator_mapping = BINARY_OPERATOR_MAPPING

        bytecode.extend(
            self._generate_bytecode(
                node.child_by_field_name("left"), source_code_bytes, file_path
            )
        )
        bytecode.extend(
            self._generate_bytecode(
                node.child_by_field_name("right"), source_code_bytes, file_path
            )
        )
        op_node = node.child_by_field_name("operator")
        if op_node:
            op_text = self._get_node_text(op_node, source_code_bytes)
            # Get operator mapping (returns tuple for BINARY_OP or single opcode for fallback)
            op_mapping = binary_operator_mapping.get(op_text, OpCode.BINARY_OPERATION)
            if isinstance(op_mapping, tuple):
                # New BINARY_OP format: (OpCode.BINARY_OP, argument)
                op_code, op_arg = op_mapping
                bytecode.append(emit(op_code, op_arg))
            else:
                # Old format or fallback
                bytecode.append(
                    emit(
                        op_mapping,
                        op_text if op_mapping == OpCode.BINARY_OPERATION else None,
                    )
                )
        return bytecode

    def _handle_unary_operator(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle unary operators like -, +, ~, not, etc."""
        bytecode = []
        unary_operator_mapping = UNARY_OPERATOR_MAPPING

        operand_node = node.child_by_field_name("operand") or node.children[-1]
        bytecode.extend(
            self._generate_bytecode(operand_node, source_code_bytes, file_path)
        )
        op_node = node.child_by_field_name("operator") or node.children[0]
        if op_node:
            op_text = self._get_node_text(op_node, source_code_bytes)
            op_code = unary_operator_mapping.get(op_text, OpCode.BINARY_OPERATION)
            bytecode.append(
                emit(op_code, op_text if op_code == OpCode.BINARY_OPERATION else None)
            )
        return bytecode

    def _handle_boolean_operator(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle boolean operators like 'and', 'or', '&&', '||'."""
        bytecode = []
        binary_operator_mapping = BINARY_OPERATOR_MAPPING

        # Handle 'and', 'or', '&&', '||' operators
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        op_node = node.child_by_field_name("operator")

        if left_node and right_node:
            bytecode.extend(
                self._generate_bytecode(left_node, source_code_bytes, file_path)
            )
            bytecode.extend(
                self._generate_bytecode(right_node, source_code_bytes, file_path)
            )

            if op_node:
                op_text = self._get_node_text(op_node, source_code_bytes)
                # Get operator mapping (returns tuple for BINARY_OP or single opcode for fallback)
                op_mapping = binary_operator_mapping.get(
                    op_text, OpCode.BINARY_OPERATION
                )
                if isinstance(op_mapping, tuple):
                    # New BINARY_OP format: (OpCode.BINARY_OP, argument)
                    op_code, op_arg = op_mapping
                    bytecode.append(emit(op_code, op_arg))
                else:
                    # Old format or fallback
                    bytecode.append(
                        emit(
                            op_mapping,
                            (
                                op_text
                                if op_mapping == OpCode.BINARY_OPERATION
                                else None
                            ),
                        )
                    )
            else:
                bytecode.append(emit(OpCode.BINARY_OPERATION, None))
        return bytecode

    def _handle_comparison_operator(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle comparison chains like 'a < b < c'."""
        bytecode = []
        children = list(node.named_children)
        for i, child in enumerate(children):
            bytecode.extend(
                self._generate_bytecode(child, source_code_bytes, file_path)
            )
            # For comparison chains with multiple comparisons, copy intermediate values
            if i > 0 and i < len(children) - 1:
                bytecode.append(emit(OpCode.COPY, 1))
        # For comparison chains, we'll use the generic COMPARE_OP
        bytecode.append(emit(OpCode.COMPARE_OP, None))
        return bytecode

    def _handle_not_operator(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle 'not' operator."""
        bytecode = []
        operand_node = node.child_by_field_name("operand") or node.children[-1]
        bytecode.extend(
            self._generate_bytecode(operand_node, source_code_bytes, file_path)
        )
        bytecode.append(emit(OpCode.LOGICAL_NOT, None))
        return bytecode

    def _handle_function_call(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle function calls with various argument types."""
        bytecode = []
        func_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")

        # Push NULL for function call optimization (Python 3.11+)
        bytecode.append(emit(OpCode.PUSH_NULL, None))

        if func_node:
            bytecode.extend(
                self._generate_bytecode(func_node, source_code_bytes, file_path)
            )

        arg_count = 0
        kwarg_count = 0
        has_starargs = False
        kw_names = []  # Collect keyword names for KW_NAMES

        if args_node:
            for arg in args_node.children:
                if arg.type not in [",", "(", ")"]:
                    if arg.type == "list_splat":
                        # Handle *args
                        argument_node = (
                            arg.child_by_field_name("argument") or arg.named_children[0]
                        )
                        if argument_node:
                            bytecode.extend(
                                self._generate_bytecode(
                                    argument_node, source_code_bytes, file_path
                                )
                            )
                            has_starargs = True
                    elif arg.type == "dictionary_splat":
                        # Handle **kwargs
                        argument_node = (
                            arg.child_by_field_name("argument") or arg.named_children[0]
                        )
                        if argument_node:
                            bytecode.extend(
                                self._generate_bytecode(
                                    argument_node, source_code_bytes, file_path
                                )
                            )
                            pass  # kwargs found
                    elif arg.type == "keyword_argument":
                        # Handle key=value - Python approach: load values only, names in KW_NAMES
                        name_node = arg.child_by_field_name("name")
                        value_node = arg.child_by_field_name("value")
                        if name_node and value_node:
                            key_name = self._get_node_text(name_node, source_code_bytes)
                            # Collect keyword name for KW_NAMES tuple
                            kw_names.append(key_name)
                            # Load only the value (not the name)
                            bytecode.extend(
                                self._generate_bytecode(
                                    value_node, source_code_bytes, file_path
                                )
                            )
                            kwarg_count += 1
                    else:
                        # Regular positional argument
                        bytecode.extend(
                            self._generate_bytecode(arg, source_code_bytes, file_path)
                        )
                        arg_count += 1

        # Choose appropriate call instruction based on argument types
        if kwarg_count > 0:
            # For calls with keyword arguments, emit KW_NAMES with actual tuple
            kw_names_tuple = tuple(kw_names)
            bytecode.append(emit(OpCode.KW_NAMES, kw_names_tuple))
            # Use CALL opcode for Python 3.11+ compatibility
            bytecode.append(emit(OpCode.CALL, arg_count + kwarg_count))
        elif has_starargs:
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
            )  # CALL with variable arguments
        else:
            # Use CALL opcode for Python 3.11+ compatibility
            bytecode.append(emit(OpCode.CALL, arg_count))

        return bytecode

    def _handle_if_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle if-else statements with proper jump logic."""
        bytecode = []
        condition_node = node.child_by_field_name("condition")
        consequence_node = node.child_by_field_name("consequence")
        alternative_node = node.child_by_field_name("alternative")

        bytecode.extend(
            self._generate_bytecode(condition_node, source_code_bytes, file_path)
        )

        jump_instr_index = len(bytecode)
        bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))

        consequence_bytecode = self._generate_bytecode(
            consequence_node, source_code_bytes, file_path
        )
        bytecode.extend(consequence_bytecode)

        if alternative_node:
            jump_over_else_index = len(bytecode)
            bytecode.append(emit(OpCode.JUMP_FORWARD, -1))
            # Set jump target for the initial if to point after the 'then' block
            bytecode[jump_instr_index] = emit(OpCode.POP_JUMP_IF_FALSE, len(bytecode))

            alternative_bytecode = self._generate_bytecode(
                alternative_node, source_code_bytes, file_path
            )
            bytecode.extend(alternative_bytecode)
            # Set the jump to point after the 'else' block
            bytecode[jump_over_else_index] = emit(OpCode.JUMP_FORWARD, len(bytecode))

        else:
            # If no 'else', the jump just goes to the end of the 'then' block
            bytecode[jump_instr_index] = emit(OpCode.POP_JUMP_IF_FALSE, len(bytecode))

        return bytecode

    def _handle_update_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle ++, -- operators (JavaScript)."""
        bytecode = []
        argument_node = node.child_by_field_name("argument")
        if argument_node:
            # Load current value
            bytecode.extend(
                self._generate_bytecode(argument_node, source_code_bytes, file_path)
            )
            # Perform increment/decrement
            bytecode.append(emit(OpCode.LOAD_CONST, 1.0))
            op_text = self._get_node_text(node, source_code_bytes)
            if "++" in op_text:
                bytecode.append(emit(OpCode.BINARY_ADD, None))
            else:  # "--"
                bytecode.append(emit(OpCode.BINARY_OP, 2))  # BINARY_OP 2 = subtract
            # Store back
            var_name = self._get_node_text(argument_node, source_code_bytes)
            bytecode.append(self._emit_store(var_name))
        return bytecode

    def _handle_new_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle `new Constructor()` calls."""
        bytecode = []
        constructor_node = node.child_by_field_name("constructor")
        if constructor_node:
            bytecode.extend(
                self._generate_bytecode(constructor_node, source_code_bytes, file_path)
            )

        # Process arguments
        arguments_node = node.child_by_field_name("arguments")
        arg_count = 0
        if arguments_node:
            for child in arguments_node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
                arg_count += 1
        # Use CALL opcode for Python 3.11+ compatibility
        bytecode.append(emit(OpCode.CALL, arg_count))
        return bytecode

    def _handle_import_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle various import statements for Python and JavaScript."""
        bytecode = []
        node_type = node.type

        if node_type == "import_statement":
            # Handle "import module" or "import module as alias"
            for child in node.named_children:
                if child.type == "dotted_name" or child.type == "identifier":
                    module_name = self._get_node_text(child, source_code_bytes)
                    # Python import pattern: LOAD_CONST 0 + LOAD_CONST None + IMPORT_NAME + STORE_NAME
                    bytecode.append(
                        emit(OpCode.LOAD_CONST, 0)
                    )  # Import level (0 = absolute)
                    bytecode.append(
                        emit(OpCode.LOAD_CONST, None)
                    )  # fromlist (None for simple import)
                    bytecode.append(emit(OpCode.IMPORT_NAME, module_name))
                    bytecode.append(emit(OpCode.STORE_NAME, module_name))
                elif child.type == "aliased_import":
                    # Handle "import module as alias"
                    module_node = child.child_by_field_name("name")
                    alias_node = child.child_by_field_name("alias")
                    if module_node and alias_node:
                        module_name = self._get_node_text(
                            module_node, source_code_bytes
                        )
                        alias_name = self._get_node_text(alias_node, source_code_bytes)
                        bytecode.append(emit(OpCode.LOAD_CONST, 0))
                        bytecode.append(emit(OpCode.LOAD_CONST, None))
                        bytecode.append(emit(OpCode.IMPORT_NAME, module_name))
                        bytecode.append(
                            emit(OpCode.STORE_NAME, alias_name)
                        )  # Store with alias name

        elif node_type == "import_from_statement":
            # Handle "from module import name" or "from module import name1, name2"
            module_node = node.child_by_field_name("module_name")

            if module_node:
                module_name = self._get_node_text(module_node, source_code_bytes)

                # Collect all imported names and their aliases
                import_info = []  # List of (original_name, store_name) tuples
                imported_names = []  # List of original names for fromlist

                for i in range(node.child_count):
                    child = node.child(i)
                    if child.type == "aliased_import":
                        # Handle "name as alias"
                        name_node = child.child_by_field_name("name")
                        alias_node = child.child_by_field_name("alias")
                        if name_node and alias_node:
                            original_name = self._get_node_text(
                                name_node, source_code_bytes
                            )
                            alias_name = self._get_node_text(
                                alias_node, source_code_bytes
                            )
                            import_info.append((original_name, alias_name))
                            imported_names.append(original_name)
                    elif node.field_name_for_child(i) == "name":
                        # Handle direct import (no alias)
                        name_node = node.child(i)
                        name = self._get_node_text(name_node, source_code_bytes)
                        import_info.append((name, name))
                        imported_names.append(name)

                if import_info:
                    # Create fromlist tuple for the import
                    bytecode.append(emit(OpCode.LOAD_CONST, 0))  # Import level
                    bytecode.append(
                        emit(OpCode.LOAD_CONST, tuple(imported_names))
                    )  # fromlist as tuple
                    bytecode.append(emit(OpCode.IMPORT_NAME, module_name))

                    # Import each name and store it (using alias if available)
                    for original_name, store_name in import_info:
                        bytecode.append(emit(OpCode.IMPORT_FROM, original_name))
                        bytecode.append(emit(OpCode.STORE_NAME, store_name))
                    bytecode.append(
                        emit(OpCode.POP_TOP, None)
                    )  # Clean up module object

        else:  # JavaScript import_declaration
            for child in node.named_children:
                if child.type == "identifier" or child.type == "dotted_name":
                    name = self._get_node_text(child, source_code_bytes)
                    bytecode.append(emit(OpCode.LOAD_CONST, 0))
                    bytecode.append(emit(OpCode.LOAD_CONST, None))
                    bytecode.append(emit(OpCode.IMPORT_NAME, name))
                    bytecode.append(emit(OpCode.STORE_NAME, name))
            # Handle other cases as needed
            pass

        return bytecode

    def _handle_export_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle export statements (JavaScript ES6)."""
        bytecode = []
        node_type = node.type

        # Process exports - for malware analysis, we track exported names
        # Handle both named exports and default exports
        for child in node.named_children:
            if child.type == "identifier":
                name = self._get_node_text(child, source_code_bytes)
                if node_type == "export_default":
                    bytecode.append(emit(OpCode.EXPORT_DEFAULT, name))
                else:
                    bytecode.append(emit(OpCode.EXPORT_NAMED, name))
            elif child.type == "function_declaration":
                # Handle export function name() {}
                func_name = None
                for grandchild in child.named_children:
                    if grandchild.type == "identifier":
                        func_name = self._get_node_text(grandchild, source_code_bytes)
                        break
                if func_name:
                    bytecode.append(emit(OpCode.EXPORT_NAMED, func_name))
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            elif child.type == "variable_declaration":
                # Handle export const/let/var declarations
                for grandchild in child.named_children:
                    if grandchild.type == "variable_declarator":
                        for great_grandchild in grandchild.named_children:
                            if great_grandchild.type == "identifier":
                                name = self._get_node_text(
                                    great_grandchild, source_code_bytes
                                )
                                bytecode.append(emit(OpCode.EXPORT_NAMED, name))
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            else:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )

        return bytecode

    def _handle_try_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle try/except/finally blocks with Python exception protocol."""
        bytecode = []
        body_node = node.child_by_field_name("body")
        except_clauses = []

        # Collect except and finally clauses
        for child in node.children:
            if child.type in ["except_clause", "catch_clause"]:
                except_clauses.append(child)
            elif child.type == "finally_clause":
                pass  # finally clause found

        # Add NOP for try block start (Python pattern)
        bytecode.append(emit(OpCode.NOP, None))

        # Generate try block
        if body_node:
            bytecode.extend(
                self._generate_bytecode(body_node, source_code_bytes, file_path)
            )

        # Normal completion - return/exit
        bytecode.append(emit(OpCode.RETURN_CONST, None))

        # Exception handling starts here - PUSH_EXC_INFO
        bytecode.append(emit(OpCode.PUSH_EXC_INFO, None))

        # Generate except clauses
        for except_clause in except_clauses:
            # Check if this except has a specific exception type
            exception_node = except_clause.child_by_field_name("value")
            except_body = None

            # Find the exception body (last block child)
            for child in except_clause.children:
                if child.type == "block":
                    except_body = child

            if exception_node:
                # Load exception type and check match
                exception_name = self._get_node_text(exception_node, source_code_bytes)
                bytecode.append(emit(OpCode.LOAD_NAME, exception_name))
                bytecode.append(emit(OpCode.CHECK_EXC_MATCH, None))

                # Jump if no match
                no_match_jump = len(bytecode)
                bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))  # Will patch

                # Pop exception info
                bytecode.append(emit(OpCode.POP_TOP, None))

                # Generate except body
                if except_body:
                    bytecode.extend(
                        self._generate_bytecode(
                            except_body, source_code_bytes, file_path
                        )
                    )

                # Clean up and return
                bytecode.append(emit(OpCode.POP_EXCEPT, None))
                bytecode.append(emit(OpCode.RETURN_CONST, None))

                # Patch the no-match jump to point here
                bytecode[no_match_jump] = emit(OpCode.POP_JUMP_IF_FALSE, len(bytecode))

        # Re-raise if no handler matched
        bytecode.append(emit(OpCode.RERAISE, 0))

        # Exception cleanup (simplified)
        bytecode.append(emit(OpCode.COPY, 3))
        bytecode.append(emit(OpCode.POP_EXCEPT, None))
        bytecode.append(emit(OpCode.RERAISE, 1))
        # Note: Simplified exception handling - real Python uses exception tables
        # This provides basic structural compatibility

        return bytecode

    def _handle_with_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle with statements - Python context manager protocol."""
        bytecode = []
        with_items = []

        # Look for with_clause first, then extract with_items from it
        for child in node.children:
            if child.type == "with_clause":
                for grandchild in child.children:
                    if grandchild.type == "with_item":
                        with_items.append(grandchild)

        # Process each context manager
        for with_item in with_items:
            # Generate bytecode for the context expression
            context_expr = None
            as_pattern = None

            for child in with_item.children:
                if child.type == "as_pattern":
                    # Extract the expression and the target from as_pattern
                    for as_child in child.children:
                        if as_child.type not in ["as", "as_pattern_target"]:
                            context_expr = as_child
                        elif as_child.type == "as_pattern_target":
                            # Extract identifier from as_pattern_target
                            for target_child in as_child.children:
                                if target_child.type == "identifier":
                                    as_pattern = target_child
                elif child.type not in ["as", "identifier", ","]:
                    context_expr = child

            if context_expr:
                # Generate context expression (e.g., open("file", "r"))
                bytecode.extend(
                    self._generate_bytecode(context_expr, source_code_bytes, file_path)
                )
                # Python WITH protocol: BEFORE_WITH
                bytecode.append(emit(OpCode.BEFORE_WITH, None))

                # Handle 'as' variable if present (e.g., "as f:")
                if as_pattern:
                    var_name = self._get_node_text(as_pattern, source_code_bytes)
                    bytecode.append(emit(OpCode.STORE_NAME, var_name))

        # Process the body
        body_node = node.child_by_field_name("body")
        if body_node:
            bytecode.extend(
                self._generate_bytecode(body_node, source_code_bytes, file_path)
            )

        # Python WITH cleanup: Load None, None, None + CALL + POP_TOP (normal exit)
        bytecode.append(emit(OpCode.LOAD_CONST, None))
        bytecode.append(emit(OpCode.LOAD_CONST, None))
        bytecode.append(emit(OpCode.LOAD_CONST, None))
        bytecode.append(emit(OpCode.CALL, 2))
        bytecode.append(emit(OpCode.POP_TOP, None))

        # WITH exception handling protocol
        bytecode.append(emit(OpCode.PUSH_EXC_INFO, None))
        bytecode.append(emit(OpCode.WITH_EXCEPT_START, None))

        # Jump to cleanup if exception handler returns True
        cleanup_jump_pos = len(bytecode)
        bytecode.append(emit(OpCode.POP_JUMP_IF_TRUE, -1))  # Placeholder

        # Re-raise exception if handler returns False
        bytecode.append(emit(OpCode.RERAISE, 2))

        # Cleanup handler (jump target)
        cleanup_start = len(bytecode)
        bytecode.append(emit(OpCode.POP_TOP, None))
        bytecode.append(emit(OpCode.POP_EXCEPT, None))
        bytecode.append(emit(OpCode.POP_TOP, None))
        bytecode.append(emit(OpCode.POP_TOP, None))

        # Jump back to normal flow
        return_jump_pos = len(bytecode)
        bytecode.append(emit(OpCode.JUMP_BACKWARD, -1))  # Placeholder

        # Exception re-raise cleanup
        bytecode.append(emit(OpCode.COPY, 3))
        bytecode.append(emit(OpCode.POP_EXCEPT, None))
        bytecode.append(emit(OpCode.RERAISE, 1))

        # Fix jump targets
        bytecode[cleanup_jump_pos] = emit(OpCode.POP_JUMP_IF_TRUE, cleanup_start)
        bytecode[return_jump_pos] = emit(
            OpCode.JUMP_BACKWARD, len(bytecode) - return_jump_pos + 1
        )

        return bytecode

    def _handle_function_definition(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle function definitions and declarations."""
        bytecode = []
        node_type = node.type

        func_name = self._get_node_text(
            node.child_by_field_name("name"), source_code_bytes
        )
        body_node = node.child_by_field_name("body")

        # Check if this is an async or generator function
        is_async = False
        is_generator = False

        # Generator functions are explicitly marked by node type in JavaScript
        if node_type == "generator_function_declaration":
            is_generator = True

        for child in node.children:
            if (
                child.type == "async"
                or self._get_node_text(child, source_code_bytes) == "async"
            ):
                is_async = True
            elif (
                child.type == "*"
                or self._get_node_text(child, source_code_bytes) == "*"
            ):
                is_generator = True

        # Also check for generator functions by looking for yield in the body
        if not is_generator and body_node:
            is_generator = self._contains_yield(body_node, source_code_bytes)

        # Extract parameters and set context for this function
        params = self._extract_function_parameters(node, source_code_bytes)
        previous_params = self.current_function_params
        previous_in_function = self._in_function_scope
        previous_nesting_depth = self._nesting_depth
        self.current_function_params = params
        self._in_function_scope = True
        self._nesting_depth += 1

        if body_node:
            func_body_bytecode = self._generate_bytecode(
                body_node, source_code_bytes, file_path
            )
        else:
            # Bodyless function declaration (e.g., in traits or extern blocks)
            func_body_bytecode = []
        if (
            not func_body_bytecode
            or func_body_bytecode[-1].opcode != OpCode.RETURN_VALUE
        ):
            func_body_bytecode.append(emit(OpCode.RETURN_VALUE, None))

        # Restore previous parameter context
        self.current_function_params = previous_params
        self._in_function_scope = previous_in_function
        self._nesting_depth = previous_nesting_depth

        func_source = self._get_node_text(node, source_code_bytes)
        location = (node.start_point[0] + 1, node.end_point[0] + 1)

        # Only create separate MalwiObject for top-level functions (nesting_depth == 0)
        if self._nesting_depth == 0:
            # Create separate MalwiObject and add to collection
            from .malwi_object import MalwiObject

            func_code_obj = MalwiObject(
                name=func_name,
                language=self.language_name,
                file_path=str(file_path),
                file_source_code=source_code_bytes.decode("utf-8", errors="replace"),
                byte_code=func_body_bytecode,
                source_code=func_source,
                location=location,
            )
            self.code_objects.append(func_code_obj)

            # Python-like structure: LOAD_CONST -> MAKE_FUNCTION -> STORE_NAME
            # Load the function name as reference instead of full MalwiObject
            bytecode.append(emit(OpCode.LOAD_CONST, func_name))

            # Use appropriate opcode based on function type with arg=0 (no defaults)
            if is_async and is_generator:
                # Async generator function
                bytecode.append(emit(OpCode.ASYNC_FUNCTION, 0))
            elif is_async:
                bytecode.append(emit(OpCode.ASYNC_FUNCTION, 0))
            elif is_generator:
                bytecode.append(emit(OpCode.GENERATOR_FUNCTION, 0))
            else:
                bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))
            bytecode.append(self._emit_store(func_name))
        else:
            # For nested functions, inline the bytecode directly
            # Use appropriate opcode based on function type (but inline the body)
            if is_async and is_generator:
                bytecode.append(emit(OpCode.ASYNC_FUNCTION, func_name))
            elif is_async:
                bytecode.append(emit(OpCode.ASYNC_FUNCTION, func_name))
            elif is_generator:
                bytecode.append(emit(OpCode.GENERATOR_FUNCTION, func_name))
            else:
                bytecode.append(emit(OpCode.MAKE_FUNCTION, func_name))

            # Inline the function body bytecode
            bytecode.extend(func_body_bytecode)
            bytecode.append(self._emit_store(func_name))

        return bytecode

    def _handle_class_definition(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle class definitions and declarations."""
        bytecode = []

        class_name = self._get_node_text(
            node.child_by_field_name("name"), source_code_bytes
        )
        body_node = node.child_by_field_name("body")

        # Track nesting depth for classes too
        previous_nesting_depth = self._nesting_depth
        self._nesting_depth += 1

        class_body_bytecode = self._generate_bytecode(
            body_node, source_code_bytes, file_path
        )

        # Restore nesting depth
        self._nesting_depth = previous_nesting_depth

        class_source = self._get_node_text(node, source_code_bytes)
        location = (node.start_point[0] + 1, node.end_point[0] + 1)

        # Only create separate MalwiObject for top-level classes
        if self._nesting_depth == 0:
            # Create separate MalwiObject and add to collection
            from .malwi_object import MalwiObject

            class_code_obj = MalwiObject(
                name=class_name,
                language=self.language_name,
                file_path=str(file_path),
                file_source_code=source_code_bytes.decode("utf-8", errors="replace"),
                byte_code=class_body_bytecode,
                source_code=class_source,
                location=location,
            )
            self.code_objects.append(class_code_obj)

            # Python class protocol: PUSH_NULL + LOAD_BUILD_CLASS + LOAD_CONST + MAKE_FUNCTION + class_name + CALL
            bytecode.append(emit(OpCode.PUSH_NULL, None))
            bytecode.append(emit(OpCode.LOAD_BUILD_CLASS, None))
            bytecode.append(
                emit(OpCode.LOAD_CONST, class_name)
            )  # Class name instead of full MalwiObject
            bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))  # No defaults
            bytecode.append(emit(OpCode.LOAD_CONST, class_name))  # Class name
            bytecode.append(emit(OpCode.CALL, 2))  # Call build class with 2 args
            bytecode.append(self._emit_store(class_name))
        else:
            # For nested classes, inline the bytecode directly
            bytecode.append(emit(OpCode.MAKE_CLASS, class_name))
            # Inline the class body bytecode
            bytecode.extend(class_body_bytecode)
            bytecode.append(self._emit_store(class_name))

        return bytecode

    def _handle_macro_definition(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle Rust macro definitions."""
        bytecode = []
        name_node = node.child_by_field_name("name")
        macro_name = self._get_node_text(name_node, source_code_bytes)
        if not macro_name:
            macro_name = "<macro>"

        bytecode.append(emit(OpCode.LOAD_CONST, macro_name))
        bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))
        bytecode.append(self._emit_store(macro_name))
        return bytecode

    def _handle_macro_invocation(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle Rust macro invocations."""
        bytecode = []

        # Load the macro name
        path_node = node.child_by_field_name("path") or node.child_by_field_name(
            "macro"
        )
        macro_name = self._get_node_text(path_node, source_code_bytes)

        bytecode.append(emit(OpCode.PUSH_NULL, None))
        if macro_name:
            bytecode.append(emit(OpCode.LOAD_NAME, macro_name))

        # Macros use token trees; treat named children as arguments
        arg_count = 0
        token_tree = node.child_by_field_name("token_tree")
        if token_tree:
            for child in token_tree.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
                arg_count += 1

        bytecode.append(emit(OpCode.CALL, arg_count))
        return bytecode

    def _handle_comprehension(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle list, dict, set comprehensions and generator expressions."""
        bytecode = []
        node_type = node.type

        # Process comprehensions with for_in_clause and if_clause support
        element_expr = None
        for_clauses = []
        if_clauses = []

        for child in node.named_children:
            if child.type == "for_in_clause":
                # Handle: for var in iterable
                var_node = child.child_by_field_name("left")
                iterable_node = child.child_by_field_name("right")
                for_clauses.append((var_node, iterable_node))
            elif child.type == "if_clause":
                # Handle: if condition
                condition_node = (
                    child.child_by_field_name("condition") or child.named_children[0]
                )
                if_clauses.append(condition_node)
            elif child.type in ["pair"]:
                # Dictionary comprehension key:value pair
                element_expr = child
            else:
                # Expression to evaluate (list/set element)
                if not element_expr:
                    element_expr = child

        # Generate bytecode for comprehension
        # Start with empty collection
        if node_type == "list_comprehension":
            bytecode.append(emit(OpCode.BUILD_LIST, 0))
        elif node_type == "dictionary_comprehension":
            bytecode.append(emit(OpCode.BUILD_MAP, 0))
        elif node_type == "set_comprehension":
            bytecode.append(emit(OpCode.BUILD_SET, 0))

        # Track comprehension variables for proper scoping
        comp_vars = set()

        # Process for clauses (nested loops)
        for var_node, iterable_node in for_clauses:
            if iterable_node:
                bytecode.extend(
                    self._generate_bytecode(iterable_node, source_code_bytes, file_path)
                )
                bytecode.append(emit(OpCode.GET_ITER, None))

                # Loop start
                loop_start = len(bytecode)
                bytecode.append(emit(OpCode.FOR_ITER, -1))  # Will be patched

                if var_node:
                    var_name = self._get_node_text(var_node, source_code_bytes)
                    bytecode.append(emit(OpCode.STORE_FAST, var_name))
                    # Track this as comprehension variable
                    comp_vars.add(var_name)
                    self.comprehension_variables.add(var_name)

                # Process if clauses (filters)
                for condition_node in if_clauses:
                    bytecode.extend(
                        self._generate_bytecode(
                            condition_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, loop_start))

                # Generate element expression
                if element_expr:
                    if node_type == "dictionary_comprehension":
                        # For dict comprehensions, element_expr is a pair node
                        key_node = element_expr.child_by_field_name("key")
                        value_node = element_expr.child_by_field_name("value")
                        if key_node and value_node:
                            # Load key
                            bytecode.extend(
                                self._generate_bytecode(
                                    key_node, source_code_bytes, file_path
                                )
                            )
                            # Load value
                            bytecode.extend(
                                self._generate_bytecode(
                                    value_node, source_code_bytes, file_path
                                )
                            )
                            # Add to dict
                            bytecode.append(emit(OpCode.MAP_ADD, 1))
                    else:
                        # For list/set comprehensions, generate the element
                        bytecode.extend(
                            self._generate_bytecode(
                                element_expr, source_code_bytes, file_path
                            )
                        )
                        # Add to collection
                        if node_type == "list_comprehension":
                            bytecode.append(emit(OpCode.LIST_APPEND, 1))
                        elif node_type == "set_comprehension":
                            bytecode.append(emit(OpCode.SET_ADD, 1))

                # Jump back to loop start
                bytecode.append(emit(OpCode.JUMP_FORWARD, loop_start))

                # Patch FOR_ITER to jump here when done
                bytecode[loop_start] = emit(OpCode.FOR_ITER, len(bytecode))

        # Clean up comprehension variables from scope tracking
        for var_name in comp_vars:
            self.comprehension_variables.discard(var_name)

        return bytecode

    def _handle_string_literal(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle string literals including f-strings with interpolation."""
        bytecode = []

        # Check if this string has interpolation children (f-string)
        has_interpolation = any(
            child.type == "interpolation" for child in node.children
        )

        if has_interpolation:
            # Handle f-string with proper BUILD_STRING/FORMAT_VALUE
            parts = []

            # Check if it's an f-string by looking at string_start
            if node.children and node.children[0].type == "string_start":
                string_start = self._get_node_text(node.children[0], source_code_bytes)
                if string_start.startswith("f"):
                    # Process f-string children
                    for child in node.children[
                        1:-1
                    ]:  # Skip string_start and string_end
                        if child.type == "string_content":
                            # Regular string part
                            text = self._get_node_text(child, source_code_bytes)
                            if text:  # Only add non-empty strings
                                bytecode.append(emit(OpCode.LOAD_CONST, text))
                                parts.append("str")
                        elif child.type == "interpolation":
                            # Expression to format
                            for expr_child in child.children:
                                if expr_child.type not in ["{", "}"]:
                                    bytecode.extend(
                                        self._generate_bytecode(
                                            expr_child, source_code_bytes, file_path
                                        )
                                    )
                                    bytecode.append(emit(OpCode.FORMAT_VALUE, None))
                                    parts.append("fmt")
                                    break

                    # Build the final string
                    if len(parts) > 0:
                        bytecode.append(emit(OpCode.BUILD_STRING, len(parts)))
                    return bytecode

            # Fallback for other interpolation patterns
            string_parts = 0
            for child in node.children:
                if child.type == "interpolation":
                    # Handle {expression} in f-string
                    for expr_child in child.children:
                        if expr_child.type not in ["{", "}"]:
                            bytecode.extend(
                                self._generate_bytecode(
                                    expr_child, source_code_bytes, file_path
                                )
                            )
                            string_parts += 1
                            break
                elif child.type == "string_content":
                    # Handle regular string parts
                    text_content = self._get_node_text(child, source_code_bytes)
                    if text_content.strip():  # Only add non-empty content
                        bytecode.append(emit(OpCode.LOAD_CONST, text_content))
                        string_parts += 1

            # Build the formatted string if we have multiple parts
            if string_parts > 1:
                bytecode.append(
                    emit(OpCode.BINARY_OPERATION, None)
                )  # String format/join
            elif string_parts == 0:
                # Fallback if no parts were processed
                str_content = self._get_node_text(node, source_code_bytes)
                bytecode.append(emit(OpCode.LOAD_CONST, str_content))
        else:
            # Regular string without interpolation
            str_content = self._get_node_text(node, source_code_bytes)
            bytecode.append(emit(OpCode.LOAD_CONST, str_content))

        return bytecode

    def _handle_sequence_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle comma operator (JavaScript)."""
        bytecode = []
        for child in node.named_children:
            bytecode.extend(
                self._generate_bytecode(child, source_code_bytes, file_path)
            )
            # Only the last expression's value is kept
        return bytecode

    def _handle_yield_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle Python yield and yield from expressions."""
        bytecode = []
        value_node = node.child_by_field_name("argument") or node.child_by_field_name(
            "value"
        )

        if value_node:
            bytecode.extend(
                self._generate_bytecode(value_node, source_code_bytes, file_path)
            )
        else:
            # yield without value yields None
            bytecode.append(emit(OpCode.LOAD_CONST, None))

        # Emit proper YIELD_VALUE opcode
        bytecode.append(emit(OpCode.YIELD_VALUE, None))
        return bytecode

    def _handle_template_string(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle template literals with ${} substitutions."""
        bytecode = []
        for child in node.named_children:
            if child.type == "template_substitution":
                # Handle ${expression}
                expr_node = child.child_by_field_name("expression")
                if expr_node:
                    bytecode.extend(
                        self._generate_bytecode(expr_node, source_code_bytes, file_path)
                    )
            else:
                # Handle regular string parts
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
        # Concatenate all parts
        bytecode.append(
            emit(OpCode.BINARY_OPERATION, None)
        )  # Placeholder for string formatting
        return bytecode

    def _handle_assignment(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle assignment statements including destructuring."""
        bytecode = []
        # This handles python `a=b`, JS `a=b`, and JS `var a=b`
        value_node = node.child_by_field_name("right") or node.child_by_field_name(
            "value"
        )
        name_node = node.child_by_field_name("left") or node.child_by_field_name("name")

        if value_node and name_node:
            # Check if this is tuple/list unpacking (Python)
            if name_node.type == "pattern_list":
                # First evaluate the right side
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )
                # Count the number of targets
                target_count = len(
                    [
                        child
                        for child in name_node.named_children
                        if child.type == "identifier"
                    ]
                )
                # Emit UNPACK_SEQUENCE
                bytecode.append(emit(OpCode.UNPACK_SEQUENCE, target_count))
                # Store each unpacked value
                for child in name_node.named_children:
                    if child.type == "identifier":
                        var_name = self._get_node_text(child, source_code_bytes)
                        bytecode.append(self._emit_store(var_name))
            else:
                # For other patterns, evaluate right side first
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )

            # Handle destructuring patterns (e.g., const { exec, spawn } = ...)
            if name_node.type == "object_pattern":
                # Extract individual identifiers from destructuring pattern
                for child in name_node.named_children:
                    if child.type == "shorthand_property_identifier_pattern":
                        identifier_name = self._get_node_text(child, source_code_bytes)
                        bytecode.append(emit(OpCode.STORE_NAME, identifier_name))
                    elif child.type == "pair_pattern":
                        # Handle { key: alias } patterns
                        value_child = child.child_by_field_name("value")
                        if value_child and value_child.type == "identifier":
                            identifier_name = self._get_node_text(
                                value_child, source_code_bytes
                            )
                            bytecode.append(emit(OpCode.STORE_NAME, identifier_name))
            elif name_node.type == "array_pattern":
                # Handle array destructuring [a, b] = ...
                for child in name_node.named_children:
                    if child.type == "identifier":
                        identifier_name = self._get_node_text(child, source_code_bytes)
                        bytecode.append(emit(OpCode.STORE_NAME, identifier_name))
            elif name_node.type in ["subscript_expression", "subscript"]:
                # Handle subscript assignment: obj[key] = value
                object_node = name_node.child_by_field_name(
                    "object"
                ) or name_node.child_by_field_name("value")
                index_node = name_node.child_by_field_name(
                    "index"
                ) or name_node.child_by_field_name("subscript")

                if object_node and index_node:
                    # Load object
                    bytecode.extend(
                        self._generate_bytecode(
                            object_node, source_code_bytes, file_path
                        )
                    )
                    # Load index/key
                    bytecode.extend(
                        self._generate_bytecode(
                            index_node, source_code_bytes, file_path
                        )
                    )
                    # Store subscript
                    bytecode.append(emit(OpCode.STORE_SUBSCR, None))
            elif name_node.type in ["attribute", "member_expression"]:
                # Handle attribute assignment: obj.attr = value
                object_node = name_node.child_by_field_name(
                    "object"
                ) or name_node.child_by_field_name("value")
                attribute_node = name_node.child_by_field_name(
                    "attribute"
                ) or name_node.child_by_field_name("property")

                if object_node and attribute_node:
                    # Load object
                    bytecode.extend(
                        self._generate_bytecode(
                            object_node, source_code_bytes, file_path
                        )
                    )
                    # Get attribute name
                    attr_name = self._get_node_text(attribute_node, source_code_bytes)
                    # Store attribute
                    bytecode.append(emit(OpCode.STORE_ATTR, attr_name))
            else:
                # Regular single variable assignment
                var_name = self._get_node_text(name_node, source_code_bytes)
                bytecode.append(self._emit_store(var_name))

        return bytecode

    def _handle_return_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle return statements."""
        bytecode = []
        if node.child_count > 1 and node.children[1].type not in [";"]:
            return_val_node = node.children[1]
            bytecode.extend(
                self._generate_bytecode(return_val_node, source_code_bytes, file_path)
            )
        bytecode.append(emit(OpCode.RETURN_VALUE, None))
        return bytecode

    def _handle_augmented_assignment(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle +=, -=, *=, etc."""
        bytecode = []
        target_node = node.child_by_field_name("left")
        value_node = node.child_by_field_name("right")
        if target_node and value_node:
            # Load current value
            bytecode.extend(
                self._generate_bytecode(target_node, source_code_bytes, file_path)
            )
            # Load new value
            bytecode.extend(
                self._generate_bytecode(value_node, source_code_bytes, file_path)
            )
            # Perform operation - use BINARY_OP to match Python's pattern
            bytecode.append(emit(OpCode.BINARY_OP, None))
            # Store result
            var_name = self._get_node_text(target_node, source_code_bytes)
            bytecode.append(self._emit_store(var_name))
        return bytecode

    def _handle_regex(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle regex literals."""
        bytecode = []
        pattern_text = self._get_node_text(node, source_code_bytes)
        bytecode.append(emit(OpCode.LOAD_CONST, pattern_text))
        return bytecode

    def _handle_lambda_arrow_function(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle lambda expressions and arrow functions."""
        bytecode = []
        body_node = node.child_by_field_name("body")
        if body_node:
            # Extract parameters and set context for this function
            params = self._extract_function_parameters(node, source_code_bytes)
            previous_params = self.current_function_params
            previous_in_function = self._in_function_scope
            self.current_function_params = params
            self._in_function_scope = True

            func_body_bytecode = self._generate_bytecode(
                body_node, source_code_bytes, file_path
            )
            if (
                not func_body_bytecode
                or func_body_bytecode[-1].opcode != OpCode.RETURN_VALUE
            ):
                func_body_bytecode.append(emit(OpCode.RETURN_VALUE, None))

            # Restore previous parameter context
            self.current_function_params = previous_params
            self._in_function_scope = previous_in_function

            func_source = self._get_node_text(node, source_code_bytes)
            location = (node.start_point[0] + 1, node.end_point[0] + 1)

            # Create separate MalwiObject and add to collection
            func_code_obj = MalwiObject(
                name="lambda",
                language=self.language_name,
                file_path=str(file_path),
                file_source_code=source_code_bytes.decode("utf-8", errors="replace"),
                byte_code=func_body_bytecode,
                source_code=func_source,
                location=location,
            )
            self.code_objects.append(func_code_obj)

            # Use function name in bytecode instead of nested MalwiObject
            bytecode.append(emit(OpCode.MAKE_FUNCTION, "lambda"))

        return bytecode

    def _handle_conditional_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle ternary operator: condition ? true_expr : false_expr."""
        bytecode = []
        condition_node = node.child_by_field_name("condition")
        consequence_node = node.child_by_field_name("consequence")
        alternative_node = node.child_by_field_name("alternative")

        if condition_node:
            bytecode.extend(
                self._generate_bytecode(condition_node, source_code_bytes, file_path)
            )

        jump_if_false = len(bytecode)
        bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))

        if consequence_node:
            bytecode.extend(
                self._generate_bytecode(consequence_node, source_code_bytes, file_path)
            )

        jump_over_else = len(bytecode)
        bytecode.append(emit(OpCode.JUMP_FORWARD, -1))

        bytecode[jump_if_false] = emit(OpCode.POP_JUMP_IF_FALSE, len(bytecode))

        if alternative_node:
            bytecode.extend(
                self._generate_bytecode(alternative_node, source_code_bytes, file_path)
            )

        bytecode[jump_over_else] = emit(OpCode.JUMP_FORWARD, len(bytecode))
        return bytecode

    def _handle_f_string_literal(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle f-string with interpolation: f'Hello {name}!'."""
        bytecode = []
        # Collect string parts and format positions
        parts = []
        format_count = 0
        # Handle f-strings more accurately
        if node.type == "string" and len(node.children) > 0:
            # Check if it's an f-string by looking at string_start
            first_child = node.children[0]
            if first_child.type == "string_start":
                string_start = self._get_node_text(first_child, source_code_bytes)
                if string_start.startswith("f"):
                    # Process f-string children
                    for child in node.children[
                        1:-1
                    ]:  # Skip string_start and string_end
                        if child.type == "string_content":
                            # Regular string part
                            text = self._get_node_text(child, source_code_bytes)
                            if text:  # Only add non-empty strings
                                bytecode.append(emit(OpCode.LOAD_CONST, text))
                                parts.append("str")
                        elif child.type == "interpolation":
                            # Expression to format
                            expr_node = child.child_by_field_name("expression")
                            if not expr_node and child.named_children:
                                expr_node = child.named_children[0]
                            if expr_node:
                                bytecode.extend(
                                    self._generate_bytecode(
                                        expr_node, source_code_bytes, file_path
                                    )
                                )
                                bytecode.append(emit(OpCode.FORMAT_VALUE, None))
                                parts.append("fmt")
                                format_count += 1
                    # Build the final string
                    if len(parts) > 0:
                        bytecode.append(emit(OpCode.BUILD_STRING, len(parts)))
                    return bytecode
        # Fallback to old behavior for other string types
        string_parts = 0
        for child in node.named_children:
            if child.type == "interpolation":
                # Handle {expression} in f-string
                expr_node = child.named_children[0] if child.named_children else None
                if expr_node:
                    bytecode.extend(
                        self._generate_bytecode(expr_node, source_code_bytes, file_path)
                    )
                    string_parts += 1
            else:
                # Handle regular string parts
                text_content = self._get_node_text(child, source_code_bytes)
                bytecode.append(emit(OpCode.LOAD_CONST, text_content))
                string_parts += 1
        # Build the formatted string
        if string_parts > 1:
            bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # String format/join
        return bytecode

    def _handle_do_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle do-while loops (JavaScript)."""
        bytecode = []
        body_node = node.child_by_field_name("body")
        condition_node = node.child_by_field_name("condition")
        # Execute body first
        if body_node:
            bytecode.extend(
                self._generate_bytecode(body_node, source_code_bytes, file_path)
            )
        # Then check condition
        if condition_node:
            bytecode.extend(
                self._generate_bytecode(condition_node, source_code_bytes, file_path)
            )
            bytecode.append(
                emit(OpCode.POP_JUMP_IF_TRUE, len(bytecode) - 10)
            )  # Jump back to start
        return bytecode

    def _handle_decorated_definition(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle @decorator def function() patterns."""
        bytecode = []
        decorators = []
        function_node = node.child_by_field_name("definition")
        # Collect decorators
        for child in node.children:
            if child.type == "decorator":
                # Extract decorator name from @decorator_name
                for decorator_child in child.children:
                    if decorator_child.type == "identifier":
                        decorator_name = self._get_node_text(
                            decorator_child, source_code_bytes
                        )
                        decorators.append(decorator_name)
        if function_node and decorators:
            func_name = self._get_node_text(
                function_node.child_by_field_name("name"), source_code_bytes
            )
            # Load decorator (outermost first for nested decorators)
            for decorator_name in reversed(decorators):
                bytecode.append(emit(OpCode.LOAD_NAME, decorator_name))
            # Generate function code object and MAKE_FUNCTION (but don't store yet)
            # This mimics Python's pattern: LOAD_CONST <code_object> + MAKE_FUNCTION
            body_node = function_node.child_by_field_name("body")
            if body_node:
                # Extract function parameters
                params = self._extract_function_parameters(
                    function_node, source_code_bytes
                )
                # Set context for this function
                previous_params = self.current_function_params
                previous_in_function = self._in_function_scope
                self.current_function_params = params
                self._in_function_scope = True
                # Generate function body bytecode
                func_body_bytecode = self._generate_bytecode(
                    body_node, source_code_bytes, file_path
                )
                # Ensure function ends with RETURN_VALUE
                if (
                    not func_body_bytecode
                    or func_body_bytecode[-1].opcode != OpCode.RETURN_VALUE
                ):
                    func_body_bytecode.append(emit(OpCode.RETURN_VALUE, None))
                # Restore previous context
                self.current_function_params = previous_params
                self._in_function_scope = previous_in_function
                # Get function source and location
                func_source = self._get_node_text(function_node, source_code_bytes)
                location = (
                    function_node.start_point[0] + 1,
                    function_node.end_point[0] + 1,
                )
                # Create separate MalwiObject and add to collection
                func_code_obj = MalwiObject(
                    name=func_name,
                    language=self.language_name,
                    file_path=str(file_path),
                    file_source_code=source_code_bytes.decode(
                        "utf-8", errors="replace"
                    ),
                    byte_code=func_body_bytecode,
                    source_code=func_source,
                    location=location,
                )
                self.code_objects.append(func_code_obj)
                # Load function name as reference instead of full MalwiObject
                bytecode.append(emit(OpCode.LOAD_CONST, func_name))
                bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))
                # Apply decorator(s) - CALL with 0 args (function is on stack)
                for i in range(len(decorators)):
                    bytecode.append(emit(OpCode.CALL, 0))
                # Store the decorated function
                bytecode.append(emit(OpCode.STORE_NAME, func_name))
        return bytecode

    def _handle_named_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle walrus operator (:=) in Python."""
        bytecode = []
        target_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")

        if value_node:
            # Generate bytecode for the value expression
            bytecode.extend(
                self._generate_bytecode(value_node, source_code_bytes, file_path)
            )

            # Copy the value on stack (so one copy remains for return)
            bytecode.append(emit(OpCode.COPY, 1))

            # Store the copied value in the target variable
            if target_node:
                target_name = self._get_node_text(target_node, source_code_bytes)
                bytecode.append(emit(OpCode.STORE_NAME, target_name))
            # Original value remains on stack for parent expression
        return bytecode

    def _handle_concatenated_string(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle implicit string concatenation: 'hello' 'world'."""
        bytecode = []
        for child in node.named_children:
            if child.type == "string":
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
        # Concatenate strings
        bytecode.append(emit(OpCode.BINARY_ADD, None))
        return bytecode

    def _handle_global_nonlocal_statements(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle global/nonlocal declarations."""
        bytecode = []
        node_type = node.type
        # Process global/nonlocal declarations
        # These are just declarations and don't generate load/store instructions
        for child in node.named_children:
            if child.type == "identifier":
                name = self._get_node_text(child, source_code_bytes)
                if node_type == "global_statement":
                    # Track this as a global variable for future references
                    self.global_variables.add(name)
                    # No bytecode generated - this is just a declaration
                elif node_type == "nonlocal_statement":
                    # Track this as a nonlocal variable for future references
                    self.nonlocal_variables.add(name)
                    # No bytecode generated - this is just a declaration
        return bytecode

    def _handle_delete_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle delete statements: del x, del obj[key], del obj.attr."""
        bytecode = []
        # Process delete targets with specific DELETE opcodes
        for child in node.named_children:
            if child.type == "identifier":
                # Simple variable deletion: del x
                var_name = self._get_node_text(child, source_code_bytes)
                bytecode.append(emit(OpCode.DELETE_NAME, var_name))
            elif child.type in ["subscript", "subscript_expression"]:
                # Subscript deletion: del lst[i] or del dict[key]
                obj_node = child.child_by_field_name(
                    "value"
                ) or child.child_by_field_name("object")
                index_node = child.child_by_field_name(
                    "index"
                ) or child.child_by_field_name("subscript")

                if obj_node and index_node:
                    # Load object
                    bytecode.extend(
                        self._generate_bytecode(obj_node, source_code_bytes, file_path)
                    )
                    # Load index/key
                    bytecode.extend(
                        self._generate_bytecode(
                            index_node, source_code_bytes, file_path
                        )
                    )
                    # Delete subscript
                    bytecode.append(emit(OpCode.DELETE_SUBSCR, None))
            elif child.type in ["attribute", "member_expression"]:
                # Attribute deletion: del obj.attr
                obj_node = child.child_by_field_name(
                    "object"
                ) or child.child_by_field_name("value")
                attr_node = child.child_by_field_name(
                    "attribute"
                ) or child.child_by_field_name("property")

                if obj_node and attr_node:
                    # Load object
                    bytecode.extend(
                        self._generate_bytecode(obj_node, source_code_bytes, file_path)
                    )
                    # Get attribute name
                    attr_name = self._get_node_text(attr_node, source_code_bytes)
                    # Delete attribute (using generic DELETE_OPERATOR for now)
                    bytecode.append(emit(OpCode.DELETE_OPERATOR, attr_name))
            else:
                # For other delete targets, fall back to processing the expression
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
                bytecode.append(emit(OpCode.DELETE_OPERATOR, None))
        return bytecode

    def _handle_debugger_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle JavaScript debugger statement."""
        bytecode = []
        # JavaScript debugger statement
        bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # Placeholder for debugger
        return bytecode

    def _handle_labeled_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle labeled statements (JavaScript)."""
        bytecode = []
        label_node = node.child_by_field_name("label")
        statement_node = node.child_by_field_name("body")

        if label_node:
            label_name = self._get_node_text(label_node, source_code_bytes)
            bytecode.append(emit(OpCode.LOAD_CONST, label_name))

        if statement_node:
            bytecode.extend(
                self._generate_bytecode(statement_node, source_code_bytes, file_path)
            )
        return bytecode

    def _handle_await_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle await expressions: await expression."""
        bytecode = []
        awaitable_node = node.child_by_field_name(
            "awaitable"
        ) or node.child_by_field_name("argument")
        if awaitable_node:
            bytecode.extend(
                self._generate_bytecode(awaitable_node, source_code_bytes, file_path)
            )
        else:
            # Fallback: look for first expression child
            for child in node.named_children:
                if child.type not in ["await"]:  # Skip await keyword
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                    break
        bytecode.append(emit(OpCode.AWAIT_EXPRESSION, None))
        return bytecode

    def _handle_decorator(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle decorator nodes."""
        bytecode = []
        decorator_node = node.child_by_field_name("decorator")
        if decorator_node:
            bytecode.extend(
                self._generate_bytecode(decorator_node, source_code_bytes, file_path)
            )
        return bytecode

    def _handle_switch_match_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle switch/match statements."""
        bytecode = []
        subject_node = node.child_by_field_name("subject")
        if subject_node:
            bytecode.extend(
                self._generate_bytecode(subject_node, source_code_bytes, file_path)
            )
        # Process cases
        for child in node.children:
            if child.type in ["case_clause", "case", "switch_case"]:
                # Process case value/pattern
                value_node = child.child_by_field_name(
                    "value"
                ) or child.child_by_field_name("pattern")
                if value_node:
                    bytecode.extend(
                        self._generate_bytecode(
                            value_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append(
                        emit(OpCode.BINARY_OPERATION, None)
                    )  # Compare with subject
                # Process case body
                body_node = child.child_by_field_name("body")
                if body_node:
                    bytecode.extend(
                        self._generate_bytecode(body_node, source_code_bytes, file_path)
                    )
            elif child.type in ["switch_default", "else_clause"]:
                # Process default case
                body_node = child.child_by_field_name("body")
                if body_node:
                    bytecode.extend(
                        self._generate_bytecode(body_node, source_code_bytes, file_path)
                    )
        return bytecode

    def _handle_expression_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle expression statements - expressions whose values are discarded."""
        bytecode = []
        for child in node.children:
            if child.type not in [";", "\n"]:  # Skip semicolons and newlines
                # Check if this is an assignment (which doesn't need POP_TOP)
                if child.type not in [
                    "assignment",
                    "assignment_expression",
                    "augmented_assignment",
                ]:
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                    # Add POP_TOP to discard the expression result (but not for assignments)
                    bytecode.append(emit(OpCode.POP_TOP, None))
                else:
                    # For assignments, just generate the bytecode without POP_TOP
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
        return bytecode

    def _handle_spread_element(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle ...spread syntax."""
        bytecode = []
        argument_node = node.child_by_field_name("argument")
        if argument_node:
            bytecode.extend(
                self._generate_bytecode(argument_node, source_code_bytes, file_path)
            )
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for spread
        return bytecode

    def _handle_optional_chain(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle ?. optional chaining."""
        bytecode = []
        for child in node.named_children:
            bytecode.extend(
                self._generate_bytecode(child, source_code_bytes, file_path)
            )
        bytecode.append(
            emit(OpCode.BINARY_OPERATION, None)
        )  # Placeholder for optional access
        return bytecode

    def _handle_break_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle break statements."""
        bytecode = []
        bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # Placeholder for break
        return bytecode

    def _handle_continue_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle continue statements."""
        bytecode = []
        bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # Placeholder for continue
        return bytecode

    def _handle_assert_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle assert statements."""
        bytecode = []
        # Process the assertion condition
        condition_node = node.children[1] if len(node.children) > 1 else None
        if condition_node:
            bytecode.extend(
                self._generate_bytecode(condition_node, source_code_bytes, file_path)
            )
        bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # Placeholder for assert
        return bytecode

    def _handle_raise_or_throw_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle raise/throw statements."""
        bytecode = []
        # Process the exception/error to raise
        if len(node.children) > 1:
            exception_node = node.children[1]
            bytecode.extend(
                self._generate_bytecode(exception_node, source_code_bytes, file_path)
            )
        bytecode.append(
            emit(OpCode.BINARY_OPERATION, None)
        )  # Placeholder for raise/throw
        return bytecode

    def _handle_for_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle for/for-in loops with proper Python iteration protocol: GET_ITER → FOR_ITER → body → JUMP_BACKWARD → END_FOR."""
        bytecode = []
        iterable_node = node.child_by_field_name("right") or node.child_by_field_name(
            "iterable"
        )
        left_node = node.child_by_field_name("left") or node.child_by_field_name(
            "variable"
        )
        body_node = node.child_by_field_name("body")

        if iterable_node:
            # Generate iterable expression (e.g., [1, 2, 3] or range(5))
            bytecode.extend(
                self._generate_bytecode(iterable_node, source_code_bytes, file_path)
            )
            # Get iterator from iterable
            bytecode.append(emit(OpCode.GET_ITER, None))

            # FOR_ITER instruction - will jump to end when iteration is complete
            for_iter_jump_pos = len(bytecode)
            bytecode.append(emit(OpCode.FOR_ITER, -1))  # Placeholder, will fix later

            # Store loop variable (e.g., 'i' in 'for i in ...')
            if left_node:
                # Handle different types of loop variables
                if left_node.type == "identifier":
                    var_name = self._get_node_text(left_node, source_code_bytes)
                    bytecode.append(emit(OpCode.STORE_NAME, var_name))
                elif (
                    left_node.type == "pattern_list"
                    or left_node.type == "tuple_pattern"
                ):
                    # Handle tuple unpacking: for x, y in items
                    var_count = len(
                        [
                            child
                            for child in left_node.named_children
                            if child.type == "identifier"
                        ]
                    )
                    bytecode.append(emit(OpCode.UNPACK_SEQUENCE, var_count))
                    for child in left_node.named_children:
                        if child.type == "identifier":
                            var_name = self._get_node_text(child, source_code_bytes)
                            bytecode.append(emit(OpCode.STORE_NAME, var_name))

            # Generate loop body
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Jump back to FOR_ITER for next iteration
            bytecode.append(
                emit(OpCode.JUMP_BACKWARD, len(bytecode) - for_iter_jump_pos + 1)
            )

            # END_FOR - target for FOR_ITER when iteration completes
            end_for_pos = len(bytecode)
            bytecode.append(emit(OpCode.END_FOR, None))

            # Fix the FOR_ITER jump target to point to END_FOR
            bytecode[for_iter_jump_pos] = emit(
                OpCode.FOR_ITER, end_for_pos - for_iter_jump_pos - 1
            )

        return bytecode

    def _handle_while_statement(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle while loops with proper Python pattern: condition → POP_JUMP_IF_FALSE → body → JUMP_BACKWARD."""
        bytecode = []
        condition_node = node.child_by_field_name("condition")
        body_node = node.child_by_field_name("body")

        # Mark the start of the loop for JUMP_BACKWARD
        loop_start = len(bytecode)

        if condition_node:
            # Generate condition check
            bytecode.extend(
                self._generate_bytecode(condition_node, source_code_bytes, file_path)
            )

            # Jump out of loop if condition is false (will patch later)
            exit_jump_pos = len(bytecode)
            bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))  # Placeholder

        if body_node:
            # Generate loop body
            bytecode.extend(
                self._generate_bytecode(body_node, source_code_bytes, file_path)
            )

        # Jump back to condition check
        bytecode.append(emit(OpCode.JUMP_BACKWARD, len(bytecode) - loop_start + 1))

        # Fix the exit jump to point here (after the loop)
        if condition_node:
            bytecode[exit_jump_pos] = emit(
                OpCode.POP_JUMP_IF_FALSE, len(bytecode) - exit_jump_pos - 1
            )

        return bytecode

    def _handle_subscript_expression(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle subscript access and slicing: obj[key] or obj[start:end:step]."""
        bytecode = []
        object_node = node.child_by_field_name("object") or node.child_by_field_name(
            "value"
        )
        index_node = node.child_by_field_name("index") or node.child_by_field_name(
            "subscript"
        )

        if object_node:
            bytecode.extend(
                self._generate_bytecode(object_node, source_code_bytes, file_path)
            )

        if index_node:
            if index_node.type == "slice":
                # Handle slice notation [start:stop:step]
                start_node = index_node.child_by_field_name("start")
                stop_node = index_node.child_by_field_name("stop")
                step_node = index_node.child_by_field_name("step")

                # Load slice components (None for missing parts)
                if start_node:
                    bytecode.extend(
                        self._generate_bytecode(
                            start_node, source_code_bytes, file_path
                        )
                    )
                else:
                    bytecode.append(emit(OpCode.LOAD_CONST, None))

                if stop_node:
                    bytecode.extend(
                        self._generate_bytecode(stop_node, source_code_bytes, file_path)
                    )
                else:
                    bytecode.append(emit(OpCode.LOAD_CONST, None))

                if step_node:
                    bytecode.extend(
                        self._generate_bytecode(step_node, source_code_bytes, file_path)
                    )
                else:
                    bytecode.append(emit(OpCode.LOAD_CONST, None))

                bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # BUILD_SLICE
                bytecode.append(emit(OpCode.BINARY_SUBSCR, None))
            else:
                # Regular subscript access
                bytecode.extend(
                    self._generate_bytecode(index_node, source_code_bytes, file_path)
                )
                bytecode.append(emit(OpCode.BINARY_SUBSCR, None))

        return bytecode

    def _handle_attribute_access(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """Handle attribute access: obj.attr (Python) or obj.prop (JavaScript)."""
        bytecode = []
        object_node = node.child_by_field_name("object") or node.child_by_field_name(
            "value"
        )
        attribute_node = node.child_by_field_name(
            "attribute"
        ) or node.child_by_field_name("property")

        if object_node:
            # Load the object first (this may recursively handle chained attributes)
            bytecode.extend(
                self._generate_bytecode(object_node, source_code_bytes, file_path)
            )

        if attribute_node:
            attr_name = self._get_node_text(attribute_node, source_code_bytes)
            bytecode.append(emit(OpCode.LOAD_ATTR, attr_name))

        return bytecode

    def _generate_bytecode(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """
        Recursively traverses a Python, JavaScript or Rust AST and generates bytecode.

        Sub-functions created (32 handlers):

        LITERALS & IDENTIFIERS:
        - _handle_numeric_literal: integers, floats, complex numbers, BigInts
        - _handle_simple_literals: booleans, None/null, ellipsis
        - _handle_identifier: variable/identifier references

        DATA STRUCTURES:
        - _handle_list_or_array: list/array construction
        - _handle_tuple: tuple construction
        - _handle_set: set construction
        - _handle_dictionary_or_object: dictionary/object construction

        EXPRESSIONS & OPERATORS:
        - _handle_binary_operator: binary operators (+, -, *, /, etc.)
        - _handle_unary_operator: unary operators (-, +, ~, not, etc.)
        - _handle_boolean_operator: boolean operators (and, or, &&, ||)
        - _handle_comparison_operator: comparison chains (a < b < c)
        - _handle_not_operator: 'not' operator
        - _handle_update_expression: JavaScript ++/-- operators
        - _handle_new_expression: JavaScript 'new Constructor()' calls
        - _handle_sequence_expression: JavaScript comma operator
        - _handle_yield_expression: Python yield expressions
        - _handle_template_string: JavaScript template literals
        - _handle_regex: regex literals
        - _handle_spread_element: JavaScript ...spread syntax
        - _handle_optional_chain: JavaScript ?. optional chaining
        - _handle_subscript_expression: subscript access (obj[key])
        - _handle_attribute_access: attribute access (obj.attr)

        FUNCTION CALLS & CONTROL FLOW:
        - _handle_function_call: function calls with various argument types
        - _handle_if_statement: if-else statements with jump logic
        - _handle_for_statement: for/for-in loops with iteration protocol
        - _handle_while_statement: while loops with condition checking

        STATEMENTS:
        - _handle_assignment: assignment with destructuring support
        - _handle_return_statement: return statements
        - _handle_augmented_assignment: +=, -=, *=, etc.
        - _handle_break_statement: break statements
        - _handle_continue_statement: continue statements
        - _handle_assert_statement: assert statements
        - _handle_raise_or_throw_statement: exception raising
        """
        bytecode = []
        node_type = node.type

        # --- Handle Literals and Identifiers ---
        if node_type in ["integer", "float", "number"]:  # Examples: 42, 3.14, 0x1F
            bytecode.extend(self._handle_numeric_literal(node, source_code_bytes))
        elif node_type == "string":  # Examples: "hello", 'world', f"name: {name}"
            bytecode.extend(
                self._handle_string_literal(node, source_code_bytes, file_path)
            )
        elif node_type == "identifier":  # Examples: x, my_var, className
            bytecode.extend(self._handle_identifier(node, source_code_bytes))
        elif node_type in [
            "true",
            "false",
            "none",
            "null",
            "ellipsis",
        ]:  # Examples: True, False, None, null, ...
            bytecode.extend(self._handle_simple_literals(node, source_code_bytes))

        # --- Handle Data Structures ---
        elif node_type in ["list", "array"]:  # Examples: [1, 2, 3], ["a", "b"]
            bytecode.extend(
                self._handle_list_or_array(node, source_code_bytes, file_path)
            )
        elif node_type == "tuple":  # Examples: (1, 2), (x,)
            bytecode.extend(self._handle_tuple(node, source_code_bytes, file_path))
        elif node_type == "set":  # Examples: {1, 2, 3}, set()
            bytecode.extend(self._handle_set(node, source_code_bytes, file_path))
        elif node_type in [
            "dictionary",
            "object",
        ]:  # Examples: {"key": "value"}, {x: 1, y: 2}
            bytecode.extend(
                self._handle_dictionary_or_object(node, source_code_bytes, file_path)
            )

        # --- Handle Expressions and Calls ---
        elif node_type in [
            "binary_operator",
            "binary_expression",
        ]:  # Examples: a + b, x * y, n // 2
            bytecode.extend(
                self._handle_binary_operator(node, source_code_bytes, file_path)
            )
        elif node_type in [
            "unary_operator",
            "unary_expression",
        ]:  # Examples: -x, +y, ~bits, not flag
            bytecode.extend(
                self._handle_unary_operator(node, source_code_bytes, file_path)
            )
        elif node_type in [
            "boolean_operator",
            "logical_expression",
        ]:  # Examples: a and b, x or y, p && q
            bytecode.extend(
                self._handle_boolean_operator(node, source_code_bytes, file_path)
            )
        elif node_type in ["comparison_operator"]:  # Examples: a < b, x == y, a < b < c
            bytecode.extend(
                self._handle_comparison_operator(node, source_code_bytes, file_path)
            )
        elif node_type in ["not_operator"]:  # Examples: not x, !flag
            bytecode.extend(
                self._handle_not_operator(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "call",
            "call_expression",
        ]:  # Examples: func(), obj.method(a, b), f(*args, **kwargs)
            bytecode.extend(
                self._handle_function_call(node, source_code_bytes, file_path)
            )

        elif node_type in ["update_expression"]:  # Examples: ++i, i++, --count
            bytecode.extend(
                self._handle_update_expression(node, source_code_bytes, file_path)
            )
        elif node_type in ["new_expression"]:  # Examples: new Date(), new Map()
            bytecode.extend(
                self._handle_new_expression(node, source_code_bytes, file_path)
            )
        elif node_type in ["sequence_expression"]:  # Examples: (a, b, c)
            bytecode.extend(
                self._handle_sequence_expression(node, source_code_bytes, file_path)
            )
        elif node_type in [
            "yield_expression",
            "yield",
        ]:  # Examples: yield x, yield from iterable
            bytecode.extend(
                self._handle_yield_expression(node, source_code_bytes, file_path)
            )
        elif node_type in ["template_string"]:  # Examples: `Hello ${name}`
            bytecode.extend(
                self._handle_template_string(node, source_code_bytes, file_path)
            )

        elif node_type == "regex":  # Examples: /pattern/flags, r'\d+'
            bytecode.extend(self._handle_regex(node, source_code_bytes, file_path))
        elif node_type in ["spread_element"]:  # Examples: ...args, ...{a: 1}
            bytecode.extend(
                self._handle_spread_element(node, source_code_bytes, file_path)
            )
        elif node_type in ["optional_chain"]:  # Examples: obj?.prop, func?.()
            bytecode.extend(
                self._handle_optional_chain(node, source_code_bytes, file_path)
            )

        # --- Handle Statements ---
        elif node_type in [
            "assignment",
            "assignment_expression",
            "variable_declarator",
        ]:  # Examples: x = 5, [a, b] = arr, {x, y} = obj
            bytecode.extend(self._handle_assignment(node, source_code_bytes, file_path))
        elif (
            node_type == "return_statement"
        ):  # Examples: return x, return func(), return
            bytecode.extend(
                self._handle_return_statement(node, source_code_bytes, file_path)
            )
        elif (
            node_type == "augmented_assignment"
        ):  # Examples: x += 1, arr *= 2, dict |= other
            bytecode.extend(
                self._handle_augmented_assignment(node, source_code_bytes, file_path)
            )
        elif node_type == "pass_statement":  # Examples: pass
            # Pass is a no-op, but we'll add a placeholder
            pass

        elif node_type == "break_statement":  # Examples: break
            bytecode.extend(
                self._handle_break_statement(node, source_code_bytes, file_path)
            )
        elif node_type == "continue_statement":  # Examples: continue
            bytecode.extend(
                self._handle_continue_statement(node, source_code_bytes, file_path)
            )
        elif (
            node_type == "assert_statement"
        ):  # Examples: assert x > 0, assert len(arr) == 5
            bytecode.extend(
                self._handle_assert_statement(node, source_code_bytes, file_path)
            )
        elif node_type in [
            "raise_statement",
            "throw_statement",
        ]:  # Examples: raise ValueError(), throw new Error()
            bytecode.extend(
                self._handle_raise_or_throw_statement(
                    node, source_code_bytes, file_path
                )
            )

        elif node_type in [
            "import_statement",
            "import_from_statement",
            "import_declaration",
        ]:  # Examples: import os, from math import sin, import { func } from 'module'
            bytecode.extend(
                self._handle_import_statement(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "export_statement",
            "export_default",
        ]:  # Examples: export const x = 1, export default func
            bytecode.extend(
                self._handle_export_statement(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "global_statement",
            "nonlocal_statement",
        ]:  # Examples: global x, nonlocal count
            bytecode.extend(
                self._handle_global_nonlocal_statements(
                    node, source_code_bytes, file_path
                )
            )

        elif node_type == "delete_statement":  # Examples: del x, delete obj.prop
            bytecode.extend(
                self._handle_delete_statement(node, source_code_bytes, file_path)
            )

        # --- Control Flow ---
        elif (
            node_type == "if_statement"
        ):  # Examples: if x > 0:, if condition: ... else: ...
            bytecode.extend(
                self._handle_if_statement(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "for_statement",
            "for_in_statement",
        ]:  # Examples: for i in range(10):, for (let i = 0; i < 10; i++)
            bytecode.extend(
                self._handle_for_statement(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "while_statement"
        ):  # Examples: while x > 0:, while (condition)
            bytecode.extend(
                self._handle_while_statement(node, source_code_bytes, file_path)
            )

        elif node_type == "do_statement":  # Examples: do { ... } while (condition)
            bytecode.extend(
                self._handle_do_statement(node, source_code_bytes, file_path)
            )

        elif node_type == "debugger_statement":  # Examples: debugger;
            bytecode.extend(
                self._handle_debugger_statement(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "labeled_statement"
        ):  # Examples: label: statement, outerLoop: for (...)
            bytecode.extend(
                self._handle_labeled_statement(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "try_statement"
        ]:  # Examples: try: ... except:, try { ... } catch (e) { ... }
            bytecode.extend(
                self._handle_try_statement(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "with_statement"
        ):  # Examples: with open(file) as f:, with lock:
            bytecode.extend(
                self._handle_with_statement(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "lambda",
            "arrow_function",
        ]:  # Examples: lambda x: x + 1, (x) => x * 2
            bytecode.extend(
                self._handle_lambda_arrow_function(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "conditional_expression"
        ):  # Examples: x if condition else y, condition ? x : y
            bytecode.extend(
                self._handle_conditional_expression(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "named_expression"
        ):  # Examples: (n := len(arr)), walrus operator
            bytecode.extend(
                self._handle_named_expression(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "subscript",
            "subscript_expression",
        ]:  # Examples: arr[0], obj['key'], matrix[1:3, :]
            bytecode.extend(
                self._handle_subscript_expression(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "attribute",
            "member_expression",
        ]:  # Examples: obj.attr, self.method, module.function
            bytecode.extend(
                self._handle_attribute_access(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "f_string",
            "formatted_string_literal",
        ]:  # Examples: f"Hello {name}", f'Value: {x:.2f}'
            bytecode.extend(
                self._handle_f_string_literal(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "concatenated_string"
        ):  # Examples: "hello" "world", 'part1' 'part2'
            bytecode.extend(
                self._handle_concatenated_string(node, source_code_bytes, file_path)
            )

        # --- Decorated Definitions (Functions with decorators) ---
        elif (
            node_type == "decorated_definition"
        ):  # Examples: @decorator\ndef func():, @property\ndef getter():
            bytecode.extend(
                self._handle_decorated_definition(node, source_code_bytes, file_path)
            )

        # --- High-Level Structures (Functions, Classes) ---
        elif node_type in [
            "function_definition",
            "function_declaration",
            "generator_function_declaration",
            "function_item",
        ]:  # Examples: def func():, function name() {}, function* gen() {}
            bytecode.extend(
                self._handle_function_definition(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "class_definition",
            "class_declaration",
        ]:  # Examples: class MyClass:, class Component extends React.Component
            bytecode.extend(
                self._handle_class_definition(node, source_code_bytes, file_path)
            )

        elif node_type == "macro_definition":
            bytecode.extend(
                self._handle_macro_definition(node, source_code_bytes, file_path)
            )

        elif node_type == "macro_invocation":
            bytecode.extend(
                self._handle_macro_invocation(node, source_code_bytes, file_path)
            )

        # --- Comprehensions and Generators ---
        elif (
            node_type
            in [
                "list_comprehension",
                "dictionary_comprehension",
                "set_comprehension",
                "generator_expression",
            ]
        ):  # Examples: [x for x in range(10)], {k: v for k, v in items}, (x for x in data)
            bytecode.extend(
                self._handle_comprehension(node, source_code_bytes, file_path)
            )

        elif node_type in [
            "await",
            "await_expression",
        ]:  # Examples: await func(), await promise
            bytecode.extend(
                self._handle_await_expression(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "decorator"
        ):  # Examples: @staticmethod, @property, @app.route('/path')
            bytecode.extend(self._handle_decorator(node, source_code_bytes, file_path))

        elif node_type in [
            "switch_statement",
            "match_statement",
        ]:  # Examples: switch (x) { ... }, match value: case pattern:
            bytecode.extend(
                self._handle_switch_match_statement(node, source_code_bytes, file_path)
            )

        elif (
            node_type == "expression_statement"
        ):  # Examples: func(); (expression as statement), x + y;
            bytecode.extend(
                self._handle_expression_statement(node, source_code_bytes, file_path)
            )

        # --- Block, Module, and Program Handling ---
        elif node_type in [
            "block",
            "module",
            "program",
            "lexical_declaration",
            "variable_declaration",
            "const_declaration",
            "let_declaration",
            "var_declaration",
            # JavaScript specific
            "template_string",
            "template_literal",
            "parenthesized_expression",
            "subscript",
            "attribute",
            # Python specific
            "concatenated_string",
            "f_string",
            "format_expression",
            # Exception handling
            "except_clause",
            "catch_clause",
            "finally_clause",
            "with_item",
            # Patterns and others
            "case_clause",
            "else_clause",
            "elif_clause",
        ]:
            for child in node.children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )

        # Fallback for unhandled nodes
        else:
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
        return bytecode

    def bytes_to_treesitter_ast(
        self, source_code_bytes: bytes, file_path: str
    ) -> Optional[Node]:
        """
        Parses source code bytes into a tree-sitter AST using the compiler's
        configured parser.
        """
        try:
            tree = self.parser.parse(source_code_bytes)
            return tree.root_node
        except Exception as e:
            logging.warning(
                f"Parsing error in file {file_path} with language {self.language_name}: {e}"
            )
            return None

    def process_file(self, file_path: Path) -> List[MalwiObject]:
        """Processes a single file and returns its generated MalwiObjects."""
        import sys

        # Store original recursion limit
        original_limit = sys.getrecursionlimit()

        try:
            source_code_bytes = file_path.read_bytes()

            # Increase recursion limit significantly for complex mathematical files
            # Some files like Galois polynomial resolvents can be extremely complex
            sys.setrecursionlimit(15000)

            ast = self.bytes_to_treesitter_ast(
                source_code_bytes=source_code_bytes,
                file_path=str(file_path),
            )

            if ast:
                malwicode_objects = self.treesitter_to_bytecode(
                    root_node=ast,
                    source_code_bytes=source_code_bytes,
                    file_path=file_path,
                )
                return malwicode_objects

        except RecursionError:
            # Try once more with an even higher limit for extremely complex files
            try:
                logging.warning(
                    f"Recursion limit exceeded for {file_path}, trying with higher limit"
                )
                sys.setrecursionlimit(25000)

                ast = self.bytes_to_treesitter_ast(
                    source_code_bytes=source_code_bytes,
                    file_path=str(file_path),
                )

                if ast:
                    malwicode_objects = self.treesitter_to_bytecode(
                        root_node=ast,
                        source_code_bytes=source_code_bytes,
                        file_path=file_path,
                    )
                    return malwicode_objects
            except RecursionError:
                logging.error(
                    f"File {file_path} too complex even with maximum recursion limit - processing failed"
                )
                return []
        except Exception as e:
            logging.error(f"Failed to process {file_path}: {e}")
        finally:
            # Always restore original recursion limit
            sys.setrecursionlimit(original_limit)

        return []


# Main function and CLI removed - use src.research.preprocess instead
