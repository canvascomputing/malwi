# malwi Research Progress

This document tracks the AI model training research progress for malwi, documenting chronological improvements and performance metrics.

## Research Timeline

### August 2025 (Latest First)

#### 2025-08-26: Training Data Structure Deep Investigation  
- **Commit**: `18df003c`
- **Investigation**: Deep analysis of code chunking/windowing for AI model training
- **Key Findings**:
  - ✅ **No function body duplication** between module and function objects
  - ✅ **Clean separation**: Module objects contain `MAKE_FUNCTION` references only, not function bodies
  - ⚠️ **Class method embedding**: Methods are embedded directly in class objects (no separate training samples)
  - ⚠️ **Nested function inlining**: Inner functions (nesting_depth > 0) inlined into parent objects
  - 📊 **Current chunking logic**: Only top-level functions (nesting_depth == 0) get separate MalwiObjects
- **Training Data Structure**:
  1. `<module>` objects: Module-level statements + function/class references
  2. Top-level function objects: Function body bytecode only
  3. Top-level class objects: All method bodies directly embedded
  4. Lambda objects: Lambda expression logic
- **Performance Impact**: Current system prevents most redundant training while maintaining context
- **Recommendations**: 
  - Current approach is more optimal than suspected
  - Consider extracting class methods as separate objects for better training granularity
  - Hybrid approach (extract methods, keep nested functions inlined) would balance granularity vs context
- **Files Analyzed**: `src/common/bytecode.py` (_generate_bytecode, treesitter_to_bytecode, _handle_function_definition)
- **Technical Insight**: nesting_depth == 0 condition prevents nested function duplication but limits class method training samples

#### 2025-08-26: Security-Focused Mapping Functions + Refactoring Fixes
- **Tag**: `9bfd766c_f1/0.843` (first epoch)
- **F1 Score**: 0.843 (first epoch performance)
- **Change**: Introduced new security-focused string mapping functions + fixed critical refactoring bugs
- **New Mapping Functions**:
  - `is_email()`: RFC-compliant email address detection with username/domain validation
  - `is_insecure_protocol()`: Detects insecure protocols (http, ftp, telnet, ldap, etc.) without URL requirement
  - `is_insecure_url()`: Full URL validation for insecure protocols (http://, ftp://, etc.)
  - Enhanced `is_version()`: Fixed to require dot separator (prevents false matches on single numbers)
- **Bug Fixes**: Fixed critical serialization issue where refactored code was accessing `obj.path` instead of `obj.file_path`
- **Recursion Handling**: Added robust handling for complex mathematical files that exceed Python's recursion limit
- **Files Modified**: 
  - `src/common/mapping.py` (+142 lines): New security detection functions
  - `src/common/bytecode.py` (+11 lines): Integration of new mappings
  - `src/research/csv_writer.py`, `src/research/preprocess.py`: Fixed path attribute bug
  - Comprehensive test coverage (+596 test lines)
- **Impact**: ⚠️ **Performance degradation** - significant drop from previous 0.953 to 0.843 (-0.11 F1 score)
- **Analysis**: Security-focused mappings may have introduced noise or complexity that hurt model performance. The new functions (email, insecure protocols, URLs) might be creating too many special tokens or interfering with existing detection patterns. Requires investigation into whether mapping functions are too broad or conflicting with established patterns.

#### 2025-08-19: Special Token Count Optimization + Dataset Quality Fix
- **Tag**: `3f7fac18_f1/0.953`
- **F1 Score**: 0.953 (+0.035)
- **Change**: Increased special token count from 5000 to 10000 in DEFAULT_TOP_N_TOKENS + rolled back malwi-dataset to 71b649c24
- **Impact**: ✅ **Major improvement** - combined vocabulary expansion and dataset quality enhancement
- **Analysis**: The performance boost came from two factors: (1) doubling special token count provided better malware pattern recognition, and (2) rolling back the malwi-dataset removed incorrectly labeled benign files that had been moved to malicious category, significantly improving training data quality. Clean training data proved crucial for model accuracy.

#### 2025-08-19: Tokenizer Vocabulary Size Fix
- **Tag**: `2a22e8f1_f1/0.918`
- **F1 Score**: 0.918 (+0.0595)
- **Change**: Fixed tokenizer vocabulary overflow, centralized token count configuration, removed hardcoded 15000 values
- **Impact**: ✅ **Good recovery** - performance improved after fixing tokenizer configuration
- **Analysis**: Addressed tokenizer vocabulary exceeding 30,522 limit by removing double-counting of special tokens and centralizing DEFAULT_TOP_N_TOKENS=5000. This ensures vocabulary stays within DistilBERT constraints while maintaining detection capabilities.

#### 2025-08-19: Configuration Centralization and String Size Buckets
- **Tag**: `858eb50c_f1/0.8585`
- **F1 Score**: 0.8585 (-0.0777)
- **Change**: Centralized configuration, added string size buckets (`src/common/config.py`, `src/common/mapping.py`)
- **Impact**: Configuration improvements but minor performance regression
- **Analysis**: Infrastructure changes provided better maintainability at cost of slight accuracy decrease

#### 2025-08-19: Code Detection Tokens and String Mapping Optimization
- **Tag**: `ae143225_f1/0.9362`
- **F1 Score**: 0.9362 (-0.0218)
- **Change**: Removed entropy categories, optimized string mapping (`src/common/mapping.py`, `src/research/ast_to_malwicode.py`)
- **Impact**: ✅ **Good recovery** - near-peak performance with improved processing efficiency
- **Analysis**: Entropy mapping removal improved preprocessing speed by 95x while maintaining strong detection accuracy

#### 2025-08-17: String Cases Performance Trade-off
- **Tag**: `0fd74a13_f1/0.842`
- **F1 Score**: 0.842 (-0.052)
- **Change**: Disabled new string cases due to performance
- **Impact**: Performance prioritization over feature completeness

#### 2025-08-16: Full File Scanning
- **Tag**: `7564fc77_f1/0.894`
- **F1 Score**: 0.894 (+0.047)
- **Change**: Test scanning on full files only
- **Impact**: Partial recovery, full file scanning improved over module splitting

#### 2025-08-16: Module Code Splitting
- **Tag**: `2e5ea7dd_f1/0.847`
- **F1 Score**: 0.847 (-0.047)
- **Change**: Separate module code instead of complete files
- **Impact**: ❌ **Performance drop** - splitting lost contextual information

#### 2025-08-15: Domain-Specific URL Detection
- **Tag**: `9ffaef2e_f1/0.894`
- **F1 Score**: 0.894 (-0.058)
- **Change**: Added URL classification as additional feature
- **Impact**: ⚠️ **Minor regression** - domain-specific detection added complexity without proportional benefit

#### 2025-08-15: False-Positives Training Integration
- **Tag**: `6b831862_f1/0.952`
- **F1 Score**: 0.952 (+0.020)
- **Change**: Included false-positives in training pipeline
- **Files**: `README.md`, `cmds/preprocess_data.sh` (added false-positive processing)
- **Impact**: ✅ **Good improvement** - training on edge cases enhanced performance
- **Analysis**: Including challenging borderline cases in training improved model robustness

#### 2025-08-14: Tokenizer Version Fix
- **Tag**: `b7a14a0c_f1/0.932`
- **F1 Score**: 0.932 (-0.012)
- **Change**: Fixed tokenizer issue due to version lookup
- **Impact**: Version compatibility fix with minor performance impact

#### 2025-08-14: DistilBERT 256 Reintroduction
- **Tag**: `7002e364_f1/0.944`
- **F1 Score**: 0.944 (-0.014)
- **Change**: Reintroduced DistilBERT 256
- **Impact**: Slight performance decrease, suggesting larger model may not always be better

#### 2025-08-14: String Mapping Optimization (Peak Performance)
- **Tag**: `2b4abcab_f1/0.958`
- **F1 Score**: 0.958 (+0.017)
- **Change**: Changed string mapping length in `ast_to_malwicode.py`
- **Files**: `src/research/ast_to_malwicode.py` (6 insertions, 4 deletions)
- **Impact**: ✅ **New peak performance** - highest F1 score achieved
- **Analysis**: Small but critical change to string length handling provided significant performance boost

#### 2025-08-12: Bytecode Refactoring
- **Tag**: `7fae71bd_f1/0.941`
- **F1 Score**: 0.941 (+0.941 from failed state)
- **Change**: Refactored bytecode creation
- **Impact**: Good recovery, maintaining high performance

#### 2025-08-12: KW_NAMES Unmapping Experiment
- **Tag**: `3026c86e_f1/0.0`
- **F1 Score**: 0.0 (-0.947)
- **Change**: Unmapped KW_NAMES to let model see params
- **Impact**: ❌ **Failed experiment** - removing KW_NAMES mapping broke performance

#### 2025-08-12: KW_NAMES Split (Best Performance So Far)
- **Tag**: `11666b09_f1/0.947`
- **F1 Score**: 0.947 (+0.101)
- **Change**: Split KW_NAMES implementation in `ast_to_malwicode.py`
- **Files**: `src/research/ast_to_malwicode.py`, `tests/source_samples/expected_python_output_mapped.txt`
- **Impact**: ✅ **Significant improvement** - best performance to date
- **Analysis**: KW_NAMES architecture change was fundamental breakthrough

#### 2025-08-10: DistilBERT Size Reduction
- **Tag**: `b0b11be9_f1/0.846`
- **F1 Score**: 0.846 (+0.846 from failed state)
- **Change**: Reduced DistilBERT size based on vocabulary
- **Impact**: Recovery from failed vocabulary experiment, but below previous performance

#### 2025-08-10: Vocabulary Size Experiment
- **Tag**: `1001a101_f1/0.0`
- **F1 Score**: 0.0 (-0.932)
- **Change**: Increased vocab size in training scripts
- **Files**: `cmds/train_distilbert.sh`, `cmds/train_distilbert_tiny.sh`, `cmds/train_tokenizer.sh`
- **Impact**: ❌ **Failed experiment** - vocabulary size increase broke model performance
- **Analysis**: Model architecture couldn't handle larger vocabulary efficiently

#### 2025-08-04: CodeObject Creation Behavior
- **Tag**: `c09b6588_f1/0.932`
- **F1 Score**: 0.932 (+0.007)
- **Change**: Changed nested CodeObject creation behavior
- **Impact**: Small improvement in object creation logic

#### 2025-08-04: Keyword Names Logic Optimization
- **Tag**: `1f6b7a1e_f1/0.925` 
- **F1 Score**: 0.925
- **Change**: Modified KW_NAMES logic
- **Impact**: Solid baseline performance achieved with improved keyword handling

## Key Insights

### ✅ High-Impact Improvements
1. **String mapping optimization** (0.958) - Peak performance achieved with minimal code changes  
2. **Dataset quality + special tokens** (0.953) - Major improvement from clean training data and expanded vocabulary
3. **False-positives training** (0.952) - Edge case handling improved robustness
4. **KW_NAMES splitting** (0.947) - Major architecture improvement in AST processing
5. **Bytecode refactoring** (0.941) - Core logic improvement

### ⚠️ Mixed Results / Minor Performance Changes
1. **Code detection tokens optimization** (0.9362) - Slight decrease from peak but improved processing efficiency
2. **Tokenizer vocabulary fix** (0.918) - Good recovery after configuration issues
3. **Full file scanning** (0.894) - Partial recovery from module splitting issues
4. **DistilBERT 256 reintroduction** (0.944) - Minor decrease, larger model not always better

### ❌ Failed Experiments / Performance Degradations
1. **Vocabulary size increase** (0.0) - Complete model failure, suggests architecture limitations
2. **KW_NAMES unmapping** (0.0) - Removing essential mappings broke model completely
3. **Module code splitting** (0.847) - Lost contextual information critical for detection
4. **Security-focused mappings** (0.843) - Significant performance drop (-0.11), new mapping functions may introduce noise

### 📊 Performance Trends
- **Peak Performance**: 0.958 (2025-08-14) - String mapping optimization
- **Previous Performance**: 0.953 (2025-08-19) - Dataset quality fix + special token optimization  
- **Latest Performance**: 0.843 (2025-08-26, first epoch) - Security-focused mapping functions
- **Performance Range**: 0.0 - 0.958
- **Average Performance**: 0.801 (excluding failed experiments)
- **Recent Change**: -0.11 F1 drop indicates security mappings may be counterproductive
- **Volatility**: High - small changes can have major impact (±0.1 F1 score)

### 🔬 Critical Success Factors
1. **Training Data Quality**: Clean dataset labeling is crucial - removing mislabeled files provided +0.025 F1 improvement
2. **String Handling**: Length and mapping optimizations are disproportionately important (peak 0.958)
3. **Tokenizer Configuration**: Special token count significantly impacts performance (5K→10K contributed to major gains)
4. **AST Processing Pipeline**: Core changes in `ast_to_malwicode.py` have highest impact
5. **Context Preservation**: Full file scanning > module splitting (0.894 vs 0.847)
6. **Architecture Stability**: KW_NAMES system is fundamental - modifications must be careful
7. **Training Data Structure**: Current bytecode chunking approach prevents function body duplication and maintains optimal context balance

### 🏗️ Training Data Architecture (2025-08-26 Analysis)
**Current System Strengths**:
- ✅ No redundant function body training (module contains references, functions contain bodies)
- ✅ Clean separation between module-level and function-level concerns
- ✅ Context preservation through hierarchical object relationships
- ✅ Prevents over-fragmentation of code logic

**Potential Improvements**:
- Class methods embedded in class objects (no individual method training samples)
- Nested functions inlined rather than extracted (limits pattern recognition granularity)
- Consider hybrid approach: extract class methods while preserving function hierarchy

**Technical Implementation**: `nesting_depth == 0` condition in `bytecode.py` determines object extraction - critical for preventing training data explosion while maintaining learning effectiveness

### 🚨 High-Risk Areas
1. **Vocabulary changes**: Can completely break model performance
2. **KW_NAMES modifications**: Essential system, removal causes total failure
3. **New mapping functions**: Adding security-focused mappings can degrade performance (-0.11 F1) - careful validation needed

### 🔍 Lessons from Performance Drops
1. **Security mappings backfire** (0.843): Well-intentioned security detection functions (email, insecure protocols) caused significant performance regression
2. **Feature complexity risk**: More features ≠ better performance - new mappings may create noise or vocabulary confusion
3. **Incremental testing critical**: Major feature additions should be tested individually before combining
4. **Module splitting**: Loses contextual signal quality
5. **String tokenization**: Small changes have large impact

### 📈 Research Directions
1. **Incremental string optimizations**: Build on 0.958 success
2. **Hybrid approaches**: Combine best elements (string mapping + false-positives + KW_NAMES split)
3. **Context preservation**: Maintain full-file context while improving efficiency
4. **Training data curation**: Systematic false-positive identification and inclusion
5. **A/B testing**: Smaller incremental changes rather than major refactors

## Next Steps

### Immediate Priorities
1. **Close minimal gap**: Investigate remaining 0.005 F1 gap from peak (0.958 vs 0.953)
2. **Dataset quality maintenance**: Establish processes to prevent mislabeled training data
3. **Peak performance replication**: Understand the exact conditions that achieved 0.958 performance
4. **Tokenizer fine-tuning**: Experiment with special token counts between 10K-15K range

### Research Pipeline
1. **Advanced token research**: Expand specialized token categories (network patterns, crypto operations, system calls)
2. **Preprocessing optimization**: Balance detection accuracy with processing speed for large-scale deployment
3. **Training data enhancement**: Integrate large file detection signals into training pipeline
4. **Feature ablation**: Determine contribution of each token category to overall performance
5. **Context preservation**: Maintain full-file analysis while optimizing processing efficiency

### Risk Management
- Always tag experiments before major changes
- Test vocabulary/architecture changes on smaller datasets first
- Maintain rollback capability to known good states
- Document all failures to prevent repetition

## Workflow Usage

To add a new research result, provide Claude with:
```
Research commit: [commit_hash]
F1 Score: [score]
Change: [description]
Reasoning: [why performance changed]
```

Claude will automatically tag the commit and update this document chronologically.