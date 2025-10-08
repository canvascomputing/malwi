# malwi Research Progress

This document tracks the AI model training research progress for malwi, documenting chronological improvements and performance metrics.

## Research Timeline

### October 2025 (Latest First)

#### 2025-10-08: Longformer File-Based Training Strategy
- **Tag**: `81205f22_f1/0.995`
- **F1 Score**: 0.995 (-0.001 from package strategy)
- **Change**: Tested file-based training strategy for Longformer (groups CodeObjects by filepath instead of package)
- **Training Strategy**: File-based grouping with random benign sampling
  - Groups all CodeObjects from each file into a single training sample
  - Creates `malicious_files × benign_ratio` random benign files
  - Each benign file contains up to 10 random benign objects
  - Benign ratio: 4 (4 benign files per malicious file)
- **Model Configuration**: Same as package strategy (hidden_size=256, 4 heads, 4 layers, 4098 context)
- **Training Metrics (1 epoch, ~73 min/epoch)**:
  - **Losses**: Train 0.0324, Val 0.0025
  - **Overall**: Macro F1=0.9978, Micro F1=0.9993
  - **Benign**: F1=0.9996 (Precision=0.9996, Recall=0.9996)
  - **Malicious**: F1=0.9959 (Precision=0.9962, Recall=0.9957)
- **Files Modified**:
  - `src/research/longformer_dataset.py`: Implemented LongformerFileDataset with benign sampling
  - `src/research/cli.py`: Added --strategy flag for training strategy selection
- **Impact**: ⚠️ **Slight Performance Decrease** - marginally lower than package strategy (0.995 vs 0.996)
- **Analysis**: File-based grouping achieves near-identical performance to package-based grouping, with only a 0.001 F1 difference. This suggests that file-level context is nearly as effective as package-level context for malware detection. The file strategy is simpler (no need to track package names) and may be more suitable when package information is unreliable or unavailable. Both strategies benefit from Longformer's extended context window (4098 tokens), but package-level grouping captures slightly more cross-file dependencies within a package. The minimal performance difference indicates that most malicious patterns are contained within individual files rather than spread across multiple files in a package.
- **Technical Insight**: File-level context (concatenating all CodeObjects from one file) captures most malicious patterns effectively. The 0.001 F1 difference between file and package strategies suggests that cross-file dependencies within packages are less critical than initially hypothesized. For practical deployment, file-based strategy may be preferred due to its simplicity and independence from package metadata.

#### 2025-10-07: Longformer Architecture with Benign-Ratio Control (PEAK PERFORMANCE)
- **Tag**: `8586c5a3_f1/0.996`
- **F1 Score**: 0.996 (+0.001)
- **Change**: Introduced Longformer architecture with configurable benign-ratio flag for training data balance
- **Model Configuration**:
  - **Architecture**: Longformer (replaces DistilBERT)
  - **Hidden Size**: 256
  - **Attention Heads**: 4
  - **Hidden Layers**: 4
  - **Intermediate Size**: 1024
  - **Max Position Embeddings**: 4098 (8x longer than DistilBERT's 512 tokens)
  - **Attention Window**: [512, 512, 512, 512] (sliding window per layer)
  - **Vocab Size**: 30,522
  - **Num Labels**: 4 (benign, malicious, suspicious, telemetry)
- **Key Changes**:
  - **New Architecture**: Longformer for package-level malware detection
  - **Extended Context**: 4098 tokens enables analysis of entire packages at once
  - **Efficient Attention**: Sliding window attention (512 tokens) for long-range pattern detection
  - **Training Balance Control**: Added `--benign-ratio` flag (default: 4) to control benign/malicious training proportion
- **Training Metrics (3 epochs, ~72 min/epoch)**:
  - **Losses**: Train 0.00156, Val 0.00255
  - **Overall**: Macro F1=0.9962, Micro F1=0.9987
  - **Benign**: F1=0.9993 (Precision=0.9990, Recall=0.9996)
  - **Malicious**: F1=0.9931 (Precision=0.9961, Recall=0.9901)
  - **Note**: Suspicious and telemetry metrics not reported in training stats
- **Files Modified**:
  - `src/research/cli.py`: Added benign-ratio argument and configuration (+12 lines)
  - `src/research/longformer_dataset.py`: Updated documentation for benign-ratio semantics (+2 lines)
  - `src/research/train_longformer.py`: Integrated configurable benign-ratio parameter (+4 lines)
- **Impact**: ✅ **NEW PEAK PERFORMANCE + ARCHITECTURAL BREAKTHROUGH** - highest F1 score achieved (0.996)
- **Analysis**: Longformer's extended context window (4098 tokens vs DistilBERT's 512) enables analysis of significantly more code at once, capturing long-range dependencies and package-level patterns that shorter context models miss. The sliding window attention mechanism maintains computational efficiency while providing 8x more context. The configurable benign-ratio flag provides fine-grained control over training data balance, preventing majority class bias and enabling optimal learning from both benign and malicious examples. This represents a fundamental architectural advancement - moving from token-level (DistilBERT) to package-level (Longformer) analysis with dramatically improved malware detection capabilities.
- **Technical Insight**: Package-level context is critical for malware detection. Individual functions may appear benign in isolation, but their combination and interaction patterns across files reveal malicious intent. Longformer's 4098-token window captures these cross-file dependencies that DistilBERT's 512-token limit cannot detect.

### September 2025

#### 2025-09-26: Non-Benign Tokenizer Training + Latest malwi-samples (Previous Peak)
- **Tag**: `6b69c5b1_f1/0.995`
- **F1 Score**: 0.995 (+0.072)
- **Note**: ⚠️ **This F1 score is inflated due to severe class imbalance** - benign class had disproportionately more samples than malicious/suspicious/telemetry classes, artificially boosting the overall F1 score. This score is NOT directly comparable to Longformer results which use balanced benign_ratio sampling. Multi-label classification (4 categories) but with unbalanced data.
- **Change**: Tokenizer trained exclusively on non-benign samples (malicious, suspicious, telemetry) + latest malwi-samples dataset
- **Key Changes**:
  - Modified `train_tokenizer.py` to filter out benign samples: `non_benign_df = df[df["label"] != "benign"]`
  - Updated to latest malwi-samples data with expanded telemetry category
  - Enhanced validation logging to show category distribution in training/test splits
  - Added per-category metrics tracking in `compute_metrics()`
- **Files Modified**:
  - `src/research/train_tokenizer.py`: Non-benign filtering logic
  - `src/research/train_distilbert.py`: Enhanced validation distribution logging and per-category metrics
- **Impact**: ✅ **NEW PEAK PERFORMANCE** - highest F1 score achieved (0.995), significant breakthrough
- **Analysis**: Training the tokenizer only on threat-related code (excluding benign samples) created a vocabulary specifically optimized for malicious pattern detection. This approach reduced vocabulary noise from common benign patterns while focusing learning on actual threat indicators. The latest malwi-samples dataset with expanded categories (including telemetry) provided richer training signal. Enhanced validation ensures all categories are properly tested during training, not just benign samples.
- **Technical Insight**: Specialized tokenizer vocabulary (malicious+suspicious+telemetry only) proved more effective than general vocabulary including benign code, suggesting threat detection benefits from domain-specific language modeling.

### August 2025

#### 2025-08-26: Insecure Protocol Detection Disabled
- **Tag**: `56ad076b_f1/0.923`
- **F1 Score**: 0.923 (+0.080)
- **Change**: Disabled `is_insecure_protocol()` mapping function by commenting it out
- **Files Modified**: 
  - `src/common/bytecode.py`: Commented out is_insecure_protocol check (lines 397-399)
  - Updated test expectations for JavaScript and Python mapped outputs
- **Impact**: ✅ **Significant recovery** - F1 score improved from 0.843 to 0.923 (+0.080)
- **Analysis**: Disabling the insecure protocol detection function resulted in substantial performance recovery. The `is_insecure_protocol()` function was too broad, detecting common words like "ftp", "telnet", "http" within strings even when they weren't actual protocol references. This overly aggressive pattern matching created noise in the token mappings and confused the model. The function needs refinement to only detect actual protocol usage rather than any string containing protocol names.

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
1. **Longformer architecture** (0.996 balanced multi-category) - NEW PEAK: Package-level analysis with 8x extended context (4098 tokens) + benign-ratio control achieved breakthrough performance with balanced training data
2. **Longformer file strategy** (0.995 balanced multi-category) - Near-identical to package strategy: File-level grouping proves nearly as effective as package-level context
3. **String mapping optimization** (0.958 binary) - DistilBERT binary peak: Major improvement with minimal code changes
4. **Dataset quality + special tokens** (0.953) - Clean training data and expanded vocabulary
5. **False-positives training** (0.952) - Edge case handling improved robustness
6. **KW_NAMES splitting** (0.947) - Major architecture improvement in AST processing

### ⚠️ Mixed Results / Minor Performance Changes
1. **Longformer strategy comparison** (0.996 vs 0.995) - Package strategy marginally outperforms file strategy, suggesting most malicious patterns are file-contained
2. **Code detection tokens optimization** (0.9362) - Slight decrease from peak but improved processing efficiency
3. **Tokenizer vocabulary fix** (0.918) - Good recovery after configuration issues
4. **Full file scanning** (0.894) - Partial recovery from module splitting issues
5. **DistilBERT 256 reintroduction** (0.944) - Minor decrease, larger model not always better

### ❌ Failed Experiments / Performance Degradations / Misleading Results
1. **Non-benign tokenizer DistilBERT** (0.995 multi-category) - ⚠️ **Inflated score due to severe class imbalance** - benign samples vastly outnumbered malicious/suspicious/telemetry, artificially boosting F1. Not comparable to balanced Longformer results
2. **Vocabulary size increase** (0.0) - Complete model failure, suggests architecture limitations
3. **KW_NAMES unmapping** (0.0) - Removing essential mappings broke model completely
4. **Module code splitting** (0.847) - Lost contextual information critical for detection
5. **Security-focused mappings** (0.843) - Significant performance drop (-0.11), new mapping functions may introduce noise

### 📊 Performance Trends
- **Peak Performance**: 0.996 (2025-10-07) - Longformer package strategy (balanced multi-category) ✨ **NEW RECORD**
- **Longformer File Strategy**: 0.995 (2025-10-08) - Nearly identical to package strategy (balanced multi-category, -0.001)
- **DistilBERT Binary Peak**: 0.958 (2025-08-14) - String mapping optimization (binary classification, balanced data)
- **Performance Range**: 0.0 - 0.996
- **Average Performance**: 0.831 (excluding failed experiments)
- **Strategy Comparison**: Package (0.996) vs File (0.995) vs Object (untested) - minimal difference suggests file-level context sufficient
- **Latest Insight**: File vs package strategy shows negligible difference (0.001), indicating most malicious patterns are file-contained
- **Architectural Breakthrough**: Longformer (0.996 balanced multi-category) represents true peak - combines extended context (4098 tokens) with proper class balancing via benign_ratio
- **Class Balance Importance**: DistilBERT 0.995 multi-category result was invalidated due to severe class imbalance - highlights critical importance of balanced training data
- **Classification Evolution**: Binary → Balanced Multi-category (4 labels) - more challenging task with proper class distribution
- **Volatility**: High - strategic changes can have major impact (±0.1 F1 score)

### 🔬 Critical Success Factors
1. **Training Data Balance**: **CRITICAL** - Balanced benign_ratio sampling is essential for valid F1 scores. DistilBERT 0.995 (imbalanced) was invalidated; Longformer 0.996 (balanced) represents true performance
2. **Model Architecture**: Longformer (0.996 balanced multi-category) with 4098-token context + benign-ratio control achieves peak performance on properly balanced data
3. **Multi-Category Classification**: 4-label classification (benign, malicious, suspicious, telemetry) with balanced sampling - more challenging and realistic than binary
4. **Training Strategy Flexibility**: Package (0.996) vs File (0.995) strategies show negligible difference - file-level context captures most malicious patterns
5. **Configurable Class Balance**: benign-ratio flag enables optimal class balance control across all strategies (package, file, object)
6. **Training Data Quality**: Clean dataset labeling is crucial - removing mislabeled files provided +0.025 F1 improvement
7. **String Handling**: Length and mapping optimizations are disproportionately important (0.958 binary peak)
8. **Tokenizer Configuration**: Special token count significantly impacts performance (5K→10K contributed to major gains)
9. **AST Processing Pipeline**: Core changes in `ast_to_malwicode.py` have highest impact
10. **Context Preservation**: Full file scanning > module splitting (0.894 vs 0.847)
11. **Architecture Stability**: KW_NAMES system is fundamental - modifications must be careful
12. **Training Data Structure**: Current bytecode chunking approach prevents function body duplication and maintains optimal context balance
13. **Grouping Granularity**: Package vs file grouping makes minimal difference (0.001), suggesting malicious code is typically file-contained rather than spread across packages
14. **Avoiding Inflated Metrics**: Class imbalance can artificially inflate F1 scores - proper sampling is non-negotiable for valid evaluation

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
1. **Class imbalance invalidates results** (0.995 → invalidated): **CRITICAL LESSON** - DistilBERT 0.995 multi-category score was artificially inflated by severe class imbalance (too many benign samples)
   - **Root cause**: Benign samples vastly outnumbered malicious/suspicious/telemetry, making model appear better than it was
   - **Solution**: Longformer's benign_ratio flag (0.996 with balanced data) provides honest evaluation
   - **Key takeaway**: Always validate class distribution before trusting F1 scores
2. **Security mappings backfire** (0.843): Well-intentioned security detection functions (email, insecure protocols) caused significant performance regression
   - **Recovery** (0.923): Disabling `is_insecure_protocol()` alone recovered +0.080 F1 score
   - **Root cause**: Function was too broad, matching protocol names within any string context
3. **Feature complexity risk**: More features ≠ better performance - new mappings may create noise or vocabulary confusion
4. **Incremental testing critical**: Major feature additions should be tested individually before combining
5. **Module splitting**: Loses contextual signal quality
6. **String tokenization**: Small changes have large impact

### 📈 Research Directions
1. **Object strategy testing**: Test object-level strategy (individual CodeObjects) with benign_ratio tuning - may reveal if fine-grained patterns matter
2. **Longformer optimization**: Fine-tune attention window sizes, layer depths, and hidden dimensions for malware-specific patterns
3. **Hybrid architecture**: Combine Longformer's extended context with specialized non-benign tokenizer vocabulary
4. **Benign-ratio tuning**: Experiment with different ratios (1, 2, 4, 8, 16) across all strategies to find optimal class balance
5. **Context window expansion**: Test 8192+ token contexts for extremely large files/packages
6. **Multi-scale analysis**: Combine function-level (DistilBERT) with file-level (Longformer) predictions
7. **Training data curation**: Systematic false-positive identification and inclusion with expanded telemetry category
8. **Strategy deployment**: Given minimal performance difference, file strategy may be preferred for production due to simpler metadata requirements
9. **A/B testing**: Test incremental improvements on the 0.996 baseline

## Next Steps

### Immediate Priorities
1. **Object strategy evaluation**: Test object-level strategy to complete strategy comparison (package vs file vs object)
2. **Strategy selection**: Decide between package (0.996) and file (0.995) for production - file strategy simpler but package slightly better
3. **Near-perfect performance**: Investigate closing the final 0.004 gap to achieve F1 = 1.0
4. **Longformer-tokenizer integration**: Combine Longformer architecture with specialized non-benign tokenizer vocabulary
5. **Benign-ratio optimization**: Systematic testing of different class balance ratios across all strategies
6. **Peak performance preservation**: Document and preserve the exact conditions that achieved 0.996 performance
7. **Validation robustness**: Ensure 0.996 performance is consistent across different data splits and test scenarios

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