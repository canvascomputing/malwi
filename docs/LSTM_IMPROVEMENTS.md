# LSTM Sequence Pattern Learning Improvements

## Problem: Single Embedding Detection vs Sequence Learning

The original LSTM model learned a simplistic rule: "if ANY embedding is malicious → sequence is malicious". This defeats the purpose of using an LSTM for sequence analysis.

## Solution: Multi-Strategy Approach

### 1. **Mixed Training Sequences with Contextual Labels**

Instead of pure malicious/benign sequences, we create challenging mixed sequences:

```python
# Example Training Data Structure:
- Pure Malicious: [mal, mal, mal] → Label: MALICIOUS
- Pure Benign: [ben, ben, ben] → Label: BENIGN
- Mostly Benign: [ben, ben, mal, ben, ben] → Label: SUSPICIOUS
- Malicious Cluster: [ben, mal, mal, mal, ben] → Label: MALICIOUS
```

This forces the model to learn:
- **Context matters**: Single malicious in benign context = suspicious
- **Patterns matter**: Clustered malicious = truly malicious
- **Proportion matters**: 90% benign with 10% malicious ≠ fully malicious

### 2. **Architecture Enhancements**

#### A. Sequence Attention Layer
```python
class SequenceAttentionLayer:
    - Multi-head self-attention: Learn relationships between embeddings
    - Pattern convolution: Detect local malicious patterns
    - Positional encoding: Emphasize sequence order
```

#### B. Multiple Pooling Strategies
```python
# Instead of just using last hidden state:
1. Max pooling: Captures strongest signal (but can overfit)
2. Mean pooling: Considers all embeddings equally
3. Weighted pooling: Learns importance of positions
→ Concatenate all three for robust representation
```

#### C. Embedding Perturbation
```python
# Prevent over-reliance on exact embedding values:
- Dropout(0.2) on embeddings
- Gaussian noise injection (σ=0.1)
- Forces learning of patterns, not memorization
```

### 3. **Training Strategies**

#### A. Focal Loss
```python
FocalLoss(α=1, γ=2)
# Focuses on hard examples
# Prevents model from taking shortcuts on easy cases
```

#### B. Data Augmentation
- Random position injection of malicious embeddings
- Variable sequence lengths
- Noise injection during training

#### C. Regularization
- Weight decay (AdamW optimizer)
- Gradient clipping
- Dropout at multiple levels

### 4. **Three-Class Classification**

Instead of binary (malicious/benign), we use:
1. **BENIGN**: Clean code
2. **SUSPICIOUS**: Mixed content, needs review
3. **MALICIOUS**: Definite malware

This allows nuanced predictions for real-world scenarios where code may have both legitimate and suspicious elements.

## Key Improvements Over Original

| Aspect | Original LSTM | Improved LSTM |
|--------|--------------|---------------|
| **Learning Target** | Any malicious = malicious | Pattern-based detection |
| **Training Data** | Pure sequences only | Mixed contextual sequences |
| **Architecture** | Simple LSTM → Linear | LSTM → Attention → Multi-pool → Linear |
| **Attention** | None | Self-attention + positional encoding |
| **Loss Function** | CrossEntropy | Focal Loss (hard example mining) |
| **Robustness** | Memorizes embeddings | Noise + dropout prevents memorization |
| **Output** | Binary | Three-class (benign/suspicious/malicious) |

## Expected Results

With these improvements, the LSTM should:
1. ✅ Not classify benign sequences with one suspicious call as fully malicious
2. ✅ Detect concentrated malicious patterns even with benign padding
3. ✅ Learn sequence relationships and context
4. ✅ Provide nuanced suspicious classifications for borderline cases

## Usage

```bash
# Train improved model
uv run python -m src.research.train_lstm_improved training_rl_embeddings.csv \
    --output-model malwi_models/malware_lstm_improved.pth \
    --epochs 20 \
    --use-focal-loss

# The model will:
# 1. Create mixed training sequences
# 2. Apply attention mechanisms
# 3. Use multiple pooling strategies
# 4. Focus on hard examples with focal loss
```

## Validation Strategy

To ensure the model learns sequences properly:
1. Test with single malicious embedding in long benign sequence → Should predict SUSPICIOUS
2. Test with clustered malicious pattern → Should predict MALICIOUS
3. Test with pure benign → Should predict BENIGN with high confidence

The improved model should show significantly better sequence understanding rather than simple max-pooling behavior.