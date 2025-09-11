import numpy as np
from .. import Tensor

def softmax(x, dim=-1):
    arr = np.asarray(x)
    e_x = np.exp(arr - np.max(arr, axis=dim, keepdims=True))
    result = e_x / e_x.sum(axis=dim, keepdims=True)
    return Tensor(result)
