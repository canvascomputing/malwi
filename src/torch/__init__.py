import numpy as np

__all__ = [
    "Tensor",
    "tensor",
    "ones",
    "cat",
    "long",
    "device",
    "cuda",
    "backends",
    "no_grad",
    "argmax",
]


class Tensor(np.ndarray):
    """Minimal Tensor implementation backed by numpy arrays."""

    def __new__(cls, input_array):
        obj = np.asarray(input_array).view(cls)
        return obj

    def unsqueeze(self, axis):
        return Tensor(np.expand_dims(self, axis))

    def item(self):
        # Use numpy's item() to preserve integer types when possible
        return np.asarray(self).item()

    def to(self, device=None):  # pragma: no cover - simple no-op
        """Mimic PyTorch's tensor.to; returns self since devices are not used."""
        return self

    def numel(self):  # pragma: no cover - simple helper
        return self.size

    def cpu(self):  # pragma: no cover - tensors are always on CPU
        return self


def tensor(data, dtype=None, device=None):
    arr = np.array(data, dtype=_dtype_from_torch(dtype))
    return Tensor(arr)


def ones(shape, dtype=None):
    arr = np.ones(shape, dtype=_dtype_from_torch(dtype))
    return Tensor(arr)


def cat(tensors, dim=0):
    arrs = [np.asarray(t) for t in tensors]
    return Tensor(np.concatenate(arrs, axis=dim))


def argmax(tensor, dim=None):  # pragma: no cover - simple helper
    arr = np.asarray(tensor)
    return Tensor(np.argmax(arr, axis=dim))


def device(name):
    return name


class _Cuda:
    def is_available(self):
        return False

    def device_count(self):
        return 0


class _MpsBackend:
    def is_available(self):
        return False


class _Backends:
    mps = _MpsBackend()


cuda = _Cuda()
backends = _Backends()

long = np.int64


def _dtype_from_torch(dtype):
    if dtype is None:
        return None
    if dtype in (long, "long"):
        return np.int64
    return dtype


class _NoGrad:
    def __enter__(self):  # pragma: no cover - trivial
        return None

    def __exit__(self, exc_type, exc, tb):  # pragma: no cover
        return False


def no_grad():  # pragma: no cover - simple context manager
    return _NoGrad()
