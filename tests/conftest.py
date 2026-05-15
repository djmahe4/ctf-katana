import warnings
import pytest

def pytest_configure(config):
    """
    Globally suppress annoying library-level warnings during test runs.
    """
    # Suppress torch deprecation warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", message=".*torch.ao.quantization.*")
    warnings.filterwarnings("ignore", message=".*pt2e quantization.*")
    
    # Suppress torch dataloader warnings about pin_memory when no GPU is present
    warnings.filterwarnings("ignore", message=".*pin_memory.*")
    
    # Suppress DrissionPage and other library noise
    warnings.filterwarnings("ignore", message=".*ChromiumPage.*")
    warnings.filterwarnings("ignore", message=".*DrissionPage.*")
    warnings.filterwarnings("ignore", message=".*easyocr.*")
    warnings.filterwarnings("ignore", message=".*tqdm.*")
