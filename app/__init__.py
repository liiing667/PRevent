import sys

from src import config

# Expose 'app.config' as the same module object as 'src.config',
# so patching 'app.config.<name>' also affects 'src.config' consumers.
sys.modules.setdefault(__name__ + '.config', config)
