"""
Configurazione comune per i test pytest
"""

import sys
from pathlib import Path

# Aggiungi la root del progetto al path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
