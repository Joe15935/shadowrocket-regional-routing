"""Public entry point for the validate stage."""
import sys
from pipeline import main

if __name__ == "__main__":
    sys.argv.insert(1, "validate")
    main()
