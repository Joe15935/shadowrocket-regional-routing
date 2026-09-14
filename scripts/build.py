"""Public entry point for the build stage."""
import sys
from pipeline import main

if __name__ == "__main__":
    sys.argv.insert(1, "build")
    main()
