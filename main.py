import sys
from parser import parse_file
import sys


def main():
    if (len(sys.argv) == 2):
        targets = sys.argv[1:] 
        
    else:
        print("Usage: python main.py <file_name/file_folder>")
        sys.exit(1)


if __name__ == "__main__":
    main()