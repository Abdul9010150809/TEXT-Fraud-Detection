
import sys
import json
import argparse
from ai_modules.text_classifier.text_classifier import TextClassifier

def main():
    parser = argparse.ArgumentParser(description="AI Fraud Detection Engine - CLI Demo")
    parser.add_argument("text", nargs="?", help="The message text to analyze")
    parser.add_argument("--file", help="Path to a file containing the message text")
    
    args = parser.parse_args()
    
    content = ""
    if args.file:
        try:
            with open(args.file, 'r') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.text:
        content = args.text
    else:
        # Interactive mode or pipe
        if not sys.stdin.isatty():
             content = sys.stdin.read()
        else:
             print("Enter message text (Ctrl+D to finish):", file=sys.stderr)
             content = sys.stdin.read()

    if not content.strip():
        print("Error: No text provided.", file=sys.stderr)
        sys.exit(1)

    classifier = TextClassifier()
    result = classifier.classify(content)
    
    # Strict JSON output as requested
    print(json.dumps(result.to_json(), indent=2))

if __name__ == "__main__":
    main()
