import sys
from typing import Any


def print_dictionary_keys(dictionary: dict[str, Any], indent: int = 0):
    for key in dictionary.keys():
        print("  " * indent + str(key), file=sys.stderr)
        if isinstance(dictionary[key], dict):
            print_dictionary_keys(dictionary[key], indent + 1)
        elif isinstance(dictionary[key], list):
            for elem in dictionary[key]:
                print_dictionary_keys(elem, indent + 1)
        elif key == 'mimeType':
            print(f": {dictionary[key]}", file=sys.stderr)


def sprint_dictionary_keys(dictionary: dict[str, Any], indent: int = 0) -> str:
    text: str = ''
    for key in dictionary.keys():
        text += "  " * indent + str(key)
        if isinstance(dictionary[key], dict):
            text += "\n" + sprint_dictionary_keys(dictionary[key], indent + 1)
        elif isinstance(dictionary[key], list):
            text += "\n"
            for elem in dictionary[key]:
                text += sprint_dictionary_keys(elem, indent + 1)
        else:
            text += f": {str(dictionary[key])[:20]}\n"
    return text
