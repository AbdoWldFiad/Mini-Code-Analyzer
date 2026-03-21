# parsers/tree_sitter_loader.py
from tree_sitter_language_pack import get_parser as tsp_get_parser
from tree_sitter import Parser

SUPPORTED_LANGUAGES = ["javascript", "php", "html"]

def get_parser(language: str) -> Parser:
    language = language.lower()
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"[ERROR] Unsupported language '{language}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}"
        )

    # tsp_get_parser already returns a Parser instance ready to use
    parser = tsp_get_parser(language)
    return parser