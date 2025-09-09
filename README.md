
# Keyword Extractor

A Python command-line tool to extract and analyze keywords from websites using site maps.

## Features

- Automatically fetches and parses sitemaps via robots.txt
- Expands sitemap indices recursively to discover all URLs
- Fetches and downloads web pages gracefully with retries, backoff, and SSL fallback
- Extracts keywords strictly from JSON-LD structured data for accuracy
- Detects and reports keyword cannibalization across pages
- Provides CSV and text reports of keywords mapped to pages

## Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the program with a target website or a CSV list of URLs.

```bash
python keywords.py --site example.com --verbose
python keywords.py --csv urls.csv --max-urls 100
```

### Options

- `--site`: Target website domain or URL to crawl
- `--csv`: Input CSV file with list of seed URLs
- `--timeout`: HTTP request timeout (default 25 seconds)
- `--sleep-ms`: Milliseconds sleep between requests (default 100 ms)
- `--retries`: Number of retries for HTTP requests (default 2)
- `--backoff`: Backoff seconds between retries (default 0.6s)
- `--max-children`: Maximum number of child sitemaps to expand (default 5000)
- `--max-urls`: Maximum number of URLs to process (0 for unlimited)
- `--verbose`: Enable verbose logging
- `--insecure`: Disable HTTPS SSL verification

## Output

- `keyword.csv`: Keyword-to-primary-URL mapping (semicolon separated, no header)
- `kw.csv`: Keyword-to-all-URLs mapping (CSV format)
- `cannibalization.txt`: List of keywords found in multiple URLs (cannibalization)

## Notes

- This program respects robots.txt sitemap declarations and attempts polite crawling.
- Always verify you have permission to crawl target websites.
- Treat all data respectfully and avoid overloading servers.

## License

This repository is licensed under the AGPL License.
