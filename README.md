<h1 align="center">WebLog Triage</h1>

<p align="center">Analysing large volumes of web server access logs to identify malicious behaviour is tedious and error-prone. WebLogTriage helps streamline this process.</p>

<p align="center">
  <img src="docs/logo.jpg" alt="WebLogTriage Logo" height="300"/>
</p>

<p align="center">WebLogTriage is a tool for parsing and analysing web server access logs to detect suspicious activity. It normalises logs into a standard DataFrame format for efficient querying and applies risk-scoring rules to highlight potential threats. User-defined rules and detection signatures help uncover scanning tools, webshells, and other malicious patterns.</p>


## 🌟 Features

- 🔎 **Log Parsing**: Supports 6 access log formats including Apache and Nginx, converting them into a unified Pandas DataFrame for structured analysis.

- 🛠 **User Defined Rules**: Applies custom rules (defined in `rules.yaml`) to detect threats based on fields like IP, URI path, status code, user-agent, and more. Matching entries are tagged with a rule name and risk score.

- 💀 **Malicious Tool Detection**: Detects common web scanners (e.g., DirSearch) using patterns defined in `config.yaml`. Known webshell paths listed in `shells.txt` are flagged.

- ✂ **Flexible Filtering**: Supports queries by URI keywords, IP addresses (including CIDR ranges), HTTP methods, HTTP status codes, timestamp ranges, and more. See Usage section for examples. 

- 🥞 **Timestamp Clustering**: Detects gaps between timestamps and clusters related activity into distinct sessions. Terminal output highlights a new session in blue. 

- 💻 **Output Options**
  - Terminal output with colured highlights for quick inspection
  - CSV output for in-depth analysis
  - Email support for sending reports
  - Optional filtering of static files (.js, .css, etc)


## 💾 Installation

Install WebLogTriage using pip:

```bash
pip install .
```

Ensure `config.yaml`, `rules.yaml`, and `shells.txt` are present. See [Configuration](#configuration) for details.

## ⚙️ Configuration

- **`config.yaml`**: Specifies configuration options, including settings for risk score calculation such as sensitive paths like `/admin` and extensions like `.sql`. Tool signature definition for detecting scanners like DirSearch. See `config.yaml` for examples.

- **`rules.yaml`**: Defines Sigma-style matching rules to flag suspicious log entries and assign risk scores. See `rules.yaml` for examples. 

- **`shells.txt`**: A list of known webshell filenames (e.g., `cmd.php`, `wshell.jsp`), used for URI risk detection.

## 🚀 Usage

Run via the main script:

```bash
triage.py --help
```

### Examples

1. **Analyse Logs with Default Settings** - Process all logs in a directory, apply rules from `rules.yaml`, detect scanning tools, and filter out static file extensions:
   ```bash
   triage.py --path WebLogs/ |less -R
   ```

2. **Filter High-Risk Entries** -
   Show entries with a risk score of 70 or higher (based on `rules.yaml`):
   ```bash
   triage.py --path WebLogs/accesslog1.txt --risk-score 70 |less -R
   ```

3. **Focus on Scanning Tool Activity** - Display an overview of detected malicious scanning tools and related log entries:
   ```bash
   triage.py --path WebLogs/ --tool-focus
   triage.py --path WebLogs/ --tool-focus --output-format csv
   ```

4. **Filter PUT Requests by IP and Output to CSV** - Extract successful PUT requests from specific IPs or CIDR ranges, outputting full details in CSV format:
   ```bash
   triage.py --path WebLogs/ --method PUT --ip 192.168.1.1 10.10.10.0/24 --status 200 --output-format csv
   ```

5. **Filter POST Requests by Time Range** - Show successful POST requests within a specific time window:
   ```bash
   triage.py --path WebLogs/ --start-time "2025-04-21 18:23:00+10" --end-time "2025-04-21 18:24:00+10" --method POST --status 200
   ```

6. **Search for Suspicious URIs with High Request Counts** - Filter logs for URIs containing “upload” with over 1000 requests, adjusting timestamps by 300 seconds (5 minutes) to correct any time skew in logs:
   ```bash
   triage.py --path WebLogs/ --uripath-keyword "upload" --time-offset 300 --request-count 1000
   ```

7. **Identify Logs with Uncommon Status Codes** - Exclude common HTTP status codes and limit static file filtering to `.php` and `.js`:
   ```bash
   triage.py --path WebLogs/access* --ignore-status-code 200 404 500 302 400 403 401 301 --ignore-extension php js
   ```

8. **Filter by Referrer and User Agent, Email Results** - Identify logs with a specific referrer and user agent, emailing results in CSV format:
   ```bash
   triage.py --path WebLogs --referrer fofa.info --ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/120.0" --email terry.uppercut+gh@gmail.com
   ```

## 💻 Output

- **Terminal Output** (default): Provides a concise overview of log entries by truncating some fields for readability. Ideal for exploring data and identifying entries of interest. Use (`--cluster-off`) to turn off session clustering and order by timestamp instead. 
- **CSV Output** (`--output-format csv`): Includes all fields without truncation or clustering, suitable for detailed analysis or reporting.
- **Email** - With the --email option, send results to an address in CSV format.

To customise output, adjust filtering options (e.g., `--ignore-extension`) or use CSV mode for full data.

## Error Handling

- Parsing failures or unsupported formats are logged to `error.log`.
- To support new log formats, add patterns to `access_log_formats` in `parser.py`.