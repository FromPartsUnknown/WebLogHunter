import logging
import pandas as pd
import re
import os
import sys


access_log_formats = [
    ("apache", r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] "(?P<method>[A-Z]+) (?P<request_uri>[^ ]+) HTTP/[0-9.]+" (?P<status>\d{3}) (?P<resp_size>\d+|-) "(?P<referrer>.*?|-)" "(?P<user_agent>.*?|-)"\s*$'),
    ("no_method", r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] "(?P<request_uri>[^"]+)" (?P<status>\d{3}) (?P<resp_size>\d+|-) "(?P<referrer>.*?|-)" "(?P<user_agent>.*?|-)"$'),
    ("apache extended", r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] "(?P<method>[A-Z]+) (?P<request_uri>[^ ]+) HTTP/[0-9.]+" (?P<status>\d{3}) (?P<resp_size>\d+) "(?P<referrer>.*?|-)" "(?P<user_agent>.*?|-)" "(?P<extra>.*?|-)"$'),
    ("clf", r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] "(?P<method>[A-Z]+) (?P<request_uri>[^ ]+) HTTP/[0-9.]+" (?P<status>\d{3}) (?P<resp_size>\d+|-)$'),
    ("unknown", r'^\S+ \S+ \S+ (?P<ip>\S+) \S+ \S+ \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] "(?P<method>[A-Z]+) (?P<request_uri>[^ ]+) HTTP/[0-9.]+" (?P<status>\d{3}) (?P<resp_size>\d+)$'),
    ("nginx", r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] "(?P<method>[A-Z]+) (?P<request_uri>[^ ]+) HTTP/[0-9.]+" (?P<status>\d{3}) (?P<resp_size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>.*?|-)"$'),
    ("apache_ssl", r'^\[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\] (?P<ip>\S+) (?P<extra>[^"]+) "(?P<method>[A-Z]+) (?P<request_uri>[^ ]+) HTTP/[0-9.]+" (?P<resp_size>\d+|-)$')
]

class AccessLogParserError(Exception):
    def __init__(self, message, *args, **kwargs):
        logger = logging.getLogger(__name__)
        logger.error(message, exc_info=True)
        super().__init__(message, *args, **kwargs)

class InfoOnlyFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO

class AccessLogParser():
    def __init__(self, debug_path=None):
            self._log_init()
            self.log_patterns = []
            for name, pattern in access_log_formats:
                self.add_pattern(name, pattern) 

    def _log_init(self, level=logging.INFO, filename="errors.log"):
        self._logger = logger = logging.getLogger(__name__)
        if self._logger.hasHandlers():
            self._logger.handlers.clear()
        
        handler   = logging.FileHandler(filename, mode='a')
        formatter = logging.Formatter('AccessLogDataFrameError - %(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        handler.setLevel(level)
        self._logger.addHandler(handler)

        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.INFO)
        handler.addFilter(InfoOnlyFilter())
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

        self._logger.setLevel(level)
        
    def add_pattern(self, name, pattern):
        try:
            self.log_patterns.append((name, re.compile(pattern)))
        except re.error as e:
            raise AccessLogParserError(f"Failed to compile regex pattern for AccessLogParser: {str(e)}") from e    
        
    def load_logfile(self, path):
        self._logger.info(f"[*] Parsing {' '.join(path)}")
        log_entries = self._read_log_paths(path)
        return log_entries

    def _read_log_paths(self, path_arg):
        logline_entries = []
        for path in path_arg:
            if os.path.isfile(path):
                try:
                    self._logger.debug(f"Opening: {path}")
                    if path.lower().endswith('.csv'):
                        # Splunk
                        log_lines = pd.read_csv(path, usecols=['_raw'])['_raw'].astype(str).tolist()
                    else:
                        with open(path, 'r') as fp:
                            log_lines = fp.readlines()
                    logline_entries += self._read_log_file(log_lines, path)
                except OSError as e:
                    self._logger.error(f"Error opening file '{path}': {str(e)}")
                except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as e:
                    self._logger.error(f"CSV related error for '{path}': {str(e)}")       
            elif os.path.isdir(path):
                for filename in os.listdir(path):
                    file_path = os.path.join(path, filename)
                    if os.path.isfile(file_path):
                        try:
                            self._logger.debug(f"Opening: {file_path}")
                            if path.lower().endswith('.csv'):
                                log_lines = pd.read_csv(path, usecols=['_raw'])['_raw'].astype(str).tolist()
                            else:
                                with open(file_path, 'rb') as fp:
                                    log_lines = fp.readlines()
                            logline_entries += self._read_log_file(log_lines, file_path) 
                        except OSError as e:
                            self._logger.error(f"Error opening file '{path}': {str(e)}")
                        except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as e:
                            self._logger.error(f"CSV related error for '{path}': {str(e)}")
            else:
                raise AccessLogParserError(f"Path '{path}' is not a file or directory.")
        return logline_entries

    def _read_log_file(self,log_lines, path):
        logline_entries = []
        for line in log_lines:
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='replace')
            try:
                # Strip grep filename
                strip_grep = re.sub(r'^[\w./-]+:\s*', '', line)
                if strip_grep:
                    line = strip_grep
                    self._logger.debug(f"Removed grep output: {line}")
            except re.error as e:
                self._logger.error(f"Regex error for {line}") 
            entry = self._parse_log_line(line)
            if entry:
                entry['source'] = os.path.basename(path)
                logline_entries.append(entry)
            else:
                self._logger.error(f"Failed to parse: {line.strip()}")
        self._logger.info(f"[*] Extracted {len(logline_entries)} log lines from {path}.")
        return logline_entries
        
    def _parse_log_line(self, line):
        try:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('\n'):
                self._logger.debug(f"Skipping empty or comment line: {line}")
                return None
            
            line = re.sub(r'(\".*?\"|-\" \".*?\"|-\")$.*', r'\1', line)
            self._logger.debug(f"Processing line: {line}")
            
            for pattern_name, pattern in self.log_patterns:
                self._logger.debug(f"Testing {pattern_name} pattern")
                log_match = re.match(pattern, line)
                if not log_match:
                    continue
                entry = log_match.groupdict()
                entry['user_agent'] = entry.get('user_agent') or '-'
                entry['referrer'] = entry.get('referrer') or '-'
                # Missing status in ssl logs. Assuming 200. 
                if pattern_name == 'apache_ssl':
                    entry['status'] = int(200)
                else:
                    status = entry.get('status')
                    entry['status'] = int(status) if status and status.isdigit() else 0
                resp_size = entry.get('resp_size')
                entry['resp_size'] = int(resp_size) if resp_size and resp_size.isdigit() else 0
                entry['method']= entry.get('method') or 'INVALID' 
                if not all(key in entry for key in ['timestamp', 'request_uri', 'status', 'method', 'resp_size', 'referrer', 'user_agent']):
                    self._logger.error(f"Missing key {entry} for:\n{line}")
                    continue
                self._logger.debug(f"Matched on {pattern_name} log format. Captured:\n{entry}")
                return entry  
        except re.error as e:
            self._logger.error(f"Regex issue processing line: {line}\nError: {str(e)}")
        except Exception as e:
            self._logger.error(f"Exception parsing line: {line}\nError: {str(e)}")
        return None
       