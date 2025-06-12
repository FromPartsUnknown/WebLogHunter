import yaml
import ipaddress
import logging
import pandas as pd
import re
from urllib.parse import urlparse, unquote
import os
import sys
from collections import defaultdict
import numpy as np

class InfoOnlyFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO

class AccessLogRiskError(Exception):
    def __init__(self, message, *args, **kwargs):
        logger = logging.getLogger(__name__)
        logger.error("%s", message, exc_info=True)
        super().__init__(message, *args, **kwargs)

class AccessLogRisk:
    def __init__(
        self, 
        tool_signatures, 
        uri_risk_paths,
        uri_risk_extensions,
        rules_path,
        webshell_path
    ):
        try:
            self._log_init()
            self._tool_signatures     = tool_signatures
            self._uri_risk_paths      = uri_risk_paths
            self._uri_risk_extensions = uri_risk_extensions
            self._webshell_path       = webshell_path
            self._bad_shells          = None

            with open(rules_path, 'r') as fp:
                rules_yaml = fp.read()

            self._sigma_rules = yaml.safe_load(rules_yaml)

        except Exception as e:
            raise AccessLogRiskError(f"Failed to load config: {rules_path}: {str(e)}") from e
        

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

# - title: Suspicious Method & OK Status
#   id: 523e4567-e89b-12d3-a456-426614174004
#   description: Detect high risk method with successful status
#   status: stable
#   logsource:
#     category: access_log
#   detection:
#     selection:
#       method_risk|gte: 70
#       status: [200, 201, 202]
#     condition: selection
#   level: moderate
#   fields:
#     - status
#     - method_risk
#   tags:
#     - risk_score: 70.0

    def balatro(self, df):
        try:

            self._logger.info(f"[*] Calculating risk scores for {len(df)} entries.")

            req_cols = ['request_uri', 'status', 'request_count', 'method', 'ip']
            if not all(col in df for col in req_cols):
                self._logger.error(f"Missing required columns: {set(req_cols) - set(df.columns)}")
                raise ValueError(f"Missing required columns: {set(req_cols) - set(df.columns)}")

            df['uri_risk']     = df['request_uri'].apply(self._calc_uri_risk)
            df['method_risk']  = df['method'].apply(self._calc_method_risk)
            df['status_risk']  = df['status'].apply(self._calc_status_risk)
            df['risk_score']   = 0.0
            df['rule_applied'] = ''

            for rule in self._sigma_rules:
                selection  = rule['detection']['selection']
                risk_score = float(rule['tags'][0]['risk_score'])
                rule_title = rule['title']

                mask = pd.Series(True, index=df.index)
                for field, condition in selection.items():
                    if '|' in field:
                        field_name, op = field.split('|')
                        condition_value = condition
                        self._logger.debug(f"Rule: {rule_title}, Field: {field_name}, Op: {op}, Condition: {condition}, Value: {condition_value}")
                        if op in ['gt', 'gte', 'lt', 'lte', 'eq', 'ne']:
                            try:
                                condition_value = float(condition)
                            except (ValueError, TypeError):
                                raise ValueError(f"Invalid condition value for {field}: {condition}")
                            if   op == 'gte':
                                mask &= df[field_name] >= condition_value
                            elif op == 'gt':
                                mask &= df[field_name]  > condition_value
                            elif op == 'lte':
                                mask &= df[field_name] <= condition_value
                            elif op == 'lt':
                                mask &= df[field_name]  < condition_value
                            elif op == 'eq':
                                mask &= df[field_name] == condition_value
                            elif op == 'ne':
                                mask &= df[field_name] != condition_value
                        # String operators
                        elif op == 'contains':
                            mask &= df[field_name].str.contains(condition_value, case=False, na=False)
                        elif op == 'startswith':
                            mask &= df[field_name].str.startswith(condition_value, na=False)
                        elif op == 'endswith':
                            mask &= df[field_name].str.endswith(condition_value, na=False)
                        elif op == 'regex':
                            mask &= df[field_name].apply(lambda x: bool(re.search(condition_value, str(x), re.IGNORECASE)))
                        elif op == 'contains|all':
                            if not isinstance(condition_value, list):
                                raise ValueError(f"Condition for {field}|contains|all must be a list: {condition_value}")
                            for val in condition_value:
                                mask &= df[field_name].str.contains(val, case=False, na=False)
                        # List operators
                        elif op == 'in':
                            mask &=  df[field_name].isin(condition_value)
                        elif op == 'notin':
                            mask &= ~df[field_name].isin(condition_value)
                        elif op == 'cidr':
                            try:
                                if isinstance(condition_value, str):
                                    ip_list = [condition_value]
                                elif isinstance(condition_value, list):
                                    ip_list = condition_value
                                else:
                                    raise ValueError(f"Invalid CIDR condition value: {condition_value} (must be string or list)")
                                cidr_mask = pd.Series(False, index=df.index, dtype=bool)
                                for ip_test in ip_list:
                                    try:
                                        network = ipaddress.ip_network(ip_test, strict=False)
                                        n_mask = df[field_name].apply(lambda x: self._ip_in_network(x, network))
                                        cidr_mask |= n_mask
                                    except ValueError as e:
                                        self._logger.warning(f"[-] Skipping invalid CIDR {ip_test}: {str(e)}")
                                        continue
                                mask &= cidr_mask
                            except Exception as e:
                                raise ValueError(f"Failed to process CIDR for {field}: {condition_value} ({str(e)})")                        
                        else:
                            raise ValueError(f"Unsupported sigma operator: {op}")
                    elif field in ['status', 'method', 'user_agent']:
                        mask &= df[field].isin(condition)
                        self._logger.debug(f"Rule: {rule_title}, Status condition: {condition}, Matches: {df['status'].isin(condition).sum()}")

                 # Use highest risk score
                cur_risk_scores = df.loc[mask, 'risk_score']
                ssede_mask = mask & ((risk_score > cur_risk_scores) | cur_risk_scores.isna())
                if ssede_mask.any():
                    df.loc[ssede_mask, 'risk_score']   = risk_score
                    df.loc[ssede_mask, 'rule_applied'] = rule_title
                    self._logger.debug(f"Rule {rule_title} applied to {ssede_mask.sum()} rows")
                else:
                    self._logger.debug(f"Rule {rule_title} not applied (no new matches or lower risk score)")

        except Exception as e:
            raise AccessLogRiskError(f"Failed to calculate risk score:  {str(e)}") from e
        return df
    
    def _ip_in_network(self, ip_member, network):
        try:
            ip = ipaddress.ip_address(ip_member)
            return ip in network
        except ValueError:
            return False 

    def _calc_uri_risk(self, request_uri):
        score = 0
        uri, depth = self._uri_decode_nested(request_uri)
        
        # 10 points per urlencoded depth
        score = 20 if depth >= 2 else 10 if depth == 1 else 0
        
        # Sensitive path increment
        sensitive_match = any(path in uri.lower() for path in self._uri_risk_paths)
        if sensitive_match:
            score += 25

        # Path traversal
        is_path, is_query = self._uri_path_traversal(uri)
        if is_path:
            score += 80 
        elif is_query: 
            score += 15

        # Know web shell extension
        if self._uri_webshell(uri, self._webshell_path) == True:
            score += 50
            
        # PHP double extension
        double_ext = self._uri_double_extension(uri)
        if double_ext:
            score += 80
        
        if self._uri_risky_extension(uri):
            score += 10
        
        #self._logger.debug(f"URI risk: {request_uri}: score: {score}")
        return min(score, 100)

    def _uri_decode_nested(self, url, max_depth=3):
        depth = 0
        decoded = ''
        for _ in range(max_depth):
            try:
                decoded = unquote(url)
                if decoded == url:
                    break
            except:
                break
            depth += 1
            url = decoded
        return url, depth

    def _uri_path_traversal(self, uri):
        pt_in_path   = False
        pt_in_params = False
        path_traversal_patterns = [
            r'\.\./', r'\.\.\\', r'/\.\.', r'\\\.\.',
            r'%00',
            r'\uFFFD'
        ]
        uri_parse = urlparse(uri)
        path  = uri_parse.path or ''
        query = uri_parse.query or ''
    
        for pattern in path_traversal_patterns:
            if path and re.search(pattern, path, re.IGNORECASE):
                pt_in_path = True
            if query and re.search(pattern, query, re.IGNORECASE):
                pt_in_params = True
        return pt_in_path, pt_in_params

    def _uri_double_extension(self, uri):
        pattern = r"\.php\.[a-zA-Z0-9]+$"
        match = re.search(pattern, uri, re.IGNORECASE)
        return bool(match)

    def _uri_risky_extension(self, uri):
        uri = uri.lower()
        for pattern in self._uri_risk_extensions:
            if re.search(pattern, uri):
                return True
        return False

    def _calc_method_risk(self, method):
        method = method.upper()
        risk_scores = {
            'GET':     10,
            'HEAD':    20,
            'OPTIONS': 25,
            'POST':    45,
            'PUT':     80,
            'DELETE':  80,
            'TRACE':   80,
            'CONNECT': 80
        }
        return risk_scores.get(method, 60)

    def _calc_status_risk(self, status):
        score = 0
        risk_scores = {
            100: 20, 101: 20, 
            200: 30, 201: 90, 202: 35, 204: 25, 207: 70,
            301: 10, 302: 10, 304: 20, 
            400: 15, 401: 30, 403: 40, 404: 10, 429: 35, 
            500: 90, 502: 70, 503: 70, 504: 70
        }
        if status in risk_scores:
            score = risk_scores[status]
        elif 100 <= status < 200:
            score = 25
        elif 200 <= status < 300:
            score = 35
        elif 300 <= status < 400:
            score = 15
        elif 400 <= status < 500:
            score = 25
        elif 500 <= status < 600:
            score = 80
        else:
            score = 90
        return score

    def _uri_webshell(self, uri, filename='shells.txt'):
        try:
            if self._bad_shells == None:
                with open(filename) as fp:
                    self._bad_shells = set(line.strip() for line in fp if line.strip() and not line.startswith('#'))
            if self._extract_filename(uri) in self._bad_shells:
                self._logger.info(f"Found known webshell name in {uri}")
                return True 
        except OSError:
            raise AccessLogRiskError(f"Failed to open shells.txt")
        except Exception as e:    
            raise AccessLogRiskError(f"Web shell check failed: {str(e)}") from e
        return False
    
    def _extract_filename(self, uri):
        decoded_uri = unquote(uri)
        clean_uri = decoded_uri.split('?', 1)[0]
        filename = os.path.basename(clean_uri)
        return filename


    def burp_intruder(self, df, risk_score=95.0, min_requests=100, max_gap_seconds=1.0):
        try:
            self._logger.info(f"[*] Scanning for Burp Intruder pattern.")
            required_cols = ['utc_timestamp', 'source', 'status', 'method', 'ip', 'request_uri', 'cluster']
            if not all(col in df.columns for col in required_cols):
                raise ValueError(f"DataFrame is missing required columns: {set(required_cols) - set(df.columns)}")

            status_500 = df[df['status'] == 500].copy()
            if status_500.empty:
                return df

            group_cols = ['source', 'ip', 'cluster', 'request_uri', 'method']   
            status_500.sort_values(by=group_cols + ['utc_timestamp'], inplace=True)
            time_diff = status_500.groupby(group_cols)['utc_timestamp'].diff()
            is_new_burst = (time_diff > pd.Timedelta(seconds=max_gap_seconds))

            status_500['burst_id'] = is_new_burst.groupby([status_500[col] for col in group_cols]).cumsum()
            
            burst_group_cols = group_cols + ['burst_id']
            burst_stats = status_500.groupby(burst_group_cols)['utc_timestamp'].agg(
                burst_count='size',
                min_time='min',
                max_time='max'
            ).reset_index()

            sus_bursts = burst_stats[burst_stats['burst_count'] >= min_requests]
            if sus_bursts.empty:
                return df
            
            for _, attack_burst in sus_bursts.iterrows():
                source, cluster_id, ip, uri, method = attack_burst['source'], attack_burst['cluster'], attack_burst['ip'], attack_burst['request_uri'], attack_burst['method']
                start_time = attack_burst['min_time']
                
                success_check = df[
                    (df['status'] == 200) & (df['source'] == source) &
                    (df['ip'] == ip) & (df['request_uri'] == uri) & (df['cluster'] == cluster_id) & 
                    (df['utc_timestamp'] >= start_time) 
                ]

                if not success_check.empty:
                    success_indices = success_check.index
                    df.loc[success_indices, 'risk_score'] = risk_score 
                    df.loc[success_indices, 'rule_applied'] = 'Attack Success After High-Frequency Server Failures'

        except Exception as e:
            raise AccessLogRiskError(f"Failed to analyse for attack bursts: {str(e)}") from e
        
        return df

    def tool_scanner(self, df_input):
        try:
            cols = ['source', 'ip', 'request_uri', 'utc_timestamp', 'cluster']
            if not all(col in df_input for col in cols):
                missing = set(cols) - set(df_input.columns)
                raise ValueError(f"Missing required columns: {missing}")

            df = df_input.copy()
            df['tool'] = ''
            df['tool_name'] = ''
            df['tool_desc'] = ''
            df['request_uri_lower'] = df['request_uri'].astype(str).str.lower()

            if df['utc_timestamp'].isna().any():
                raise ValueError("utc_timestamp contains NaT values after coercion.")
            df['unix_timestamp'] = df['utc_timestamp'].astype(np.int64) // 1_000_000_000

            tool_match_info = defaultdict(dict)
            tool_uri = {}

            for tool_sigs in self._tool_signatures:
                tid = tool_sigs['tool']
                keywords_for_tool = tool_sigs.get('keyword', [])
                if not keywords_for_tool:
                    self._logger.debug(f"Tool '{tid}' has no keywords.")
                    tool_uri[tid] = set()
                    continue
                
                tool_uri[tid] = {kw.lower().strip() for kw in keywords_for_tool if isinstance(kw, str) and kw.strip()}

                for kw in keywords_for_tool:
                    if not isinstance(kw, str) or not kw.strip():
                        self._logger.warning(f"Tool '{tid}' has an empty or invalid keyword: '{kw}'. Skipping.")
                        continue
                    kw_str = kw.lower().strip()
                    kw_pattern = re.escape(kw_str)
                    tool_match_info[tid][kw_str] = df['request_uri_lower'].str.contains(kw_pattern, na=False, regex=True)
            
            self._logger.info(f"[*] Pre-calculated tool matches applied. Starting tool scan on {len(df)} entries.")
            
            assignments = []
            df_sorted = df.sort_values(['source', 'ip', 'unix_timestamp'])
            group = df_sorted.groupby(['source', 'ip', 'cluster'], sort=False)

            for group_key, group_df in group:
                for tool_sigs in self._tool_signatures:
                    tid = tool_sigs['tool']
                    time_window_seconds = tool_sigs['time_window']
                    
                    req_kw = tool_uri.get(tid)
                    if not req_kw: 
                        continue

                    mask = pd.Series(False, index=group_df.index)
                    for kw_str in req_kw:
                        kw_match = tool_match_info[tid].get(kw_str)
                        if kw_match is not None:
                            mask |= kw_match.loc[group_df.index]
                    
                    cand_df = group_df[mask]
                    if cand_df.empty:
                        continue 

                    kw_cand = pd.DataFrame(index=cand_df.index)
                    for kw_str in req_kw:
                        kw_match = tool_match_info[tid].get(kw_str)
                        if kw_match is not None:
                             kw_cand[kw_str] = kw_match.loc[cand_df.index]
                        else:
                             kw_cand[kw_str] = False

                    cand_sorted = cand_df.index.tolist()
                    index_cache = set()
                    for i in range(len(cand_sorted)):
                        start_cand_index = cand_sorted[i]
                        if start_cand_index in index_cache:
                            continue

                        start_time = df.loc[start_cand_index, 'unix_timestamp']
                        cluster_index = [start_cand_index]
                        found_kw = set()
                        for kw_c in req_kw:
                            if kw_cand.loc[start_cand_index, kw_c]:
                                found_kw.add(kw_c)

                        for j in range(i + 1, len(cand_sorted)):
                            next_index = cand_sorted[j]
                            next_time = df.loc[next_index, 'unix_timestamp']

                            if time_window_seconds > 0 and (next_time - start_time) > time_window_seconds:
                                break

                            cluster_index.append(next_index)
                            for kw_c in req_kw:
                                if kw_cand.loc[next_index, kw_c]:
                                    found_kw.add(kw_c)
                            
                            if found_kw.issuperset(req_kw):
                                break 

                        cluster_timestamps = df.loc[cluster_index, 'unix_timestamp']
                        time_span = 0
                        if len(cluster_timestamps) > 1:
                            time_span = cluster_timestamps.max() - cluster_timestamps.min()
                        
                        found_all = found_kw.issuperset(req_kw)
                        time_ok   = (time_window_seconds == 0) or (time_span <= time_window_seconds)

                        if found_all and time_ok:
                            self._logger.debug(f"Tool '{tid}' event cluster found for group {group_key} on index {cluster_index} (Time span: {time_span}s)")
                            for index in cluster_index:
                                assignments.append((index, tid, tool_sigs['name'], tool_sigs['description']))
                                index_cache.add(index) 

            if assignments:
                assignment_df = pd.DataFrame(assignments, columns=['index', 'tool', 'tool_name', 'tool_desc'])
                assignment_df = assignment_df.drop_duplicates(subset=['index'], keep='last').set_index('index')
                df.update(assignment_df)

            cols_to_drop = ['request_uri_lower', 'unix_timestamp'] 
            for tid_key in tool_match_info:
                for kw_clean_key in tool_match_info[tid_key]:
                    pass
            
            return df.drop(columns=['request_uri_lower', 'unix_timestamp'], errors='ignore') 

        except ValueError as e:
            raise AccessLogRiskError(f"Tool scanner validation error: {str(e)}") from e
        except Exception as e:
            raise AccessLogRiskError(f"Failed to analyse tool pattern: {str(e)}") from e