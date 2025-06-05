import pandas as pd
import ipaddress
import re
import logging
import numpy as np
from prettytable import PrettyTable
import textwrap
from termcolor import colored
import sys


class AccessLogDataFrameError(Exception):
    def __init__(self, message, *args, **kwargs):
        logger = logging.getLogger(__name__)
        logger.error("%s", message, exc_info=True)
        super().__init__(message, *args, **kwargs)

class InfoOnlyFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO

class AccessLogDataFrame:
    OUTPUT_RISK_WRAP_THRESHOLD = 70
    OUTPUT_TERM      = 0x01
    OUTPUT_CSV       = 0x02
    OUTPUT_ALL       = 0x03
    OUTPUT_RISK_WRAP = 0x10
    OUTPUT_TRUNC_REV = 0x20
    DISPLAY_CONFIG = [
        ('source',           'Source',            8, OUTPUT_ALL),
        ('timestamp',        'Orig Timestamp',   26, OUTPUT_ALL),
        ('utc_timestamp',    'UTC Timestamp',    26, OUTPUT_ALL),
        ('ip',               'IP',               16, OUTPUT_ALL),
        ('method_path',      'Method + Path',    30, OUTPUT_ALL|OUTPUT_RISK_WRAP),
        ('status',           'Status',            6, OUTPUT_ALL),
        ('resp_size',        'Size',              6, OUTPUT_ALL),
        ('user_agent',       'User Agent',       12, OUTPUT_ALL|OUTPUT_TRUNC_REV|OUTPUT_RISK_WRAP),
        ('referrer',         'Referrer',         14, OUTPUT_ALL|OUTPUT_RISK_WRAP),
        ('request_count',    'Count',             6, OUTPUT_ALL),
        ('risk_score',       'Score',             6, OUTPUT_ALL),
        ('rule_applied',     'Rule',             15, OUTPUT_ALL|OUTPUT_RISK_WRAP),
        ('cluster',          'Cluster ID',        6, OUTPUT_CSV),
        ('tool',             'TID',               6, OUTPUT_ALL),
        ('tool_name',        'Tool Name',        15, OUTPUT_CSV),
        ('tool_desc',        'Tool Description', 30, OUTPUT_CSV),
        ('extra',            'Extra Info',       30, OUTPUT_CSV) 
    ]

    def __init__(self, log_entries, time_offset=0, cluster_off=False):
        try:
            self._log_init()

            self._output_format  = 'standard'
            self._output_colour  = True
            self._cluster_enabled = False if cluster_off == True else True

            if not log_entries:
                raise ValueError("No log entries")
            
            self._df = pd.DataFrame(log_entries)
            self._df = self._df.fillna('')

            self._remove_dups()
            self._set_utc_time(time_offset)
        
            self._logger.info("[*] Counting repeat requests for source, ip, uri pairs.")
            count = self._df.groupby(
                [
                    'source',
                    'ip',
                    'method',
                    'request_uri', 
                ]
            ).size().reset_index(name='request_count')
               
            self._df = self._df.merge(count, 
                on=[
                    'source',                 
                    'ip',    
                    'method',             
                    'request_uri',      
                ], 
                how='left'
            )
            
            self._f_df = None

        except Exception as e:
            raise AccessLogDataFrameError(f"Failed to create dataframe: {str(e)}") from e

    @property
    def empty(self):
        return self._df.empty
    
    @property
    def df(self):
        return self._df
    
    @property
    def f_df(self):
        return self._f_df
    
    @property
    def output_format(self):
        return self._output_format
    @output_format.setter
    def output_format(self, value):
        if not isinstance(value, str):
            raise TypeError(f"Output format must be a string.")
        if value not in ('csv', 'standard'):
            raise ValueError("Output format must be either 'csv' or 'standard'.")
        self._output_format = value

    @property
    def output_colour(self):
        return self._output_colour
    @output_colour.setter
    def output_colour(self, value):
        if not isinstance(value, bool):
            raise TypeError(f"Output format must be either True or False.")
        self._output_colour = value

    @property
    def output_cluster(self):
        return self._output_cluster
    @output_cluster.setter
    def output_cluster(self, value):
        if not isinstance(value, bool):
            raise TypeError(f"Output cluster must be either True or False.")
        self._output_cluster = value        

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


    def from_dataframe(self, df):
        self._df = df        

    def _remove_dups(self):
        try:
            cols = ['timestamp', 'ip', 'method', 'request_uri', 'status', 'resp_size', 'user_agent', 'referrer']
            if not all(col in self._df for col in cols):
                raise ValueError(f"Missing required columns: {set(cols) - set(self._df.columns)}")
            if self._df[cols].isna().any(axis=None):
                raise ValueError(f"DataFrame contains at least one null value")
            
            df = self._df.copy()
            df['timestamp'] = df['timestamp'].astype(str).str.strip()

            for c_col in ['status', 'resp_size']:
                df[c_col] = pd.to_numeric(
                    df[c_col], 
                    errors='coerce'
                ).fillna(0).astype(int)

            for c_col in ['timestamp', 'ip', 'method', 'request_uri', 'user_agent', 'referrer']:
                df[c_col] = (
                    df[c_col]
                    .astype(str)
                    .str.strip()
                    .str.lower()
                    .str.replace(r'^"|"$', '', regex=True)
                    .replace('nan', '')
                )

            mask = df.duplicated(subset=cols, keep='first')
            groups = df.groupby(cols)['source'].nunique().reset_index()
            dup_groups = groups[groups['source'] > 1][cols]
            if not dup_groups.empty:
                merge_key = df[cols].merge(dup_groups, on=cols, how='inner').index
                dup_mask  = mask & df.index.isin(merge_key)
            else:
                dup_mask = pd.Series(False, index=df.index)
            num_dups = dup_mask.sum()
            if num_dups > 0:
                self._logger.info(f"[*] Removing {num_dups} duplicate entries.")
                self._df.drop(self._df[dup_mask].index, inplace=True)
            else:
                self._logger.debug("No duplicate rows found with differing 'source'")
        except Exception as e:
            raise AccessLogDataFrameError(f"Duplicate removal failed: {str(e)}") from e

    def _set_utc_time(self, time_offset):
        try:
            if self._df['timestamp'].isna().any():
                raise ValueError("timestamp contains null value")
            
            ts_pattern = r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s(?:[+-]\d{4}|UTC|[A-Za-z]+))'
            ts_invalid = self._df[~self._df['timestamp'].str.match(ts_pattern, na=False)]
            if not ts_invalid.empty:
                raise ValueError(f"Invalid timestamp format:\n{ts_invalid}")
            
            self._df['utc_timestamp'] = \
                pd.to_datetime(self._df['timestamp'], 
                format='%d/%b/%Y:%H:%M:%S %z', 
                utc=True, errors='coerce') + \
            pd.Timedelta(seconds=time_offset)

            if self._df['utc_timestamp'].isna().any():
                null_rows = self._df[self._df['utc_timestamp'].isna()]
                raise AccessLogDataFrameError(f"utc_timestamp contains null value: {null_rows}")
        except Exception as e:
           raise ValueError(f"Failed to convert timestamp: {str(e)}") from e
  
    def filter(
        self,
        start_time       = None,
        end_time         = None,
        risk_score       = 0, 
        request_count    = 0,
        status_ignore    = None, 
        status_include   = None, 
        method_include   = None,
        method_ignore    = None,
        uri_include      = None, 
        all_extension    = None,
        extension_ignore = None,
        ip_include       = None,
        ip_ignore        = None,
        ua_include       = None,
        ua_ignore        = None,
        ref_include      = None,
        ref_ignore       = None,
        min_size         = None,
        max_size         = None,
        tools_present    = False
    ):     
        try:
            
            self._logger.info("[*] Applying filters.")

            self._f_df = self.df.copy()
            mask = pd.Series(True, index=self._f_df.index)

            if self._f_df.isna().any(axis=None):
                raise ValueError("Dataframe contains at least one null value")
            if risk_score and (not isinstance(risk_score, float) or (risk_score < 0 or risk_score > 100)):
                raise ValueError(f"Bad risk score {risk_score}")
            if request_count and (not isinstance(request_count, int) or request_count < 0):
                raise ValueError(f"Bad request count: {request_count}")
            if min_size and (not isinstance(min_size, int) or min_size < 0):
                raise ValueError(f"Bad request count: {min_size}")
            if max_size and (not isinstance(max_size, int)):
                raise ValueError(f"Bad request count: {max_size}")
            if status_ignore and (not (isinstance(status_ignore, list) and all(isinstance(x, int) for x in status_ignore))):
                raise ValueError(f"Bad status ignore value: {status_ignore}")
            if status_include and (not (isinstance(status_include, list) and all(isinstance(x, int) for x in status_include))):
                raise ValueError(f"Bad status ignore value: {status_ignore}")
            try:
                if start_time:
                    s_time = pd.to_datetime(start_time, utc=True) 
                if end_time:
                    e_time = pd.to_datetime(end_time, utc=True)
            except ValueError as e:
                raise ValueError(f"Invalid format for {start_time} or {end_time}.")

            if start_time:
                mask &= self._f_df['utc_timestamp'] >= s_time
            if end_time:
                mask &= self._f_df['utc_timestamp'] <= e_time                
            if all_extension == False and extension_ignore:
                extension_ignore = tuple(extension_ignore)
                mask &= ~self._f_df['request_uri']\
                    .str.lower()\
                    .str.split('?')\
                    .str[0].str.endswith(extension_ignore, na=False)                                        
            if 'risk_score' in self._f_df.columns and risk_score > 0:
                mask &= self._f_df['risk_score'] >= risk_score
            if request_count > 0:
                mask &= self._f_df['request_count'] >= request_count
            if min_size:
                mask &= self._f_df['resp_size'] >= min_size
            if max_size:
                mask &= self._f_df['resp_size'] <= max_size
            if status_include:
                mask &= self._f_df['status'].isin(status_include)
            if status_ignore:
                mask &= ~self._f_df['status'].isin(status_ignore)
            if method_include:
                mask &= self._f_df['method'].isin(method_include)
            if method_ignore:
                mask &= ~self._f_df['method'].isin(method_ignore)                
            if uri_include:
                pattern = '|'.join(map(re.escape, uri_include))
                mask &= self._f_df['request_uri']\
                    .astype(str).str.contains(pattern, na=False, regex=True)
            if ip_include:
                networks = []
                for ip in ip_include:
                    networks.append(ipaddress.ip_network(ip, strict=False))
                mask &= self._f_df['ip'].apply(lambda x: self._filter_is_in_cidr(x, networks))
            if ip_ignore:
                networks = []
                for ip in ip_ignore:
                    networks.append(ipaddress.ip_network(ip, strict=False))
                mask &= ~self._f_df['ip'].apply(lambda x: self._filter_is_in_cidr(x, networks))
            if ua_include:
                pattern = '|'.join(map(re.escape, ua_include))
                mask &= self._f_df['user_agent'].astype(str).str.contains(pattern, na=False)
            if ua_ignore:
                pattern = '|'.join(map(re.escape, ua_ignore))
                mask &= ~self._f_df['user_agent'].astype(str).str.contains(pattern, na=False) 
            if ref_include:
                pattern = '|'.join(map(re.escape, ref_include))
                mask &= self._f_df['referrer'].astype(str).str.contains(pattern, na=False)
            if ref_ignore:
                pattern = '|'.join(map(re.escape, ref_ignore))
                mask &= ~self._f_df['referrer'].astype(str).str.contains(pattern, na=False)
            if tools_present:
                mask &= self._f_df.index.isin(self._f_df[self._f_df['tool'] != '']\
                    .groupby(['source', 'ip', 'tool'])['utc_timestamp']\
                    .agg([pd.Series.idxmin, pd.Series.idxmax]).stack())
                
            self._f_df = self._f_df[mask].sort_values(by=['source', 'utc_timestamp'])
        except Exception as e:
            raise AccessLogDataFrameError(f"Failed to apply filter to dataframe: {str(e)}") from e
    

    def _filter_is_in_cidr(self, ip_test, networks):
        try:
            ip = ipaddress.ip_address(ip_test)
            for network in networks:
                if ip in network:
                    return True
            return False
        except ValueError:
            return False   

#
# Output 
#

    def __str__(self): 
        try:
            if self._f_df.empty:
                return "<EMPTY>"
            if self.output_format == 'csv':
                return self._render_as_csv()
            else:
                return self._render_as_table()
        except Exception as e:
            raise AccessLogDataFrameError(f"Error during string conversion: {str(e)}") from e


    def _column_filter(self, max_rows=None):
        try:
            display_config = []
            df = self._f_df.copy()

            df['method_path'] = df.apply(lambda row: f"{row['method']} {row['request_uri']}", axis=1)
            df = df.drop(['method', 'request_uri'], axis=1)

            if self.output_format != 'csv':
                # Look for empty rows we can drop. Only applicable for 'terminal/standard' format.
                for entry in self.DISPLAY_CONFIG:
                    col_name, _, _, col_options = entry
                    if col_name == 'cluster' and self._cluster_enabled:
                        display_config.append(entry)
                        continue
                    if col_name == 'risk_score': 
                        display_config.append(entry)
                        continue
                    elif not col_options & self.OUTPUT_TERM:
                        self._logger.debug(f"Dropping column: {col_name} due to options: {col_options}.")
                        continue
                    elif df[col_name].eq(0).all():
                        self._logger.debug(f"Dropping column: {col_name} due to all 0 values.")
                        continue
                    elif df[col_name].isna().all():
                        self._logger.debug(f"Dropping column: {col_name} due to all NaN values.")
                        continue
                    elif (df[col_name] == '').all():
                        self._logger.debug(f"Dropping column: {col_name} due to empty values.")
                        continue
                    elif (df[col_name] == '-').all():
                        self._logger.debug(f"Dropping column: {col_name} due to all '-' values.")
                        continue
                    else:
                        display_config.append(entry)
            else:
                for entry in self.DISPLAY_CONFIG:
                    col_name, _, _, col_options = entry
                    if col_options & self.OUTPUT_CSV and col_name in df.columns:
                        display_config.append(entry)

            col_names = [col_name for col_name, _, _, _ in display_config]
            self._logger.debug(f"Selected columns names: {col_names}")

            self._f_df = df[col_names]
            return display_config

        except Exception as e:
            raise AccessLogDataFrameError(f"Error filtering output columns: {str(e)}") from e
        

    def _truncate_value(self, value, max_len, from_end=False):
            s_value = str(value) if pd.notna(value) else '-'
            
            if max_len is not None and max_len > 0 and len(s_value) > max_len:
                if max_len < 2:
                    return s_value[:max_len] if not from_end else s_value[-max_len:]
                if from_end:
                    return ".." + s_value[-(max_len - 2):]
                else:
                    return s_value[:max_len - 2] + ".." 
            return s_value
    
    def _wrap(self, value, width):
        return "\n".join(textwrap.wrap(value, width=width))

    def _truncate_values(self, df, display_config):
        try:
            for col_name, _, trunc_size, col_options in display_config:
                is_rev = bool(col_options & self.OUTPUT_TRUNC_REV)

                if col_options & self.OUTPUT_RISK_WRAP:
                    self._logger.debug(f"Wrapping or truncating {col_name} based on OUTPUT_RISK_WRAP_THRESHOLD.")
                    df[col_name] = df.apply(
                        lambda row: self._wrap(row[col_name], trunc_size)
                        if float(row['risk_score']) >= float(self.OUTPUT_RISK_WRAP_THRESHOLD)
                            else self._truncate_value(row[col_name], trunc_size, is_rev),axis=1)
                else:
                    self._logger.debug(f"Truncating {col_name} to {trunc_size}. Options: {col_options}")
                    df[col_name] = df[col_name].apply(
                        lambda x: self._truncate_value(x, trunc_size, is_rev))
            return df
        except Exception as e:
            raise AccessLogDataFrameError(f"Error during truncation of values: {str(e)}") from e
    
    def _render_as_table(self):
        try:

            if self._cluster_enabled:
                self._cluster()

            display_config = self._column_filter()
            if self._f_df.empty or display_config == None:
                ValueError("DataFrame or display config is empty")

            df = self._f_df

            headers = [col_label for _, col_label, _, _ in display_config]
            cols    = [col_name for col_name, _, _, _ in display_config]
            self._logger.debug(f"_render_as_table: header labels: {headers} columns: {cols}")
            
            df = self._truncate_values(df, display_config)
     
            table = PrettyTable()
            table.break_on_hyphens = False
           
            row_count = len(df)
            if row_count > 30000:
                print(f"[*] Processing {row_count} entries. This can take a short while to display.", flush=True)

            if self._cluster_enabled:
                prev_row = {'ip': None, 'source': None, 'cluster': None}

            for row in df.itertuples(index=True):
                idx = row.Index 

                if self._cluster_enabled:
                    is_new_cluster = (
                        row.ip      != prev_row['ip'] or
                        row.source  != prev_row['source'] or
                        row.cluster != prev_row['cluster']
                    )
                    prev_row['ip']      = row.ip
                    prev_row['source']  = row.source
                    prev_row['cluster'] = row.cluster                

                display_row = []
                for col_name, col_header, _, col_options in display_config:
                    if (col_options & self.OUTPUT_TERM):
                        val = df.loc[idx, col_name]
                        if col_name in ['risk_score']:
                            if   float(row.risk_score) >= 95:
                                    display_row.append(colored(str(val), 'white', 'on_red', attrs=["bold"], force_color = True))
                            elif float(row.risk_score) >= 90: 
                                    display_row.append(colored(str(val), 'red', force_color = True))
                            elif float(row.risk_score) >= 80: 
                                    display_row.append(colored(str(val), 'magenta', attrs=["bold"], force_color = True))
                            elif float(row.risk_score) >= 70: 
                                    display_row.append(colored(str(val), 'blue', attrs=["bold"], force_color = True))
                            elif float(row.risk_score) >= 60: 
                                    display_row.append(colored(str(val), 'cyan', attrs=["bold"], force_color = True))
                            else:
                                display_row.append(str(val))

                        elif self._cluster_enabled and is_new_cluster and col_name in ['source', 'timestamp', 'utc_timestamp', 'ip']:
                            display_row.append(colored(str(val), 'blue', attrs=["bold"], force_color = True))
                        else:
                            display_row.append(str(val))
                    else:
                        if col_header in headers:
                            headers.remove(col_header)

                if display_row is not None:
                    table.add_row(display_row)
    
            table.field_names = headers
            
            for field in table.field_names:
                table.align[field] = "l"

            if not len(table._rows):
                return '<EMPTY>' 
            else:
                return str(table)

        except Exception as e:
            raise AccessLogDataFrame(f"Issue rendering table: {str(e)}") from e
        
    def _render_as_csv(self):
        display_config = self._column_filter()
        self._f_df.sort_values(['source', 'utc_timestamp'])

        df = self._f_df
        if df.empty or display_config is None:
            raise ValueError("DataFrame or display config is empty")

        headers = []
        output_col_names = []
        for col_name, header, _, col_option in display_config:
            if col_option & self.OUTPUT_CSV:
                headers.append(header)
                output_col_names.append(col_name)

        output_lines = [','.join(headers)]

        for _, row in df.iterrows():
            values = [
                self._escape_csv_value(row.get(col))
                for col in output_col_names
            ]
            output_lines.append(','.join(str(v) for v in values))

        return '\n'.join(output_lines) + '\n'
    
    
    def _escape_csv_value(self, field):
        if field is None:
            return ''
        field = str(field)
        if any(c in field for c in [',', '"', '\n']):
            field = f'"{field.replace('"', '""')}"'
        return field
    

    def _cluster(self, threshold=300):
        try:
            if self._f_df is None or self._f_df.empty:
                self._logger.warning("DataFrame is empty, skipping clustering.")
                return self._f_df if self._f_df is not None else pd.DataFrame()

            self._logger.info(f"[*] Clustering {len(self._f_df)} records. Threshold X = {threshold}.")
            df = self._f_df.copy()
    
            req_cols  = ['source', 'ip', 'utc_timestamp', 'status']
            miss_cols = [col for col in req_cols if col not in df.columns]
            if miss_cols:
                raise ValueError(f"Missing required columns for clustering: {miss_cols}")

            mask = df['utc_timestamp'].notna()
            if not mask.all():
                raise ValueError(f"{(~mask).sum()} NaT values in 'utc_timestamp'")
            
            df['unix_timestamp'] = pd.NA 
            df.loc[mask, 'unix_timestamp'] = df.loc[mask, 'utc_timestamp'].astype(np.int64) // 1_000_000_000
            df['unix_timestamp'] = pd.to_numeric(df['unix_timestamp'], errors='coerce')

          
            df_diff = df.sort_values(['source', 'ip', 'unix_timestamp'])
            df['time_delta'] = df_diff.groupby(['source', 'ip'])['unix_timestamp'].diff().fillna(0)
           
            X = threshold
            try:
                status_code = pd.to_numeric(df['status'], errors='coerce').fillna(0)
            except Exception:
                raise ValueError("Could not convert 'status' to numeric")

            df['is_success'] = ((status_code == 200) | \
                               ((status_code >= 300) & (status_code < 400))).astype(int)
            
            df = df.sort_values(['source', 'ip', 'unix_timestamp']) 
            df['prev_is_success'] = df.groupby(['source', 'ip'], sort=False)['is_success'].shift(1).fillna(0)

            both_success = (df['is_success'] == 1) & (df['prev_is_success'] == 1)
            same_cluster = (df['time_delta'] < X) | \
                                        (both_success & (df['time_delta'] < 2 * X))
            df['new_cluster'] = (~same_cluster).astype(int)
            df['local_cluster'] = df.groupby(['source', 'ip'], sort=False)['new_cluster'].cumsum()
            
            cluster_strings = df['source'].astype(str) + "_" + \
                              df['ip'].astype(str) + "_" + \
                              df['local_cluster'].astype(str)
            
            df['cluster'] = pd.factorize(cluster_strings)[0] 
            
            cluster_min_timestamps = df.groupby('cluster')['unix_timestamp'].transform('min')
            df['final_cluster_min_timestamp'] = cluster_min_timestamps

            df = df.sort_values(
                by=['final_cluster_min_timestamp', 'cluster', 'unix_timestamp'],
                na_position='last'
            )
            
            cols_to_drop = ['unix_timestamp', 'final_cluster_min_timestamp', 'time_delta',
                            'new_cluster', 'prev_is_success', 'local_cluster', 'is_success']
            df = df.drop(columns=cols_to_drop, errors='ignore')
    
            self._logger.debug("Vectorised clustering complete. DataFrame ordered by earliest cluster timestamp.")
            
            self._f_df = df
            return df
        
        except ValueError as e:
            raise AccessLogDataFrameError(f"Validation error in clustering: {str(e)}") from e
        except Exception as e:
            raise AccessLogDataFrameError(f"Clustering failed: {str(e)}") from e
