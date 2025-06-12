#!/usr/bin/env python3

import argparse
from WebLogTriage import ConfigOptions, AccessLogParser, AccessLogDataFrame, AccessLogRisk
from utils import Email
import sys

def main():
    config = ConfigOptions()
    
    parser = argparse.ArgumentParser(
        description="A tool to analyse web server logs for suspicious activity.",
        epilog=("""
    Examples:\n
        triage.py --path WebLogs/ |less -R
        triage.py --path WebLogs/accesslog1.txt --risk-score 70 |less -R
        triage.py --path WebLogs/ --tool-focus --output-format csv
        triage.py --path WebLogs/ --method PUT --ip 192.168.1.1 10.10.10.0/24 --status 200 --output-format csv
        triage.py --path WebLogs/ --start-time "2025-04-21 18:23:00+10" --end-time "2025-04-21 18:24:00+10" --method POST --status 200
        triage.py --path WebLogs/ --uripath-keyword "upload" --time-offset 300 --request-count 1000
        triage.py --path WebLogs/host1* --ignore-status-code 200 404 500 302 400 403 401 301 --ignore-extension php js
        triage.py --path WebLogs --referrer fofa.info --ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/120.0" --email terry.schnitzel@gmail.com
    """),
    formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--path",
        type=str,
        nargs="+",
        help="Path to the log file or directory to analyse."
    )

    parser.add_argument(
        "--rules-path",
        type=str,
        default=config.rules_path,
        help="Path to user-defined rules file (rules.yaml)."
    )  

    parser.add_argument(
        "--time-offset",
        type=int,
        default=0,
        help="Time offset in seconds to adjust UTC time (positive to add, negative to subtract)."
    )
   
    parser.add_argument(
        "--tool-focus",
        action="store_true",
        help="Display entries identified as scanning tool related activity"
    )


    parser.add_argument(
        "--cluster-off",
        action="store_true",
        default=False,
        help="Sort by timestamp. Don't attempt to cluster results into sessions."
    )

    parser.add_argument(
        "-o", "--output-format",
        type=str,
        default='standard',
        help="Specify output format (e.g., csv). CSV format includes full data."
    )
    parser.add_argument(
        "--email",
        type=str,
        nargs="+",
        help="Enable email and specify recipients (e.g., terry.uppercut@gmail.com)."
    )

    parser.add_argument(
        "--start-time",
        type=str,
        default=None,
        help="Start time (e.g., '2025-05-11 10:00:00' or '2025-04-21 10:00+10:00')"
    )    
    parser.add_argument(
        "--end-time",
        type=str,
        default=None,
        help="End time (e.g., '2025-05-11 11:00:00' or '2025-04-21 11:00+10:00')"
    )    

    parser.add_argument(
        "-r", "--risk-score",
        type=float,
        default=0,
        help="Minimum risk score to include in results (float between 0 and 100)."
    )
    parser.add_argument(
        "--request-count",
        type=int,
        default=0,
        help="Reoccuring requests identical by IP and URI path matches are grouped together and counted. Provice the minimum number of recurring requests to include in output."
    )    
    
    parser.add_argument(
        "--status-code",
        type=int,
        nargs="+",
        help="Include results with these status codes (e.g., 403 401)."
    )

    parser.add_argument(
        "--ignore-status-code",
        type=int,
        nargs="+",
        help="Status codes to exclude from results (e.g., 200 404 500 for common codes)."
    )

    parser.add_argument(
        "--cluster-id",
        type=int,
        nargs="+",
        help="Cluster ID"
    )

    parser.add_argument(
        "--ignore-cluster-id",
        type=int,
        nargs="+",
        help="Cluster ID"
    )    

    parser.add_argument(
        "--min-size",
        type=int,
        help="Minimum response size (e.g., 91')"
    )

    parser.add_argument(
        "--max-size",
        type=int,
        help="Max response size (e.g., 91')"
    )    

    parser.add_argument(
        "--method",
        type=str,
        nargs="+",
        help="Include requests with these HTTP methods (e.g., GET POST)."
    )
    parser.add_argument(
        "--ignore-method",
        type=str,
        nargs="+",
        help="Status codes to exclude from results (e.g., 200 404 500 for common codes)."
    )

    parser.add_argument(
        "--all-extension",
        action="store_true",
        default=False,
        help="Include all file extensions."
    )  

    parser.add_argument(
        "--ignore-extension",
        type=str,
        nargs="+",
        default=config.ignore_extensions,
        help="File extensions to ignore (e.g., .js .css .jpg). By default common static file extensions are ignored."
    )  

    parser.add_argument(
        "--uripath-keyword",
        type=str,
        nargs="+",
        help="Keyword substring match in the request URI path (e.g., login password register)"
    )

    parser.add_argument(
        "--ignore-uripath-keyword",
        type=str,
        nargs="+",
        help="Keyword substring to ignore in the request URI path (e.g., boringpath)"
    )   

    parser.add_argument(
        "--ip",
        type=str,
        nargs="+",
        help="Include logs by IP address (e.g., 10.10.10.10 192.168.0.0/24)"
    )
    parser.add_argument(
        "--ignore-ip",
        type=str,
        default=config.ignore_ip,
        nargs="+",
        help="Ignore logs containing IP address (e.g., 10.10.10.10 192.168.0.0/24)"
    )
    parser.add_argument(
        "--ua",
        type=str,
        nargs="+",
        help="Include logs by user agent"
    )
    parser.add_argument(
        "--ignore-ua",
        type=str,
        nargs="+",
        help="Ignore logs containing user agent"
    ) 
    parser.add_argument(
        "--referrer",
        type=str,
        nargs="+",
        help="Include logs by referrer"
    )
    parser.add_argument(
        "--ignore-referrer",
        type=str,
        nargs="+",
        help="Ignore logs containing referrer."
    )     

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        log_parser = AccessLogParser()
        entries = log_parser.load_logfile(args.path)
        
        db = AccessLogDataFrame(entries, args.time_offset, args.cluster_off)
        db.output_format = args.output_format
        
        risk = AccessLogRisk(
            config.tool_signatures, 
            config.uri_risk_paths, 
            config.uri_risk_extensions,
            args.rules_path,
            config.webshell_path
        )

        df = db.df
        df = risk.balatro(df)
        df = risk.burp_intruder(df)
        df = risk.tool_scanner(df)
        db.from_dataframe(df)

       
        db.filter(
            args.start_time, args.end_time, 
            args.risk_score,
            args.request_count, 
            args.ignore_status_code, args.status_code, 
            args.method, args.ignore_method, 
            args.uripath_keyword, 
            args.all_extension, args.ignore_extension, 
            args.ip, args.ignore_ip, 
            args.ua, args.ignore_ua,
            args.referrer, args.ignore_referrer,
            args.min_size, args.max_size,
            args.tool_focus,
            args.cluster_id,
            args.ignore_cluster_id
        )

        if args.email:
            email = Email(
                args.email, 
                config.email_sender, 
                config.email_smtp_server, 
                config.email_smtp_port, 
            )
            
            db.output_format = 'csv'
            email.body(config.email_body)
            email.add_attachment('results.csv', str(db))
            email.send()
        
        else:
            print(db)

    except Exception as e:
        print(f"[-] Fatal Error (see errors.log): {str(e)}")


# main()
if __name__ == "__main__":
    main()