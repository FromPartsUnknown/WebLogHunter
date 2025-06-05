import yaml

class ConfigOptionsError(Exception):
    pass

class ConfigOptions:
    def __init__(self, file_path='config.yaml'):
        self.from_file(file_path)

    def from_file(self, yaml_file):
        try:
            try:
                with open(yaml_file, 'r') as fp:
                    config_data = yaml.safe_load(fp)
            except yaml.YAMLError as e:
                raise ConfigOptionsError(f"Invalid yaml configuration {yaml_file}: {str(e)}") from e
            
            self.rules_path    = config_data.get('rules_path', str)
            self.webshell_path = config_data.get('rules_path', str)

            self.ignore_extensions = \
                tuple(config_data.get('ignore_extensions', []))
            
            self.ignore_ip = tuple(config_data.get('ignore_ip', []))

            email_config = config_data.get('email', {})
            self.email_sender = email_config.get('sender', '')
            self.email_smtp_server = email_config.get('smtp_server', '')
            self.email_smtp_port = email_config.get('smtp_port', 25)
            self.email_body = email_config.get('body', '')
            
            self.tool_signatures = config_data.get('tool_signatures', [])
            required_keys = {'keyword', 'time_window'}
            for tool_name in self.tool_signatures:
                if not required_keys.issubset(tool_name):
                    raise ValueError(f"Missing required configuration keys: {required_keys - set(config_data)}")
                tool_name['keyword'] = tuple(tool_name.get('keyword', []))


            uri_risk_config = config_data.get('uri_risk', {})
            self.uri_risk_paths = uri_risk_config.get('sensitive_paths', [])
          
            self.uri_risk_extensions = []
            for ext in uri_risk_config.get('sensitive_extensions', []):
                self.uri_risk_extensions.append(rf'\.{ext.lstrip(".")}')
                
        except Exception as e:
            raise ConfigOptionsError(f"ConfigOptions: error: {str(e)}") from e