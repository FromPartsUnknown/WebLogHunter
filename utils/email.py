import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
   
class Email():
    def __init__(
        self,
        recipients,
        sender,
        smtp_server,
        smtp_port=25, 
        body=None,
    ):

        if not recipients:
            raise ValueError("Email requires recipient(s) to be provided")
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

        self._smtp_server = smtp_server
        self._smtp_port = smtp_port
        self._sender = sender
        self._recipients = recipients

        self._msg = MIMEMultipart()
        self._msg['From'] = self._sender
        self._msg['To'] = ', '.join(self._recipients)
        self._msg['Subject'] = f'WeblogHunter Report: {timestamp}'

        if body:
            self.body(body)
        
        
    def add_attachment(self, filename, content):
        attachment = MIMEBase('application', 'octet-stream')   
        attachment.set_payload(content.encode('utf-8'))
        encoders.encode_base64(attachment)
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        if not filename:
            filename = f"access_log_{timestamp}.csv"
        attachment.add_header(
            'Content-Disposition',
            f'attachment; filename={filename}'
        )
        self._msg.attach(attachment)

    def body(self, value):
        self._body = value
        self._msg.attach(MIMEText(self._body, 'plain'))

    def send(self):
        try:
            with smtplib.SMTP(self._smtp_server, self._smtp_port) as server:
                server.sendmail(self._sender, self._recipients, self._msg.as_string())
                print(f"Email sent successfully to {', '.join(self._recipients)}.")
        except smtplib.SMTPException as e:
            raise smtplib.SMTPException(f"Failed to send email: {str(e)}")
        except Exception as e:
            raise ValueError(f"Email sending error: {str(e)}")    
