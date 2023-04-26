# If modifying these scopes, delete the file token.json.
import os
from enum import Enum
from ssl import SSLEOFError
from typing import Any, Dict

from google.auth.exceptions import RefreshError  # type: ignore
from google.auth.transport.requests import Request  # type: ignore
from google.oauth2.credentials import Credentials  # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore
from googleapiclient.discovery import build  # type: ignore
from googleapiclient.errors import HttpError  # type: ignore

from pyservice import FatalServiceError, ServiceException

SCOPES = ['https://www.googleapis.com/auth/gmail.compose',
          'https://www.googleapis.com/auth/gmail.modify']

CLIENT_SECRETS_FILE = os.path.expanduser('~/.credentials/gmail.json')
TOKEN_FILE = os.path.expanduser('~/.credentials/gmail-token.json')


class GmailErrorCode(Enum):
    """
    Represents an error code that occurred while interacting with the
    Gmail API.
    """

    Gmail = "ERROR_GMAIL"


class GmailException(ServiceException):
    """
    Represents an exception that occurred while interacting with the
    Gmail API.

    :param inner: The inner exception.
    :type inner: Exception
    """

    def __init__(self, inner: Exception):
        super(GmailException, self).__init__(GmailErrorCode.Gmail, str(inner))


class Proxy:
    """
    A proxy to the Gmail API.
    """

    def authenticate(self) -> 'Proxy':
        """
        Authenticates to the Gmail API.

        :returns: The proxy to the Gmail API.
        :rtype: Proxy
        """
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        CLIENT_SECRETS_FILE, SCOPES)
                    creds = flow.run_local_server(port=0)
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    CLIENT_SECRETS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())

        try:
            # Call the Gmail API
            self.service = build('gmail', 'v1', credentials=creds)
            return self
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)

    def archive_thread(self, thread_id: str) -> None:
        """
        Archives the given thread.

        :param thread_id: The ID of the thread to archive.
        :type thread_id: str
        :raises GmailException: If an error occurs while archiving the thread.
        """
        try:
            self.service.users().threads().modify(userId="me", id=thread_id,
                                                  body={"removeLabelIds": ["INBOX"]}).execute()
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)

    def query_messages(self, query: str) -> Dict[str, Any]:
        """
        Queries the Gmail API for messages matching the given query in INBOX.

        :param query: The query to use.
        :type query: str
        :returns: The messages matching the query.
        :rtype: Dict[str, Any]
        :raises GmailException: If an error occurs while querying the messages.
        """
        try:
            return self.service.users().messages().list(userId='me', q=query + ' label:inbox').execute()
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)

    def get_message(self, message_id: str) -> Dict[str, Any]:
        """
        Gets the message with the given ID.

        :param message_id: The ID of the message to get.
        :type message_id: str
        :returns: The message with the given ID.
        :rtype: Dict[str, Any]
        :raises GmailException: If an error occurs while getting the message.
        """
        try:
            return self.service.users().messages().get(userId='me', id=message_id).execute()
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)

    def query_threads(self, query: str) -> Dict[str, Any]:
        """
        Queries the Gmail API for threads matching the given query in INBOX.

        :param query: The query to use.
        :type query: str
        :returns: The threads matching the query.
        :rtype: Dict[str, Any]
        :raises GmailException: If an error occurs while querying the threads.
        """
        try:
            return self.service.users().threads().list(userId='me', q=query + ' label:inbox', maxResults=1).execute()
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)

    def get_thread(self, thread_id: str) -> Dict[str, Any]:
        """
        Gets the thread with the given ID.

        :param thread_id: The ID of the thread to get.
        :type thread_id: str
        :returns: The thread with the given ID.
        :rtype: Dict[str, Any]
        :raises GmailException: If an error occurs while getting the thread.
        """
        try:
            return self.service.users().threads().get(userId='me', id=thread_id).execute()
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)

    def send_message(self, message: Dict[str, str]):
        """
        Forwards the given structure containing a message to Gmail API for
        sending.

        :param message: The message to send.
        :type message: Dict[str, str]
        :raises GmailException: If an error occurs while sending the message.
        """
        try:
            self.service.users().messages().send(userId="me", body=message).execute()
        except SSLEOFError as error:
            raise FatalServiceError(str(error))
        except HttpError as error:
            raise GmailException(error)
