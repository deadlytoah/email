import base64
import os.path
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from google.auth.exceptions import RefreshError  # type: ignore
from google.auth.transport.requests import Request  # type: ignore
from google.oauth2.credentials import Credentials  # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore
from googleapiclient.discovery import build  # type: ignore
from googleapiclient.errors import HttpError  # type: ignore

from pyservice import ProtocolException
from pyservice.email import Headers, Message, MimeBody, Thread

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.compose',
          'https://www.googleapis.com/auth/gmail.modify']

CLIENT_SECRETS_FILE = os.path.expanduser('~/.credentials/gmail.json')
TOKEN_FILE = os.path.expanduser('~/.credentials/gmail-token.json')


class Gmail:
    def authenticate(self):
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
        except HttpError as error:
            raise GmailException(error)

    def archive(self, thread_id: str) -> None:
        """
        Archives the given thread.

        Args:
            thread_id: The ID of the thread to archive.

        Raises:
            GmailException: If an error occurs while archiving the thread.
        """
        try:
            self.service.users().threads().modify(
                userId="me", id=thread_id, body={"removeLabelIds": ["INBOX"]}).execute()
        except HttpError as error:
            raise GmailException(error)

    def reply(self, thread_id: str, reply_to_message_id: str, mailfrom: str, mailto: str, subject: str, body: str) -> None:
        """
        Replies to the given thread.

        Args:
            mailto: The email address to send the message to.
            subject: The subject of the email.
            body: The body of the email.

        Raises:
            GmailException: If an error occurs while sending the email.
        """
        try:
            message = self.__create_message(
                thread_id, mailfrom, mailto, subject, body, reply_to=reply_to_message_id)
            self.service.users().messages().send(userId="me", body=message).execute()
        except HttpError as error:
            raise GmailException(error)

    def next_thread(self, mailto: str) -> Thread:
        """
        Retrieves all messages in the next thread, addressed to the
        given email (i.e., "mailto" address).

        Args:
            mailto: A string specifying the email address to search
            for in the "to" field of the messages.

        Returns:
            A list of decoded messages in the next thread. Each
            dictionary has a single key "body" whose value is a string
            representing the decoded body of a message.

        Raises:
            GmailException: If an error occurs while searching for
            messages in the Gmail API.
            ProtocolException: If there is an unexpected content in a
            message payload.
        """
        query: str = "to:" + mailto
        thread = self.query_next_thread(query)
        thread.messages = [decode_mime_message(
            message) for message in thread.messages]
        return thread

    def check(self, mailto: str) -> List[Message]:
        """
        Searches for messages addressed to the specified email address
        and returns their decoded content.

        Args:
            mailto (str): The email address to search for in the "To"
            field of the messages.

        Returns:
            List[Dict[str, str]]: A list of dictionaries representing
            the messages found. "body" key in each dictionary contains
            the decoded content of the message body.

        Raises:
            GmailException: If an error occurs while searching for
            messages in the Gmail API.
            ProtocolException: If there is an unexpected content in a
            message payload.
        """
        query: str = "to:" + mailto
        return [decode_mime_message(message) for message in self.__query_messages(query)]

    def __query_messages(self, query: str) -> List[Message]:
        """
        Searches for MIME messages in the Gmail account that match the
        specified query.

        Args:
            query (str): The search query to use when searching for
            messages.

        Returns:
            List[Message]: A list of messages found.  Each message
            contains the base64-decoded plain text content of the
            message body.

        Raises:
            GmailException: If an error occurs while searching for
            messages in the Gmail API.
            ProtocolException: If there is an unexpected content in a
            message payload.
        """
        try:
            results: Dict[str, Any] = self.service.users().messages().list(
                userId='me', q=query).execute()
            messages: List[Dict[str, str]] = results.get('messages', [])
            # Retrieve the message details for each matching message
            response: List[Message] = []
            for message in messages:
                msg: Dict[str, Any] = self.service.users().messages().get(
                    userId='me', id=message['id']).execute()
                payload: Dict[str, Any] = msg['payload']
                response.append(self.__read_message(payload))
            return response
        except HttpError as error:
            raise GmailException(error)

    def query_next_thread(self, query: str) -> Thread:
        """
        Searches for MIME messages in the Gmail account that match the
        specified query.

        Args:
            query (str): The search query to use when searching for
            messages.

        Returns:
            List[Dict[str, str]]: A list of dictionaries representing
            the messages found.  "mime_body" in each dictionary
            contains the base64-decoded plain text content of the
            message body.

        Raises:
            GmailException: If an error occurs while searching for
            messages in the Gmail API.
            ProtocolException: If there is an unexpected content a
            message payload.
        """
        try:
            results: Dict[str, Any] = self.service.users().threads().list(
                userId='me', q=query + ' label:inbox', maxResults=1).execute()

            # Get the first thread
            if results['threads']:
                thread_id: str = results['threads'][0]['id']

                # Get the messages in the thread
                thread_messages: List[Message] = []
                thread: Dict[str, Any] = self.service.users().threads().get(
                    userId='me', id=thread_id).execute()
                messages: List[Dict[str, Any]] = thread['messages']
                for message in messages:
                    if 'TRASH' not in message['labelIds']:
                        payload: Dict[str, Any] = message['payload']
                        thread_messages.append(self.__read_message(payload))
                return Thread(thread_id, thread_messages)
            else:
                raise ProtocolException('No threads key or it has no value.')
        except KeyError as error:
            raise ProtocolException(f'No key {error} or it has no value.')
        except HttpError as error:
            raise GmailException(error)

    def __read_message(self, payload: Dict[str, Any]) -> Message:
        """
        Extracts the plain text content of the specified Gmail message
        payload.

        Args:
            payload (Dict): A dictionary representing the payload of a
            Gmail message.

        Returns:
            Message: The message containing the base64-encoded plain
            text content of the message body.

        Raises:
            ProtocolException: If there is no plain text MIME part in
            the message payload, or if the MIME part is empty.
        """
        content_type = payload['mimeType']
        if content_type == 'text/plain':
            return Gmail.__read_plaintext(payload)
        elif content_type == 'multipart/alternative':
            return Gmail.__read_multipart_alternative(payload)
        else:
            raise ProtocolException(
                f'Unexpected MIME type {content_type} in message payload.')

    def __create_message(self, thread_id: str, sender: str, to: str, subject: str, message_text: str, reply_to: Optional[str] = None) -> Dict[str, str]:
        """
        Creates a message for an email.

        Args:
            sender (str): Email address of the sender.
            to (str): Email address of the receiver.
            subject (str): The subject of the email message.
            message_text (str): The text of the email message.
            reply_to (str): The message ID of the original email
                            message, found in the "Message-ID" header.

        Returns:
            Dict[str, str]: A dictionary containing a base64url encoded
            email object.
        """
        message: EmailMessage = EmailMessage()
        message.set_content(message_text)
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject
        if reply_to is not None:
            message['In-Reply-To'] = reply_to
            message['References'] = reply_to
        raw_message: bytes = base64.urlsafe_b64encode(message.as_bytes())
        return {'raw': raw_message.decode(),
                'threadId': thread_id}

    @staticmethod
    def __read_multipart_alternative(payload: Dict[str, Any]) -> Message:
        message: Optional[Message] = None
        parts: List[Dict[str, Any]] = payload['parts']
        for part in parts:
            body: Dict[str, Any] = part['body']
            if body['size'] > 0:
                content_type: str = part['mimeType']
                if content_type == 'text/plain':
                    headers = Headers.from_email_headers(payload['headers'])
                    message = Message(headers, body=MimeBody(content_type=content_type,
                                                             content=body['data']))
                    break
        if message is not None:
            return message
        else:
            raise ProtocolException('text/plain MIME part is missing or empty')

    @staticmethod
    def __read_plaintext(payload: Dict[str, Any]) -> Message:
        body: Dict[str, Any] = payload['body']
        data: str
        if body['size'] > 0:
            data = body['data']
        else:
            data = ''
        headers = payload['headers']
        return Message(Headers.from_email_headers(headers),
                       body=MimeBody(content_type='text/plain',
                                     content=data))


def base64_string_decode(base64_text: str) -> str:
    """
    Decodes a base64 encoded string.

    Args:
        base64_text (str): The base64 encoded string.

    Returns:
        str: The decoded string.
    """
    return base64.urlsafe_b64decode(base64_text.encode('UTF-8')).decode('UTF-8')


def decode_mime_message(message: Message) -> Message:
    """
    Decodes a MIME message and returns the decoded message.

    Args:
        message (Message): Represents a MIME message.

    Returns:
        message (Message): A new message that contains the decoded
        body as a string.

    Raises:
        ValueError: If the message is not a MIME message.
    """
    return Message(message.headers, base64_string_decode(message.get_body_mime().content))


class GmailException(Exception):
    """
    Represents an exception that occurred while interacting with the
    Gmail API.

    :param inner: The inner exception.
    :type inner: Exception
    """

    def __init__(self, inner: Exception):
        super(GmailException, self).__init__(inner)
