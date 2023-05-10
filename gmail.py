from __future__ import print_function

import base64
import os.path
import sys
import zmq

from enum import Enum
from google.auth.transport.requests import Request # type: ignore
from google.oauth2.credentials import Credentials # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow # type: ignore
from googleapiclient.discovery import build # type: ignore
from googleapiclient.errors import HttpError # type: ignore
from typing import Any, Dict, List

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

CLIENT_SECRETS_FILE = os.path.expanduser('~/.credentials/gmail.json')
TOKEN_FILE = os.path.expanduser('~/.credentials/gmail-token.json')

EMAIL_ADDRESS = "thevoicekorea+chat@gmail.com"

gmail = None

class ErrorCode(Enum):
    UNKNOWN_COMMAND = "ERROR_UNKNOWN_COMMAND"
    UNCATEGORISED = "ERROR_UNCATEGORISED"

class State(Enum):
    SENDING = 0
    RECEIVING = 1

class StateException(Exception):
    def __init__(self, state):
        self.state = state

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
                creds.refresh(Request())
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
        except HttpError as error:
            raise GmailException(error)

    def check(self, mailto: str) -> List[Dict[str, str]]:
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
        return [decode_mime_message(message) for message in self.query_messages(query)]

    def query_messages(self, query: str) -> List[Dict[str, str]]:
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
            ProtocolException: If there is an unexpected content in a
            message payload.
        """
        try:
            results: Dict[str, Any] = self.service.users().messages().list(
                userId='me', q=query).execute()
            messages: List[Dict[str, str]] = results.get('messages', [])
            # Retrieve the message details for each matching message
            response: List[Dict[str, str]] = []
            for message in messages:
                msg: Dict[str, Any] = self.service.users().messages().get(userId='me', id=message['id']).execute()
                payload: Dict[str, Any] = msg['payload']
                response.append(self.read_message(payload))
            return response
        except HttpError as error:
            raise GmailException(error)

    def read_message(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """
        Extracts the plain text content of the specified Gmail message
        payload.

        Args:
            payload (Dict): A dictionary representing the payload of a
            Gmail message.

        Returns:
            Dict[str, str]: A dictionary representing a
            message. "mime_body" contains the base64-decoded plain
            text content of the message body.

        Raises:
            ProtocolException: If there is no plain text MIME part in
            the message payload, or if the MIME part is empty.
        """
        message: Dict[str, str] = {}
        parts: List[Dict[str, Any]] = payload['parts']
        for part in parts:
            body: Dict[str, Any] = part['body']
            if body['size'] > 0:
                content_type: str = part['mimeType']
                if content_type == 'text/plain':
                    message['mime_body'] = body['data']
                    break
        if message.get('mime_body'):
            return message
        else:
            raise ProtocolException('text/plain MIME part is missing or empty')

def base64_string_decode(base64_text: str) -> str:
    """
    Decodes a base64 encoded string.

    Args:
        base64_text (str): The base64 encoded string.

    Returns:
        str: The decoded string.
    """
    return base64.urlsafe_b64decode(base64_text.encode('UTF-8')).decode('UTF-8')

def decode_mime_message(mime_message: Dict[str, str]) -> Dict[str, str]:
    """
    Decodes a MIME message and returns its body as a string.

    Args:
        mime_message (dict): Represents a MIME message, with
        'mime_body' containing the encoded body.

    Returns:
        message (dict): A dictionary with a key 'body' that
        contains the decoded body as a string.
    """
    mime_body: str = mime_message['mime_body']
    message: Dict[str, str] = {'body': base64_string_decode(mime_body)}
    return message

class GmailException(Exception):
    def __init__(self, inner):
        super().__init__(inner)

class ProtocolException(Exception):
    """
    An exception that indicates unexpected data format in Gmail API
    request or response.

    Attributes:
        message (str): The error message associated with the
        exception.
    """
    def __init__(self, message: str):
        """
        Initializes a new instance of the ProtocolException class.

        Args:
            message (str): The error message associated with the
            exception.
        """
        super(ProtocolException, self).__init__(message)

def ok(socket, array):
    socket.send_multipart([b"OK"] + [arg.encode() for arg in array])

def error(socket, code, message):
    socket.send_multipart([b"ERROR", code.value.encode(), message.encode()])

def list_commands():
    return list(command_map().keys())

def check():
    return [message['body'] for message in gmail.check(mailto=EMAIL_ADDRESS)]

def command_map():
    return {
        "check": check,
        "help": list_commands,
    }

def main():
    global gmail
    gmail = Gmail().authenticate()

    context = zmq.Context()

    # Create a socket for the server
    socket = context.socket(zmq.REP)
    socket.bind("tcp://*:0")

    # Print the port number to stdout
    port = socket.getsockopt(zmq.LAST_ENDPOINT).decode().rsplit(":", 1)[-1]
    print(port)

    state = State.RECEIVING

    while True:
        try:
            # Wait for a request from a client
            if state == State.RECEIVING:
                message = socket.recv_multipart()
                state = State.SENDING
            else:
                raise StateException(state)

            command = message[0].decode()
            arguments = [arg.decode() for arg in message[1:]]

            print("received command", command, file=sys.stderr)

            # Process the request
            if command in command_map():
                response = command_map()[command]()

                # Send the response back to the client
                if state == State.SENDING:
                    ok(socket, response)
                    state = State.RECEIVING
                else:
                    raise StateException(state)
            else:
                if state == State.SENDING:
                    error(socket, ErrorCode.UNKNOWN_COMMAND, "unknown command")
                    state = State.RECEIVING
                else:
                    raise StateException(state)

        except KeyboardInterrupt:
            break
        except StateException as e:
            print("Illegal state: ", e.state, file=sys.stderr)
            exit(1)
        except Exception as e:
            # Handle any errors that occur during processing
            error_response = str(e)
            if state == State.SENDING:
                error(socket, ErrorCode.UNCATEGORISED, error_response)
                state = State.RECEIVING
            else:
                print("Illegal state: ", state, file=sys.stderr)
                print("While trying to respond with error message: ", error_response, file=sys.stderr)

if __name__ == '__main__':
    main()
