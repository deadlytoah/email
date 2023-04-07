from __future__ import print_function

import base64
import json
import os.path
import subprocess
import sys
import zmq

from dataclasses import dataclass
from enum import Enum
from google.auth.exceptions import RefreshError # type: ignore
from google.auth.transport.requests import Request # type: ignore
from google.oauth2.credentials import Credentials # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow # type: ignore
from googleapiclient.discovery import build # type: ignore
from googleapiclient.errors import HttpError # type: ignore
from typing import Any, Callable, Dict, List, Optional, Union

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

CLIENT_SECRETS_FILE = os.path.expanduser('~/.credentials/gmail.json')
TOKEN_FILE = os.path.expanduser('~/.credentials/gmail-token.json')

EMAIL_ADDRESS = "thevoicekorea+chat@gmail.com"

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

    def next_thread(self, mailto: str) -> List[Dict[str, str]]:
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
        return [decode_mime_message(message) for message in self.query_next_thread(query)]

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

    def query_next_thread(self, query: str) -> List[Dict[str, str]]:
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
                userId='me', q=query).execute()

            # Get the first thread
            if 'threads' in results and results['threads']:
                thread_id: int = results['threads'][0]['id']

                # Get the messages in the thread
                thread_messages: List[Dict[str, str]] = []
                thread: Dict[str, Any] = self.service.users().threads().get(userId='me', id=thread_id).execute()
                messages: List[Dict[str, Any]] = thread.get('messages', [])
                for message in messages:
                    payload: Dict[str, Any] = message.get('payload', [])
                    thread_messages.append(self.read_message(payload))
                return thread_messages
            else:
                raise ProtocolException('No threads key or it has no value.')
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

gmail: Gmail = Gmail()

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
    An exception that indicates unexpected data format in the external API
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

class UnknownCommandException(Exception):
    """
    Indicates the given command is invalid.
    """
    def __init__(self, command):
        super(UnknownCommandException, self).__init__(f'unknown command {command}')
        self.command = command

class Timeout(Enum):
    DEFAULT = 300
    LONG = 3000

@dataclass
class Metadata:
    name: str
    description: str
    timeout: Timeout
    arguments: str
    returns: str
    errors: str

    def to_dictionary(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'timeout': self.timeout.value,
            'arguments': self.arguments,
            'returns': self.returns,
            'errors': self.errors
        }

def ok(socket, array):
    socket.send_multipart([b"OK"] + [arg.encode() for arg in array])

def error(socket, code, message):
    socket.send_multipart([b"ERROR", code.value.encode(), message.encode()])

def list_commands(arguments: List[str]) -> List[str]:
    return list(command_map().keys())

def help_screen(arguments: List[str]) -> List[str]:
    response: List[str] = []
    for command, command_info in command_map().items():
        metadata = command_info.get('metadata')
        if metadata and isinstance(metadata, Metadata):
            help_string = f'**{command}**\\\n'
            help_string += f'{metadata.description}\\\n'
            if metadata.timeout.value > 300:
                help_string += 'Can take a long time to run.\\\n'
            help_string += '\\\n**Arguments**\\\n'
            help_string += f'{metadata.arguments}\\\n\\\n'
            help_string += '**Returns**\\\n'
            help_string += f'{metadata.returns}\\\n\\\n'
            help_string += '**Errors**\\\n'
            help_string += metadata.errors
            response.append(help_string)
        else:
            raise RuntimeError(f'metadata missing or invalid for {command}')
    return response

def metadata(arguments: List[str]) -> List[str]:
    """
    Retrieves metadata for specified service functions.

    Args:
        arguments: A list of names of the service functions to
        retrieve metadata for.

    Returns:
        A list of metadata for the specified service functions, as a
        JSON-encoded string.

    Raises:
        ValueError: arguments are empty.
        RuntimeError: metadata is missing.
    """
    if len(arguments) > 0:
        return [json.dumps(__metadata_impl(command).to_dictionary()) for command in arguments]
    else:
        raise ValueError("Expected one or more commands as arguments")

def __metadata_impl(function_name: str) -> Metadata:
    command = command_map().get(function_name)
    if command:
        metadata = command.get('metadata')
        if metadata and isinstance(metadata, Metadata):
            return metadata
        else:
            raise RuntimeError(f'metadata missing for {function_name}')
    else:
        raise UnknownCommandException(command)

def check(arguments: List[str]) -> List[str]:
    global gmail
    return [message['body'] for message in gmail.check(mailto=EMAIL_ADDRESS)]

def thread(arguments: List[str]) -> List[str]:
    global gmail
    return [message['body'] for message in gmail.next_thread(mailto=EMAIL_ADDRESS)]

def command_map() -> Dict[str, Dict[str, Union[Callable[[List[str]], List[str]], Metadata]]]:
    return {
        "help": {
            'handler': help_screen,
            'metadata': Metadata('help',
                                 'Describes available service commands.',
                                 Timeout.DEFAULT,
                                 'None',
                                 'A list of strings describing the available service commands.',
                                 '*RuntimeError* - metadata is missing or invalid.'),
        },
        "metadata": {
            'handler': metadata,
            'metadata': Metadata('metadata',
                                 'Describes the given command.',
                                 Timeout.DEFAULT,
                                 'A list of commands to describe.',
                                 'A list of metadata for the commmands in JSON',
                                 '''*ValueError* - arguments are empty.\\
                                    *RuntimeError* - metadata is missing.'''),
        },
        "check": {
            'handler': check,
            'metadata': Metadata('check',
                                'Retrieves messages in INBOX.',
                                Timeout.DEFAULT,
                                'None',
                                'A list of strings containing the decoded body of the messages.',
                                '''*GmailException* - If an error occurs while searching for
                                    messages in the Gmail API.\\
                                    *ProtocolException* - If there is an unexpected content in a
                                    message payload.'''),
        },
        "thread": {
            'handler': thread,
            'metadata': Metadata('thread',
                                 'Retrieves messages in the first thread.',
                                 Timeout.DEFAULT,
                                 'None',
                                 'A list of decoded messages in the first thread.',
                                 '''*GmailException* - If an error occurs while searching for
                                    messages in the Gmail API.\\
                                    *ProtocolException* - If there is an unexpected content in a
                                    message payload.'''),
        },
        # "send": send,
    }

def main() -> None:
    global gmail
    gmail.authenticate()

    context: zmq.Context = zmq.Context()

    # Create a socket for the server
    socket: zmq.Socket = context.socket(zmq.REP)
    socket.bind("tcp://*:0")

    # Print the port number to stdout
    port_bytes = socket.getsockopt(zmq.LAST_ENDPOINT)
    assert(isinstance(port_bytes, bytes))
    port: str = port_bytes.decode().rsplit(":", 1)[-1]
    print(port)
    subprocess.call(f'/bin/echo -n {port} | pbcopy', shell=True)

    state: State = State.RECEIVING

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
            command_info = command_map().get(command)
            if command_info:
                handler = command_info.get('handler')
                if handler and callable(handler):
                    response = handler(arguments)

                    # Send the response back to the client
                    if state == State.SENDING:
                        ok(socket, response)
                        state = State.RECEIVING
                    else:
                        raise StateException(state)
                else:
                    raise RuntimeError(f'handler missing or not valid for {command}')
            else:
                raise UnknownCommandException(f'unknown command {command}')

        except KeyboardInterrupt:
            break
        except StateException as e:
            print("Illegal state: ", e.state, file=sys.stderr)
            exit(1)
        except UnknownCommandException as e:
            error_response = str(e)
            if state == State.SENDING:
                error(socket, ErrorCode.UNKNOWN_COMMAND, "unknown command")
                state = State.RECEIVING
            else:
                print("Illegal state: ", state, file=sys.stderr)
                print("While trying to respond with error message: ", error_response, file=sys.stderr)
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
