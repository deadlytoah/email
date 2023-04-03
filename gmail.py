from __future__ import print_function

import os.path
import sys
import zmq

from enum import Enum
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

CLIENT_SECRETS_FILE = os.path.expanduser('~/.credentials/gmail.json')
TOKEN_FILE = os.path.expanduser('~/.credentials/gmail-token.json')

EMAIL_ADDRESS = "thevoicekorea+chat@gmail.com"

gmail = None

class NoMessagesException(Exception):
    def __init__(self):
        super().__init__("no messages")

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

    def check(self, mailto):
        try:
            # Call the Gmail API to search for messages addressed to "mailto"
            query = "to:" + mailto
            results = self.service.users().messages().list(userId='me', q=query).execute()
            messages = results.get('messages', [])
            # Retrieve the message details for each matching message
            for message in messages:
                msg = self.service.users().messages().get(userId='me', id=message['id']).execute()
                # Process the message as needed
            return messages
        except HttpError as error:
            print("print error", error)
            print("print str(error)", str(error))
            raise GmailException(error)

class GmailException(Exception):
    def __init__(self, inner):
        super().__init__(inner)

def ok(socket, array):
    socket.send_multipart([b"OK"] + [arg.encode() for arg in array])

def error(socket, message):
    socket.send_multipart([b"ERROR", message])

def list_commands():
    return list(command_map().keys())

def check():
    messages = gmail.check(mailto=EMAIL_ADDRESS)
    if messages:
        return messages
    else:
        raise NoMessagesException()

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
                    error(socket, b"unknown command")
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
            error_response = str(e).encode()
            if state == State.SENDING:
                error(socket, error_response)
                state = State.RECEIVING
            else:
                print("Illegal state: ", state, file=sys.stderr)
                print("While trying to respond with error message: ", error_response, file=sys.stderr)

if __name__ == '__main__':
    main()
