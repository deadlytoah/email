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

class State(Enum):
    SENDING = 0
    RECEIVING = 1

class StateException(Exception):
    def __init__(self, state):
        self.state = state

def gmail_main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
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
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        if not labels:
            print('No labels found.')
            return
        print('Labels:')
        for label in labels:
            print(label['name'])

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')

def error(socket, message):
    socket.send_multipart([b"ERROR", message])

def list_commands():
    return list(COMMAND_MAP.keys())

COMMAND_MAP = {
    "help": list_commands,
}

def main():
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
            if command in COMMAND_MAP:
                response = COMMAND_MAP[command]()

                # Send the response back to the client
                if state == State.SENDING:
                    socket.send_multipart([b"OK"] + response)
                    state = State.RECEIVING
                else:
                    raise StateException(state)
            else:
                if state == State.SENDING:
                    error(socket, b"unknown command")
                    state = State.RECEIVING
                else:
                    raise StateException(state)
                response = nil

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
