from __future__ import print_function

import os.path
import zmq

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

CLIENT_SECRETS_FILE = os.path.expanduser('~/.credentials/gmail.json')
TOKEN_FILE = os.path.expanduser('~/.credentials/gmail-token.json')

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

def main():
    context = zmq.Context()

    # Create a socket for the server
    socket = context.socket(zmq.REP)
    socket.bind("tcp://*:0")

    # Print the port number to stdout
    port = socket.getsockopt(zmq.LAST_ENDPOINT).decode().rsplit(":", 1)[-1]
    print(port)

    while True:
        try:
            # Wait for a request from a client
            message = socket.recv_multipart()

            command = message[0].decode()
            arguments = [arg.decode() for arg in message[1:]]

            # Process the request
            if command == "error":
                raise ValueError("Invalid request")

            response = b"Hello, client!"

            # Send the response back to the client
            socket.send_multipart([b"OK", response])
        except KeyboardInterrupt:
            break
        except Exception as e:
            # Handle any errors that occur during processing
            error_response = str(e).encode()
            socket.send_multipart([b"ERROR", error_response])

if __name__ == '__main__':
    main()
