#
# Proxy Service for Email API
# Copyright (C) 2023  Hee Shin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import base64
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from pyservice import ProtocolException
from pyservice.email import Headers, Message, MimeBody, Thread

import util
from proxy import Proxy


class Gmail:
    def __init__(self, proxy: Proxy) -> None:
        self.proxy = proxy

    def archive(self, thread_id: str) -> None:
        """
        Archives the given thread.

        Args:
            thread_id: The ID of the thread to archive.

        Raises:
            GmailException: If an error occurs while archiving the thread.
        """
        self.__archive_thread(thread_id)

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
        message = self.__create_message(
            thread_id, mailfrom, mailto, subject, body, reply_to=reply_to_message_id)
        self.__send_message(message)

    def next_thread(self, mailto: str) -> Optional[Thread]:
        """
        Retrieves all messages in the next thread, addressed to the
        given email (i.e., "mailto" address).

        :arg mailto: The email address to search for in the "to" field
                     of the messages.
        :type mailto: str
        :returns: A list of decoded messages in the next thread. Each
                  dictionary has a single key "body" whose value is a
                  string representing the decoded body of a message.
        :rtype: Optional[Thread]
        :raises GmailException: If an error occurs while searching for
                                messages in the Gmail API.
        :raises ProtocolException: If there is an unexpected content in
                                   a message payload.
        """
        query: str = "to:" + mailto
        if thread := self.__query_next_thread(query):
            thread.messages = [decode_mime_message(
                message) for message in thread.messages]
            return thread
        else:
            return None

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

    def __archive_thread(self, thread_id: str) -> None:
        self.proxy.archive_thread(thread_id)

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
            ProtocolException: If there is an unexpected content in a
            message payload.
        """
        results: Dict[str, Any] = self.proxy.query_messages(query)
        messages: List[Dict[str, str]] = results.get('messages', [])
        # Retrieve the message details for each matching message
        response: List[Message] = []
        for message in messages:
            msg: Dict[str, Any] = self.proxy.get_message(message['id'])
            payload: Dict[str, Any] = msg['payload']
            response.append(self.__read_message(payload))
        return response

    def __query_next_thread(self, query: str) -> Optional[Thread]:
        """
        Searches for MIME messages in the Gmail account that match the
        specified query.

        :param query: The search query to use.
        :type query: str
        :return: A list of messages in the thread that matches the
                 query.  "mime_body" in each dictionary contains the
                 base64-decoded plain text content of the message
                 body.  None if there was no match.
        :rtype: Optional[Thread]
        :raises ProtocolException: If there is an unexpected content
                                   in a message payload.
        """
        results: Dict[str, Any] = self.proxy.query_threads(query)

        try:
            if results['resultSizeEstimate'] > 0:
                # Get the first thread
                thread_id: str = results['threads'][0]['id']

                # Get the messages in the thread
                thread_messages: List[Message] = []
                thread: Dict[str, Any] = self.proxy.get_thread(thread_id)
                messages: List[Dict[str, Any]] = thread['messages']
                for message in messages:
                    if 'TRASH' not in message['labelIds']:
                        payload: Dict[str, Any] = message['payload']
                        thread_messages.append(self.__read_message(payload))
                return Thread(thread_id, thread_messages)
            else:
                return None
        except KeyError as error:
            raise ProtocolException(
                f'No key {error} or it has no value.', context=f"Response from Gmail API:\n{results}")

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
        elif content_type == 'multipart/mixed':
            return Gmail.__read_multipart_mixed(payload)
        else:
            tree = util.sprint_dictionary_keys(payload)
            raise ProtocolException(
                f'Unexpected MIME type {content_type} in message payload.',
                context=tree)

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

    def __send_message(self, message: Dict[str, str]) -> None:
        self.proxy.send_message(message)

    @staticmethod
    def __read_multipart_mixed(payload: Dict[str, Any]) -> Message:
        maybe_multipart_alternative = [
            part for part in payload['parts'] if part['mimeType'] == 'multipart/alternative']
        if len(maybe_multipart_alternative) > 0:
            multipart_alternative = maybe_multipart_alternative[0]
            assert isinstance(multipart_alternative, dict)
            multipart_alternative['headers'] += payload['headers']
            return Gmail.__read_multipart_alternative(multipart_alternative)
        else:
            raise ProtocolException(
                'text/alternative MIME part missing within text/mixed')

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
