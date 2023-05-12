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

import argparse
import asyncio
import json
from typing import List, Optional

from gmail import Gmail
from proxy import Proxy
from pyservice import Metadata, Service, Timeout
from pyservice.metadata import Argument, Arguments

EMAIL_ADDRESS = "thevoicekorea+chat@gmail.com"


class GmailService(Service):
    """
    A service that provides access to Gmail.

    :param gmail: The proxy to the Gmail API.
    :type gmail: Gmail
    """

    def __init__(self, gmail: Gmail):
        super(GmailService, self).__init__()
        self.gmail = gmail
        self.__register_service_commands()

    def __register_service_commands(self: 'GmailService') -> None:
        self.register_command(
            'check',
            self.check,
            Metadata(
                name='check',
                description='Retrieves messages in INBOX.',
                timeout=Timeout.LONG,
                arguments=Arguments.none(),
                returns='A list of strings containing the decoded body of the messages.',
                errors='''*GmailException* - If an error occurs while searching for
                            messages in the Gmail API.\\
                            *ProtocolException* - If there is an unexpected content in a
                            message payload.'''))
        self.register_command(
            'thread',
            self.thread,
            Metadata(
                name='thread',
                description='Retrieves messages in the first thread.',
                timeout=Timeout.LONG,
                arguments=Arguments.none(),
                returns='''A list of decoded messages in the first thread.  The first
                            element is the thread ID.  The remaining elements are the
                            messages in the thread.  Each message is an alternating pair
                            of a JSON string containing the message headers and the decoded
                            message body.''',
                errors='''*GmailException* - If an error occurs while searching for
                            messages in the Gmail API.\\
                            *ProtocolException* - If there is an unexpected content in a
                            message payload.'''))
        self.register_command(
            'reply',
            self.reply,
            Metadata(
                name='reply',
                description='Replies to a thread.',
                timeout=Timeout.LONG,
                arguments=Arguments(
                    Argument('Thread ID', 'ID of the thread to reply to.'),
                    Argument('Original Message ID',
                             'ID of the message to reply to.'),
                    Argument('Sender', 'Email address of the sender.'),
                    Argument('Subject', 'The subject of the email message.'),
                    Argument('Body', 'The text of the email message.')
                ),
                returns='None',
                errors='''*GmailException* - If an error occurs while searching for
                        messages in the Gmail API.'''))
        self.register_command(
            'archive',
            self.archive,
            Metadata(
                name='archive',
                description='Archives a thread.',
                timeout=Timeout.LONG,
                arguments=Arguments(
                    Argument('Thread ID', 'ID of the thread to archive.')),
                returns='None',
                errors='''*GmailException* - If an error occurs while searching for
                        messages in the Gmail API.'''))

    def name(self) -> str:
        return f"Gmail Service [{EMAIL_ADDRESS}]"

    def description(self) -> str:
        return f"Provides access to the Gmail account: {EMAIL_ADDRESS}"

    def check(self, arguments: List[str]) -> List[str]:
        """
        Retrieves messages in INBOX.

        :param arguments: The arguments to the command.
        :type arguments: List[str]
        :return: A list of strings containing the decoded body of the
                 messages.
        :rtype: List[str]
        :raises GmailException: If an error occurs while searching for
                                messages in the Gmail API.
        """
        return [message.get_body_str() for message in self.gmail.check(mailto=EMAIL_ADDRESS)]

    def thread(self, arguments: List[str]) -> List[str]:
        """
        Retrieves messages in the first thread the server returns.

        :param arguments: The arguments to the command.
        :type arguments: List[str]
        :return: A list of decoded messages in the first thread.  The first
                 element is the thread ID.  The remaining elements are the
                 messages in the thread.  Each message is an alternating pair
                 of a JSON string containing the message headers and the
                 decoded message body.  Returns an empty list if there are no
                 threads to return.
        :rtype: List[str]
        :raises GmailException: If an error occurs while searching for
                                messages in the Gmail API.
        :raises ProtocolException: If there is an unexpected content in a
                                   message payload.
        """
        if thread := self.gmail.next_thread(mailto=EMAIL_ADDRESS):
            response = [thread.id]
            for message in thread.messages:
                response.append(json.dumps(
                    message.headers, ensure_ascii=False))
                response.append(message.get_body_str())
            return response
        else:
            return []

    def reply(self, arguments: List[str]) -> List[str]:
        """
        Replies to the given thread.

        :param arguments: The arguments to the command.
        :type arguments: List[str]
        :return: An empty list.
        :rtype: List[str]
        :raises GmailException: If an error occurs while searching for
                                messages in the Gmail API.
        :raises ValueError: If the number of arguments is not 5.
        """
        if len(arguments) == 5:
            self.gmail.reply(thread_id=arguments[0], reply_to_message_id=arguments[1],
                             mailfrom=EMAIL_ADDRESS, mailto=arguments[2], subject=arguments[3], body=arguments[4])
            return []
        else:
            raise ValueError('reply requires 5 arguments')

    def archive(self, arguments: List[str]) -> List[str]:
        """
        Archives the given thread.

        :param arguments: The arguments to the command.
        :type arguments: List[str]
        :return: An empty list.
        :rtype: List[str]
        :raises GmailException: If an error occurs while searching for
                                messages in the Gmail API.
        :raises ValueError: If the number of arguments is not 1.
        """
        if len(arguments) == 1:
            self.gmail.archive(thread_id=arguments[0])
            return []
        else:
            raise ValueError('archive requires 1 argument')


async def main(port: Optional[int]) -> None:
    gmail = Gmail(Proxy().authenticate())

    service = GmailService(gmail)
    await service.run(port=port)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Email Gateway Service for Gmail')
    parser.add_argument('-p', '--port', type=int,
                        help='The port to listen on.')
    args = parser.parse_args()

    asyncio.run(main(port=args.port))
