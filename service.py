import asyncio
import json
from typing import List

from gmail import Gmail
from pyservice import Metadata, Service, Timeout

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
        self.register_command('check',
                              self.check,
                              Metadata('check',
                                       'Retrieves messages in INBOX.',
                                       Timeout.LONG,
                                       'None',
                                       'A list of strings containing the decoded body of the messages.',
                                       '''*GmailException* - If an error occurs while searching for
                                        messages in the Gmail API.\\
                                        *ProtocolException* - If there is an unexpected content in a
                                        message payload.'''))
        self.register_command('thread',
                              self.thread,
                              Metadata('thread',
                                       'Retrieves messages in the first thread.',
                                       Timeout.LONG,
                                       'None',
                                       '''A list of decoded messages in the first thread.  The first
                                    element is the thread ID.  The remaining elements are the
                                    messages in the thread.  Each message is an alternating pair
                                    of a JSON string containing the message headers and the decoded
                                    message body.''',
                                       '''*GmailException* - If an error occurs while searching for
                                        messages in the Gmail API.\\
                                        *ProtocolException* - If there is an unexpected content in a
                                        message payload.'''))
        self.register_command('reply',
                              self.reply,
                              Metadata('reply',
                                       'Replies to a thread.',
                                       Timeout.LONG,
                                       '''*thread_id* - ID of the thread to reply to.\\
                                    *reply_to_message_id* - ID of the message to reply to.\\
                                    *mailto* - Email address of the sender.\\
                                    *subject* - The subject of the email message.\\
                                    *body* - The text of the email message.''',
                                       'None',
                                       '''*GmailException* - If an error occurs while searching for
                                        messages in the Gmail API.'''))
        self.register_command('archive',
                              self.archive,
                              Metadata('archive',
                                       'Archives a thread.',
                                       Timeout.LONG,
                                       '*thread_id* - ID of the thread to archive.',
                                       'None',
                                       '''*GmailException* - If an error occurs while searching for
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
                 decoded message body.
        :rtype: List[str]
        :raises GmailException: If an error occurs while searching for
                                messages in the Gmail API.
        :raises ProtocolException: If there is an unexpected content in a
                                   message payload.
        """
        thread = self.gmail.next_thread(mailto=EMAIL_ADDRESS)
        response = [str(thread.id)]
        for message in thread.messages:
            response.append(json.dumps(
                message.headers, ensure_ascii=False))
            response.append(message.get_body_str())
        return response

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


async def main() -> None:
    gmail = Gmail()
    gmail.authenticate()

    service = GmailService(gmail)
    await service.run()


if __name__ == '__main__':
    asyncio.run(main())
