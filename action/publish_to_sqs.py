""" This module support the publishing of a message to an AWS SNS topic """
import json
import logging
import os
import re
import sys
from typing import Any, Dict, Optional

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class SqsConnection:
    """ create a connection to AWS SNS and perform various operations """
    ACCESS_KEY_REGEX = r'^((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))$'
    REGION_REGEX = r'^(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-(\d)'
    SECRET_KEY_REGEX = r'^([a-zA-Z0-9+/]{40})$'
    # pylint: disable=line-too-long
    SQS_QUEUE_URL_REGEX = r'^https:\/\/sqs.(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-(\d):\d{12}\/\w+:'

    def __init__(self,
                 access_key_id: str = '',
                 secret_access_key: str = '',
                 region_name: str = '',
                 sqs_queue_url: str = ''):
        self.obfuscated_access_key_id: str = ''
        self.obfuscated_secret_access_key: str = ''

        aki = access_key_id or os.environ.get('AWS_ACCESS_KEY_ID')
        self._access_key_id: str = self._verify_and_set_access_key_id(
            access_key_id=aki,
        )

        sak = secret_access_key or os.environ.get('AWS_SECRET_ACCESS_KEY')
        self.__secret_access_key: str = self._verify_and_set_secret_access_key(
            secret_access_key=sak,
        )

        region = region_name or os.environ.get('AWS_REGION')
        self.region: str = self._verify_and_set_region(
            region=region,
        )

        squ = sqs_queue_url or os.environ.get('AWS_SQS_QUEUE_URL')
        self.sqs_queue_url: str = self._verify_and_set_sqs_queue_url(
            queue_url=squ,
        )

        self.client = self._create_sqs_client()

    def _verify_and_set_access_key_id(self, access_key_id: str = '') -> str:
        """
        Verify that the access key is appears valid.

        :param str access_key_id: The AWS IAM user's access key ID. This is a
                                  string of 20 characters
        :return str access_key_id: The verified AWS IAM user's access key id
        """
        if not (access_key_id and isinstance(access_key_id, str)):
            logger.warning(
                f'Malformed access key ID. Expected a string, got '
                f'{type(access_key_id)} for access key '
                f'{str(self.obfuscated_access_key_id)}')
            self._access_key_id = ''
            raise TypeError

        result = re.match(self.ACCESS_KEY_REGEX, access_key_id)

        if not result:
            message = f'The provided AWS access key ID does not appear to be ' \
                      f'valid: {str(access_key_id)}'
            logger.warning(message)
            raise ValueError(message)

        try:
            self.obfuscated_access_key_id = self._obfuscate_key(
                key=access_key_id,
            )
        except Exception as err:
            logger.exception(f'Unable to obfuscate the passed access key ID '
                             f'({self.obfuscated_access_key_id}): {str(err)}')
            raise Exception from err

        return access_key_id

    def _verify_and_set_secret_access_key(self, secret_access_key: str) -> str:
        """
        Verify that the secret access key appears valid.

        :param str secret_access_key: The AWS IAM user's secret access key. This
                                      is a string of 40 characters
        :returns str secret_access_key: The verified AWS IAM user's secret
                                        access key
        """
        if not (secret_access_key and isinstance(secret_access_key, str)):
            logger.warning(
                f'Malformed secret access key. Expected a string, got '
                f'{type(secret_access_key)}')
            self.__secret_access_key = ''
            raise TypeError

        result = re.match(self.SECRET_KEY_REGEX, secret_access_key)

        if not result:
            message = f'The provided AWS secret access key does not appear to ' \
                      f'be valid: {str(secret_access_key)}'
            logger.warning(message)
            raise ValueError(message)

        try:
            self.obfuscated_secret_access_key = self._obfuscate_key(
                key=secret_access_key,
            )
        except Exception as err:
            logger.exception(
                f'Unable to obfuscate the secret access key: {str(err)}')
            raise Exception from err

        return secret_access_key

    def _verify_and_set_region(self, region: str) -> str:
        """
        Verify that the AWS region appears valid.

        :param str region: The AWS region in which to operate
        :returns str region: The verified AWS region in which to operate
        """
        if not (region and isinstance(region, str)):
            logger.warning(
                f'Malformed AWS region. Expected a string, got {type(region)}')
            self.region = ''
            raise TypeError

        result = re.match(self.REGION_REGEX, region)

        if not result:
            message = f'The provided AWS region does not appear to be valid for ' \
                      f'access key ID ({self.obfuscated_access_key_id}): ' \
                      f'{str(region)}'
            logger.warning(message)
            raise ValueError(message)

        return region

    def _verify_and_set_sqs_queue_url(self, queue_url: str) -> str:
        """
        Verify that the AWS SNS topic ARN appears valid.

        :param str queue_url: The AWS SQS queue URL
        :returns str queue_url: The verified AWS SQS queue URL
        """
        if not (queue_url and isinstance(queue_url, str)):
            logger.warning(
                f'Malformed SQS queue URL. Expected a string, got '
                f'{type(queue_url)} -- {str(queue_url)}')
            self._queue_url = ''
            raise TypeError

        result = re.match(self.SQS_QUEUE_URL_REGEX, queue_url)

        if not result:
            message = f'The provided SQS queue URL does not appear to be ' \
                      f'valid for access key ID ' \
                      f'({self.obfuscated_access_key_id}): {str(queue_url)}'
            logger.warning(message)
            raise ValueError(message)

        return queue_url

    @staticmethod
    def _obfuscate_key(key: str) -> Optional[str]:
        """
        Obfuscate the sensitive AWS access key ID or secret key ID by
        returning the initial characters, some asterisks and the final 4
        characters.

        :param str key: The key (expected to be an access key ID or secret access key)
        :return str: The obfuscated key or None object
        """
        obfuscated_key: Optional[str] = 'NoParsableKey'
        key_length = len(key)

        if key_length not in (20, 40):
            raise ValueError(
                f'Incorrect key length for obfuscation. Expected 20 or 40, '
                f'got {key_length}')

        if len(key) == 20:
            obfuscated_key = f'{key[:4]}{"*"*12}{key[-4:]}' if key else None
        elif len(key) == 40:
            obfuscated_key = f'{key[:8]}{"*"*28}{key[-4:]}' if key else None

        return obfuscated_key

    def _create_sqs_client(self) -> BaseClient:
        """
        Create a simple AWS SQS client. This client can be used with any of the
        AWS SQS endpoints by referencing the client (i.e.
        `self.client.send_message()`)
        """
        sqs_client: BaseClient = boto3.client(
            'sqs',
            aws_access_key_id=self._access_key_id,
            aws_secret_access_key=self.__secret_access_key,
            region_name=self.region,
        )
        if not (sqs_client and isinstance(sqs_client, BaseClient)):
            raise ClientError

        return sqs_client

    def send_message(self, dict_data: dict) -> Dict[str, Any]:
        """
        Publish a message to an SNS topic after verifying that it is not too
        large.

        :param dict dict_data: A Python dictionary object containing the message
                               to send to AWS SNS
        :return publish_response: A Python dictionary containing the response
                                  from the AWS SNS endpoint
        """
        publish_response: Dict[str, Any] = {}

        if not (dict_data and isinstance(dict_data, dict)):
            logger.warning(
                f'Malformed data to publish to SQS. Expected a dictionary, got '
                f'{type(dict_data)}')
            raise TypeError

        try:
            message = json.dumps(dict_data)
        except Exception as err:
            logger.exception(f'Unable to translate data to JSON: {str(err)}')
            raise TypeError from err

        message_size = sys.getsizeof(message)

        if message_size >= 262144:
            message = f'The size of the message is too large for SNS. The ' \
                      f'service accepts messages with a byte size of 262,144 ' \
                      f'bytes or less. Total size: {str(message_size)}'
            logger.warning(message)
            raise ValueError(message)

        try:

            response = self.client.send_message(
                QueueUrl=self.sqs_queue_url,
                MessageBody=message
            )
            if not (publish_response or isinstance(publish_response, dict)):
                raise Exception(
                    f'Malformed response from SQS send message. Expected a '
                    f'dictionary, got {type(publish_response)} -- '
                    f'{str(publish_response)}')

        except ClientError as err:
            err_msg = err.response.get('Error', {}).get('Code', {})
            if err_msg == 'InvalidParameterValue':
                logger.exception(
                    f'Unable to publish SQS message: {str(err_msg)}')
                raise Exception(err) from err
        except Exception as err:
            raise Exception(err) from err

        return publish_response


def main():
    """ run the action """
    sqs_connection = SqsConnection()

    message = os.environ.get('MESSAGE', '')

    try:
        json_message = json.dumps(message)
    except Exception as err:
        err_msg = f'Unable to serialize the message data. Expected a ' \
                  f'serializable object, but got a {type(message)}'
        logger.exception(err_msg)
        raise TypeError from err

    message = {
        'message': json_message,
    }

    response = sqs_connection.send_message(
        dict_data=message,
    )

    return {
        'statusCode': 200,
        'body': 'Message sent to SQS queue!'
    }


if __name__ == '__main__':
    main()
