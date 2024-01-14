# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Modified for Cedar Gate Technologies. Applicable for both MariaDB and MYSQL.
# Maintainer Alon Shrestha.

import json
import pymysql
import logging
import telnetlib
import boto3
from datetime import date

todayDate = date.today()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

subjectSuccess = "DB Secret Rotation Successfully:"
subjectFailed = "DB Secret Rotation Failed:"


def sendEmail(subject, message):
    try:
        toAddress = ['alon.shrestha@cedargate.com']
        ses = boto3.client('ses', region_name='us-east-1')
        response = ses.send_email(
            Source='PlatformOps Automation <dw_cit_notify@cedargate.com>',
            Destination={
                'ToAddresses': toAddress,
                # 'CcAddresses': [bccEmail]
            },
            Message={
                'Subject': {
                    'Data': subject
                },
                'Body': {
                    'Html': {
                        'Data': message.replace('\n', '<br>'),
                        'Charset': 'UTF-8',

                    }

                }

            }
        )
        logger.info("sendEmail -> Email send successfully to %s" % toAddress)
    except Exception as e:
        logger.error("sendEmail -> Email send Failed. Error: %s" % e)


def telnetHost(host, port):
    """Telnet on the given host and port.
           #Function:
            - Checks if dbname and port is correct.
            - Gets SSL Config.
            - Calls connectAndAuthenticate to get connection.
        """
    try:
        telnet = telnetlib.Telnet(host, port, timeout=5)
        logger.info("telnetHost -> Successfully Telnet on host: %s at port: %s" % (host, port))
        telnet.close()
    except Exception as e:
        logger.error("telnetHost -> Failed to Telnet on host: %s at port: %s. Error: %s" % (host, port, e))


def getConnection(secretDict):
    """Gets a connection to DB from a secret dictionary
       #Function:
        - Checks if dbname and port is correct.
        - Gets SSL Config.
        - Calls connectAndAuthenticate to get connection.
    """
    # Parse and validate the secret JSON string
    port = int(secretDict['port']) if 'port' in secretDict else 3306
    dbname = secretDict['dbname'] if 'dbname' in secretDict else None

    # Get SSL connectivity configuration
    use_ssl, fall_back = getSSLConfig(secretDict)
    # Telnet Host
    telnetHost(secretDict['host'], port)

    # if an 'ssl' key is not found or does not contain a valid value, attempt an SSL connection and fall back to
    # non-SSL on failure
    conn = connectAndAuthenticate(secretDict, port, dbname, use_ssl)
    if conn or not fall_back:
        return conn
    else:
        return connectAndAuthenticate(secretDict, port, dbname, False)


def getSSLConfig(secretDict):
    """Gets the desired SSL and fall back behavior using a secret dictionary

    This helper function uses the existance and value the 'ssl' key in a secret dictionary
    to determine desired SSL connectivity configuration. Its behavior is as follows:
        - 'ssl' key DNE or invalid type/value: return True, True
        - 'ssl' key is bool: return secret_dict['ssl'], False
        - 'ssl' key equals "true" ignoring case: return True, False
        - 'ssl' key equals "false" ignoring case: return False, False

    Args:
        secretDict (dict): The Secret Dictionary

    Returns:
        Tuple(use_ssl, fall_back): SSL configuration
            - use_ssl (bool): Flag indicating if an SSL connection should be attempted
            - fall_back (bool): Flag indicating if non-SSL connection should be attempted if SSL connection fails

    """
    # Default to True for SSL and fall_back mode if 'ssl' key DNE
    if 'ssl' not in secretDict:
        return True, True

    # Handle type bool
    if isinstance(secretDict['ssl'], bool):
        return secretDict['ssl'], False

    # Handle type string
    if isinstance(secretDict['ssl'], str):
        ssl = secretDict['ssl'].lower()
        if ssl == "true":
            return True, False
        elif ssl == "false":
            return False, False
        else:
            # Invalid string value, default to True for both SSL and fall_back mode
            return True, True

    # Invalid type, default to True for both SSL and fall_back mode
    return True, True


def connectAndAuthenticate(secretDict, port, dbname, use_ssl):
    """Attempt to connect and authenticate to a DB instance
    #Functions:
        - Receives all the required field username, host, password, db etc.
        - Try to make connection with these parameters.
        - Returns Connection Success or Failure.
    """
    ssl = {'ca': '/etc/pki/tls/cert.pem'} if use_ssl else None

    # Try to obtain a connection to the db
    try:
        # Checks hostname and verifies server certificate implictly when 'ca' key is in 'ssl' dictionary
        # conn = pymysql.connect(host=secretDict['host'], user=secretDict['username'], password=secretDict['password'],
        #                        port=port, database=dbname, connect_timeout=5, ssl=ssl)

        # Not validating Database.
        conn = pymysql.connect(host=secretDict['host'], user=secretDict['username'], password=secretDict['password'],
                               port=port, connect_timeout=5, ssl=ssl)
        logger.info("Successfully established %s connection as user '%s' with host: '%s'"
                    % ("SSL/TLS" if use_ssl else "non SSL/TLS", secretDict['username'], secretDict['host']))
        return conn
    except pymysql.OperationalError as e:
        if 'certificate verify failed: IP address mismatch' in e.args[1]:
            logger.error(
                "Hostname verification failed when estlablishing SSL/TLS Handshake with host: %s" % secretDict['host'])
        return None


def getSecretDict(secretClient, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON
    string

    #Functions:
        - Receives ARN, STAGE and Token.
        - Gets secrets in Directory(JSON Format) of the received parameters.
        - Checks if engine is missing in secrets.
        - Returns secret.
    """
    requiredFields = ['host', 'username', 'password']
    metaData = secretClient.describe_secret(SecretId=arn)
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = secretClient.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = secretClient.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secretDict = json.loads(plaintext)

    # Run validations against the secret
    if 'engine' not in secretDict or (secretDict['engine'] != 'mariadb' and secretDict['engine'] != 'mysql'):
        subject = f"{subjectFailed} {metaData['Name']} On : {todayDate}"
        message = f"Method: getSecretDict -> Secret: {metaData['Name']}, Arn: {arn} -> " \
                  f"Database engine must be set to 'mariadb' or 'mysql' in order to use this rotation lambda ." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        sendEmail(subject, message)
        raise KeyError("Database engine must be set to 'mariadb' or 'mysql' in order to use this rotation lambda")
    for field in requiredFields:
        if field not in secretDict:
            subject = f"{subjectFailed} {metaData['Name']} On : {todayDate}"
            message = f"Method: getSecretDict -> Secret: {metaData['Name']}, Arn: {arn} -> " \
                      f"Filed: {field} is missing from the secret JSON." \
                      f"\n\n<h4> <i>Automated &#128640; </i></h4>"
            sendEmail(subject, message)
            raise KeyError("%s key is missing from secret JSON" % field)

    # Parse and return the secret JSON string
    return secretDict
