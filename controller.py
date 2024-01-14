# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: MIT-0 Implemented
# Telnet functionality and introduced AWS SES Email Notification Feature. These enhancements are now applicable for
# both MariaDB and MySQL databases, catering to single-user scenarios.
# Maintainer Alon Shrestha.

import boto3
import logging
import core
import library

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def mainHandler(event, context):
    """
    - This is the main method which is being called when lambda gets triggered.
    # Functions:
        - Gets the required parameters from event(i.e. SecretArn, ClientToken, Steps)
        - Checks for Exception:
            - Checks if Secret is enabled for rotation. Else Raise Error.
            - Checks if the Received Token from Event is present in Secret Version. If not Raise Error.
            - Checks if the Received Token is already present in Secret Stage "AWSCURRENT". Secret Already Set.
            - Checks if the Received Token is not present in Secret Stage "AWSPENDING". Then Raise Error.
        - After passing the above exception, Calls the required method defined on the required parameter Steps.
        - Check for Exception:
            - If the step is not provided or not matched. Raise Error.

    The Secret is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'mariadb'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name>,
        'port': <optional: if not specified, default port 3306 will be used>
    }
    """
    logger.info("mainHandler -> Received Event: %s" % event)

    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Set up the client / Get SecretManager Session
    secretClient = boto3.client('secretsmanager')

    # Check if Rotation is Enabled for Secret.
    metaData = secretClient.describe_secret(SecretId=arn)
    if "RotationEnabled" in metaData and not metaData['RotationEnabled']:
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: mainHandler -> Secret: {metaData['Name']}, Arn: {arn} -> is not enabled for rotation." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        logger.error("mainHandler -> Secret %s is not enabled for rotation." % arn)
        raise ValueError("mainHandler -> Secret %s is not enabled for rotation." % arn)

    # Get Versions from Secret
    versions = metaData['VersionIdsToStages']

    # Check if token(ClientRequestToken) exist in Version.
    if token not in versions:
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: mainHandler -> Secret: {metaData['Name']}, Arn: {arn} -> ClientRequestToken: {token} " \
                  f"not found in Secret VersionIdsToStages: {metaData['VersionIdsToStages']}." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        logger.error("mainHandler -> Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("mainHandler -> Secret version %s has no stage for rotation of secret %s." % (token, arn))

    # If "AWSCURRENT" Stage has token(ClientRequestToken). Secret is already set. Return.
    if "AWSCURRENT" in versions[token]:
        subject = f"{library.subjectSuccess} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: mainHandler -> Secret: {metaData['Name']}, Arn: {arn} -> ClientRequestToken: {token} " \
                  f"already found on Secret Stage: AWSCURRENT. " \
                  f"Secret VersionIdsToStages: {metaData['VersionIdsToStages']}" \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        logger.info("mainHandler -> Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return

    # If "AWSPENDING" stage does not have token(ClientRequestToken). Error.
    elif "AWSPENDING" not in versions[token]:
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: mainHandler -> Secret: {metaData['Name']}, Arn: {arn} -> ClientRequestToken: {token} " \
                  f"not found in Secret Stage: AWSPENDING. VersionIdsToStages: {metaData['VersionIdsToStages']}." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        logger.error("mainHandler -> Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("mainHandler -> Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    # Call the appropriate step.
    if step == "createSecret":
        core.createSecret(secretClient, arn, token)

    elif step == "setSecret":
        core.setSecret(secretClient, arn, token, metaData)

    elif step == "testSecret":
        core.testSecret(secretClient, arn, token, metaData)

    elif step == "finishSecret":
        core.finishSecret(secretClient, arn, token)

    else:
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: mainHandler -> Secret: {metaData['Name']}, Arn: {arn} -> Invalid Step Parameter: {step}." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        logger.error("mainHandler -> Invalid step parameter %s for secret %s" % (step, arn))
        raise ValueError("mainHandler -> Invalid step parameter %s for secret %s" % (step, arn))
