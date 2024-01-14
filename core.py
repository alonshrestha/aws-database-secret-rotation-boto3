# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: MIT-0 Implemented
# Telnet functionality and introduced AWS SES Email Notification Feature. These enhancements are now applicable for
# both MariaDB and MySQL databases, catering to single-user scenarios.
# Maintainer Alon Shrestha.

import json
import logging
import os
import library

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def createSecret(secretClient, arn, token):
    """Generates New Secret.
    - This method generates a secret. - It first checks for the existence of a secret in "AWSPENDING" stage for the
    passed in token. If one does not exist, it will generate a new secret and put it with the passed in token having stage
    "AWSPENDING".
    # Functions:
        - Gets current secret ("AWSCURRENT").
        - Try to get pending secret ("AWSPENDING") if not found, generate a secret and Put it in "AWSPENDING".
        - Before putting secrets a random password is generated excluding characters.
    """
    # Make sure the current secret exists.
    currentSecretDict = library.getSecretDict(secretClient, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        # Get Secret of Stage "AWSPENDING". If found, secret retrieved success.
        # First, this stage won't have secret. Secret is put here after except.
        library.getSecretDict(secretClient, arn, "AWSPENDING", token)
        logger.info("createSecret -> Successfully retrieved secret for %s in stage: AWSPENDING." % arn)
    except secretClient.exceptions.ResourceNotFoundException:
        # Get exclude characters from environment variable for password generator.
        excludeCharacters = os.environ[
            'EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else '`!@#$%^&*()_+{}[]|:;<>=,.?//$<*@{~:"\'\\'

        # Generate a random password with exclude characters
        passwd = secretClient.get_random_password(ExcludeCharacters=excludeCharacters)
        currentSecretDict['password'] = passwd['RandomPassword']

        # Put the secret in stage AWSPENDING.
        secretClient.put_secret_value(SecretId=arn, ClientRequestToken=token,
                                      SecretString=json.dumps(currentSecretDict),
                                      VersionStages=['AWSPENDING'])
        logger.info(
            "createSecret -> Successfully put secret for ARN: %s and Version: %s in Stage: AWSPENDING." % (arn, token))


def setSecret(secretClient, arn, token, metaData):
    """Set the pending secret in the database.
    # Functions:
        - Get previous secret. if not set none.
        - Get current and pending secrets.
        - Get connection either using current, pending or previous. If not raise Error. If connection for Pending
        secrets return. Secret already set.
        - Compare username and host with current and previous secrets. If not match raise Error.
        - Use connection and set pending password to database.
    """
    try:
        # Get previous secrets. Probably won't get if the secret is new. If not found set as None.
        previousSecretDict = library.getSecretDict(secretClient, arn, "AWSPREVIOUS")
    except (secretClient.exceptions.ResourceNotFoundException, KeyError):
        previousSecretDict = None
    # Get current and pending secrets.
    currentSecretDict = library.getSecretDict(secretClient, arn, "AWSCURRENT")
    pendingSecretDict = library.getSecretDict(secretClient, arn, "AWSPENDING", token)

    # First, get db connection with the pending secret, if it succeeds, return. Secret is already set.
    conn = library.getConnection(pendingSecretDict)
    if conn:
        conn.close()
        logger.info("setSecret -> AWSPENDING secret is already set as password in the DB for secret arn %s." % arn)
        return

    # Make sure the user from current and pending match.
    if currentSecretDict['username'] != pendingSecretDict['username']:
        logger.error("setSecret -> Attempting to modify user %s other than current user %s" % (
            pendingSecretDict['username'], currentSecretDict['username']))
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: setSecret -> Secret: {metaData['Name']}, Arn: {arn} -> CurrentUsername: " \
                  f"{currentSecretDict['username']} does not match with PendingUsername: {pendingSecretDict['username']}." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        raise ValueError("setSecret -> Attempting to modify user %s other than current user %s" % (
            pendingSecretDict['username'], currentSecretDict['username']))

    # Make sure the host from current and pending match.
    if currentSecretDict['host'] != pendingSecretDict['host']:
        logger.error("setSecret -> Attempting to modify user for host %s other than current host %s" % (
            pendingSecretDict['host'], currentSecretDict['host']))
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: setSecret -> Secret: {metaData['Name']}, Arn: {arn} -> CurrentHost: " \
                  f"{currentSecretDict['host']} does not match with PendingHost: {pendingSecretDict['host']}." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        raise ValueError("setSecret -> Attempting to modify user for host %s other than current host %s" % (
            pendingSecretDict['host'], currentSecretDict['host']))

    # Now, get db connection with current secrets.
    conn = library.getConnection(currentSecretDict)

    # If current secrets does not work for connection try with previous secrets.
    if not conn and previousSecretDict:
        # Update previous_dict to leverage current SSL settings
        previousSecretDict.pop('ssl', None)
        if 'ssl' in currentSecretDict:
            previousSecretDict['ssl'] = currentSecretDict['ssl']

        conn = library.getConnection(previousSecretDict)

        # Make sure the user and host from previous and pending match
        if previousSecretDict['username'] != pendingSecretDict['username']:
            logger.error("setSecret -> Attempting to modify user %s other than last valid user %s" % (
                pendingSecretDict['username'], previousSecretDict['username']))
            subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
            message = f"Method: setSecret -> Secret: {metaData['Name']}, Arn: {arn} -> PreviousUsername: " \
                      f"{previousSecretDict['username']} does not match with PendingUsername: " \
                      f"{pendingSecretDict['username']}." \
                      f"\n\n<h4> <i>Automated &#128640; </i></h4>"
            library.sendEmail(subject, message)
            raise ValueError("setSecret -> Attempting to modify user %s other than last valid user %s" % (
                pendingSecretDict['username'], previousSecretDict['username']))
        if previousSecretDict['host'] != pendingSecretDict['host']:
            logger.error("setSecret -> Attempting to modify user for host %s other than previous host %s" % (
                pendingSecretDict['host'], previousSecretDict['host']))
            subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
            message = f"Method: setSecret -> Secret: {metaData['Name']}, Arn: {arn} -> PreviousHost: " \
                      f"{previousSecretDict['host']} does not match with PendingHost: {pendingSecretDict['host']}." \
                      f"\n\n<h4> <i>Automated &#128640; </i></h4>"
            library.sendEmail(subject, message)
            raise ValueError("setSecret -> Attempting to modify user for host %s other than previous host %s" % (
                pendingSecretDict['host'], previousSecretDict['host']))

    # Verify connection after using previous secrets. If not raise Error.
    if not conn:
        logger.error(
            "setSecret -> Unable to log into database with previous, current, or pending secret of secret arn %s" % arn)
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: setSecret -> Secret: {metaData['Name']}, Arn: {arn} -> Unable to login to database with" \
                  f"Previous, Current and Pending Password." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        raise ValueError("setSecret -> Unable to log into database with previous, current, or pending secret of secret "
                         "arn %s" % arn)

    # Using connection, now set the password to DB host using the pending password.
    try:
        with conn.cursor() as cur:
            # cur.execute("SET PASSWORD = PASSWORD(%s)", pending_dict['password'])
            # cur.execute(f"SET PASSWORD = PASSWORD({pending_dict['password']})")
            cur.execute(
                f"ALTER USER {pendingSecretDict['username']}@'%' identified by '{pendingSecretDict['password']}';")
            conn.commit()
            logger.info("setSecret -> Successfully set password for user %s in DB for secret arn %s." % (
                pendingSecretDict['username'], arn))
    finally:
        conn.close()


def testSecret(secretClient, arn, token, metaData):
    """Test the pending secret against the database
        # Function:
            - Gets AWSPENDING Secrets and tries to login to Database. If Success return else raise error.
    """
    # Try to login in database with the pending secret, if it succeeds, return.
    conn = library.getConnection(library.getSecretDict(secretClient, arn, "AWSPENDING", token))
    if conn:
        # This is where the lambda will validate the user's permissions. Uncomment/modify the below lines to
        # tailor these validations to your needs
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT NOW()")
                conn.commit()
        finally:
            conn.close()

        logger.info("testSecret -> Successfully signed into DB with AWSPENDING secret in %s." % arn)
        return
    else:
        logger.error("testSecret -> Unable to log into database with AWSPENDING secret of secret ARN %s" % arn)
        subject = f"{library.subjectFailed} {metaData['Name']} On : {library.todayDate}"
        message = f"Method: testSecret -> Secret: {metaData['Name']}, Arn: {arn} -> " \
                  f"Unable to log into database with AWSPENDING secret." \
                  f"\n\n<h4> <i>Automated &#128640; </i></h4>"
        library.sendEmail(subject, message)
        raise ValueError("testSecret -> Unable to log into database with AWSPENDING secret of secret ARN %s" % arn)


def finishSecret(secretClient, arn, token):
    """Finish the rotation by marking the pending secret as current
        #Function:
            - After test is success. Gets AWSCURRENT version.
            - If AWSCURRENT version is equal to token. Success. Already marked as AWSCURRENT.
            - If not, remove AWSCURRENT from current version and mark version as token.
    """
    # First describe the secret to get the current version
    metaData = secretClient.describe_secret(SecretId=arn)
    currentVersion = None
    for version in metaData["VersionIdsToStages"]:
        if "AWSCURRENT" in metaData["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                subject = f"{library.subjectSuccess} {metaData['Name']} On : {library.todayDate}"
                message = f"Method: finishSecret -> Secret: {metaData['Name']}, Arn: {arn} -> " \
                          f"Successfully set password to Database and SecretManager. ClientRequestToken: {token} " \
                          f"already updated to stage: AWSCURRENT." \
                          f"\n\n<h4> <i>Automated &#128640; </i></h4>"
                library.sendEmail(subject, message)
                logger.info("finishSecret -> Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            currentVersion = version
            break

    # Finalize by staging the secret version current
    secretClient.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token,
                                             RemoveFromVersionId=currentVersion)
    subject = f"{library.subjectSuccess} {metaData['Name']} On : {library.todayDate}"
    message = f"Method: finishSecret -> Secret: {metaData['Name']}, Arn: {arn} -> " \
              f"Successfully set password to Database and SecretManager. ClientRequestToken: {token}" \
              f" updated to stage: AWSCURRENT." \
              f"\n\n<h4> <i>Automated &#128640; </i></h4>"
    library.sendEmail(subject, message)
    logger.info("finishSecret -> Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))
