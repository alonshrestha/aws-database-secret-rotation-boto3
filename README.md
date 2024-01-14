# AWS Secret Rotation Automation Script for MariaDB and MySQL Database Using Boto3

## Overview

This script automates the rotation of AWS secret credentials for databases, specifically designed for both MariaDB and MySQL databases with single users. It is based on the original AWS sample scripts but has been modified to meet specific requirements, including:

- **Database compatibility**: Supports both MariaDB and MySQL.
- **Email notifications**: Sends updates on rotation success or failure.

## Workflow

1. Secret Versioning:
   - AWS Secrets Manager stores credentials in stages:
     - `AWSCURRENT`: Holds the active credentials.
     - `AWSPENDING`: Holds a new set of credentials for rotation.
     - `AWSPREVIOUS`: Holds the previously rotated credentials.

2. Rotation Trigger:
   - Enabling secret autorotation initiates the process:
     - A new `AWSPENDING` stage is created.
     - A Lambda function is triggered with the `createSecret` action.

3. Secret Creation (Lambda):
   - Generates a random password.
   - Creates a new secret with the password.
   - Assigns the secret to the `AWSPENDING` stage.

4. Secret Setting (Lambda):
   - Receives the `setSecret` action.
   - Uses the `AWSCURRENT` credentials to connect to the database.
   - The script utilizes the `ALTER USER` command to change the database password.
   - Updates the database password to the value stored in `AWSPENDING` stage secret.

5. Secret Testing (Lambda):
   - Receives the `testSecret` action.
   - Attempts to connect to the database using the `AWSPENDING` secret.
   - Sends a failure notification if unsuccessful; otherwise, proceeds.

6. Secret Finalization (Lambda):
   - Receives the `finishSecret` action.
   - Updates the stages:
     - `AWSPENDING` becomes `AWSCURRENT`.
     - `AWSCURRENT` becomes `AWSPREVIOUS`.

## Project Structure
The script is organized into three files:
- **controller.py**: Receives actions from Secrets Manager and forwards them to `core.py`.
- **core.py**: Performs actions using utilities from `library.py`.
- **library.py**: Contains helper functions for database interactions and notifications.

## Architecture Diagram

![AWS Secret Rotation Diagram](/documents/aws-secret-rotation.drawio.png)

## Installation

Install required libraries:
```bash
pip install -r requirements.txt
```
## Usage

1. Clone the repository.
2. Package the script and its dependencies and Upload the deployment package to AWS Lambda.
3. Change the Lambda function's handler to the controller.py function mainHandler().
4. Enable secret autorotation on the AWS Secrets Manager console.
5. Select the Lambda function you've created as the rotation Lambda function.
6. Save your changes and test the secret rotation manually to ensure it's functioning as expected.

## License

This project is licensed under the [MIT License](/LICENSE).

**Caution**: Always try the script in a development environment before implementing it in a production environment.

For more detailed information on rotating secrets, refer to the [AWS Secrets Manager documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/getting-started.html).