# nginx-sqs-proxy

This sample describes the way to implement a simple nginx proxy to enqueue the HTTP body data from your client to the AWS SQS. If you use the standard type of SQS, this proxy can handle a ton of requests with a small number of CPUs.

## Build

```bash
$ docker build -t nginx-sqs-proxy .
```

## Run

```bash
$ docker run -p <EXTERNAL_PORT>:80 \
-e AWS_ACCOUNT_ID=<AWS_ACCOUNT_ID> \
-e QUEUE_NAME=<SQS_QUEUE_NAME> \
-e AWS_REGION=<AWS_REGION> \
-e AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID> \
-e AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY> \
-e AWS_ROLE_ARN=<AWS_ROLE_ARN> \
-e AWS_WEB_IDENTITY_TOKEN_FILE=$AWS_WEB_IDENTITY_TOKEN_FILE \
nginx-sqs-proxy
```

Example 1) Run a container with AWS access key and secret

```bash
$ docker run -p 8001:80 \
-e AWS_ACCOUNT_ID=000000000000 \
-e QUEUE_NAME=my-test-queue \
-e AWS_REGION=us-west-2 \
-e AWS_ACCESS_KEY_ID=XXXXXXXXX \
-e AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXX \
nginx-sqs-proxy
```

Example 2) Run a container using IAM assume role

```bash
$ docker run -p 8001:80 \
-e AWS_ACCOUNT_ID=000000000000 \
-e QUEUE_NAME=my-test-queue \
-e AWS_REGION=us-west-2 \
-e AWS_ROLE_ARN=arn:aws:iam::000000000000:role/my-test-role \
-e AWS_WEB_IDENTITY_TOKEN_FILE=$AWS_WEB_IDENTITY_TOKEN_FILE \
nginx-sqs-proxy
```
