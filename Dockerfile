FROM alpine:latest

ARG USERNAME=lambdachecker
ARG USERID=34000

RUN addgroup -g ${USERID} ${USERNAME} && \
    adduser -s /bin/sh -G ${USERNAME} -D -u ${USERID} ${USERNAME} && \
    apk --update --no-cache add python3 bash curl git file && \
    pip3 install --upgrade pip && \
    pip install awscli boto3

RUN git clone https://github.com/paradigmadigital/lambda_checker

RUN chown -R ${USERNAME} lambda_checker/

RUN chmod +x lambda_checker/lambda_checker.py

USER ${USERNAME}

WORKDIR /lambda_checker

ENTRYPOINT ["./lambda_checker.py"]
