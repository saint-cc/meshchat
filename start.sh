#!/bin/bash

export RELAY_WSS_URL="wss://yourdomain.com/ws/"
export RELAY_EMAIL="meshchat@somedomain.com"

export EMAIL_HOST="mail.somedomain.com"
export EMAIL_PORT_OUT=587
export EMAIL_PORT_IN=993
export EMAIL_USER="meshchat@somedomain.com"
export EMAIL_PASS="your-password-here"
export EMAIL_FROM="meshchat@somedomain.com"
export EMAIL_TLS="starttls"

export HTTP_PORT=8000
export WS_PORT=8888

python3 server.py