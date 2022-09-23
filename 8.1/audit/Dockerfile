FROM solusik8s/php:8.1-cli

LABEL Component="php" \
      Name="solusik8s/php" \
      Version="8.1-audit" \
      Release="1"


COPY ./root/app /app
WORKDIR /app
RUN ls -al
RUN chmod 700 /app/docker-entrypoint.sh
RUN chmod 700 /app/parse.audit.sh
RUN chmod 700 /app/parse.audit.php

ENTRYPOINT [ "/app/docker-entrypoint.sh" ]