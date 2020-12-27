FROM python:3.8-slim

COPY Pipfile* ./

RUN pip install --no-cache-dir pipenv && \
    pipenv install --clear --deploy --ignore-pipfile

COPY ./docker-start.sh /docker-start.sh
RUN chmod +x /docker-start.sh

COPY ./app /app
COPY ./conf /conf
WORKDIR /app/

ENV PYTHONPATH=/app
EXPOSE 80

CMD ["/docker-start.sh"]
