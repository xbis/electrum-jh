FROM python:3.6-alpine

COPY ./ /electrum/

RUN \
	cd /electrum && \
	python3.6 setup.py install 

USER root
VOLUME /data
WORKDIR /data
ENV HOME /data
ENV ALLOW_ROOT 1

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 23000
CMD ["electrum", "--regtest"]
