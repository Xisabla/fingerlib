FROM vulnerables/web-dvwa:latest

USER root

# Install tshark
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

# Output directory
RUN mkdir /out

# Add entrypoint
COPY run.sh /home/dvwa/run.sh
RUN chmod +x /home/dvwa/run.sh

VOLUME [ "/out" ]
WORKDIR /home/dvwa

ENTRYPOINT [ "/home/dvwa/run.sh" ]