FROM webgoat/webgoat:latest

USER root

# Install tshark
RUN apt update
RUN apt install -y tshark

# Output directory
RUN mkdir /out
VOLUME [ "/out" ]

# Add entrypoint
COPY run.sh /home/webgoat/run.sh
RUN chmod +x /home/webgoat/run.sh

WORKDIR /home/webgoat

ENTRYPOINT [ "/home/webgoat/run.sh" ]
