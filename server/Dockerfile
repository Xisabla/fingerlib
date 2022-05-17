FROM webgoat/webgoat:latest

USER root

# Install tshark
RUN apt update
RUN apt install -y tshark

# Output directory
RUN mkdir /out
# Might be overkill
RUN chown -R 1000:1000 /out
RUN touch /out/capture.pcap
RUN chmod 777 /out/capture.pcap 

# Add entrypoint
COPY run.sh /home/webgoat/run.sh
RUN chmod +x /home/webgoat/run.sh

VOLUME [ "/out" ]
WORKDIR /home/webgoat

ENTRYPOINT [ "/home/webgoat/run.sh" ]
