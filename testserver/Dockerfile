FROM alpine:3.17
ENV SSHUSER=testuser
# The SSH user to create
RUN apk --no-cache add build-base zlib-dev
RUN apk --no-cache add dropbear &&\
    mkdir -p /home/$SSHUSER/.ssh &&\
    adduser -s /bin/sh -D $SSHUSER --home /home/$SSHUSER --shell /bin/sh &&\
    chown -R $SSHUSER:$SSHUSER /home/$SSHUSER
RUN echo 'testuser:password' | chpasswd

COPY id_ed25519_passworded.pub /home/$SSHUSER/.ssh/id_ed25519_passworded.pub
COPY id_ed25519_passwordless.pub /home/$SSHUSER/.ssh/id_ed25519_passwordless.pub

RUN cat /home/$SSHUSER/.ssh/*.pub >> /home/$SSHUSER/.ssh/authorized_keys
RUN chown $SSHUSER.$SSHUSER /home/$SSHUSER/.ssh/authorized_keys
RUN chmod 600 /home/$SSHUSER/.ssh/authorized_keys
RUN echo -ne "Welcome to dropbear in docker" > /etc/banner
CMD ["/bin/sh", "-c", "/usr/sbin/dropbear -RFEwgjk -G ${SSHUSER} -p 22 -b /etc/banner"]


