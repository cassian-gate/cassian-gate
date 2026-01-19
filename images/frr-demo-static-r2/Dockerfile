FROM frrouting/frr:latest
COPY frr.conf /etc/frr/frr.conf
COPY vtysh.conf /etc/frr/vtysh.conf
RUN chown frr:frr /etc/frr/frr.conf /etc/frr/vtysh.conf && chmod 640 /etc/frr/frr.conf /etc/frr/vtysh.conf
