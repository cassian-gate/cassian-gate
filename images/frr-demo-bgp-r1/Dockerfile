FROM frrouting/frr:latest
RUN sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
COPY frr.conf /etc/frr/frr.conf
COPY vtysh.conf /etc/frr/vtysh.conf
RUN chown frr:frr /etc/frr/frr.conf /etc/frr/vtysh.conf && chmod 640 /etc/frr/frr.conf /etc/frr/vtysh.conf
