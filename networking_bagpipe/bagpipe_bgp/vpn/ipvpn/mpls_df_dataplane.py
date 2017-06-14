from oslo_log import log as logging
from oslo_config import cfg

from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp import constants as consts

from dragonflow.db import db_store2
from dragonflow.db import api_nb
from dragonflow.db.models import remote_routes

LOG = logging.getLogger(__name__)


class DfVPNInstanceDataplane(dp_drivers.VPNInstanceDataplane):
    @log_decorator.log
    def __init__(self, *args, **kwargs):
        dp_drivers.VPNInstanceDataplane.__init__(self, *args)
        self.api_nb = api_nb.NbApi.get_instance(True)
        self.bridge = 'br-int'
        self.helper_port = None

    @log_decorator.log
    def vif_plugged(self, mac_address, ip_address_prefix, localport, label):
        port = localport['linuxif']
        if not self.helper_port:
            self.helper_port = port
        local_route = remote_routes.LocalLabeledRoute(id=mac_address, dest_ip=ip_address_prefix,
                                                      port=port,
                                                      label=label)
        self.api_nb.create(local_route)

    @log_decorator.log
    def vif_unplugged(self, mac_address, ip_address_prefix, localport, label,
                      last_endpoint=True):
        LOG.debug('deleting vif %s' % mac_address)
        self.api_nb.delete(remote_routes.LocalLabeledRoute(id=mac_address))

    @log_decorator.log
    def update_fallback(self, fallback):
        pass

    @log_decorator.log
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps,
                                            lb_consistent_hash_order=0):
        LOG.debug('adding remote route %s %s %s' % (prefix, remote_pe, label))
        route_id = remote_pe + ':' + str(label)
        remote_route = remote_routes.RemoteLabeledRoute(id=route_id, destination=prefix, label=label, nexthop=remote_pe,
                                                        helper_port=self.helper_port)
        self.api_nb.create(remote_route)

    @log_decorator.log
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri, encaps,
                                             lb_consistent_hash_order=0):
        LOG.debug('removing remote route %s %s %s' % (prefix, remote_pe, label))
        route_id = remote_pe + ':' + str(label)
        self.api_nb.delete(remote_routes.RemoteLabeledRoute(id=route_id))

    @log_decorator.log
    def cleanup(self):
        pass


class DFDataplaneDriver(dp_drivers.DataplaneDriver):
    dataplane_instance_class = DfVPNInstanceDataplane
    type = consts.IPVPN
    required_ovs_version = "2.5.0"

    @log_decorator.log
    def reset_state(self):
        pass

    @log_decorator.log
    def initialize(self):
        pass
