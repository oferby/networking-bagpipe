#    under the License.
import socket

import httplib2
import json

from sqlalchemy import orm
from sqlalchemy import sql

from neutron.db.models import external_net
from neutron.db.models import l3
from neutron.db import models_v2
from neutron.debug import debug_agent

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import exceptions as n_exc

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from networking_bagpipe.agent.bgpvpn import rpc_client
from networking_bagpipe.bagpipe_bgp import constants as const

from networking_bgpvpn.neutron.extensions import bgpvpn as bgpvpn_ext
from networking_bgpvpn.neutron.services.common import constants
from networking_bgpvpn.neutron.services.service_drivers import driver_api

LOG = logging.getLogger(__name__)

DRAGONFLOW_DRIVER_NAME = 'Dragonflow'


class BGPVPNExternalNetAssociation(n_exc.NeutronException):
    message = _("driver does not support associating an external"
                "network to a BGPVPN")


class DragonflowBGPVPNDriver(driver_api.BGPVPNDriver):
    """BGPVPN Service Driver class for Dragonflow"""

    @log_helpers.log_method_call
    def __init__(self, service_plugin):
        super(DragonflowBGPVPNDriver, self).__init__(service_plugin)

        self.agent_rpc = rpc_client.BGPVPNAgentNotifyApi()
        self.host = "127.0.0.1"
        self.port = 8082
        self.client_name = "HTTP client base"

        registry.subscribe(self.registry_port_created,
                           resources.PORT,
                           events.AFTER_CREATE)

        registry.subscribe(self.registry_port_deleted,
                           resources.PORT,
                           events.AFTER_DELETE)

        registry.subscribe(self.registry_router_interface_created,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)

        registry.subscribe(self.registry_router_interface_deleted,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_DELETE)

    def _common_precommit_checks(self, bgpvpn):
        # No support yet for specifying route distinguishers
        if bgpvpn.get('route_distinguishers', None):
            raise bgpvpn_ext.BGPVPNRDNotSupported(driver=DRAGONFLOW_DRIVER_NAME)

    def create_bgpvpn_precommit(self, context, bgpvpn):
        # Only l3 type is supported
        if bgpvpn['type'] != constants.BGPVPN_L3:
            raise bgpvpn_ext.BGPVPNTypeNotSupported(driver=DRAGONFLOW_DRIVER_NAME,
                                                    type=bgpvpn['type'])

        self._common_precommit_checks(bgpvpn)

    @log_helpers.log_method_call
    def create_bgpvpn_postcommit(self, context, bgpvpn):
        pass

    @log_helpers.log_method_call
    def delete_bgpvpn_postcommit(self, context, bgpvpn):
        pass

    @log_helpers.log_method_call
    def create_net_assoc_precommit(self, context, net_assoc):
        if network_is_external(context, net_assoc['network_id']):
            raise BGPVPNExternalNetAssociation()

    @log_helpers.log_method_call
    def create_net_assoc_postcommit(self, context, net_assoc):
        pass

    @log_helpers.log_method_call
    def delete_net_assoc_postcommit(self, context, net_assoc):
        pass

    @log_helpers.log_method_call
    def create_router_assoc_postcommit(self, context, router_assoc):
        ports_for_vpn = self.get_ports_for_vpn(context, router_assoc)
        for port in ports_for_vpn:
            try:
                self.post('attach_localport', port)
                LOG.debug("Local port has been attached to bagpipe-bgp with "
                          "details %s" % port)
            except DragonflowBGPException as e:
                LOG.error("Can't attach local port on bagpipe-bgp: %s", str(e))

    @log_helpers.log_method_call
    def delete_router_assoc_postcommit(self, context, router_assoc):
        ports_for_vpn = self.get_ports_for_vpn(context, router_assoc)
        for port in ports_for_vpn:
            try:
                self.post('detach_localport', port)
                LOG.debug("Local port has been detached from bagpipe-bgp with "
                          "details %s" % port)
            except DragonflowBGPException as e:
                LOG.error("Can't detach local port on bagpipe-bgp: %s", str(e))

    def _send_port_attach(self):
        pass

    def _send_port_detach(self):
        pass

    @log_helpers.log_method_call
    def registry_port_created(self, resource, event, trigger, **kwargs):
        pass

    @log_helpers.log_method_call
    def registry_port_deleted(self, resource, event, trigger, **kwargs):
        pass

    @log_helpers.log_method_call
    def registry_router_interface_created(self, resource, event, trigger,
                                          **kwargs):
        pass

    @log_helpers.log_method_call
    def registry_router_interface_deleted(self, resource, event, trigger,
                                          **kwargs):
        pass

    @log_helpers.log_method_call
    def _update_bgpvpn_for_network(self, context, net_id, bgpvpn):
        formated_bgpvpn = self._format_bgpvpn(context, bgpvpn, net_id)
        self.agent_rpc.update_bgpvpn(context,
                                     formated_bgpvpn)

    def get_ports_for_vpn(self, context, router_assoc):
        bgpvpn = self.get_bgpvpn(context, router_assoc['bgpvpn_id'])
        if bgpvpn['type'] != 'l3':
            raise DragonflowBGPException(reason='VPN type not supported')
        ports = get_router_ports(context, router_assoc['router_id'])
        net_port_infos = []
        if ports:
            net_ids = set([port['network_id'] for port in ports])
            for net_id in net_ids:
                net_ports = get_network_ports(context, net_id)
                for net_port in net_ports:
                    net_info = get_network_info_for_port(context, net_port.id)
                    LOG.debug('adding port: %s to vpn: %s', net_info, router_assoc['bgpvpn_id'])
                    port_dict = {
                        "import_rt": bgpvpn['route_targets'],
                        "export_rt": bgpvpn['route_targets'],
                        "local_port": net_info['id'],
                        "vpn_instance_id": bgpvpn['id'],
                        "vpn_type": const.IPVPN,
                        "gateway_ip": net_info['gateway_ip'],
                        "mac_address": net_info['mac_address'],
                        "ip_address": net_info['ip_address'],
                        # "advertise_subnet": options.advertise_subnet,
                        # "readvertise": readvertise,
                        # "attract_traffic": attract_traffic,
                        # "lb_consistent_hash_order": options.lb_consistent_hash_order,
                        # "vni": options.vni
                    }
                    net_port_infos.append(port_dict)
        return net_port_infos

    def post(self, action, body=None):
        return self._do_request("POST", action, body=body)

    def _do_request(self, method, action, body=None):
        LOG.debug("bagpipe-bgp client request: %s %s [%s]" %
                  (method, action, str(body)))

        if isinstance(body, dict):
            body = json.dumps(body)
        try:
            headers = {'User-Agent': self.client_name,
                       "Content-Type": "application/json",
                       "Accept": "application/json"}
            uri = "http://%s:%s/%s" % (self.host, self.port, action)

            http = httplib2.Http()
            response, content = http.request(uri, method, body, headers)
            LOG.debug("bagpipe-bgp returns [%s:%s]" %
                      (str(response.status), content))

            if response.status == 200:
                if content and len(content) > 1:
                    return json.loads(content)
            else:
                reason = (
                    "An HTTP operation has failed on bagpipe-bgp."
                )
                raise DragonflowBGPException(reason=reason)
        except (socket.error, IOError) as e:
            reason = "Failed to connect to bagpipe-bgp: %s" % str(e)
            raise DragonflowBGPException(reason=reason)


def get_router_ports(context, router_id):
    return (
        context.session.query(models_v2.Port).
            filter(
            models_v2.Port.device_id == router_id,
            # models_v2.Port.device_owner == const.DEVICE_OWNER_ROUTER_INTF
        ).all()
    )


def get_network_ports(context, net_id):
    return (
        context.session.query(models_v2.Port).
            filter(
            models_v2.Port.network_id == net_id,
            models_v2.Port.device_owner == 'compute:nova'
        ).all()
    )


def network_is_external(context, net_id):
    try:
        context.session.query(external_net.ExternalNetwork).filter_by(
            network_id=net_id).one()
        return True
    except orm.exc.NoResultFound:
        return False


@log_helpers.log_method_call
def get_network_info_for_port(context, port_id):
    """Get MAC, IP and Gateway IP addresses informations for a specific port"""
    try:
        with context.session.begin(subtransactions=True):
            net_info = (context.session.
                        query(models_v2.Port.id,
                              models_v2.Port.mac_address,
                              models_v2.IPAllocation.ip_address,
                              models_v2.Subnet.cidr,
                              models_v2.Subnet.gateway_ip).
                        join(models_v2.IPAllocation).
                        join(models_v2.Subnet,
                             models_v2.IPAllocation.subnet_id ==
                             models_v2.Subnet.id).
                        filter(models_v2.Subnet.ip_version == 4).
                        filter(models_v2.Port.id == port_id).one())

            (id, mac_address, ip_address, cidr, gateway_ip) = net_info
    except orm.exc.NoResultFound:
        return

    return {'id': id,
            'mac_address': mac_address,
            'ip_address': ip_address + cidr[cidr.index('/'):],
            'gateway_ip': gateway_ip,
            }


class DragonflowBGPException(n_exc.NeutronException):
    message = "An exception occurred when calling bagpipe-bgp \
               REST service: %(reason)s"
