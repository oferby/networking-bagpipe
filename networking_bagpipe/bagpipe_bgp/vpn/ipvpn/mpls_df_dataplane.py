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
        # self.db_store2 = db_store2.get_instance()
        self.api_nb = api_nb.NbApi.get_instance(False)
        self.bridge = 'br-int'

    @log_decorator.log
    def vif_plugged(self, mac_address, ip_address_prefix, localport, label):
        (ovs_port_from_vm, localport_match,
         push_vlan_action, port_unplug_action, port_name) = (
            self._get_ovs_port_specifics(localport)
        )
        local_route = remote_routes.LocalLabeledRoute(id=mac_address, dest_ip=ip_address_prefix, port=port_name,
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
        remote_route = remote_routes.RemoteLabeledRoute(id=route_id, destination=prefix, label=label, nexthop=remote_pe)
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

    def _get_ovs_port_specifics(self, localport):
        # Returns a tuple of:
        # - OVS port numbers:
        #     - First port number is the port for traffic from the VM.
        #     - Second port number is the port for traffic to the VM.
        # - OVS actions and rules, based on whether or not a vlan is specified
        #   in localport:
        #     - OVS port match rule
        #     - OVS push vlan action
        #     - OVS strip vlan action
        # - Port unplug action
        #
        # For OVS actions, if no VLAN is specified the localport match only
        # matches the OVS port and actions are empty strings.

        # Retrieve OVS port numbers and port unplug action
        try:
            port_unplug_action = None
            if ('ovs' in localport and localport['ovs']['plugged']):
                try:
                    port = localport['ovs']['port_number']
                except KeyError:
                    self.log.info("No OVS port number provided, trying to use"
                                  " a port name")
                    port = self.driver.find_ovs_port(
                        localport['ovs']['port_name'])
            else:
                port_name = ""
                try:
                    try:
                        port_name = localport['ovs']['port_name']
                    except KeyError as e:
                        port_name = localport['linuxif']
                except Exception:
                    raise Exception("Trying to find which port to plug, but no"
                                    " portname was provided")

                try:
                    port = self.driver.find_ovs_port(port_name)
                except Exception:
                    self._run_command("ovs-vsctl --may-exist add-port %s %s" %
                                      (self.bridge, port_name),
                                      run_as_root=True)
                    port = self.driver.find_ovs_port(port_name)
                self.log.debug("Corresponding port number: %s", port)

                # Set port unplug action
                port_unplug_action = "ovs-vsctl del-port %s %s" % (
                    self.bridge, port_name)

        except KeyError as e:
            self.log.error("Incomplete port specification: %s", e)
            raise Exception("Incomplete port specification: %s" % e)

        # try:
        #     port2vm = localport['ovs']['to_vm_port_number']
        # except KeyError:
        #     self.log.debug("No specific OVS port number provided for traffic "
        #                    "to VM, trying to use a port name")
        #     try:
        #         port2vm = self.driver.find_ovs_port(
        #             localport['ovs']['to_vm_port_name'])
        #     except KeyError:
        #         self.log.debug("No specific OVS port found for traffic to VM")
        #         port2vm = port

        # Create OVS actions
        try:
            localport_match, push_vlan_action = (
                "in_port=%s,dl_vlan=%d" % (
                    port, int(localport['ovs']['vlan'])),
                "push_vlan:0x8100,mod_vlan_vid:%d," % int(
                    localport['ovs']['vlan'])
            )
        except KeyError:
            localport_match, push_vlan_action = (
                "in_port=%s" % port,
                None
            )

        # return (port, port2vm, localport_match, push_vlan_action,
        #         port_unplug_action)
        return (port, localport_match, push_vlan_action,
                port_unplug_action, port_name)


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

    def find_ovs_port(self, dev_name):
        """Find OVS port number from port name"""

        (output, code) = self._run_command("ovs-vsctl get Interface %s "
                                           "ofport" % dev_name,
                                           run_as_root=True,
                                           acceptable_return_codes=[0, 1])
        if code == 1:
            raise Exception("OVS port not found for device %s, "
                            "(known by ovs-vsctl but not by ovs-ofctl?)"
                            % dev_name)
        else:
            try:
                port = int(output[0])
                if port == -1:
                    raise Exception("OVS port not found for device %s, (known"
                                    " by ovs-vsctl but not by ovs-ofctl?)"
                                    % dev_name)
                return port
            except Exception:
                raise Exception("OVS port not found for device %s" % dev_name)
