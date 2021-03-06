# Copyright (c) 2016 Orange.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import networking_bgpvpn

from neutron.common import utils
from neutron.tests.fullstack.resources import config as neutron_cfg

BGPVPN_SERVICE = 'bgpvpn'

BGPVPN_PROVIDER = ('BGPVPN:BaGPipe:networking_bgpvpn.neutron.services.'
                   'service_drivers.bagpipe.bagpipe.BaGPipeBGPVPNDriver:'
                   'default')


class NeutronConfigFixture(neutron_cfg.NeutronConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir,
                 connection, rabbitmq_environment):
        super(NeutronConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, connection, rabbitmq_environment)

        if env_desc.bgpvpn:
            self.config['oslo_policy']['policy_dirs'] = (
                os.path.join(networking_bgpvpn.__path__[0],
                             '..', 'etc', 'neutron', 'policy.d')
            )


class OVSConfigFixture(neutron_cfg.OVSConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, local_ip, mpls_bridge):
        super(OVSConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, local_ip)

        agent_exts = self.config['agent'].get('extensions', '').split(',')
        agent_exts.append('bagpipe_bgpvpn')

        self.config['agent']['extensions'] = ','.join(filter(None, agent_exts))

        self.config.update({
            'bagpipe': {
                'bagpipe_bgp_ip': local_ip,
                'mpls_bridge': mpls_bridge,
                'tun_to_mpls_peer_patch_port':
                    self._generate_tun_to_mpls_peer(),
                'tun_from_mpls_peer_patch_port':
                    self._generate_tun_from_mpls_peer(),
                'mpls_to_tun_peer_patch_port':
                    self._generate_mpls_to_tun_peer(),
                'mpls_from_tun_peer_patch_port':
                    self._generate_mpls_from_tun_peer(),
            }
        })

    def _generate_tun_to_mpls_peer(self):
        return utils.get_rand_device_name(prefix='to-mpls')

    def _generate_tun_from_mpls_peer(self):
        return utils.get_rand_device_name(prefix='from-mpls')

    def _generate_mpls_to_tun_peer(self):
        return utils.get_rand_device_name(prefix='to-tun')

    def _generate_mpls_from_tun_peer(self):
        return utils.get_rand_device_name(prefix='from-tun')


class BGPVPNProviderConfigFixture(neutron_cfg.ConfigFixture):
    def __init__(self, env_desc, host_desc, temp_dir):
        super(BGPVPNProviderConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='networking_bgpvpn.conf')

        self.config.update({
            'service_providers': {
                'service_provider': BGPVPN_PROVIDER
            }
        })
