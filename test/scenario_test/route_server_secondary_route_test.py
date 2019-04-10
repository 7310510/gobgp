# Copyright (C) 2019 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

import sys
import time
import unittest
import inspect

from fabric.api import local
import nose
from nose.tools import (
    assert_true,
    assert_false,
)

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import (
    Bridge,
    BGP_FSM_ESTABLISHED,
    BGP_ATTR_TYPE_COMMUNITIES,
    BGP_ATTR_TYPE_EXTENDED_COMMUNITIES,
)
from lib.gobgp import GoBGPContainer
from lib.quagga import QuaggaBGPContainer
from lib.exabgp import ExaBGPContainer


counter = 1
_SCENARIOS = {}

def register_scenario(cls):
    global counter
    _SCENARIOS[counter] = cls
    counter += 1


def lookup_scenario(name):
    for value in _SCENARIOS.values():
        if value.__name__ == name:
            return value
    return None


def wait_for(f, timeout=120):
    interval = 1
    count = 0
    while True:
        if f():
            return

        time.sleep(interval)
        count += interval
        if count >= timeout:
            raise Exception('timeout')


@register_scenario
class SecondaryRouteIPv4(unittest.TestCase):
    """
    No.1 IPv4 Secondary Route

    r1 : 192.168.0.0/16, Community[0:65004]
    r1': 192.168.0.0/16

    g1's export policy for q2: Not advertise routes which have Community[0:65004]

                 --------------------------------
    e1 ->(r1)->  | ->  q1-rib -> q1-adj-rib-out | ->(r1)->  q1
                 |                              |
    e2           | ->  q2-rib -> x              |           q2
                 --------------------------------
            |
        e2 advertise r1'
            |
            v
                 --------------------------------
    e1 ->(r1)->  | ->  q1-rib -> q1-adj-rib-out | ->(r1)->  q1
                 |                              |
    e2 ->(r1')-> | ->  q2-rib -> q2-adj-rib-out | ->(r1')-> q2
                 --------------------------------
    """

    @staticmethod
    def boot(env):
        gobgp_ctn_image_name = env.parser_option.gobgp_image
        log_level = env.parser_option.gobgp_log_level
        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=log_level)
        e1 = ExaBGPContainer(name='e1', asn=65001, router_id='192.168.0.2')
        e2 = ExaBGPContainer(name='e2', asn=65002, router_id='192.168.0.3')
        q1 = QuaggaBGPContainer(name='q1', asn=65003, router_id='192.168.0.4')
        q2 = QuaggaBGPContainer(name='q2', asn=65004, router_id='192.168.0.5')

        ctns = [g1, e1, e2, q1, q2]
        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        for q in [e1, e2, q1, q2]:
            g1.add_peer(q, is_rs_client=True, secondary_route=True)
            q.add_peer(g1)

        env.g1 = g1
        env.e1 = e1
        env.e2 = e2
        env.q1 = q1
        env.q2 = q2

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        e2 = env.e2
        q1 = env.q1
        q2 = env.q2

        cs0 = {'community-sets': [{'community-set-name': 'cs0',
                                   'community-list': ['0:65004']}]}
        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0', 'match-set-options': 'any'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        for c in [e1, e2, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

        e1.add_route('192.168.0.0/16', community=['0:65004'])

    @staticmethod
    def check(env):
        g1 = env.g1
        e1 = env.e1
        e2 = env.e2
        q1 = env.q1
        q2 = env.q2

        wait_for(lambda: len(g1.get_local_rib(q1)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 1)
        path = g1.get_adj_rib_out(q1, prefix='192.168.0.0/16')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(g1.get_local_rib(q2)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 0)

        wait_for(lambda: len(q1.get_global_rib()) == 1)
        path = q1.get_global_rib(prefix='192.168.0.0/16')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(q2.get_global_rib()) == 0)

    @staticmethod
    def setup2(env):
        env.e2.add_route('192.168.0.0/16')

    @staticmethod
    def check2(env):
        g1 = env.g1
        e1 = env.e1
        e2 = env.e2
        q1 = env.q1
        q2 = env.q2

        wait_for(lambda: len(g1.get_local_rib(q1)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 1)
        path = g1.get_adj_rib_out(q1, prefix='192.168.0.0/16')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(g1.get_local_rib(q2)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 1)
        path = g1.get_adj_rib_out(q2, prefix='192.168.0.0/16')[0]
        assert_true(path['aspath'] == [e2.asn])

        wait_for(lambda: len(q1.get_global_rib()) == 1)
        path = q1.get_global_rib(prefix='192.168.0.0/16')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(q2.get_global_rib()) == 1)
        path = q2.get_global_rib(prefix='192.168.0.0/16')[0]
        assert_true(path['aspath'] == [e2.asn])

    @staticmethod
    def executor(env):
        lookup_scenario("SecondaryRouteIPv4").boot(env)
        lookup_scenario("SecondaryRouteIPv4").setup(env)
        lookup_scenario("SecondaryRouteIPv4").check(env)
        lookup_scenario("SecondaryRouteIPv4").setup2(env)
        lookup_scenario("SecondaryRouteIPv4").check2(env)


@register_scenario
class SecondaryRouteIPv6(unittest.TestCase):
    """
    No.2 IPv6 Secondary Route

    r1 : 2001:db8::/64, Community[0:65004]
    r1': 2001:db8::/64

    g1's export policy for q2: Not advertise routes which have Community[0:65004]

                 --------------------------------
    e1 ->(r1)->  | ->  q1-rib -> q1-adj-rib-out | ->(r1)->  q1
                 |                              |
    e2           | ->  q2-rib -> x              |           q2
                 --------------------------------
            |
        e2 advertise r1'
            |
            v
                 --------------------------------
    e1 ->(r1)->  | ->  q1-rib -> q1-adj-rib-out | ->(r1)->  q1
                 |                              |
    e2 ->(r1')-> | ->  q2-rib -> q2-adj-rib-out | ->(r1')-> q2
                 --------------------------------
    """

    @staticmethod
    def boot(env):
        gobgp_ctn_image_name = env.parser_option.gobgp_image
        log_level = env.parser_option.gobgp_log_level
        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=log_level)
        e1 = ExaBGPContainer(name='e1', asn=65001, router_id='192.168.0.2')
        e2 = ExaBGPContainer(name='e2', asn=65002, router_id='192.168.0.3')
        q1 = QuaggaBGPContainer(name='q1', asn=65003, router_id='192.168.0.4')
        q2 = QuaggaBGPContainer(name='q2', asn=65004, router_id='192.168.0.5')

        ctns = [g1, e1, e2, q1, q2]
        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        br01 = Bridge(name='br01', subnet='2001::/96')
        [br01.addif(ctn) for ctn in ctns]

        for q in [e1, e2, q1, q2]:
            g1.add_peer(q, is_rs_client=True, secondary_route=True, bridge=br01.name, v6=True)
            q.add_peer(g1, bridge=br01.name, v6=True)

        env.g1 = g1
        env.e1 = e1
        env.e2 = e2
        env.q1 = q1
        env.q2 = q2

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        e2 = env.e2
        q1 = env.q1
        q2 = env.q2

        cs0 = {'community-sets': [{'community-set-name': 'cs0',
                                   'community-list': ['0:65004']}]}
        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0', 'match-set-options': 'any'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        for c in [e1, e2, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

        e1.add_route('2001:db8::/64', rf='ipv6', community=['0:65004'])

    @staticmethod
    def check(env):
        g1 = env.g1
        e1 = env.e1
        e2 = env.e2
        q1 = env.q1
        q2 = env.q2

        wait_for(lambda: len(g1.get_local_rib(q1, rf='ipv6')) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q1, rf='ipv6')) == 1)
        path = g1.get_adj_rib_out(q1, prefix='2001:db8::/64', rf='ipv6')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(g1.get_local_rib(q2, rf='ipv6')) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2, rf='ipv6')) == 0)

        wait_for(lambda: len(q1.get_global_rib(rf='ipv6')) == 1)
        path = q1.get_global_rib(prefix='2001:db8::/64', rf='ipv6')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(q2.get_global_rib(rf='ipv6')) == 0)

    @staticmethod
    def setup2(env):
        env.e2.add_route('2001:db8::/64', rf='ipv6')

    @staticmethod
    def check2(env):
        g1 = env.g1
        e1 = env.e1
        e2 = env.e2
        q1 = env.q1
        q2 = env.q2

        wait_for(lambda: len(g1.get_local_rib(q1, rf='ipv6')) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q1, rf='ipv6')) == 1)
        path = g1.get_adj_rib_out(q1, prefix='2001:db8::/64', rf='ipv6')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(g1.get_local_rib(q2, rf='ipv6')) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2, rf='ipv6')) == 1)
        path = g1.get_adj_rib_out(q2, prefix='2001:db8::/64', rf='ipv6')[0]
        assert_true(path['aspath'] == [e2.asn])

        wait_for(lambda: len(q1.get_global_rib(rf='ipv6')) == 1)
        path = q1.get_global_rib(prefix='2001:db8::/64', rf='ipv6')[0]
        assert_true(path['aspath'] == [e1.asn])

        wait_for(lambda: len(q2.get_global_rib(rf='ipv6')) == 1)
        path = q2.get_global_rib(prefix='2001:db8::/64', rf='ipv6')[0]
        assert_true(path['aspath'] == [e2.asn])

    @staticmethod
    def executor(env):
        lookup_scenario("SecondaryRouteIPv6").boot(env)
        lookup_scenario("SecondaryRouteIPv6").setup(env)
        lookup_scenario("SecondaryRouteIPv6").check(env)
        lookup_scenario("SecondaryRouteIPv6").setup2(env)
        lookup_scenario("SecondaryRouteIPv6").check2(env)


class TestGoBGPBase():

    wait_per_retry = 5
    retry_limit = 10

    @classmethod
    def setUpClass(cls):
        idx = parser_option.test_index
        base.TEST_PREFIX = parser_option.test_prefix
        cls.parser_option = parser_option
        cls.executors = []
        if idx == 0:
            print 'unset test-index. run all test sequential'
            for _, v in _SCENARIOS.items():
                for k, m in inspect.getmembers(v, inspect.isfunction):
                    if k == 'executor':
                        cls.executor = m
                cls.executors.append(cls.executor)
        elif idx not in _SCENARIOS:
            print 'invalid test-index. # of scenarios: {0}'.format(len(_SCENARIOS))
            sys.exit(1)
        else:
            for k, m in inspect.getmembers(_SCENARIOS[idx], inspect.isfunction):
                if k == 'executor':
                    cls.executor = m
            cls.executors.append(cls.executor)

    def test(self):
        for e in self.executors:
            yield e


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) is not 0:
        print "docker not found"
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])