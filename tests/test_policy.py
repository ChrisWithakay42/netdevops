"""Security invariants for the home network, asserted against network/rules.yml.

Skipped until network/ is populated (`netdevops import <export.xml>`). The
evaluator fires a simulated packet through the whole ruleset, so these assert
outcomes rather than individual rules: reorganise the rules freely and they
stay green as long as the behaviour is unchanged.

    Packet(in_interface, source_ip, destination_ip, protocol="tcp", destination_port=None)

    def test_iot_cannot_reach_lan(evaluator):
        packet = Packet("opt1", "192.168.20.50", "192.168.1.10", "tcp", 445)
        assert not evaluator.evaluate(packet).allowed
"""


def test_deny_rules_are_logged(intent):
    """A blocked device should turn up in Live View instead of failing silently."""
    unlogged_denies = [
        rule
        for rule in intent.rules
        if rule.enabled and rule.action in ("block", "reject") and not rule.log
    ]
    assert not unlogged_denies, [rule.description for rule in unlogged_denies]


def test_multi_network_source_matches_any_listed_network():
    from netdevops.models import Intent, Interface, Rule
    from netdevops.policy import Packet, PolicyEvaluator

    intent = Intent(
        interfaces=[
            Interface(token="lan", cidr="10.0.1.0/24", address="10.0.1.1"),
            Interface(token="opt1", cidr="10.0.2.0/24", address="10.0.2.1"),
        ],
        rules=[Rule(
            description="multi", interface=["opt1"], sequence=1, action="pass",
            source_net="lan,opt1", destination_port="443", log=True,
        )],
    )
    evaluator = PolicyEvaluator(intent)
    assert evaluator.evaluate(Packet("opt1", "10.0.2.5", "1.1.1.1", "tcp", 443)).allowed
    assert not evaluator.evaluate(Packet("opt1", "10.0.9.5", "1.1.1.1", "tcp", 443)).allowed


def test_interface_net_includes_virtual_ip_subnets():
    # pf's (if:network) covers every address on the interface; verified live
    # on 26.7 as (vlan0.50:network:2) after adding a /24 VIP
    from netdevops.models import Intent, Interface, Rule, VirtualIP
    from netdevops.policy import Packet, PolicyEvaluator

    intent = Intent(
        interfaces=[Interface(token="opt2", cidr="192.168.20.0/27", address="192.168.20.1")],
        virtual_ips=[
            VirtualIP(address="10.20.20.1/24", interface="opt2"),
            VirtualIP(address="10.20.0.53/32", interface="lo0"),
        ],
        rules=[Rule(
            description="out", interface=["opt2"], sequence=1, action="pass",
            source_net="opt2", destination_port="443", log=True,
        )],
    )
    evaluator = PolicyEvaluator(intent)
    assert evaluator.evaluate(Packet("opt2", "10.20.20.10", "1.1.1.1", "tcp", 443)).allowed
    assert evaluator.evaluate(Packet("opt2", "192.168.20.5", "1.1.1.1", "tcp", 443)).allowed
    assert not evaluator.evaluate(Packet("opt2", "10.30.0.1", "1.1.1.1", "tcp", 443)).allowed
