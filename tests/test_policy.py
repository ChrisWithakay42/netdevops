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
