import json
from random import randint
from unittest import TestCase

from nftables import Nftables
from pqconnect.nft import NfqueueBuilder


class NfqueueBuilderTest(TestCase):
    def setUp(self) -> None:
        self.nft = Nftables()
        self.nft.set_json_output(True)
        self.table_name = "test"
        self.builder = NfqueueBuilder(self.table_name)

    def tearDown(self) -> None:
        pass

    def test_add_table(self) -> None:
        """Tests that a table is correctly added to the ruleset. Fails if an
        error is thrown during table creation or if the table cannot be found
        in the ruleset

        """
        try:
            self.builder._add_table(self.table_name)

        except Exception as e:
            self.assertTrue(False, e)

        success = False

        try:
            ruleset = dict(json.loads(self.nft.cmd("list ruleset")[1]))[
                "nftables"
            ]
            for rule in ruleset:
                if "table" in rule.keys():
                    if self.table_name == rule["table"]["name"]:
                        success = True
                        break

            self.assertTrue(success)

        except Exception:
            pass

        finally:
            self.nft.cmd(f"delete table inet {self.table_name}")

    def test_add_chain(self) -> None:
        """Tests that input chain is correctly added to the test table. Fails
        if an error is thrown during chain creation or if the chain cannot be
        found in the ruleset

        """
        try:
            self.builder._add_table(self.table_name)
            self.builder._add_input_filter_chain(self.table_name, 0)

        except Exception as e:
            self.nft.cmd(f"delete table inet {self.table_name}")
            self.assertTrue(False, e)

        success = False

        try:
            ruleset = dict(json.loads(self.nft.cmd("list ruleset")[1]))[
                "nftables"
            ]
            for rule in ruleset:
                if "chain" in rule.keys():
                    if (
                        "input" == rule["chain"]["name"]
                        and self.table_name == rule["chain"]["table"]
                    ):
                        success = True
                        break

            self.assertTrue(success)

        except Exception:
            pass

        finally:
            self.nft.cmd(f"delete table inet {self.table_name}")

    def test_add_queue_rule(self) -> None:
        """Tests that queue rule is correctly added to the test table input
        chain. Fails if an error is thrown during rule creation or if the rule
        cannot be found in the ruleset

        """
        queue_num = randint(0, 100)

        try:
            self.builder._add_table(self.table_name)
            self.builder._add_input_filter_chain(self.table_name, 0)
            self.builder._add_dns_queue_rule(self.table_name, queue_num)

        except Exception as e:
            self.nft.cmd(f"delete table inet {self.table_name}")
            self.assertTrue(False, e)

        success = False

        try:
            rules = dict(json.loads(self.nft.cmd("list ruleset")[1]))[
                "nftables"
            ]
            self.assertTrue(all([isinstance(rule, dict) for rule in rules]))
            for rule in rules:
                if isinstance(rule, dict) and "rule" in rule.keys():
                    if (
                        "input" == rule["rule"]["chain"]
                        and self.table_name == rule["rule"]["table"]
                        and {"queue": {"num": queue_num}}
                        in rule["rule"]["expr"]
                        and {
                            "match": {
                                "op": "==",
                                "left": {
                                    "payload": {
                                        "protocol": "udp",
                                        "field": "sport",
                                    }
                                },
                                "right": 53,
                            }
                        }
                        in rule["rule"]["expr"]
                    ):
                        success = True
                        break

            self.assertTrue(success)

        except Exception as e:
            self.assertTrue(False, e)

        finally:
            self.nft.cmd(f"delete table inet {self.table_name}")

    def test_build(self) -> None:
        """tests the full build method"""
        try:
            queue_num = self.builder.build()

            success = False

            rules = dict(json.loads(self.nft.cmd("list ruleset")[1]))[
                "nftables"
            ]
            self.assertTrue(all([isinstance(rule, dict) for rule in rules]))
            for rule in rules:
                if "rule" in rule.keys():
                    if (
                        "input" == rule["rule"]["chain"]
                        and self.builder.table_name == rule["rule"]["table"]
                        and {"queue": {"num": queue_num}}
                        in rule["rule"]["expr"]
                        and {
                            "match": {
                                "op": "==",
                                "left": {
                                    "payload": {
                                        "protocol": "udp",
                                        "field": "sport",
                                    }
                                },
                                "right": 53,
                            }
                        }
                        in rule["rule"]["expr"]
                    ):
                        success = True
                        break

            self.assertTrue(success)

        except Exception as e:
            self.assertTrue(False, e)

        finally:
            self.builder.tear_down()
