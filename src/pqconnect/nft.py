from sys import exit as bye

from netfilterqueue import NetfilterQueue
from nftables import Nftables

from .common.constants import NUM_QUEUE_ATTEMPTS
from .common.util import ExistingNftableError, NftablesError
from .log import logger


class NfqueueBuilder:
    """Manages the nftables state that allows netfilterqueue to proxy DNS
    responses to the client.

    TODO rename since has nothing to do with DNS really
    """

    def __init__(self, table_name: str):
        self.nfqueue = NetfilterQueue()
        self.nft = Nftables()
        self.table_name = table_name

        # Set queue_num initially to 0.
        self.queue_num = 0

    def _add_table(self, table_name: str) -> None:
        """Adds a new table to the nftables ruleset with name table_name, or
        raises an NftablesError

        """
        rc, _, error = self.nft.cmd(f"create table inet {table_name}")

        if rc != 0 or error:
            # An error is probably raised either because the table already
            # exists or we don't have cap_net_admin permissions.

            if "File exists" in error:
                raise ExistingNftableError

            elif "Operation not permitted" in error:
                raise PermissionError

            else:
                raise NftablesError

    def _add_input_filter_chain(self, table_name: str, priority: int) -> None:
        """Adds a new input filter chain to the table `table_name` or raises an
        NftablesError.

        """
        rc, _, error = self.nft.cmd(
            f"add chain inet {table_name} input {{ "
            f"type filter hook input priority {priority}; }}"
        )
        if rc != 0 or error:
            raise NftablesError

    def _add_dns_queue_rule(self, table_name: str, queue_num: int) -> None:
        """Adds a new rule to the pqconnect nftables table to queue all UDP
        packets with source port 53 to the specified `queue_num`.

        This will intercept any UDP packet with source port 53, regardless of
        source IP. DNS responses coming from other source ports (for example,
        if using DoH) will be missed. Dealing with this scenario is a TODO.

        """
        rc, _, error = self.nft.cmd(
            f"add rule inet {table_name} "
            f"input udp sport 53 queue num {queue_num}"
        )
        if rc != 0 or error:
            raise NftablesError

    def _delete_nftables_table(self, table_name: str) -> str:
        """Tries to delete the table `table_name`. Returns the error, which
        should usually be the empty string. Does not raise an exception.

        """

        rc, _, error = self.nft.cmd(f"delete table inet {table_name}")

        return error

    def tear_down(self) -> None:
        """Deletes the table and associated rules. Errors are ignored"""

        self._delete_nftables_table(self.table_name)

    def build(self, delete_existing: bool = True) -> int:
        """Create new table "pqconnect-filter" containing an input chain and
        rule that queues incoming DNS packets to netfilter_queue for NAT. The
        chain priority should be less than 0 so that it's handled before the
        rest of the input filter hook is executed. Setting priority of -10
        allows admins to prioritize other pre-filter chains relating to DNS
        they may have to occur after PQConnect performs NAT on server
        responses.

        Returns the queue number if successful

        """
        if delete_existing:
            # Delete table if it already exists
            self.tear_down()

        # Add new nftables table
        try:
            self._add_table(self.table_name)

        except ExistingNftableError:
            logger.exception(f"Table {self.table_name} already exists.")
            self.tear_down()
            bye(1)

        # Add input chain, use priority -10 just to place before normal input
        # filtering
        try:
            self._add_input_filter_chain(self.table_name, -10)

        except NftablesError as e:
            self._delete_nftables_table(self.table_name)
            logger.exception(
                f"Could not add rule to nftables ruleset. Exiting..."
            )
            bye(2)

        # Add queue rule. In case there is already a netfilter_queue running
        # for a different process we try a range of NUM_QUEUE_ATTEMPTS queue
        # numbers and stop when we are successful
        for i in range(NUM_QUEUE_ATTEMPTS):
            err = None
            try:
                self._add_dns_queue_rule(self.table_name, queue_num=i)
                self.queue_num = i
                return self.queue_num

            except NftablesError as e:
                # continue in the loop, but save the error for later in case
                # this fails
                err = e

        # loop was not interrupted, i.e. we could not add the rule. Exit
        else:
            self.tear_down()
            logger.error(f"Could not set up queue rule: {err}. Exiting...")
            bye(3)
