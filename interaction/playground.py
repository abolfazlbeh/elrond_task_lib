import logging
from argparse import ArgumentParser
from pathlib import Path

from erdpy import config
from erdpy.accounts import Account
from erdpy.contracts import SmartContract
from erdpy.environments import TestnetEnvironment
from erdpy.projects import ProjectRust
from erdpy.proxy import ElrondProxy

try:
    from sha3 import keccak_256
except ImportError:
    from sha3 import sha3_256 as keccak_256

logger = logging.getLogger("examples")

class MerkleTree:
    nodes = []
    leaves = []

    def __init__(self):
        pass

    def add(self, obj):
        self.leaves.append(obj)
        self.nodes.clear()

        self.build_tree()

    def build_tree(self, sort):
        self.nodes = [keccak_256(x).hexdigest() for x in self.leaves]
        self.nodes.sort()
        self._build_from_leaves(sort)

    def _build_upper_level(self, nodes, sort: bool):
        row = []
        i = 0

        while i < len(nodes):
            if i + 1 < len(nodes):
                row.append(self._hash_internal_nodes(nodes[i], nodes[i + 1], sort))
                i += 2
            else:
                row.append(self._hash_internal_nodes(nodes[i], None, sort))
                i += 1

        if len(row) > 1 and len(row) % 2 != 0:
            row = row + [row[-1],]

        return row

    def _build_internal_nodes(self, start, sort):
        parents = self._build_upper_level(self.nodes[start:], sort)
        self.nodes = parents + self.nodes

        while len(parents) > 1:
            parents = self._build_upper_level(parents, sort)
            self.nodes = parents + self.nodes

        self.nodes.insert(0, parents[0])

    def _build_from_leaves(self, sort):
        self._build_internal_nodes(0, sort)

    def _hash_internal_nodes(self, left, right, sort: bool):
        result = left
        if right is not None:
            p = [left, right]

            if sort:
                p.sort()
            t = ''.join(p)

            result = keccak_256(t).hexdigest()

        return result

    def root_hash_str(self):
        return self.nodes[0]

    def get_leaves(self):
        return self.nodes[-len(self.leaves):]

    def proof(self, leaf, index=-1):
        if index == -1:
            hashed = keccak_256(leaf).hexdigest()
            if hashed in self.nodes[-len(self.leaves):]:
                index = self.nodes.index(hashed, len(self.nodes) - len(self.leaves))

        if index == -1:
            return []

        proof = []
        while index != 0:
            is_right_node = index % 2
            pair_index = index - 1 if is_right_node == 0 else index + 1

            if 0 <= pair_index < len(self.nodes):
                proof.append(self.nodes[pair_index])

            index = (index - 1) / 2

        return proof


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("--proxy", help="Proxy URL", default=config.get_proxy())
    parser.add_argument("--contract", help="Existing contract address")
    parser.add_argument("--pem", help="PEM file", required=True)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    proxy = ElrondProxy(args.proxy)
    network = proxy.get_network_config()
    chain = network.chain_id
    gas_price = network.min_gas_price
    tx_version = network.min_tx_version

    environment = TestnetEnvironment(args.proxy)
    user = Account(pem_file=args.pem)

    project = ProjectRust(Path(__file__).parent.parent)
    bytecode = project.get_bytecode()

    # We initialize the smart contract with an actual address if IF was previously deployed,
    # so that we can start to interact with it ("query_flow")
    contract = SmartContract(address=args.contract)

    # make merkletree instance
    mt = MerkleTree()

    def deploy_flow():
        global contract

        # For deploy, we initialize the smart contract with the compiled bytecode
        contract = SmartContract(bytecode=bytecode)

        tx, address = environment.deploy_contract(
            contract=contract,
            owner=user,
            arguments=["0x0064"],
            gas_price=gas_price,
            gas_limit=50000000,
            value=None,
            chain=chain,
            version=tx_version
        )

        logger.info("Tx hash: %s", tx)
        logger.info("Contract address: %s", address.bech32())

    def get_state_flow():
        answer = environment.query_contract(contract, "get_state")
        logger.info(f"Answer: {answer}")

    def get_root_hash_flow():
        answer = environment.query_contract(contract, "get_root_hash")
        logger.info(f"Answer: {answer}")

    def set_hash_root_flow():
        tx = environment.execute_contract(
            contract=contract,
            caller=user,
            function="update_root_hash",
            arguments=[mt.root_hash_str(), ],
            gas_price=gas_price,
            gas_limit=50000000,
            value=None,
            chain=chain,
            version=tx_version
        )
        logger.info("Tx hash: %s (Update Root Hash)", tx)

    def set_state_flow(address, pem_path, state):
        # TODO: here must get proofs from merkletree
        proofs = mt.proof(address, -1)
        caller_user = Account(pem_file=pem_path)

        tx = environment.execute_contract(
            contract=contract,
            caller=caller_user,
            function="set_state",
            arguments=[state, proofs, ],
            gas_price=gas_price,
            gas_limit=50000000,
            value=None,
            chain=chain,
            version=tx_version
        )
        logger.info("Tx hash: %s (Set State)", tx)


    def add_address(address):
        # TODO: Create a merkle tree
        mt.add(address)
        logger.info(f"Address added: {address}")
        logger.info(f"New Root Hash: {mt.root_hash_str()}")

    user.sync_nonce(ElrondProxy(args.proxy))

    while True:
        print("Let's run a flow.")
        print("1. Deploy")
        print("2. Add Address()")
        print("3. Query get_state()")
        print("4. Query get_root_hash()")
        print("5. Exec update_root_hash()")
        print("6. Exec set_state()")

        try:
            choice = int(input("Choose:\n"))
        except Exception:
            break

        if choice == 1:
            environment.run_flow(deploy_flow)
            user.nonce += 1
        elif choice == 2:
            addr = input("Add Address To Whitelist:")
            environment.run_flow(lambda: add_address(addr))
        elif choice == 3:
            environment.run_flow(get_state_flow)
            user.nonce += 1
        elif choice == 4:
            environment.run_flow(get_root_hash_flow)
            user.nonce += 1
        elif choice == 5:
            environment.run_flow(set_hash_root_flow)
            user.nonce += 1
        elif choice == 6:
            number = int(input("Type New State: "))
            address = input("Caller Address: ")
            pem_path = input("Caller Wallet PEM Path: ")
            environment.run_flow(lambda: set_state_flow(address, pem_path, number))
            user.nonce += 1

