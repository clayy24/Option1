#!/usr/bin/env python3

import hashlib
import uuid
import time
import struct
import argparse
import datetime
import os

class BlockchainBlock:
    def __init__(self):
        self.previous_hash = b'\x00' * 32
        self.timestamp = time.time()
        self.case_id = uuid.UUID(int=0)
        self.evidence_item_id = 0
        self.state = "INITIAL"
        self.handler_name = None
        self.organization_name = None
        self.data_length = 14
        self.data = "Initial block"

    @classmethod
    def initialize_blockchain(cls):
        if cls.blockchain_file_exists():
            BlockchainBlock.verify()
            print("Blockchain file found with INITIAL block.")
        else:
            initial_block = BlockchainBlock()
            initial_block.write_to_file()
            print("Blockchain file not found. Created INITIAL block.")
    
    @classmethod
    def blockchain_file_exists(cls):
        return os.path.exists(filename)

    def calculate_hash(self):
        return hashlib.sha256(self.to_binary()).hexdigest()
    
    def getTime(self):
        a = str(datetime.datetime.utcfromtimestamp(self.timestamp))
        a = a.replace(' ', "T")
        a = a + "Z"
        return a
    
    def display_block(self):
        print(f"Previous Hash: {self.previous_hash or None}")
        print(f"Timestamp: {datetime.datetime.utcfromtimestamp(self.timestamp)}")
        print(f"Case ID: {self.case_id}")
        print(f"Evidence Item ID: {self.evidence_item_id}")
        print(f"State: {self.state}")
        print(f"Handler Name: {self.handler_name}")
        print(f"Organization Name: {self.organization_name}")
        print(f"Data Length: {self.data_length} bytes")
        print(f"Data: {self.data}")
        print("Hash: " + self.calculate_hash())

    def to_binary(self):
        try:
            self.previous_hash = bytes.fromhex(self.previous_hash)
        except TypeError:
            pass

        timestamp_bytes = struct.pack("d", self.timestamp)

        # Convert case_id to bytes or use null bytes if it's None
        case_id_bytes = self.case_id.bytes

        evidence_item_id_bytes = struct.pack("I", self.evidence_item_id) if self.evidence_item_id is not None else b'\x00' * 4

        # Convert state to bytes or use null bytes if it's None
        state_bytes = struct.pack("12s", self.state.encode('utf-8'))

        # Convert handler_name to bytes or use null bytes if it's None
        handler_name_bytes = struct.pack("20s", self.handler_name.encode('utf-8')) if self.handler_name else b'\x00' * 20

        # Convert organization_name to bytes or use null bytes if it's None
        organization_name_bytes = struct.pack("20s", self.organization_name.encode('utf-8')) if self.organization_name else b'\x00' * 20

        data_length_bytes = struct.pack("I", self.data_length)

        # Convert data to bytes or use null bytes if it's None
        data_bytes = struct.pack(f"{self.data_length}s", self.data.encode())


        return (
            self.previous_hash +
            timestamp_bytes +
            case_id_bytes +
            evidence_item_id_bytes +
            state_bytes +
            handler_name_bytes +
            organization_name_bytes +
            data_length_bytes +
            data_bytes
        )

    def write_to_file(self):
        with open(filename, "ab") as file:
            file.write(self.to_binary())

    @classmethod
    def from_binary(cls, block_binary):
        block = cls()
        (
            block.previous_hash,
            block.timestamp,
            block.case_id,
            block.evidence_item_id,
            block.state,
            block.handler_name,
            block.organization_name,
            block.data_length,
        ) = struct.unpack("32s d 16s I 12s 20s 20s I", block_binary[:116])

        block.previous_hash = block.previous_hash.hex()
        block.case_id = uuid.UUID(block.case_id.hex())
        block.state = block.state.rstrip(b'\x00').decode()
        block.handler_name = block.handler_name.decode()
        block.organization_name = block.organization_name.decode()
        block.data = block_binary[116:116 + block.data_length].decode()
        return block

    @classmethod
    def read_blocks_from_file(cls):
        if not BlockchainBlock.blockchain_file_exists():
            display_error(1)

        blocks = []
        next_block_offset = 0
        with open(filename, "rb") as file:
            while True:
                file.seek(0x70 + next_block_offset)
                data_length_binary = file.read(4)
                if not data_length_binary:
                    break

                data_length = struct.unpack("I", data_length_binary)[0]
                file.seek(next_block_offset)
                block_binary = file.read(0x74 + data_length)  # Adjust the size based on the maximum expected block size
                if len(block_binary) != 0x74 + data_length:
                    display_error(11)
                    break

                block = cls.from_binary(block_binary)
                blocks.append(block)
                next_block_offset += data_length + 4 + 0x70
        return blocks
    
    @classmethod
    def item_exists(cls, item_id):
        blocks = BlockchainBlock.read_blocks_from_file()

        for block in blocks:
            if block.evidence_item_id == item_id:
                return True
        return False
    
    @classmethod
    def valid_case_id(cls, case_id):
        if isinstance(case_id, uuid.UUID):
            return case_id
        try:
            return uuid.UUID(case_id)
        except ValueError:
            display_error(4)

    @classmethod
    def valid_item_id(cls, item_id):
        try:
            return int(item_id)
        except ValueError:
            display_error(3)

    @classmethod
    def show_cases(cls):
        blocks = BlockchainBlock.read_blocks_from_file()
        case_ids = []

        for block in blocks[1:]:
            if block.case_id not in case_ids:
                case_ids.append(block.case_id)

        for case_id in case_ids:
            print(case_id)

    @classmethod
    def show_items(cls, case_id):
        case_id = BlockchainBlock.valid_case_id(case_id)

        blocks = BlockchainBlock.read_blocks_from_file()
        items = []

        for block in blocks:
            if block.case_id == case_id and block.evidence_item_id not in items:
                items.append(block.evidence_item_id)
        
        for item in items:
            print(item)

    @classmethod
    def show_history(cls, item_id, num_entries, reverse, case_id):
        blocks = BlockchainBlock.read_blocks_from_file()
        
        if num_entries is None:
            num_entries = 999
        else:
            num_entries = int(num_entries)
        
        if item_id is not None:
            item_id = BlockchainBlock.valid_item_id(item_id)
        
        if case_id is not None:
            case_id = BlockchainBlock.valid_case_id(case_id)
            
        # item_id = BlockchainBlock.valid_item_id(item_id)
        counter = 0


        print_blocks = []

        # print("len blocks: ", len(blocks))
        
        for block in reversed(blocks):
            if (((block.evidence_item_id == item_id) or (item_id is None)) and ((block.case_id == case_id) or (case_id is None))):
                counter += 1
                print_blocks.append(block)
            if counter >= num_entries:
                break
        
        if not reverse:
            for block in reversed(print_blocks):
                print("Case:", block.case_id)
                print("Item:", block.evidence_item_id)
                print("Action:", block.state)
                print("Time:", block.getTime())
                print("")
        else:
            for block in (print_blocks):
                print("Case:", block.case_id)
                print("Item:", block.evidence_item_id)
                print("Action:", block.state)
                print("Time:", block.getTime())
                print("")

    @classmethod
    def checkout(cls, item_id, owner, org):
        item_id = BlockchainBlock.valid_item_id(item_id)
        blocks = BlockchainBlock.read_blocks_from_file()
        found = False

        for block in reversed(blocks):
            if block.evidence_item_id == item_id:
                found = True
                if block.state in ["CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]:
                    display_error(5)
                else:
                    new_block = BlockchainBlock()
                    b1 = BlockchainBlock.read_blocks_from_file()
                    new_block.previous_hash = b1[-1].calculate_hash()
                    new_block.case_id = block.case_id
                    new_block.evidence_item_id = item_id
                    new_block.state = "CHECKEDOUT"
                    new_block.data = ""
                    new_block.data_length = len(new_block.data)
                    new_block.handler_name = owner[:20]
                    new_block.organization_name = org[:20]

                    new_block.write_to_file()

                    print("Case:", block.case_id)
                    print("Checked out item:", item_id)
                    print("\tStatus:", new_block.state)
                    print("\tTime of action:", new_block.getTime())
                    break
        if not found:
            display_error(9)

    @classmethod
    def checkin(cls, item_id, name, org):
        item_id = BlockchainBlock.valid_item_id(item_id)
        blocks = BlockchainBlock.read_blocks_from_file()
        found = False

        for block in reversed(blocks):
            if block.evidence_item_id == item_id:
                found = True
                if block.state in ["CHECKEDIN", "DISPOSED", "DESTROYED", "RELEASED"]:
                    display_error(5)
                else:
                    new_block = BlockchainBlock()
                    b1 = BlockchainBlock.read_blocks_from_file()
                    new_block.previous_hash = b1[-1].calculate_hash()
                    new_block.case_id = block.case_id
                    new_block.evidence_item_id = item_id
                    new_block.state = "CHECKEDIN"
                    new_block.data = ""
                    new_block.data_length = len(new_block.data)
                    new_block.handler_name = name[:19]
                    new_block.organization_name = org[:19]

                    new_block.write_to_file()

                    print("Case:", block.case_id)
                    print("Checked out item:", item_id)
                    print("\tStatus:", new_block.state)
                    print("\tTime of action:", new_block.getTime())
                    break

        if not found:
            display_error(9)

    @classmethod
    def remove(cls, item_id, reason, owner=None):
        item_id = BlockchainBlock.valid_item_id(item_id)
        blocks = BlockchainBlock.read_blocks_from_file()
        found = False

        for block in reversed(blocks):
            if block.evidence_item_id == item_id:
                found = True
                if block.state in ["CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]:
                    display_error(5)
                else:
                    new_block = BlockchainBlock()
                    b1 = BlockchainBlock.read_blocks_from_file()
                    new_block.previous_hash = b1[-1].calculate_hash()
                    new_block.case_id = block.case_id
                    new_block.evidence_item_id = item_id
                    new_block.state = reason
                    new_block.data = ""
                    new_block.data_length = len(new_block.data)
                    new_block.handler_name = block.handler_name if owner is None else owner[:19]
                    new_block.organization_name = block.organization_name

                    new_block.write_to_file()

                    print("Case:", block.case_id)
                    print("Removed item:", item_id)
                    print("\tStatus:", new_block.state)
                    print("\tOwner info:", new_block.handler_name)
                    print("\tTime of action:", new_block.getTime())
                    break
        if not found:
            display_error(9)

    @classmethod
    def verify(cls):
        blocks = BlockchainBlock.read_blocks_from_file()
        state = "CLEAN"
        previous_block = None
        previous_parents = []
        removed_ids = []

        init = BlockchainBlock()

        if blocks[0].state != init.state:
            display_error(10)

        print("Transactions in blockchain:", len(blocks))

        for block in blocks:
            # check for valid checksums
            if previous_block is not None:
                if previous_block.calculate_hash() != block.previous_hash:
                    state = "ERROR"
                    print(f"State of blockchain: {state}")
                    print("Bad block:", block.calculate_hash())
                    print("Block contents do not match block checksum")
                    display_error(8)
                
            # check for duplicate parents
            if block.previous_hash in previous_parents:
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print("Bad block:", block.calculate_hash())
                print("Parent block:", block.previous_hash)
                print("Two blocks were found with the same parent.")
                display_error(8)
            else:
                previous_parents.append(block.previous_hash)
                
            # check for check in/out after removal
            if block.evidence_item_id in removed_ids:
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print("Bad block:", block.calculate_hash())
                print("Item checked out or checked in after removal from chain.")
                display_error(8)
            if block.state in ["DISPOSED", "DESTROYED", "RELEASED"]:
                removed_ids.append(block.evidence_item_id)

            # check for parent
            if block.previous_hash == None:
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print("Bad block:", block.calculate_hash())
                print("Parent block: NOT FOUND")
                display_error(8)
            previous_block = block

        if state == "CLEAN":
            print(f"State of blockchjain: {state}")

def add_evidence_to_blockchain(case_id, item_ids, name, org):
    if not BlockchainBlock.blockchain_file_exists():
        BlockchainBlock.initialize_blockchain()

    case_id = BlockchainBlock.valid_case_id(case_id)

    # Create a new block for each item_id
    for item_id in item_ids:

        item_id = BlockchainBlock.valid_item_id(item_id)

        if BlockchainBlock.item_exists(item_id):
            display_error(2)

        block = BlockchainBlock()

        b1 = BlockchainBlock.read_blocks_from_file()
        block.previous_hash = b1[-1].calculate_hash()
        block.case_id = case_id
        block.evidence_item_id = item_id
        block.state = "CHECKEDIN"
        block.data = ""
        block.data_length = len(block.data)
        block.handler_name = name[:20]
        block.organization_name = org[:20]

        block.write_to_file()

        print("Case: ", case_id)
        print("Added item: ", item_id)
        print("\tStatus: ", block.state)
        print("\tTime of action: ", block.getTime())
        
        

def display_error(exit_code):
    error_messages = {
        1: "No existing blockchain found.",
        2: "Evidence item with this ID already exists.",
        3: "Item ID must be an integer.",
        4: "Case ID must be a valid UUID.",
        5: "Item was not in the correct state for that action to be performed.",
        7: "Owner is required if removing item for being RELEASED",
        8: "Verification Error",
        9: "Tried to check in item before adding it",
        10: "Invalid Initial block",
        11: "Error: Incomplete block data in the file.",
    }

    print(f"Error ({exit_code}): {error_messages.get(exit_code, 'Unknown error')}")
    exit(exit_code)

if __name__ == "__main__":
    filename = os.environ.get("BCHOC_FILE_PATH", 'output')

    parser = argparse.ArgumentParser(description="Blockchain Evidence Item Management", add_help=False)
    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

    # Subparser for the 'add' command
    parser_add = subparsers.add_parser("add", help="Add a new evidence item to the blockchain", add_help=False)
    parser_add.add_argument("-c", "--case_id", required=True, help="Case identifier")
    parser_add.add_argument("-h", "--owner", help="Case identifier")
    parser_add.add_argument("-o", "--org", help="Case identifier")
    parser_add.add_argument("-i", "--item_id", nargs="+", required=True, help="Evidence item identifier(s)")


    parser_init = subparsers.add_parser("init", help="Initialize the blockchain")

    parser_show = subparsers.add_parser("show", help="Show cases or items")
    parser_show.add_argument("show_type", choices=["cases", "items", "all", "history"], help="Specify 'cases', 'items', 'history', or 'all'")
    parser_show.add_argument("-c", "--case_id", help="Case identifier (required for 'items')")
    parser_show.add_argument("-r", "--reverse", action="store_true", help="Case identifier (required for 'items')")
    parser_show.add_argument("-i", "--item_id", help="Item identifier")
    parser_show.add_argument("-n", "--num_entries", help="Shows {num_entries} number of block entries")

    parser_checkout = subparsers.add_parser("checkout", help="Checkout an evidence item", add_help=False)
    parser_checkout.add_argument("-i", "--item_id", type=int, required=True, help="Item identifier")
    parser_checkout.add_argument("-h", "--owner")
    parser_checkout.add_argument("-o", "--org")

    parser_checkin = subparsers.add_parser("checkin", help="Checkin an evidence item", add_help=False)
    parser_checkin.add_argument("-i", "--item_id", required=True, type=int, help="Item identifier")
    parser_checkin.add_argument("-h", "--owner", required=True, help="Handler name")
    parser_checkin.add_argument("-o", "--org", required=True, help="Organization name")

    parser_remove = subparsers.add_parser("remove", help="Prevents any further action from being taken on the evidence item specified")
    parser_remove.add_argument("-i", "--item_id", required=True, type=int, help="Item identifier")
    parser_remove.add_argument("-y", "--why", choices=["DISPOSED", "DESTROYED", "RELEASED"], required=True, help="Reason for the removal of the evidence item. Must be one of: DISPOSED, DESTROYED, or RELEASED. If the reason given is RELEASED, -o must also be given.")
    parser_remove.add_argument("-o", "--owner", help="Owner (required if 'RELEASED' is the reason)")

    parser_verify = subparsers.add_parser("verify", help="Verify the integrity of the blockchain")

    args = parser.parse_args()

    if args.subcommand == "add":
        add_evidence_to_blockchain(args.case_id, args.item_id, args.owner, args.org)
    elif args.subcommand == "show" and args.show_type == "all":
        if not BlockchainBlock.blockchain_file_exists():
            display_error(1)

        blocks = BlockchainBlock.read_blocks_from_file()
        for block in blocks:
            block.display_block()
    elif args.subcommand == 'init':
        BlockchainBlock.initialize_blockchain()
    elif args.subcommand == "show" and args.show_type == "cases":
        BlockchainBlock.show_cases()
    elif args.subcommand == "show" and args.show_type == "items":
        BlockchainBlock.show_items(args.case_id)
    elif args.subcommand == "show" and args.show_type == "history":
        BlockchainBlock.show_history(args.item_id, args.num_entries, args.reverse, args.case_id)
    elif args.subcommand == "checkout" and args.item_id:
        BlockchainBlock.checkout(args.item_id, args.owner, args.org)
    elif args.subcommand == "checkin" and args.item_id:
        BlockchainBlock.checkin(args.item_id, args.owner, args.org)
    elif args.subcommand == "remove" and args.item_id and args.why:
        if args.why == "RELEASED" and args.owner is None:
            display_error(7)
        elif args.why == "RELEASED":
            BlockchainBlock.remove(args.item_id, args.why, args.owner)
        else:
            BlockchainBlock.remove(args.item_id, args.why)
    elif args.subcommand == "verify":
        BlockchainBlock.verify()
    else:
        print("Invalid subcommand. Use 'bchoc help' to see more info")
