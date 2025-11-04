import json
import logging
import os

logger = logging.getLogger(__name__)


class AccountDB:
    def __init__(self):
        self.basepath = "data"
        self.wallets_dir = os.path.join(self.basepath, "wallets")
        os.makedirs(self.wallets_dir, exist_ok=True)

    def get_all_wallets(self):
        wallets = []
        if not os.path.exists(self.wallets_dir):
            return wallets
        for filename in os.listdir(self.wallets_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.wallets_dir, filename)
                with open(filepath, "r") as file:
                    wallets.append(json.load(file))
        return wallets

    def save_wallet(self, wallet_name, wallet_data):
        filepath = os.path.join(self.wallets_dir, f"{wallet_name}.json")
        if os.path.exists(filepath):
            logging.error(f"Wallet with name '{wallet_name}' already exists")
            return False
        with open(filepath, "w") as file:
            json.dump(wallet_data, file, indent=4)
        return True
