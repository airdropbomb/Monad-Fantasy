import threading
import random
import time
import requests
from src.api import FantasyAPI
from src.utils import (
    AccountStorage,
    info_log,
    success_log,
    error_log,
    debug_log
)
from time import sleep


class RetryManager:
    def __init__(self):
        self.success_accounts = set()
        self.failed_accounts = {}
        self.max_attempts = 3

    def should_process(self, account_data):
        if account_data in self.success_accounts:
            return False
        attempts = self.failed_accounts.get(account_data, 0)
        return attempts < self.max_attempts

    def add_success_account(self, account_data):
        self.success_accounts.add(account_data)
        self.failed_accounts.pop(account_data, None)

    def add_failed_account(self, account_data):
        current_attempts = self.failed_accounts.get(account_data, 0)
        self.failed_accounts[account_data] = current_attempts + 1

    def get_current_attempt(self, account_data):
        return self.failed_accounts.get(account_data, 0)

    def get_success_rate(self):
        total_processed = len(self.success_accounts) + len(self.failed_accounts)
        return len(self.success_accounts) / total_processed if total_processed > 0 else 0

    def get_failed_accounts(self):
        return [(account_data, attempts) for account_data, attempts in self.failed_accounts.items() if attempts >= self.max_attempts]


class FantasyProcessor:
    def __init__(self, config, proxies_dict, all_proxies, user_agents_cycle):
        self.config = config
        self.proxies = proxies_dict  # Can be None if no proxies
        self.all_proxies = all_proxies  # Can be empty list if no proxies
        self.user_agents_cycle = user_agents_cycle
        self.account_storage = AccountStorage()
        self.last_request_time = {}
        self.min_request_interval = 2
        self.lock = threading.Lock()
        self.retry_manager = RetryManager()
        self.retry_delay = 5
        self.max_proxy_retries = 5
        self.completed_quests = set()

    def _wait_rate_limit(self, thread_id):
        with self.lock:
            current_time = time.time()
            last_time = self.last_request_time.get(thread_id, 0)
            time_since_last = current_time - last_time
            if time_since_last < self.min_request_interval:
                sleep_time = self.min_request_interval - time_since_last
                debug_log(f"Thread {thread_id} waiting {sleep_time:.2f}s for rate limit")
                sleep(sleep_time)
            self.last_request_time[thread_id] = time.time()

    def _get_random_proxy(self):
        with self.lock:
            if not self.all_proxies:  # If no proxies, return None
                return None
            return random.choice(self.all_proxies)

    def process_account_with_retry(self, account_number, private_key, wallet_address, total_accounts):
        account_data = (account_number, private_key, wallet_address)
        
        if not self.retry_manager.should_process(account_data):
            info_log(f"Skipping account {account_number}: already processed successfully or max retries reached")
            return
            
        proxy_retries = 0
        
        while proxy_retries < self.max_proxy_retries:
            try:
                success = self.process_account(account_number, private_key, wallet_address, total_accounts)
                if success:
                    self.retry_manager.add_success_account(account_data)
                    return
                proxy_retries += 1
                sleep(2)
            except requests.exceptions.RequestException as e:
                error_log(f"Network error for account {account_number}: {str(e)}")
                proxy_retries += 1
                sleep(2)
            except Exception as e:
                error_log(f"Error processing account {account_number}: {str(e)}")
                self.retry_manager.add_failed_account(account_data)
                return

        self.retry_manager.add_failed_account(account_data)

    def process_account(self, account_number, private_key, wallet_address, total_accounts):
        max_attempts = 3
        account_data = (account_number, private_key, wallet_address)
        current_attempt = self.retry_manager.get_current_attempt(account_data)
        
        while current_attempt < max_attempts:
            try:
                thread_id = threading.get_ident()
                self._wait_rate_limit(thread_id)
                
                session = requests.Session()
                api = None
                
                try:
                    proxy = self._get_random_proxy()
                    proxy_dict = {"http": proxy, "https": proxy} if proxy else None
                    
                    if current_attempt == 0:
                        info_log(f'Processing account {account_number}: {wallet_address}')
                    else:
                        info_log(f'Retrying account {account_number}: {wallet_address} (Attempt {current_attempt + 1}/{max_attempts})')
                    
                    with self.lock:
                        user_agent = next(self.user_agents_cycle)
                    
                    api = FantasyAPI(
                        web3_provider=self.config['rpc']['url'],
                        session=session,
                        proxies=proxy_dict,  # Can be None
                        all_proxies=self.all_proxies,
                        config=self.config,
                        user_agent=user_agent,
                        account_storage=self.account_storage
                    )

                    auth_data = None
                    token = None
                    
                    if current_attempt == 0:
                        stored_success, stored_token = api.token_manager.try_stored_credentials(wallet_address, account_number)
                        if stored_success:
                            info_log(f'Using stored credentials for account {account_number}')
                            token = stored_token

                    if not token:
                        auth_data = api.login(private_key, wallet_address, account_number)
                        if auth_data is False:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue
                        
                        if isinstance(auth_data, str) and "429" in auth_data:
                            info_log(f'Rate limit on login for account {account_number}, switching proxy...')
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                        token = api.get_token(auth_data, wallet_address, account_number)
                        if not token:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                    if self.config['info_check']:
                        info_result = api.info(token, wallet_address, account_number)
                        if isinstance(info_result, str) and "429" in info_result:
                            info_log(f"Rate limit hit on info check for account {account_number}")
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue
                        if not info_result:
                            api.token_manager.mark_stored_credentials_failed(wallet_address)
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                    if self.config['daily']['enabled']:
                        daily_result = api.daily_claim(token, wallet_address, account_number)
                        if not daily_result:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                    if self.config['starter_cards']['enabled']:
                        starter_result = api.claim_starter_cards(token, wallet_address, account_number)
                        if not starter_result:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue
                        sleep(self.config['starter_cards']['wait_time_after_claim'])

                    if self.config['quest']['enabled']:
                        for quest_id in self.config['quest']['ids']:
                            quest_result = api.quest_claim(token, wallet_address, account_number, quest_id)
                            if isinstance(quest_result, str) and "429" in quest_result:
                                info_log(f"Rate limit hit on quest claim {quest_id} for account {account_number}")
                                current_attempt += 1
                                session.close()
                                sleep(2)
                                break
                            if quest_result:
                                self.completed_quests.add(quest_id)
                            sleep(1)

                    if self.config['fragments']['enabled']:
                        fragment_result = api.fragments_claim(token, wallet_address, account_number, self.config['fragments']['id'])
                        if not fragment_result:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                    if self.config['onboarding_quest']['enabled']:
                        for quest_id in self.config['onboarding_quest']['ids']:
                            onboarding_result = api.onboarding_quest_claim(token, wallet_address, account_number, quest_id)
                            if not onboarding_result:
                                current_attempt += 1
                                session.close()
                                sleep(2)
                                break
                            sleep(1)

                    if self.config['tactic']['enabled']:
                        tactic_result = api.tactic_claim(token, wallet_address, account_number, total_accounts, self.config['tactic']['old_account'])
                        if not tactic_result:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                    if self.config['tournaments']['enabled'] and self.config['tournaments']['claim_rewards']:
                        tournament_data = api.get_active_tournaments(token, wallet_address, account_number)
                        if tournament_data and not tournament_data.get('already_claimed', True):
                            tournament_ids = [t.get('id') for t in tournament_data.get('tournaments', [])]
                            if tournament_ids:
                                claim_result = api.claim_tournament_rewards(token, wallet_address, account_number, tournament_ids)
                                if not claim_result:
                                    current_attempt += 1
                                    session.close()
                                    sleep(2)
                                    continue

                    if self.config['other_rewards']['enabled']:
                        rewards_result = api.check_other_rewards(token, wallet_address, account_number)
                        if not rewards_result:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                        if self.config['other_rewards']['claim_packs']:
                            pack_result = api.process_fragment_packs(token, wallet_address, account_number, private_key)
                            if not pack_result:
                                current_attempt += 1
                                session.close()
                                sleep(2)
                                continue

                    if self.config['fragment_roulette']['enabled']:
                        roulette_result = api.fragment_roulette(token, wallet_address, account_number, private_key)
                        if not roulette_result:
                            current_attempt += 1
                            session.close()
                            sleep(2)
                            continue

                    self._write_success(private_key, wallet_address)
                    return True

                finally:
                    if session:
                        session.close()

            except Exception as e:
                error_log(f"Error processing account {account_number}: {str(e)}")
                current_attempt += 1
                sleep(2)
                continue

        error_log(f'All attempts exhausted for account {account_number}')
        self._write_failure(private_key, wallet_address)
        self.retry_manager.add_failed_account(account_data)
        return False

    def retry_failed_accounts(self):
        if not self.config.get('retry_failed_accounts', False):
            info_log("Retry of failed accounts is disabled in config")
            return

        failed_accounts = self.retry_manager.get_failed_accounts()
        if not failed_accounts:
            info_log("No accounts to retry")
            return

        info_log(f"Retrying {len(failed_accounts)} failed accounts...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['app']['threads']) as executor:
            futures = []
            for (account_number, private_key, wallet_address), _ in failed_accounts:
                future = executor.submit(
                    self.process_account_with_retry,
                    account_number,
                    private_key,
                    wallet_address,
                    len(self.account_storage.accounts)
                )
                futures.append(future)

            concurrent.futures.wait(futures)

    def _write_success(self, private_key, wallet_address):
        with self.lock:
            with open(self.config['app']['success_file'], 'a+', encoding='utf-8') as f:
                f.write(f"{private_key}:{wallet_address}\n")
            success_log(f"Added to success file: {wallet_address}")

    def _write_failure(self, private_key, wallet_address):
        with self.lock:
            with open(self.config['app']['failure_file'], 'a+', encoding='utf-8') as f:
                f.write(f"{private_key}:{wallet_address}\n")
            error_log(f"Added to failure file: {wallet_address}")
