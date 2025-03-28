import json
from time import sleep
import random
import requests
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import datetime, timedelta
from dateutil import parser
import pytz
import math
import os
import jwt
from typing import Dict, Optional, Tuple
from colorama import Fore
from .utils import error_log, success_log, info_log, rate_limit_log, debug_log
from capmonster_python import TurnstileTask
import threading
import time

class TokenManager:
    def __init__(self, account_storage, api_instance):
        self.account_storage = account_storage
        self.api = api_instance
        self.max_retries = 2
        self.rate_limit_delay = 3
        self.stored_credentials_failed = set()

    def validate_token(self, token: str) -> bool:
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = decoded.get('exp')
            if not exp_timestamp:
                return False
            
            expiration = datetime.fromtimestamp(exp_timestamp, pytz.UTC)
            current_time = datetime.now(pytz.UTC)
            
            return current_time < (expiration - timedelta(minutes=5))
        except jwt.InvalidTokenError:
            return False

    def validate_cookies(self, cookies: dict) -> bool:
        required_cookies = {
            'privy-token',
            'privy-session',
            'privy-access-token',
            'privy-refresh-token'
        }
        return all(cookie in cookies for cookie in required_cookies)

    def check_stored_credentials(self, wallet_address: str) -> tuple[bool, Optional[str], Optional[dict]]:
        account_data = self.account_storage.get_account_data(wallet_address)
        if not account_data:
            return False, None, None

        token = account_data.get('token')
        cookies = account_data.get('cookies')

        if not token or not cookies:
            return False, None, None

        if not self.validate_token(token):
            return False, None, None

        if wallet_address in self.stored_credentials_failed:
            return False, None, None

        last_claim = account_data.get('last_daily_claim')
        if last_claim:
            try:
                last_claim_time = datetime.fromisoformat(last_claim)
                next_claim = last_claim_time + timedelta(hours=24)
                if datetime.now(pytz.UTC) < next_claim:
                    info_log(f"Account {wallet_address} cannot claim daily yet. Next claim at {next_claim}")
                    return False, None, None
            except ValueError:
                return False, None, None

        return True, token, cookies

    def _test_token(self, token: str, wallet_address: str, account_number: int) -> bool:
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Authorization': f'Bearer {token}',
            'Origin': 'https://fantasy.top',
            'Referer': 'https://fantasy.top/',
        }
        
        for attempt in range(2):
            try:
                response = self.api.session.get(
                    'https://fantasy.top/api/get-player-basic-data',
                    params={"playerId": wallet_address},
                    headers=headers,
                    proxies=self.api.proxies if self.api.proxies else None,  # Optional proxy
                    timeout=10
                )
                
                if response.status_code == 429:
                    rate_limit_log(f'Rate limit hit while testing token for account {account_number}')
                    sleep(self.rate_limit_delay)
                    continue
                    
                return response.status_code == 200
                
            except requests.exceptions.RequestException:
                sleep(1)
                continue
                
        return False

    def try_stored_credentials(self, wallet_address: str, account_number: int) -> Tuple[bool, Optional[str]]:
        is_valid, token, cookies = self.check_stored_credentials(wallet_address)
        if not is_valid:
            return False, None

        if cookies:
            for cookie_name, cookie_value in cookies.items():
                self.api.session.cookies.set(cookie_name, cookie_value)

        token_valid = self._test_token(token, wallet_address, account_number)
        if not token_valid:
            return False, None
            
        return True, token

    def mark_stored_credentials_failed(self, wallet_address: str):
        self.stored_credentials_failed.add(wallet_address)

    def should_try_stored_credentials(self, wallet_address: str) -> bool:
        return wallet_address not in self.stored_credentials_failed

    def update_credentials(self, wallet_address: str, token: str, cookies: dict):
        self.account_storage.update_account(
            wallet_address,
            self.account_storage.get_account_data(wallet_address)["private_key"],
            token=token,
            cookies=cookies
        )

    def invalidate_credentials(self, wallet_address: str):
        account_data = self.account_storage.get_account_data(wallet_address)
        if account_data:
            self.account_storage.update_account(
                wallet_address,
                account_data["private_key"],
                token=None,
                cookies=None
            )

class CaptchaTokenPool:
    def __init__(self, config):
        self.config = config
        self.current_token = None
        self.last_update = 0
        self.update_interval = 7
        self.lock = threading.Lock()

    def _get_new_token(self) -> Optional[str]:
        try:
            if self.config['capmonster']['enabled']:
                capmonster = TurnstileTask(self.config['capmonster']['api_key'])
                task_id = capmonster.create_task(
                    website_url="https://monad.fantasy.top",
                    website_key="0x4AAAAAAAM8ceq5KhP1uJBt"
                )
                result = capmonster.join_task_result(task_id)
                token = result.get('token')
                if token:
                    return token
            elif self.config.get('2captcha', {}).get('enabled', False):
                api_key = self.config['2captcha']['api_key']
                solver = requests.get(
                    f"https://2captcha.com/in.php?key={api_key}&method=turnstile&sitekey=0x4AAAAAAAM8ceq5KhP1uJBt&pageurl=https://monad.fantasy.top"
                )
                if solver.text.startswith('OK|'):
                    captcha_id = solver.text.split('|')[1]
                    for i in range(30):
                        time.sleep(5)
                        response = requests.get(
                            f"https://2captcha.com/res.php?key={api_key}&action=get&id={captcha_id}"
                        )
                        if response.text.startswith('OK|'):
                            return response.text.split('|')[1]
                        if response.text != 'CAPCHA_NOT_READY':
                            error_log(f"Error from 2captcha: {response.text}")
                            break
                    error_log("Timeout waiting for 2captcha solution")
        except Exception as e:
            error_log(f"Error getting captcha token: {e}")
        return None
        
    def get_token(self) -> Optional[str]:
        with self.lock:
            current_time = time.time()
            
            if self.current_token and current_time - self.last_update < self.update_interval:
                return self.current_token

            new_token = self._get_new_token()
            if new_token:
                self.current_token = new_token
                self.last_update = current_time
            return new_token

class FantasyAPI:
    def __init__(self, web3_provider, session, proxies, all_proxies, config, user_agent, account_storage):
        self.web3 = Web3(Web3.HTTPProvider(web3_provider))
        self.session = session
        self.proxies = proxies  # Can be None
        self.all_proxies = all_proxies  # Can be empty list
        self.config = config
        self.user_agent = user_agent
        self.base_url = "https://monad.fantasy.top"
        self.privy_url = "https://auth.privy.io"
        self.account_storage = account_storage
        self.token_manager = TokenManager(account_storage, self)
        self.captcha_pool = CaptchaTokenPool(config)
        
        info_log(f"[DEBUG] FantasyAPI initialized with base_url: {self.base_url}, privy_url: {self.privy_url}")

    def _get_captcha_token(self) -> Optional[str]:
        return self.captcha_pool.get_token()

    def login(self, private_key, wallet_address, account_number):
        max_retries = 3
        retry_delay = 2
        captcha_token = None
        
        info_log(f"Starting login process for account {account_number}: {wallet_address}")
        
        for attempt in range(max_retries):
            try:
                self.session.headers.update({
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Origin': 'https://monad.fantasy.top',
                    'Referer': f'https://monad.fantasy.top/',
                    'User-Agent': self.user_agent,
                    'privy-app-id': 'cm6ezzy660297zgdk7t3glcz5',
                    'privy-client': 'react-auth:1.92.3',
                    'privy-client-id': 'client-WY5gEtuoV4UpG2Le3n5pt6QQD61Ztx62VDwtDCZeQc3sN',
                    'privy-ca-id': self.config['app'].get('privy_ca_id', '52bc773e-737a-4e32-bd36-7563dcef2de1'),
                    'Sec-Ch-Ua': '"Google Chrome";v="132", "Chromium";v="132", "Not_A Brand";v="8"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'cross-site',
                    'Priority': 'u=1, i'
                })

                if captcha_token is None:
                    captcha_token = self._get_captcha_token()
                    if not captcha_token:
                        error_log(f'Failed to get captcha token for account {account_number}')
                        sleep(retry_delay)
                        continue

                debug_log(f"Requesting nonce for account {account_number}")
                init_response = self.session.post(
                    'https://auth.privy.io/api/v1/siwe/init', 
                    json={'address': wallet_address, 'token': captcha_token},
                    headers=self.session.headers,
                    proxies=self.proxies if self.proxies else None,
                    timeout=10
                )
                
                if init_response.status_code == 429:
                    info_log(f"Rate limit hit during nonce request for account {account_number}")
                    sleep(retry_delay)
                    continue
                    
                if init_response.status_code != 200:
                    info_log(f"Failed to get nonce, status: {init_response.status_code}")
                    captcha_token = self._get_captcha_token()
                    continue

                nonce_data = init_response.json()
                message = self._create_sign_message(wallet_address, nonce_data['nonce'])
                debug_log(f"Created sign message for account {account_number}")
                signed_message = self._sign_message(message, private_key)
                debug_log(f"Message signed successfully for account {account_number}")

                auth_payload = {
                    'chainId': 'eip155:1',
                    'connectorType': 'injected',
                    'message': message,
                    'signature': signed_message.signature.hex(),
                    'walletClientType': 'metamask',
                    'mode': 'login-or-sign-up'
                }

                debug_log(f"Sending authentication request for account {account_number}")
                auth_response = self.session.post(
                    'https://auth.privy.io/api/v1/siwe/authenticate',
                    json=auth_payload,
                    proxies=self.proxies if self.proxies else None,
                    timeout=10
                )
                
                if auth_response.status_code != 200:
                    error_log(f"Auth failed with status {auth_response.status_code} for account {account_number}")
                    if attempt < max_retries - 1:
                        if self.all_proxies:  # Switch proxy only if proxies are available
                            proxy = random.choice(self.all_proxies)
                            self.proxies = {"http": proxy, "https": proxy}
                            info_log(f"Switching proxy for account {account_number}")
                        sleep(retry_delay)
                        continue
                    return False

                auth_data = auth_response.json()
                debug_log(f"Authentication successful, received token for account {account_number}")
                
                if 'token' in auth_data:
                    self.session.cookies.set('privy-token', auth_data['token'])
                    debug_log(f"Set privy-token cookie for account {account_number}")
                if auth_data.get('identity_token'):
                    self.session.cookies.set('privy-id-token', auth_data['identity_token'])
                    debug_log(f"Set privy-id-token cookie for account {account_number}")
                
                final_auth_payload = {"address": wallet_address}
                
                debug_log(f"Requesting application token for account {account_number}")
                final_auth_response = self.session.post(
                    'https://monad.fantasy.top/api/auth/privy',
                    json=final_auth_payload,
                    headers={
                        'Accept': 'application/json, text/plain, */*',
                        'Content-Type': 'application/json',
                        'Origin': 'https://monad.fantasy.top',
                        'Referer': 'https://monad.fantasy.top/',
                        'Authorization': f'Bearer {auth_data["token"]}'
                    },
                    proxies=self.proxies if self.proxies else None,
                    timeout=10
                )
                
                if final_auth_response.status_code != 200:
                    error_log(f"Failed to get application token, status: {final_auth_response.status_code}")
                    if attempt < max_retries - 1:
                        if self.all_proxies:  # Switch proxy only if proxies are available
                            proxy = random.choice(self.all_proxies)
                            self.proxies = {"http": proxy, "https": proxy}
                            sleep(retry_delay)
                        sleep(retry_delay)
                        continue
                    return False

                final_auth_data = final_auth_response.json()
                cookies_dict = {cookie.name: cookie.value for cookie in self.session.cookies}

                self.account_storage.update_account(
                    wallet_address,
                    private_key,
                    token=final_auth_data.get('token'),
                    cookies=cookies_dict
                )
                
                success_log(f"Account {account_number}: {wallet_address} Login done")
                return final_auth_data

            except Exception as e:
                error_log(f'Error during login attempt {attempt + 1}: {str(e)}')
                if attempt < max_retries - 1:
                    sleep(retry_delay)
                    continue

        return False

    def get_token(self, auth_data, wallet_address, account_number):
        try:
            if "token" in auth_data:
                token = auth_data["token"]
                self.account_storage.update_account(
                    wallet_address,
                    self.account_storage.get_account_data(wallet_address)["private_key"],
                    token=token
                )
                info_log(f'Token obtained for account {account_number}: {wallet_address}')
                return token
            
            error_log(f'No token found in auth_data for account {account_number}')
            return False

        except Exception as e:
            error_log(f'Token error for account {account_number}: {str(e)}')
            return False

    def check_tournament_rewards(self, token, wallet_address, account_number):
        try:
            privy_id_token = None
            for cookie in self.session.cookies:
                if cookie.name == 'privy-id-token':
                    privy_id_token = cookie.value
                    break
            
            auth_token = privy_id_token if privy_id_token else token
            
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Authorization': f'Bearer {auth_token}',
                'Origin': 'https://monad.fantasy.top',
                'Referer': 'https://monad.fantasy.top/',
                'User
