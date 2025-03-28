    info_log(f"[DEBUG] FantasyAPI initialized with base_url: {self.base_url}, privy_url: {self.privy_url}")

def _get_captcha_token(self) -> Optional[str]:
    return self.captcha_pool.get_token()

def _create_sign_message(self, wallet_address: str, nonce: str) -> str:
    return (
        f"{self.base_url} wants you to sign in with your Ethereum account:\n"
        f"{wallet_address}\n\n"
        f"Sign in with Ethereum to the app.\n\n"
        f"URI: {self.base_url}\n"
        f"Version: 1\n"
        f"Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {datetime.now(pytz.UTC).isoformat()}"
    )

def _sign_message(self, message: str, private_key: str):
    message_encoded = encode_defunct(text=message)
    signed_message = self.web3.eth.account.sign_message(message_encoded, private_key=private_key)
    return signed_message

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

def info(self, token, wallet_address, account_number):
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
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        url = f'https://secret-api.fantasy.top/player/basic-data/{wallet_address}'
        
        response = self.session.get(
            url,
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 429:
            return "429 Too Many Requests"
            
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                url,
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to fetch info, status: {response.status_code}")
            return False
        
        data = response.json()
        player_data = data.get('players_by_pk', {})
        
        fantasy_points = player_data.get('fantasy_points', 0)
        fragments = player_data.get('fragments', 0)
        whitelist_tickets = player_data.get('whitelist_tickets', 0)
        referral_code = player_data.get('referral_code', 'N/A')
        
        info_log(f"Account {account_number} ({wallet_address}): "
                f"Fantasy Points: {fantasy_points}, "
                f"Fragments: {fragments}, "
                f"Whitelist Tickets: {whitelist_tickets}, "
                f"Referral Code: {referral_code}")
        
        self._update_account_info(wallet_address, fantasy_points, fragments, whitelist_tickets)
        return True
        
    except Exception as e:
        error_log(f"Error in info function for account {account_number}: {str(e)}")
        return False

def _update_account_info(self, wallet_address, fantasy_points, fragments, whitelist_tickets):
    try:
        result_file = self.config['app']['result_file']
        if not os.path.exists(result_file):
            with open(result_file, 'a', encoding='utf-8') as f:
                f.write(f"{wallet_address}:fantasy_points={fantasy_points}:fragments={fragments}:whitelist_tickets={whitelist_tickets}\n")
            return
            
        lines = []
        found = False
        
        with open(result_file, 'r', encoding='utf-8') as f:
            for line in f:
                if wallet_address in line:
                    parts = line.strip().split(':')
                    parts = [part for part in parts if not (part.startswith('fantasy_points=') or 
                                                          part.startswith('fragments=') or 
                                                          part.startswith('whitelist_tickets='))]
                    parts.extend([f"fantasy_points={fantasy_points}", 
                                f"fragments={fragments}", 
                                f"whitelist_tickets={whitelist_tickets}"])
                    lines.append(':'.join(parts) + '\n')
                    found = True
                else:
                    lines.append(line)
        
        if not found:
            lines.append(f"{wallet_address}:fantasy_points={fantasy_points}:fragments={fragments}:whitelist_tickets={whitelist_tickets}\n")
        
        with open(result_file, 'w', encoding='utf-8') as f:
            f.writelines(lines)
            
    except Exception as e:
        error_log(f"Error updating account info: {str(e)}")

def daily_claim(self, token, wallet_address, account_number):
    max_retries = 2
    retry_delay = 1
    
    privy_id_token = None
    for cookie in self.session.cookies:
        if cookie.name == 'privy-id-token':
            privy_id_token = cookie.value
            break
    
    auth_token = privy_id_token if privy_id_token else token
    
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'Authorization': f'Bearer {auth_token}',
        'Origin': 'https://monad.fantasy.top',
        'Referer': 'https://monad.fantasy.top/',
        'Content-Length': '0',
        'User-Agent': self.user_agent,
        'Priority': 'u=1, i',
        'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site'
    }

    for attempt in range(max_retries):
        try:
            response = self.session.post(
                'https://secret-api.fantasy.top/quest/daily-claim',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
            
            if response.status_code == 500:
                info_log(f'Daily claim returned 500 for account {account_number}, retrying...')
                sleep(retry_delay)
                continue
                
            if response.status_code == 405:
                response = self.session.get(
                    'https://secret-api.fantasy.top/quest/daily-claim',
                    headers=headers,
                    proxies=self.proxies if self.proxies else None,
                    timeout=10
                )

            if response.status_code == 201:
                data = response.json()
                if data.get("success", False):
                    self.account_storage.update_account(
                        wallet_address,
                        self.account_storage.get_account_data(wallet_address)["private_key"],
                        last_daily_claim=datetime.now(pytz.UTC).isoformat()
                    )
                    daily_streak = data.get("dailyQuestStreak", "N/A")
                    current_day = data.get("dailyQuestProgress", "N/A")
                    prize = data.get("selectedPrize", {})
                    prize_type = prize.get("type", "Unknown")
                    prize_amount = prize.get("text", "Unknown")
                    
                    success_log(f'Account {account_number} ({wallet_address}): '
                              f'{Fore.GREEN}STREAK:{daily_streak}{Fore.RESET}, '
                              f'{Fore.GREEN}DAY:{current_day}{Fore.RESET}, '
                              f'{Fore.GREEN}PRIZE:{prize_type}({prize_amount}){Fore.RESET}')
                    return True
                else:
                    next_due_time = data.get("nextDueTime")
                    if next_due_time:
                        next_due_datetime = parser.parse(next_due_time)
                        moscow_tz = pytz.timezone('Europe/Moscow')
                        current_time = datetime.now(moscow_tz)
                        time_difference = next_due_datetime.replace(tzinfo=pytz.UTC) - current_time.astimezone(pytz.UTC)
                        hours, remainder = divmod(time_difference.total_seconds(), 3600)
                        minutes = remainder // 60
                        info_log(f"Account {account_number} ({wallet_address}): Daily claim already done. Next claim in {int(hours)}h {int(minutes)}m")
                    return False
            
            if response.status_code == 401 and auth_token == privy_id_token and token:
                auth_token = token
                headers['Authorization'] = f'Bearer {auth_token}'
                continue
            
            error_log(f"Failed daily claim for account {account_number}, status: {response.status_code}")
            return False
            
        except Exception as e:
            error_log(f"Error during daily claim attempt {attempt + 1} for account {account_number}: {str(e)}")
            if attempt < max_retries - 1:
                sleep(retry_delay)
            continue
            
    return False

def claim_starter_cards(self, token, wallet_address, account_number):
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
            'Content-Length': '0',
            'User-Agent': self.user_agent,
            'Priority': 'u=1, i',
            'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }

        quest_id = self.config['starter_cards']['onboarding_quest_id']
        response = self.session.post(
            f'https://secret-api.fantasy.top/quest/starter-cards-claim/{quest_id}',
            headers=headers,
            data="",
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.post(
                f'https://secret-api.fantasy.top/quest/starter-cards-claim/{quest_id}',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code in [200, 201]:
            success_log(f"Successfully claimed starter cards for account {account_number}")
            return True
            
        if response.status_code == 400:
            info_log(f"Starter cards already claimed for account {account_number}")
            return True
            
        error_log(f"Failed to claim starter cards, status: {response.status_code}")
        return False
        
    except Exception as e:
        error_log(f"Error claiming starter cards for account {account_number}: {str(e)}")
        return False

def quest_claim(self, token, wallet_address, account_number, quest_id):
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
            'Content-Length': '0',
            'User-Agent': self.user_agent,
            'Priority': 'u=1, i',
            'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }

        response = self.session.post(
            f'https://secret-api.fantasy.top/quest/claim/{quest_id}',
            headers=headers,
            data="",
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 429:
            return "429 Too Many Requests"
            
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.post(
                f'https://secret-api.fantasy.top/quest/claim/{quest_id}',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code in [200, 201]:
            success_log(f"Successfully claimed quest {quest_id} for account {account_number}")
            return True
            
        if response.status_code == 400:
            info_log(f"Quest {quest_id} already claimed or invalid for account {account_number}")
            return False
            
        error_log(f"Failed to claim quest {quest_id}, status: {response.status_code}")
        return False
        
    except Exception as e:
        error_log(f"Error claiming quest {quest_id} for account {account_number}: {str(e)}")
        return False

def fragments_claim(self, token, wallet_address, account_number, fragment_id):
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
            'Content-Length': '0',
            'User-Agent': self.user_agent,
            'Priority': 'u=1, i',
            'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }

        response = self.session.post(
            f'https://secret-api.fantasy.top/quest/fragments-claim/{fragment_id}',
            headers=headers,
            data="",
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.post(
                f'https://secret-api.fantasy.top/quest/fragments-claim/{fragment_id}',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code in [200, 201]:
            success_log(f"Successfully claimed fragments {fragment_id} for account {account_number}")
            return True
            
        if response.status_code == 400:
            info_log(f"Fragments {fragment_id} already claimed for account {account_number}")
            return True
            
        error_log(f"Failed to claim fragments {fragment_id}, status: {response.status_code}")
        return False
        
    except Exception as e:
        error_log(f"Error claiming fragments {fragment_id} for account {account_number}: {str(e)}")
        return False

def onboarding_quest_claim(self, token, wallet_address, account_number, quest_id):
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
            'Content-Length': '0',
            'User-Agent': self.user_agent,
            'Priority': 'u=1, i',
            'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }

        response = self.session.post(
            f'https://secret-api.fantasy.top/quest/onboarding-claim/{quest_id}',
            headers=headers,
            data="",
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.post(
                f'https://secret-api.fantasy.top/quest/onboarding-claim/{quest_id}',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code in [200, 201]:
            success_log(f"Successfully claimed onboarding quest {quest_id} for account {account_number}")
            return True
            
        if response.status_code == 400:
            info_log(f"Onboarding quest {quest_id} already claimed or invalid for account {account_number}")
            return False
            
        error_log(f"Failed to claim onboarding quest {quest_id}, status: {response.status_code}")
        return False
        
    except Exception as e:
        error_log(f"Error claiming onboarding quest {quest_id} for account {account_number}: {str(e)}")
        return False

def tactic_claim(self, token, wallet_address, account_number, total_accounts, old_account=False):
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
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        response = self.session.get(
            f'https://secret-api.fantasy.top/player/basic-data/{wallet_address}',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                f'https://secret-api.fantasy.top/player/basic-data/{wallet_address}',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to fetch player data for tactic, status: {response.status_code}")
            return False
        
        player_data = response.json().get('players_by_pk', {})
        current_deck = player_data.get('current_deck', [])
        
        if not old_account and not current_deck:
            deck = random.choice(self.config['tactic']['decks'])
            info_log(f"Account {account_number}: Setting new deck {deck}")
            
            headers['Content-Type'] = 'application/json'
            response = self.session.post(
                'https://secret-api.fantasy.top/tactic/set-deck',
                headers=headers,
                json={"deck": deck},
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
            
            if response.status_code not in [200, 201]:
                error_log(f"Failed to set deck, status: {response.status_code}")
                return False
            
            success_log(f"Successfully set deck for account {account_number}")
        
        max_attempts = self.config['tactic']['max_toggle_attempts']
        attempt = 0
        
        while attempt < max_attempts:
            response = self.session.post(
                'https://secret-api.fantasy.top/tactic/toggle',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                data = response.json()
                if data.get('success', False):
                    success_log(f"Successfully toggled tactic for account {account_number}")
                    return True
                else:
                    info_log(f"Tactic toggle returned no success for account {account_number}")
                    sleep(self.config['tactic']['delay_between_attempts'])
                    attempt += 1
                    continue
            
            if response.status_code == 400:
                info_log(f"Tactic already claimed or invalid for account {account_number}")
                return True
            
            error_log(f"Failed to toggle tactic, status: {response.status_code}")
            sleep(self.config['tactic']['delay_between_attempts'])
            attempt += 1
        
        error_log(f"Max attempts reached for tactic toggle for account {account_number}")
        return False
        
    except Exception as e:
        error_log(f"Error in tactic claim for account {account_number}: {str(e)}")
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
            'User-Agent': self.user_agent
        }

        response = self.session.get(
            'https://secret-api.fantasy.top/player/player-rewards',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                'https://secret-api.fantasy.top/player/player-rewards',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to check tournament rewards: {response.status_code}")
            return None
        
        data = response.json()
        return data
        
    except Exception as e:
        error_log(f'Error checking tournament rewards: {str(e)}')
        return None

def check_pending_packs(self, token, wallet_address, account_number):
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
            'User-Agent': self.user_agent
        }

        response = self.session.get(
            'https://secret-api.fantasy.top/rewards/has-pending-cards-from-fragments',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                'https://secret-api.fantasy.top/rewards/has-pending-cards-from-fragments',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to check pending packs: {response.status_code}")
            return None
        
        data = response.json()
        return data
        
    except Exception as e:
        error_log(f'Error checking pending packs: {str(e)}')
        return None

def get_active_tournaments(self, token, wallet_address, account_number):
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
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        rewards_response = self.session.get(
            'https://secret-api.fantasy.top/player/player-rewards',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if rewards_response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            rewards_response = self.session.get(
                'https://secret-api.fantasy.top/player/player-rewards',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        tournament_number = 3
        
        if rewards_response.status_code == 200:
            rewards_data = rewards_response.json()
            tournament_rewards = rewards_data.get('tournamentRewards', [])
            if tournament_rewards:
                tournament_numbers = [reward.get('tournament_number', 0) for reward in tournament_rewards]
                if tournament_numbers:
                    tournament_number = max(tournament_numbers)
                    debug_log(f"Tournament number determined: {tournament_number} for account {account_number}")
        
        debug_log(f"Getting tournament summary for account {account_number}, tournament number: {tournament_number}")
        response = self.session.get(
            f'https://secret-api.fantasy.top/tournaments/summary/{tournament_number}/player?playerId={wallet_address}',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                f'https://secret-api.fantasy.top/tournaments/summary/{tournament_number}/player?playerId={wallet_address}',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to get active tournaments: {response.status_code}")
            return None
        
        data = response.json()
        
        debug_log(f"Tournament summary response: {response.status_code}")
        
        if 'already_claimed' in data:
            debug_log(f"Already claimed status: {data['already_claimed']} for account {account_number}")
        
        if 'tournaments' in data:
            tournament_info = []
            for t in data['tournaments']:
                tournament_info.append(f"{t.get('name', 'Unknown')}(#{t.get('tournament_number', 'N/A')})")
            
            if 'already_claimed' in data:
                already_claimed = "Yes" if data.get('already_claimed', True) else "No"
                info_log(f"Account {account_number}: Tournaments: {', '.join(tournament_info)}. Already claimed: {already_claimed}")
        
        return data
    except Exception as e:
        error_log(f'Error getting active tournaments: {str(e)}')
        return None

def claim_tournament_rewards(self, token, wallet_address, account_number, tournament_ids):
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
            'Origin': 'https palavra://monad.fantasy.top',
            'Referer': 'https://monad.fantasy.top/',
            'Content-Length': '0',
            'User-Agent': self.user_agent,
            'Priority': 'u=1, i',
            'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }

        if isinstance(tournament_ids, list):
            tournament_ids_str = ",".join(tournament_ids)
        else:
            tournament_ids_str = tournament_ids

        debug_log(f"Claiming tournament rewards for account {account_number}: {tournament_ids_str}")
        
        response = self.session.post(
            f'https://secret-api.fantasy.top/rewards/tournament-rewards-claim/{tournament_ids_str}',
            headers=headers,
            data="",
            proxies=self.proxies if self.proxies else None,
            timeout=15
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            debug_log(f"Retrying claim with different token for account {account_number}")
            
            response = self.session.post(
                f'https://secret-api.fantasy.top/rewards/tournament-rewards-claim/{tournament_ids_str}',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=15
            )
        
        debug_log(f"Tournament claim response status: {response.status_code} for account {account_number}")
        
        if response.status_code == 400:
            try:
                response_data = response.json()
                info_log(f"Account {account_number}: Tournament rewards already claimed")
                
                self._clean_rewards_info(wallet_address)
                
                return {"status": "already_claimed", "message": "Tournament rewards were already claimed"}
            except Exception as e:
                error_log(f"Error processing 400 response: {str(e)}")
                return False
        
        if response.status_code not in [200, 201]:
            error_log(f"Failed to claim tournament rewards: {response.status_code}")
            try:
                response_data = response.json()
                error_log(f"Error details: {response_data}")
            except:
                error_log(f"Response text: {response.text[:200]}")
            return False
        
        data = response.json()
        debug_log(f"Tournament claim response data: {data}")
        
        if "claimed" in data:
            rewards = data.get("claimed", {})
            rewards_str = ", ".join([f"{k}: {v}" for k, v in rewards.items()])
            success_log(f"Successfully claimed tournament rewards for account {account_number}: {rewards_str}")
            
            self._update_account_stats_after_claim(wallet_address, rewards)
            
            return data
        else:
            info_log(f"Unexpected response format from tournament reward claim: {data}")
            return False
            
    except Exception as e:
        error_log(f'Error claiming tournament rewards: {str(e)}')
        return False

def _clean_rewards_info(self, wallet_address):
    try:
        result_file = self.config['app']['result_file']
        if not os.path.exists(result_file):
            return
            
        lines = []
        updated = False
        
        with open(result_file, 'r', encoding='utf-8') as f:
            for line in f:
                if wallet_address in line:
                    parts = line.strip().split(':')
                    
                    filtered_parts = []
                    for part in parts:
                        if not part.startswith('tournament_rewards='):
                            filtered_parts.append(part)
                    
                    parts = filtered_parts
                    line = ':'.join(parts) + '\n'
                    updated = True
                
                lines.append(line)
        
        if updated:
            with open(result_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
                debug_log(f"Cleaned tournament rewards info for {wallet_address}")
    
    except Exception as e:
        error_log(f"Error cleaning rewards info: {str(e)}")

def _update_account_stats_after_claim(self, wallet_address, claimed_rewards):
    try:
        result_file = self.config['app']['result_file']
        if not os.path.exists(result_file):
            return
            
        lines = []
        updated = False
        
        with open(result_file, 'r', encoding='utf-8') as f:
            for line in f:
                if wallet_address in line:
                    parts = line.strip().split(':')
                    
                    if 'FAN' in claimed_rewards:
                        fan_points = claimed_rewards['FAN']
                        for i, part in enumerate(parts):
                            if part.startswith('fantasy_points='):
                                try:
                                    current_points = int(part.split('=')[1])
                                    parts[i] = f"fantasy_points={current_points + fan_points}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                    
                    if 'FRAGMENT' in claimed_rewards:
                        fragments = claimed_rewards['FRAGMENT']
                        for i, part in enumerate(parts):
                            if part.startswith('fragments='):
                                try:
                                    current_fragments = int(part.split('=')[1])
                                    parts[i] = f"fragments={current_fragments + fragments}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                    
                    if 'WHITELIST_TICKET' in claimed_rewards:
                        whitelist_tickets = claimed_rewards['WHITELIST_TICKET']
                        for i, part in enumerate(parts):
                            if part.startswith('whitelist_tickets='):
                                try:
                                    current_tickets = int(part.split('=')[1])
                                    parts[i] = f"whitelist_tickets={current_tickets + whitelist_tickets}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                    
                    filtered_parts = []
                    for part in parts:
                        if not part.startswith('tournament_rewards='):
                            filtered_parts.append(part)
                    
                    parts = filtered_parts
                    
                    line = ':'.join(parts) + '\n'
                
                lines.append(line)
        
        if updated:
            with open(result_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
                debug_log(f"Updated account stats after tournament reward claim for {wallet_address}")
    
    except Exception as e:
        error_log(f"Error updating account stats after tournament reward claim: {str(e)}")

def claim_other_rewards(self, token, wallet_address, account_number, reward_id):
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
            'Content-Length': '0',
            'User-Agent': self.user_agent,
            'Priority': 'u=1, i',
            'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }

        response = self.session.post(
            f'https://secret-api.fantasy.top/rewards/rewards-claim/{reward_id}',
            headers=headers,
            data="",
            proxies=self.proxies if self.proxies else None,
            timeout=15
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            
            response = self.session.post(
                f'https://secret-api.fantasy.top/rewards/rewards-claim/{reward_id}',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=15
            )
        
        if response.status_code in [200, 201]:
            success_log(f"Successfully claimed other reward {reward_id} for account {account_number}")
            return True
        
        error_log(f"Failed to claim other reward {reward_id}: {response.status_code}")
        return False
            
    except Exception as e:
        error_log(f"Error claiming other reward: {str(e)}")
        return False

def _check_and_give_approval(self, monad_web3, wallet_address, private_key, contract_address):
    try:
        approval_abi = [
            {
                "constant": True,
                "inputs": [
                    {"name": "owner", "type": "address"},
                    {"name": "operator", "type": "address"}
                ],
                "name": "isApprovedForAll",
                "outputs": [{"name": "", "type": "bool"}],
                "payable": False,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "constant": False,
                "inputs": [
                    {"name": "operator", "type": "address"},
                    {"name": "approved", "type": "bool"}
                ],
                "name": "setApprovalForAll",
                "outputs": [],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]

        erc721_contract_address = monad_web3.to_checksum_address("0x04edb399cc24a95672bf9b880ee550de0b2d0b1e")
        erc721_contract = monad_web3.eth.contract(address=erc721_contract_address, abi=approval_abi)
        
        wallet_address_checksum = monad_web3.to_checksum_address(wallet_address)
        contract_address_checksum = monad_web3.to_checksum_address(contract_address)
        
        try:
            is_approved = erc721_contract.functions.isApprovedForAll(
                wallet_address_checksum, 
                contract_address_checksum
            ).call()
            
            if is_approved:
                debug_log(f"Contract already has approval for {wallet_address}")
                return True
                
        except Exception as e:
            debug_log(f"Error checking approval status: {str(e)}")
            pass
        
        try:
            nonce = monad_web3.eth.get_transaction_count(wallet_address_checksum, 'pending')
            
            gas_price = monad_web3.eth.gas_price
            max_priority_fee = monad_web3.to_wei(1.5, 'gwei')
            max_fee_per_gas = gas_price * 2
            
            set_approval_txn = erc721_contract.functions.setApprovalForAll(
                contract_address_checksum, 
                True
            ).build_transaction({
                'nonce': nonce,
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee,
                'gas': 100000,
                'type': 2,
                'chainId': 10143
            })
            
            account = monad_web3.eth.account.from_key(private_key)
            signed_txn = account.sign_transaction(set_approval_txn)
            tx_hash = monad_web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            debug_log(f"Approval transaction sent: {tx_hash_hex}")
            
            receipt = None
            retry_count = 10
            while retry_count > 0 and receipt is None:
                try:
                    receipt = monad_web3.eth.get_transaction_receipt(tx_hash)
                    if receipt:
                        if receipt['status'] == 1:
                            debug_log(f"Approval transaction confirmed: {tx_hash_hex}")
                            return True
                        else:
                            error_log(f"Approval transaction failed: {tx_hash_hex}")
                            return False
                except Exception:
                    sleep(2)
                    retry_count -= 1
            
            if not receipt:
                debug_log(f"Approval transaction pending: {tx_hash_hex}")
                return True
                
        except Exception as e:
            error_log(f"Error giving approval: {str(e)}")
        
        return True
        
    except Exception as e:
        error_log(f"Error checking/giving approval: {str(e)}")
        return True

def claim_fragment_pack(self, token, wallet_address, account_number, private_key, pack_id, mint_config_id):
    try:
        proof = self._get_merkle_proof(token, mint_config_id)
        if not proof:
            error_log(f"Failed to get merkle proof for account {account_number}, mint_config_id: {mint_config_id}")
            return False
            
        monad_web3 = Web3(Web3.HTTPProvider(self.config['monad_rpc']['url']))
        contract_address = monad_web3.to_checksum_address("0x9077d31a794d81c21b0650974d5f581f4000cd1a")
        
        self._check_and_give_approval(monad_web3, wallet_address, private_key, contract_address)
        
        try:
            config_parts = mint_config_id.split('_')
            if len(config_parts) > 0:
                config_id_number = int(config_parts[0])
                pack_id_hex = hex(config_id_number)[2:].zfill(64)
            else:
                error_log(f"Invalid mint_config_id format: {mint_config_id}")
                return False
        except ValueError:
            error_log(f"Invalid mint_config_id numerical part: {mint_config_id}")
            return False

        method_id = "0x1ff7712f"
        
        data = method_id
        data += pack_id_hex
        
        data += "0000000000000000000000000000000000000000000000000000000000000060"
        
        array_length = hex(len(proof))[2:].zfill(64)
        data += array_length
        
        for element in proof:
            if element.startswith('0x'):
                element = element[2:]
            data += element.zfill(64)
        
        wallet_address_checksum = monad_web3.to_checksum_address(wallet_address)
        nonce = monad_web3.eth.get_transaction_count(wallet_address_checksum, 'pending')
        
        gas_price = monad_web3.eth.gas_price
        max_priority_fee = monad_web3.to_wei(1.5, 'gwei')
        max_fee_per_gas = gas_price * 2
        
        transaction = {
            'nonce': nonce,
            'to': contract_address,
            'value': 0,
            'gas': 200000,
            'maxFeePerGas': max_fee_per_gas,
            'maxPriorityFeePerGas': max_priority_fee,
            'data': data,
            'type': 2,
            'chainId': 10143
        }
        
        try:
            account = monad_web3.eth.account.from_key(private_key)
            signed_txn = account.sign_transaction(transaction)
            tx_hash = monad_web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            debug_log(f"Transaction sent for account {account_number}: {tx_hash_hex}")
            
            receipt = None
            retry_count = 10
            while retry_count > 0 and receipt is None:
                try:
                    receipt = monad_web3.eth.get_transaction_receipt(tx_hash)
                    if receipt:
                        if receipt['status'] == 1:
                            success_log(f"Pack claim transaction confirmed for account {account_number}: {tx_hash_hex}")
                            return True
                        else:
                            error_log(f"Pack claim transaction failed for account {account_number}: {tx_hash_hex}")
                            return False
                except Exception:
                    sleep(2)
                    retry_count -= 1
            
            if not receipt:
                info_log(f"Transaction pending for account {account_number}: {tx_hash_hex}. Will check status later.")
                return True
                
        except Exception as e:
            error_log(f"Error sending transaction for account {account_number}: {str(e)}")
            return False
            
    except Exception as e:
        error_log(f"Error claiming fragment pack for account {account_number}: {str(e)}")
        return False

def _get_merkle_proof(self, token, mint_config_id):
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
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        response = self.session.get(
            f'https://secret-api.fantasy.top/card/get-merkle-proof/{mint_config_id}',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                f'https://secret-api.fantasy.top/card/get-merkle-proof/{mint_config_id}',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to get merkle proof: {response.status_code}")
            return None
        
        data = response.json()
        return data.get('proof', [])
            
    except Exception as e:
        error_log(f"Error getting merkle proof: {str(e)}")
        return None

def process_fragment_packs(self, token, wallet_address, account_number, private_key):
    try:
        packs_processed = False
        
        rewards_data = self.check_other_rewards(token, wallet_address, account_number, claim=False)
        
        if rewards_data and isinstance(rewards_data, dict) and 'otherRewards' in rewards_data:
            fragment_packs = [reward for reward in rewards_data['otherRewards'] 
                            if reward.get('type') == 'FRAGMENT_PACK' and reward.get('is_activated', False)]
            
            if not fragment_packs:
                debug_log(f"No fragment packs found for account {account_number}")
                return False
                
            success_log(f"Found {len(fragment_packs)} fragment packs for account {account_number}")
            
            for pack in fragment_packs:
                pack_id = pack.get('id')
                mint_config_id = pack.get('mint_config_id')
                
                if pack_id and mint_config_id:
                    info_log(f"Account {account_number}: Found fragment pack {pack_id} with config {mint_config_id}")
                    
                    claim_result = self.claim_fragment_pack(
                        token, wallet_address, account_number, private_key, pack_id, mint_config_id
                    )
                    
                    if claim_result:
                        success_log(f"Account {account_number}: Successfully claimed fragment pack {pack_id}")
                        packs_processed = True
                    else:
                        info_log(f"Account {account_number}: Failed to claim fragment pack {pack_id}")
        
        return packs_processed
        
    except Exception as e:
        error_log(f"Error processing fragment packs for account {account_number}: {str(e)}")
        return False

def check_other_rewards(self, token, wallet_address, account_number, claim=True):
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
            'User-Agent': self.user_agent,
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        response = self.session.get(
            'https://secret-api.fantasy.top/player/player-rewards',
            headers=headers,
            proxies=self.proxies if self.proxies else None,
            timeout=10
        )
        
        if response.status_code == 401 and auth_token == privy_id_token and token:
            auth_token = token
            headers['Authorization'] = f'Bearer {auth_token}'
            response = self.session.get(
                'https://secret-api.fantasy.top/player/player-rewards',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
        
        if response.status_code != 200:
            error_log(f"Failed to check other rewards: {response.status_code}")
            return False
        
        data = response.json()
        
        if not claim:
            return data
            
        other_rewards = data.get('otherRewards', [])
        
        if not other_rewards:
            debug_log(f"No other rewards found for account {account_number}")
            return False
        
        success_log(f"Found {len(other_rewards)} other rewards for account {account_number}")
        
        claimed_rewards = 0
        for reward in other_rewards:
            reward_id = reward.get('id')
            reward_type = reward.get('type', 'UNKNOWN')
            reward_amount = reward.get('amount', '0')
            
            if reward_type == 'FRAGMENT_PACK':
                debug_log(f"Skipping FRAGMENT_PACK reward (handled separately) for account {account_number}")
                continue
                
            if not reward_id:
                continue
                
            info_log(f"Account {account_number}: Found reward {reward_type}({reward_amount}), ID: {reward_id}")
            
            claim_result = self.claim_other_rewards(token, wallet_address, account_number, reward_id)
            if claim_result:
                claimed_rewards += 1
                self._update_account_stats_after_reward_claim(wallet_address, reward_type, reward_amount)
            
            time.sleep(1)
        
        if claimed_rewards > 0:
            success_log(f"Successfully claimed {claimed_rewards} other rewards for account {account_number}")
            return True
        return False
            
    except Exception as e:
        error_log(f"Error checking other rewards: {str(e)}")
        return False

def handle_fragment_roulette_result(self, token, wallet_address, account_number, private_key, roulette_result):
    try:
        if not roulette_result or not isinstance(roulette_result, dict) or not roulette_result.get('success', False):
            return False
            
        selected_prize = roulette_result.get('selectedPrize', {})
        prize_type = selected_prize.get('type', '')
        
        if prize_type != 'PACK':
            return False
            
        sleep(2)
            
        return self.process_fragment_packs(token, wallet_address, account_number, private_key)
        
    except Exception as e:
        error_log(f"Error handling fragment roulette result for account {account_number}: {str(e)}")
        return False

def _update_account_stats_after_reward_claim(self, wallet_address, reward_type, reward_amount):
    try:
        result_file = self.config['app']['result_file']
        if not os.path.exists(result_file):
            return
            
        lines = []
        updated = False
        
        with open(result_file, 'r', encoding='utf-8') as f:
            for line in f:
                if wallet_address in line:
                    parts = line.strip().split(':')
                    
                    if reward_type == 'FAN':
                        amount = int(reward_amount)
                        for i, part in enumerate(parts):
                            if part.startswith('fantasy_points='):
                                try:
                                    current_points = int(part.split('=')[1])
                                    parts[i] = f"fantasy_points={current_points + amount}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                    
                    elif reward_type == 'FRAGMENT':
                        amount = int(reward_amount)
                        for i, part in enumerate(parts):
                            if part.startswith('fragments='):
                                try:
                                    current_fragments = int(part.split('=')[1])
                                    parts[i] = f"fragments={current_fragments + amount}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                    
                    elif reward_type == 'WHITELIST_TICKET':
                        amount = int(reward_amount)
                        for i, part in enumerate(parts):
                            if part.startswith('whitelist_tickets='):
                                try:
                                    current_tickets = int(part.split('=')[1])
                                    parts[i] = f"whitelist_tickets={current_tickets + amount}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                    
                    line = ':'.join(parts) + '\n'
                
                lines.append(line)
        
        if updated:
            with open(result_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
                debug_log(f"Updated account stats after reward claim for {wallet_address}: {reward_type}({reward_amount})")
    
    except Exception as e:
        error_log(f"Error updating account stats after reward claim: {str(e)}")

    def fragment_roulette(self, token, wallet_address, account_number, private_key=None):
        try:
            privy_id_token = None
            for cookie in self.session.cookies:
                if cookie.name == 'privy-id-token':
                    privy_id_token = cookie.value
                    break
            
            auth_token = privy_id_token if privy_id_token else token
            
            player_data = None
            fragments = 0
            
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Authorization': f'Bearer {auth_token}',
                'Origin': 'https://monad.fantasy.top',
                'Referer': 'https://monad.fantasy.top/',
                'User-Agent': self.user_agent
            }
            
            response = self.session.get(
                f'https://secret-api.fantasy.top/player/basic-data/{wallet_address}',
                headers=headers,
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'players_by_pk' in data:
                    player_data = data['players_by_pk']
                    fragments = int(player_data.get('fragments', 0))
                    
                    if fragments < self.config['fragment_roulette']['min_fragments']:
                        info_log(f"Account {account_number} has {fragments} fragments, need {self.config['fragment_roulette']['min_fragments']} for roulette. Skipping.")
                        return False
            else:
                try:
                    with open(self.config['app']['result_file'], 'r', encoding='utf-8') as f:
                        for line in f:
                            if wallet_address in line:
                                parts = line.strip().split(':')
                                for part in parts:
                                    if part.startswith('fragments='):
                                        try:
                                            fragments = int(part.split('=')[1])
                                            if fragments < self.config['fragment_roulette']['min_fragments']:
                                                info_log(f"Account {account_number} has {fragments} fragments (from file), need {self.config['fragment_roulette']['min_fragments']} for roulette. Skipping.")
                                                return False
                                        except (ValueError, IndexError):
                                            pass
                except Exception as e:
                    error_log(f"Error reading fragments from file for account {account_number}: {str(e)}")
                    return False
            
            if fragments < self.config['fragment_roulette']['min_fragments']:
                info_log(f"Account {account_number} has insufficient fragments ({fragments}) for roulette.")
                return False
            
            info_log(f"Account {account_number} has {fragments} fragments, proceeding with fragment roulette.")
            
            headers['Content-Length'] = '0'
            headers['Priority'] = 'u=1, i'
            headers['Sec-Ch-Ua'] = '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"'
            headers['Sec-Ch-Ua-Mobile'] = '?0'
            headers['Sec-Ch-Ua-Platform'] = '"Windows"'
            headers['Sec-Fetch-Dest'] = 'empty'
            headers['Sec-Fetch-Mode'] = 'cors'
            headers['Sec-Fetch-Site'] = 'same-site'
            
            roulette_response = self.session.post(
                'https://secret-api.fantasy.top/roulette/fragment-roulette',
                headers=headers,
                data="",
                proxies=self.proxies if self.proxies else None,
                timeout=10
            )
            
            if roulette_response.status_code == 401 and auth_token == privy_id_token and token:
                auth_token = token
                headers['Authorization'] = f'Bearer {auth_token}'
                roulette_response = self.session.post(
                    'https://secret-api.fantasy.top/roulette/fragment-roulette',
                    headers=headers,
                    data="",
                    proxies=self.proxies if self.proxies else None,
                    timeout=10
                )
            
            if roulette_response.status_code == 429:
                info_log(f"Rate limit hit for fragment roulette on account {account_number}. Skipping.")
                return False
            
            if roulette_response.status_code != 200:
                error_log(f"Failed fragment roulette for account {account_number}, status: {roulette_response.status_code}")
                return False
            
            roulette_data = roulette_response.json()
            if not roulette_data.get('success', False):
                info_log(f"Fragment roulette failed or already spun for account {account_number}: {roulette_data}")
                return False
            
            selected_prize = roulette_data.get('selectedPrize', {})
            prize_type = selected_prize.get('type', 'Unknown')
            prize_amount = selected_prize.get('text', 'Unknown')
            
            success_log(f"Account {account_number}: Fragment roulette successful! Prize: {prize_type} ({prize_amount})")
            
            if prize_type == 'PACK' and private_key:
                self.handle_fragment_roulette_result(token, wallet_address, account_number, private_key, roulette_data)
            
            self._update_account_stats_after_roulette(wallet_address, fragments, prize_type, prize_amount)
            
            return True
            
        except Exception as e:
            error_log(f"Error in fragment roulette for account {account_number}: {str(e)}")
            return False

    def _update_account_stats_after_roulette(self, wallet_address, current_fragments, prize_type, prize_amount):
        try:
            result_file = self.config['app']['result_file']
            if not os.path.exists(result_file):
                return
                
            lines = []
            updated = False
            
            with open(result_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if wallet_address in line:
                        parts = line.strip().split(':')
                        
                        # Deduct the fragments used for roulette
                        fragments_used = self.config['fragment_roulette']['min_fragments']
                        for i, part in enumerate(parts):
                            if part.startswith('fragments='):
                                try:
                                    current = int(part.split('=')[1])
                                    parts[i] = f"fragments={max(0, current - fragments_used)}"
                                    updated = True
                                except (ValueError, IndexError):
                                    pass
                        
                        # Add prize if applicable
                        if prize_type == 'FAN':
                            try:
                                amount = int(prize_amount)
                                for i, part in enumerate(parts):
                                    if part.startswith('fantasy_points='):
                                        current_points = int(part.split('=')[1])
                                        parts[i] = f"fantasy_points={current_points + amount}"
                                        updated = True
                            except (ValueError, IndexError):
                                pass
                        
                        elif prize_type == 'FRAGMENT':
                            try:
                                amount = int(prize_amount)
                                for i, part in enumerate(parts):
                                    if part.startswith('fragments='):
                                        current = int(part.split('=')[1])
                                        parts[i] = f"fragments={current + amount}"
                                        updated = True
                            except (ValueError, IndexError):
                                pass
                        
                        elif prize_type == 'WHITELIST_TICKET':
                            try:
                                amount = int(prize_amount)
                                for i, part in enumerate(parts):
                                    if part.startswith('whitelist_tickets='):
                                        current_tickets = int(part.split('=')[1])
                                        parts[i] = f"whitelist_tickets={current_tickets + amount}"
                                        updated = True
                            except (ValueError, IndexError):
                                pass
                        
                        line = ':'.join(parts) + '\n'
                    
                    lines.append(line)
            
            if updated:
                with open(result_file, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                    debug_log(f"Updated account stats after fragment roulette for {wallet_address}")
        
        except Exception as e:
            error_log(f"Error updating account stats after fragment roulette: {str(e)}")
