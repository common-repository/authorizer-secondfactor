<?php

if (!defined('ABSPATH')) die('Access denied.');

class Authorizer_TFA  {

	/**
	 * Class constructor
	 *
	 */
	public function __construct()
    {
		$this->is_php_71 = (7 == PHP_MAJOR_VERSION && 1 == PHP_MINOR_VERSION);
	}
	
	/**
	 * hex2bin() does not exist before PHP 5.4 (https://php.net/hex2bin)
	 *
	 * @param String $data
	 *
	 * @return String
	 */
	private function hex2bin($data)
    {
		if (function_exists('hex2bin')) return hex2bin($data);
		$len = strlen($data);
		if (null === $len) return;
		if ($len % 2) {
			trigger_error('hex2bin(): Hexadecimal input string must have an even length', E_USER_WARNING);
			return false;
		}
		return pack('H*', $data);
	}
	
	    /**
     * @param string $jwt encoded JWT
     * @param int $section the section we would like to decode
     * @return object
     */
    private function decodeJWT($jwt, $section = 0)
    {
        $dectoken = null;
        $parts = explode('.', $jwt);
        if (count($parts) === 3) {
            $dectoken = json_decode($this->base64url_decode($parts[$section]));
        }

        return $dectoken;
    }
	
	/**
     * A wrapper around base64_decode which decodes Base64URL-encoded data,
     * which is not the same alphabet as base64.
     * @param string $base64url
     * @return bool|string
     */
    private function base64url_decode($base64url)
    {
        // error_log($base64url);
        return base64_decode($this->b64url2b64($base64url));
    }

    /**
     * Per RFC4648, "base64 encoding with URL-safe and filename-safe
     * alphabet".  This just replaces characters 62 and 63.  None of the
     * reference implementations seem to restore the padding if necessary,
     * but we'll do it anyway.
     * @param string $base64url
     * @return string
     */
    private function b64url2b64($base64url)
    {
        // "Shouldn't" be necessary, but why not
        $padding = strlen($base64url) % 4;
        if ($padding > 0) {
            $base64url .= str_repeat('=', 4 - $padding);
        }
        return strtr($base64url, '-_', '+/');
    }

	public function getAccessToken()
    {
		global $authorizer_two_factor_authentication;
		
		$accessToken = $authorizer_two_factor_authentication->get_option('tfa_default_accesstoken');
		$default_refreshtoken = $authorizer_two_factor_authentication->get_option('tfa_default_refreshtoken');
		$default_oauthurl = 'https://api.authorizer.de/auth/realms/Authorizer';
		
		$decoded_token = $this->decodeJWT($accessToken, 1);
		if ($decoded_token === null || $decoded_token->exp <= time()) {
            $method = 'POST';
            $url = $default_oauthurl."/protocol/openid-connect/token";
            $params = array(
                'grant_type' => 'refresh_token',
                'scope' => 'offline_access',
                'refresh_token' => $default_refreshtoken,
                'client_id' => 'second-factor-service'
            );
            $headers = array('Content-Type' => 'application/x-www-form-urlencoded');
            $response = $this->remoteCall($method, $url, $headers, $params);

            if (is_array($response) && !empty($response['access_token']) && !empty($response['refresh_token'])) {
                $accessToken = $response['access_token'];
                $authorizer_two_factor_authentication->update_option('tfa_default_accesstoken', $accessToken);
                $authorizer_two_factor_authentication->update_option('tfa_default_refreshtoken', $response['refresh_token']);
            }
		}

		return $accessToken;
	}

	public function PluginIsConfigured()
    {
        return substr_count($this->getAccessToken(), '.') == 2;
	}

	public function getUserLogin($login)
    {
		global $wpdb;

		$query = filter_var($login, FILTER_VALIDATE_EMAIL) ? $wpdb->prepare("SELECT ID, user_login from ".$wpdb->users." WHERE user_email=%s", $login) : $wpdb->prepare("SELECT ID, user_login from ".$wpdb->users." WHERE user_login=%s", $login);
		$user = $wpdb->get_row($query);
		
		if (!$user && filter_var($login, FILTER_VALIDATE_EMAIL)) {
			// Corner-case: login looks like an email, but is a username rather than email address
			$user = $wpdb->get_row($wpdb->prepare("SELECT ID, user_login from ".$wpdb->users." WHERE user_login=%s", $login));
		}

		return $user->user_login;
	}

	public function getUserMail($params)
    {
		global $wpdb;

		$query = filter_var($params['log'], FILTER_VALIDATE_EMAIL) ? $wpdb->prepare("SELECT ID, user_email from ".$wpdb->users." WHERE user_email=%s", $params['log']) : $wpdb->prepare("SELECT ID, user_email from ".$wpdb->users." WHERE user_login=%s", $params['log']);
		$user = $wpdb->get_row($query);
		
		if (!$user && filter_var($params['log'], FILTER_VALIDATE_EMAIL)) {
			// Corner-case: login looks like an email, but is a username rather than email address
			$user = $wpdb->get_row($wpdb->prepare("SELECT ID, user_email from ".$wpdb->users." WHERE user_login=%s", $params['log']));
		}

		return $user->user_email;
	}

	public function prepareAndExecRemoteCall($params, $call, $payload)
    {
		return $response;
	}

    public function getAllAccounts()
    {
	    global $authorizer_two_factor_authentication;

		$accessToken = $this->getAccessToken();
		$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

		$method = 'GET';
		$reqparams = array();
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/account";
		$headers = array(
		    'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken
        );
	
		$response = $this->remoteCall($method, $url, $headers, $reqparams);

		return $response;
    }

	public function getTanMethods($params)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		if ($authorizer_two_factor_authentication->get_option('tfa_account_find_by') == "byemail") {
			$account = $this->getUserMail($params);
		} else {
			$account = $this->getUserLogin($params['log']);
		}
			
		$accessToken = $this->getAccessToken();
		//$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_apiurl = 'https://api.authorizer.de/secondFactor';
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

		$method = 'GET';
		$reqparams = array();
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/account/".urlencode($account);
        $headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken
        );
	
		$response = $this->remoteCall($method, $url, $headers, $reqparams);
		$tfa_methods = array();
        if (isset($response['data']['meta']['challengeTypesAvailable']['mailTan']) && $response['data']['meta']['challengeTypesAvailable']['mailTan'] === true) {
            array_push($tfa_methods, "EMail");
        }
        if (isset($response['data']['meta']['challengeTypesAvailable']['smsTan']) && $response['data']['meta']['challengeTypesAvailable']['smsTan'] === true) {
            array_push($tfa_methods, "SMS");
        }

		return $tfa_methods;
	}

	public function getAccountData($identifier)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		$accessToken = $this->getAccessToken();
		$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

		$method = 'GET';
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/account/".urlencode($identifier);
        $headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken
        );
	
		return $this->remoteCall($method, $url, $headers);
    }

    public function getAccounts()
    {
        global $wpdb;
        global $authorizer_two_factor_authentication;

        $accessToken = $this->getAccessToken();
        $default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
        $default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

        $method = 'GET';
        $reqparams = array();
        $url = $default_apiurl."/contract/".urlencode($default_contractid)."/account";
        $headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken
        );

        $response = $this->remoteCall($method, $url, $headers, $reqparams);

        return $response;
    }

    public function createTFAAccount($login, $mail, $phone, $enmail, $ensms)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		$accessToken = $this->getAccessToken();
		$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

		$method = 'POST';
        $params = json_encode([
            'data' => [
                'type' => 'account',
                'id' => $login,
                'attributes' => [
                    'challengeTypes' => [
                        'mailTan' => [
                            'email' => $mail,
                            'enabled' => $enmail
                        ],
                        'smsTan' => [
                            'phoneNumber' => $phone,
                            'enabled' => $ensms
                        ]
                    ]
                ],
                'relationships' => [
                   'challengeTemplate' => [
                       'data' => [
                           'type' => 'challengeTemplate',
                           'id' => 1
                       ]
                   ]
                ]
            ]
        ]);
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/account";
		$headers = array(
                'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
			    'Content-Type' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
			    'Authorization' => 'Bearer '.$accessToken
        );
		$response = $this->remoteCall($method, $url, $headers, $params);

		return true;
	}

	public function modifyTFAAccount($login, $mail, $phone, $enmail, $ensms)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		$accessToken = $this->getAccessToken();
		$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

		$method = 'PATCH';
		$params = json_encode([
		    'data' => [
		        'type' => 'account',
                'id' => $login,
                'attributes' => [
                    'challengeTypes' => [
                        'mailTan' => [
                            'email' => $mail,
                            'enabled' => $enmail
                        ],
                        'smsTan' => [
                            'phoneNumber' => $phone,
                            'enabled' => $ensms
                        ]
                    ]
                ]
            ]
        ]);
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/account/".urlencode($login);
		$headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Content-Type' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken);
	
		$response = $this->remoteCall($method, $url, $headers, $params);

		return true;
	}

    public function deleteTFAAccount($login)
    {
        global $wpdb;
        global $authorizer_two_factor_authentication;

        $accessToken = $this->getAccessToken();
        $default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
        $default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

        $method = 'DELETE';
        $params = json_encode([
            'data' => [
                'type' => 'account',
                'id' => $login,
            ]
        ]);
        $url = $default_apiurl."/contract/".urlencode($default_contractid)."/account/".urlencode($login);
        $headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken);

        $response = $this->remoteCall($method, $url, $headers, $params);

        return true;
    }

	public function autoconfigTFAPlugin($autouser, $autopass)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		$method = 'POST';
		$url = "https://api.authorizer.de/auth/realms/Authorizer/protocol/openid-connect/token";
		$params = array(
			'grant_type' => 'password',
            'username' => $autouser,
            'password' => $autopass,
            'client_id' => 'control-panel-service'
		);
        $headers = array('Content-Type' => 'application/x-www-form-urlencoded');
        $response = $this->remoteCall($method, $url, $headers, $params);
		if (!array_key_exists('access_token', $response)) {
		    return $response;
        }
		$accessToken = $response['access_token'];

		$method = 'GET';
		$url = "https://api.authorizer.de/contract";
		$params = array();
        $headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken
        );
		$response = $this->remoteCall($method, $url, $headers, $params);
        if (!array_key_exists('data', $response)) {
            return $response;
        }
		$contractID = $response['data'][0]['id'];
		$tfaapiuser = $response['data'][0]['attributes']['apiuser'];
		
		$method = 'POST';
		$url = "https://api.authorizer.de/auth/realms/Authorizer/protocol/openid-connect/token";
		$params = array(
			'scope' => 'offline_access',
			'grant_type' => 'password',
			'username' => $tfaapiuser,
			'client_id' => 'second-factor-service',
			'password' => $autopass
		);
        $headers = array('Content-Type' => 'application/x-www-form-urlencoded');
		$response = $this->remoteCall($method, $url, $headers, $params);
        if (!array_key_exists('refresh_token', $response)) {
            return $response;
        }

		$authorizer_two_factor_authentication->update_option('tfa_default_contractid', $contractID);
		$authorizer_two_factor_authentication->update_option('tfa_default_refreshtoken', $response['refresh_token']);
        $authorizer_two_factor_authentication->update_option('tfa_default_accesstoken', $response['access_token']);

		return true;
	}

	public function verifyTFA($umail, $ucode)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		$accessToken = $this->getAccessToken();
		//$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_apiurl = 'https://api.authorizer.de/secondFactor';
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');

		// error_log("In verify\n");

		$method = 'GET';
		$reqparams = array();
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/account/".urlencode($umail)."/latestChallenge";
        $headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken
        );

		// error_log("$url\n");

		$response = $this->remoteCall($method, $url, $headers, $reqparams);
		$tanid = $response['data']['id'];
		$tanmethod = $response['data']['type'];

		$method = 'PATCH';
		$reqparams = '{ "data": { "type": "'.$tanmethod.'", "id": '.$tanid.', "attributes": { "solution": '.json_encode($ucode).' } } }';
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/".urlencode($tanmethod)."/".urlencode($tanid);
		$headers = array(
            'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
			'Content-Type' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
            'Authorization' => 'Bearer '.$accessToken);
	
		$response = $this->remoteCall($method, $url, $headers, $reqparams);

		return !empty($response['data']['attributes']['solution'])
            && $response['data']['attributes']['solution'] == $ucode;
	}

	public function requestTFA($params)
    {
		global $wpdb;
		global $authorizer_two_factor_authentication;

		$accessToken = $this->getAccessToken();
		$default_apiurl = $authorizer_two_factor_authentication->get_option('tfa_default_apiurl');
		$default_apiurl = 'https://api.authorizer.de/secondFactor';
		$default_contractid = $authorizer_two_factor_authentication->get_option('tfa_default_contractid');
		if ($authorizer_two_factor_authentication->get_option('tfa_account_find_by') == "byemail") {
			$account = $this->getUserMail($params);
		} else {
			$account = $this->getUserLogin($params['log']);
		}

		$tfasel = 'unknown';
		if ($params['sel'] == 'SMS') $tfasel = 'smsTan';
		if ($params['sel'] == 'EMail') $tfasel = 'mailTan';
		if ($params['sel'] == 'Card') $tfasel = 'cardTan';
	
		$method = 'POST';
		$params = '{ "data": { "type": "'.$tfasel.'", "relationships": { "account": { "data": { "type": "account", "id": '.json_encode($account).' } } } } }';
		$url = $default_apiurl."/contract/".urlencode($default_contractid)."/".urlencode($tfasel);
		$headers = array(
                'Accept' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
                'Content-Type' => 'application/vnd.api+json; profile="https://developer.authorizer.de/secondFactor/v1"',
			    'Authorization' => 'Bearer '.$accessToken);
	
		$response = $this->remoteCall($method, $url, $headers, $params);

		if ($response['data']['id'] > 1) {
			return true;
		} else {
			return false;
		}
	}

	public function preAuth($params)
    {
		global $wpdb;

		$query = filter_var($params['log'], FILTER_VALIDATE_EMAIL)
            ? $wpdb->prepare("SELECT ID, user_email from ".$wpdb->users." WHERE user_email=%s", $params['log'])
            : $wpdb->prepare("SELECT ID, user_email from ".$wpdb->users." WHERE user_login=%s", $params['log']);
		$user = $wpdb->get_row($query);
		
		if (!$user && filter_var($params['log'], FILTER_VALIDATE_EMAIL)) {
			// Corner-case: login looks like an email, but is a username rather than email address
			$user = $wpdb->get_row($wpdb->prepare("SELECT ID, user_email from ".$wpdb->users." WHERE user_login=%s", $params['log']));
		}
		
		return $user ? ($this->isActivatedForUser($user->ID) && $this->isActivatedByUser($user->ID)) : false;
	}
	
	public function authUserFromLogin($params)
    {
		$params = apply_filters('authorizertfa_auth_user_from_login_params', $params);
		global $authorizer_two_factor_authentication, $wpdb;
		
		if (!$this->isCallerActive($params)) {
		    return true;
        }
		$field = filter_var($params['log'], FILTER_VALIDATE_EMAIL) ? 'user_email' : 'user_login';
		$query = $wpdb->prepare("SELECT ID, user_registered, user_login, user_email from ".$wpdb->users." WHERE ".$field."=%s", $params['log']);
		$response = $wpdb->get_row($query);

		$user_ID = is_object($response) ? $response->ID : false;
		$user_email = is_object($response) ? $response->user_email : false;
		$user_login = is_object($response) ? $response->user_login : false;
		$user_registered = is_object($response) ? $response->user_registered : false;

		if (!$user_ID) {
		    return true;
        }
		if (!$this->isActivatedForUser($user_ID)) {
		    return true;
        }
		if (!$this->isActivatedByUser($user_ID)) {
			if (!$this->isRequiredForUser($user_ID)) {
			    return true;
            }
			$requireafter = absint($authorizer_two_factor_authentication->get_option('tfa_requireafter')) * 86400;
			$account_age = time() - strtotime($user_registered);
			if ($account_age > $requireafter) {
				return new WP_Error('tfa_required', apply_filters('authorizertfa_notfa_forbidden_login', '<strong>'.__('Error:', 'authorizer-secondfactor').'</strong> '.__('The site owner has forbidden you to login without two-factor authentication. Please contact the site owner to re-gain access.', 'authorizer-secondfactor')));
			}

			return true;
		}

		$tfa_creds_user_id = !empty($params['creds_user_id']) ? $params['creds_user_id'] : $user_ID;
		
		if ($tfa_creds_user_id != $user_ID) {
			// Authenticating using a different user's credentials (e.g. https://wordpress.org/plugins/use-administrator-password/)
			// In this case, we require that different user to have TFA active - so that this mechanism can't be used to avoid TFA
		
			if (!$this->isActivatedForUser($tfa_creds_user_id) || !$this->isActivatedByUser($tfa_creds_user_id)) {
				return new WP_Error('tfa_required', apply_filters('authorizertfa_notfa_forbidden_login_altuser', '<strong>'.__('Error:', 'authorizer-secondfactor').'</strong> '.__('You are attempting to log in to an account that has two-factor authentication enabled; this requires you to also have two-factor authentication enabled on the account whose credentials you are using.', 'authorizer-secondfactor')));
			}
		}

        $user_code = trim(@$params['two_factor_code']);
        if ($authorizer_two_factor_authentication->get_option('tfa_account_find_by') == "byemail") {
			$match = $this->verifyTFA($user_email, trim($user_code));
		} else {
			$match = $this->verifyTFA($user_login, trim($user_code));
	    }
				
		if ($match) {
			//Save the time window when the last successful login took place
			//update_user_meta($tfa_creds_user_id, 'tfa_last_login', $current_time_window);
		}
		
		return $match;
	}
	
	public function changeEnableTFA($user_id, $setting)
    {
		$setting = ($setting === 'true') ? 1 : 0;
		
		update_user_meta($user_id, 'tfa_enable_tfa', $setting);
	}
		
	public function isActivatedForUser($user_id)
    {
		if (empty($user_id)) {
		    return false;
        }
		global $authorizer_two_factor_authentication;

		// Super admin is not a role (they are admins with an extra attribute); needs separate handling
		if (is_multisite() && is_super_admin($user_id)) {
			// This is always a final decision - we don't want it to drop through to the 'admin' role's setting
			$role = '_super_admin';
			$db_val = $authorizer_two_factor_authentication->get_option('tfa_'.$role);
			$db_val = $db_val === false || $db_val ? 1 : 0; //Nothing saved or > 0 returns 1;
			
			return ($db_val) ? true : false;
		}

		$user = new WP_User($user_id);
		foreach ($user->roles as $role) {
			$db_val = $authorizer_two_factor_authentication->get_option('tfa_'.$role);
			$db_val = $db_val === false || $db_val ? 1 : 0; //Nothing saved or > 0 returns 1;
			
			if ($db_val)
				return true;
		}
		
		return false;
	}
	
	// N.B. - This doesn't check isActivatedForUser() - the caller would normally want to do that first
	public function isRequiredForUser($user_id)
    {
		if (empty($user_id)) {
		    return false;
        }
		global $authorizer_two_factor_authentication;

		// Super admin is not a role (they are admins with an extra attribute); needs separate handling
		if (is_multisite() && is_super_admin($user_id)) {
			// This is always a final decision - we don't want it to drop through to the 'admin' role's setting
			$role = '_super_admin';
			$db_val = $authorizer_two_factor_authentication->get_option('tfa_required_'.$role);
			
			return ($db_val) ? true : false;
		}

		$user = new WP_User($user_id);

		foreach ($user->roles as $role) {
			$db_val = $authorizer_two_factor_authentication->get_option('tfa_required_'.$role);
			if ($db_val) {
                return true;
            }
		}
		
		return false;
	}
	
	public function isActivatedByUser($user_id)
    {
		return !empty(get_user_meta($user_id, 'tfa_enable_tfa', true));
	}

	private function isCallerActive($params)
    {
		if (!defined('XMLRPC_REQUEST') || !XMLRPC_REQUEST) {
		    return true;
        }
		global $authorizer_two_factor_authentication;

		return !!$authorizer_two_factor_authentication->get_option('tfa_xmlrpc_on');
	}
	
	private function randString($len = 6)
    {
		$chars = '23456789QWERTYUPASDFGHJKLZXCVBNM';
		$chars = str_split($chars);
		shuffle($chars);
		$code = implode('', array_splice($chars, 0, $len));
		return $code;
	}

	private function remoteCall($method, $url, $headers, $params = null)
    {
		switch($method) {
		    case 'GET':
                $url .= ($params ? ('?' . http_build_query($params)) : '');
                $response = wp_remote_get($url, array(
                    'headers' => $headers,
                    'sslverify' => false
                ));
                $http_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
		         break;

		    case 'POST':
                $response = wp_remote_post($url, array(
                    'method' => 'POST',
                    'body' => $params,
                    'headers' => is_array($headers) ? $headers : array(),
                    'sslverify' => false
                ));
                $http_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                break;

		    case 'PUT':
                $response = wp_remote_request($url, array(
                    'method' => 'PUT',
                    'body' => $params,
                    'headers' => is_array($headers) ? $headers : array(),
                    'sslverify' => false
                ));
                $http_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                break;

		    case 'PATCH':
                $response = wp_remote_request($url, array(
                    'method' => 'PATCH',
                    'body' => $params,
                    'headers' => is_array($headers) ? $headers : array(),
                    'sslverify' => false
                ));
                $http_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                break;

		    case 'DELETE':
                $response = wp_remote_request($url, array(
                    'method' => 'DELETE',
                    'body' => $params,
                    'headers' => is_array($headers) ? $headers : array(),
                    'sslverify' => false
                ));
                $http_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                break;
		}

        if ($http_code >= 200 && $http_code < 300) {
            return json_decode($body, true);
        }

        return 'error ' . $http_code;
    }
}