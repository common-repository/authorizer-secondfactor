<?php
/*
Plugin Name: Authorizer SecondFactor
Plugin URI: https://www.authorizer.de/wordpress
Description: Secure your WordPress login forms with two factor authentication based on Authorizer SecondFactor.
Author: Signatis GmbH
Author URI: https://www.authorizer.de/wordpress
Version: 1.1.3
Text Domain: authorizer-secondfactor
Domain Path: /languages
License: GPLv2 or later
*/

define('AUTHORIZER_TFA_PLUGIN_DIR', dirname( __FILE__ ));
define('AUTHORIZER_TFA_PLUGIN_URL', plugins_url('', __FILE__));
// define('TWO_FACTOR_DISABLE',1);

class Authorizer_Two_Factor_Auth {

	public $version = '1.1.3';
	private $php_required = '5.3';
	private $frontend;

	/**
	 * Constructor, run upon plugin initiation
	 */
	public function __construct()
    {
        if (version_compare(PHP_VERSION, $this->php_required, '<' )) {
			add_action('all_admin_notices', array($this, 'admin_notice_insufficient_php'));
			$abort = true;
		}

		if (!empty($abort)) return;

		add_action('wp_ajax_nopriv_authorizertfa-init-otp', array($this, 'tfaInitLogin'));
		add_action('wp_ajax_authorizertfa-init-otp', array($this, 'tfaInitLogin'));

		add_action('wp_ajax_authorizertfa_shared_ajax', array($this, 'shared_ajax'));

		add_action('affwp_login_fields_before', array($this, 'affwp_login_fields_before'));
		if (!defined('TWO_FACTOR_DISABLE') || !TWO_FACTOR_DISABLE) {
			add_action('affwp_process_login_form', array($this, 'affwp_process_login_form'));
		}
		
		add_filter('tml_display', array($this, 'tml_display'));
		
		add_filter('do_shortcode_tag', array($this, 'do_shortcode_tag'), 10, 2);
		
		if (is_admin()) {
            add_action( 'admin_enqueue_scripts', array($this, 'wpdocs_selectively_enqueue_admin_script'));

            //Add to Settings menu on sites
			add_action('admin_menu', array($this, 'menu_entry_for_admin'));

			//Add settings link in plugin list
			$plugin = plugin_basename(__FILE__); 
			add_filter("plugin_action_links_".$plugin, array($this, 'addPluginSettingsLink' ));
			add_filter('network_admin_plugin_action_links_'.$plugin, array($this, 'addPluginSettingsLink' ));

			// Entry that everybody gets - Disabled for now
			// add_action('network_admin_menu', array($this, 'admin_menu'));
			// add_action('admin_menu', array($this, 'admin_menu'));
		}

		add_action('plugins_loaded', array($this, 'plugins_loaded'));
		add_action('init', array($this, 'init'));
		
		// We want to run first if possible, so that we're not aborted by JavaScript exceptions in other components (our code is critical to the login process for TFA users)
		// Unfortunately, though, people start enqueuing from init onwards (before that is buggy - https://core.trac.wordpress.org/ticket/11526), so, we try to detect the login page and go earlier there. 
		if ('wp-login.php' === $GLOBALS['pagenow']) {
			add_action('init', array($this, 'login_enqueue_scripts'), -99999999999);
		} else {
			add_action('login_enqueue_scripts', array($this, 'login_enqueue_scripts'), -99999999999);
		}
		
		if (!defined('TWO_FACTOR_DISABLE') || !TWO_FACTOR_DISABLE) {
			add_filter('authenticate', array($this, 'tfaVerifyCodeAndUser'), 99999999999, 3);
		}

		if (file_exists(AUTHORIZER_TFA_PLUGIN_DIR.'/updater.php')) include_once(AUTHORIZER_TFA_PLUGIN_DIR.'/updater.php');

		if (defined('DOING_AJAX') && DOING_AJAX && defined('WP_ADMIN') && WP_ADMIN && !empty($_REQUEST['action']) && 'authorizertfa-init-otp' == $_REQUEST['action']) {
			// Try to prevent PHP notices breaking the AJAX conversation
			$this->output_buffering = true;
			$this->logged = array();
			set_error_handler(array($this, 'get_php_errors'), E_ALL & ~E_STRICT);
			ob_start();
		}
	}

	// Ultimate Membership Pro support
	public function do_shortcode_tag($output, $tag)
    {
		if ('ihc-login-form' == $tag) $this->login_enqueue_scripts();
		return $output;
	}

	public function get_php_errors($errno, $errstr, $errfile, $errline)
    {
		if (0 == error_reporting()) return true;
		$logline = $this->php_error_to_logline($errno, $errstr, $errfile, $errline);
		$this->logged[] = $logline;
		# Don't pass it up the chain (since it's going to be output to the user always)
		return true;
	}

	public function php_error_to_logline($errno, $errstr, $errfile, $errline)
    {
		switch ($errno) {
			case 1:		$e_type = 'E_ERROR'; break;
			case 2:		$e_type = 'E_WARNING'; break;
			case 4:		$e_type = 'E_PARSE'; break;
			case 8:		$e_type = 'E_NOTICE'; break;
			case 16:	$e_type = 'E_CORE_ERROR'; break;
			case 32:	$e_type = 'E_CORE_WARNING'; break;
			case 64:	$e_type = 'E_COMPILE_ERROR'; break;
			case 128:	$e_type = 'E_COMPILE_WARNING'; break;
			case 256:	$e_type = 'E_USER_ERROR'; break;
			case 512:	$e_type = 'E_USER_WARNING'; break;
			case 1024:	$e_type = 'E_USER_NOTICE'; break;
			case 2048:	$e_type = 'E_STRICT'; break;
			case 4096:	$e_type = 'E_RECOVERABLE_ERROR'; break;
			case 8192:	$e_type = 'E_DEPRECATED'; break;
			case 16384:	$e_type = 'E_USER_DEPRECATED'; break;
			case 30719:	$e_type = 'E_ALL'; break;
			default:	$e_type = "E_UNKNOWN ($errno)"; break;
		}
		if (!is_string($errstr)) {
		    $errstr = serialize($errstr);
        }
		if (0 === strpos($errfile, ABSPATH)) {
		    $errfile = substr($errfile, strlen(ABSPATH));
        }

		return "PHP event: code $e_type: $errstr (line $errline, $errfile)";
	}

	/**
	 * Runs upon the WordPress 'init' action
	 */
	public function init()
    {
		if ((!is_admin() || (defined('DOING_AJAX') && DOING_AJAX)) && is_user_logged_in() && file_exists(AUTHORIZER_TFA_PLUGIN_DIR.'/includes/tfa_frontend.php')) {
			$this->load_frontend();
		} else {
			add_shortcode('twofactor_user_settings', array($this, 'shortcode_when_not_logged_in'));
		}
	}

	public function admin_notice_insufficient_php()
    {
		$this->show_admin_warning('<strong>'.__('Higher PHP version required', 'authorizer-secondfactor').'</strong><br> '.sprintf(__('The Authorizer SecondFactor plugin requires PHP version %s or higher - your current version is only %s.', 'authorizer-secondfactor'), $this->php_required, PHP_VERSION), 'error');
	}

	public function admin_notice_missing_mcrypt_and_openssl()
    {
		$this->show_admin_warning('<strong>'.__('PHP OpenSSL or mcrypt module required', 'authorizer-secondfactor').'</strong><br> '.__('The Authorizer SecondFactor plugin requires either the PHP openssl (preferred) or mcrypt module to be installed. Please ask your web hosting company to install one of them.', 'authorizer-secondfactor'), 'error');
	}

	public function show_admin_warning($message, $class = "updated")
    {
		echo '<div class="tfamessage '.$class.'">'."<p>$message</p></div>";
	}

	/**
	 * Return a new Authorizer_TFA object
	 *
	 * @returns Authorizer_TFA
	 */
	public function getTFA()
    {
		if (!class_exists('Authorizer_TFA')) {
		    require_once(AUTHORIZER_TFA_PLUGIN_DIR.'/includes/class-authorizer-tfa.php');
        }

		return new Authorizer_TFA();
	}

	// "Shared" - i.e. could be called from either front-end or back-end
	public function shared_ajax()
    {
		if (empty($_POST['subaction']) || empty($_POST['nonce']) || !is_user_logged_in() || !wp_verify_nonce($_POST['nonce'], 'tfa_shared_nonce')) {
		    die('Security check (3).');
        }

		if ($_POST['subaction'] == 'refreshotp') {
			global $current_user;

			$tfa_priv_key_64 = get_user_meta($current_user->ID, 'tfa_priv_key_64', true);

			if (!$tfa_priv_key_64) {
				echo json_encode(array('code' => ''));
				die;
			}

			echo json_encode(array('code' => $this->getTFA()->generateOTP($current_user->ID, $tfa_priv_key_64)));
			exit;
		}
	}

	public function tfaInitLogin()
    {
		$tfastep = (int) sanitize_key($_POST['tfastep']);
		$sel = sanitize_text_field($_POST['selection']);

		if (empty($_POST['user'])) die('Security check (2).');

		$sanitizedUser = sanitize_user($_POST['user']);
		if ($tfastep == 2) {
			$res = $this->getTFA()->requestTFA(array('log' => $sanitizedUser, 'sel' => $sel));
		} else {
			if ((defined('TWO_FACTOR_DISABLE') && TWO_FACTOR_DISABLE)) {
                $res = false;
			} else {
				$res = $this->getTFA()->preAuth(array('log' => $sanitizedUser));
			}
	
			if ($res == true) {
                // check password before getting TAN methods
                $userLogin = $this->getTFA()->getUserLogin($sanitizedUser);
                $user = get_user_by('login', $userLogin);
                if (!$user || !wp_check_password($_POST['pwd'], $user->data->user_pass, $user->ID)) {
                    wp_redirect('/wp-login.php');
                    exit;
                }
				$sel = $this->getTFA()->getTanMethods(array('log' => $sanitizedUser));
			} else {
				$sel = array();
			}
		}

		$results = array('jsonstarter' => 'justhere', 'status' => $res, 'selection' => $sel, 'tfastep' => $tfastep);

		if (!empty($this->output_buffering)) {
			if (!empty($this->logged)) {
				$results['php_output'] = $this->logged;
			}
			restore_error_handler();
			$buffered = ob_get_clean();
			if ($buffered) $results['extra_output'] = $buffered;
		}

		$results = apply_filters('authorizertfa_check_tfa_requirements_ajax_response', $results);
		
		echo json_encode($results);
		exit;
	}

	// Here's where the login action happens. Called on the 'authenticate' action.
	public function tfaVerifyCodeAndUser($user, $username, $password)
    {
	    if (is_wp_error($user)) {
			$ret = $user;
		} else {
			$tfa = $this->getTFA();
			$params = $_POST;
			$params['log'] = $username;
			$params['caller'] = $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['REQUEST_URI'];

			$code_ok = $tfa->authUserFromLogin($params);

			if (is_wp_error($code_ok)) {
				$ret = $code_ok;
			} elseif (!$code_ok) {
				$ret =  new WP_Error('authentication_failed', '<strong>'.__('Error:', 'authorizer-secondfactor').'</strong> '.__('The Authorizer security code you entered was incorrect.', 'authorizer-secondfactor'));
			} elseif ($user) {
				$ret = $user;
			} else {
				$ret = wp_authenticate_username_password(null, $username, $password);
			}
		}
		
		return apply_filters('authorizertfa_verify_code_and_user_result', $ret, $user, $username, $password);
	}
	
	public function tfaRegisterTwoFactorAuthSettings()
    {
		global $wp_roles;
		if (!isset($wp_roles))
			$wp_roles = new WP_Roles();
		
		foreach($wp_roles->role_names as $id => $name) {
			register_setting('tfa_user_roles_group', 'tfa_'.$id);
			register_setting('tfa_user_roles_required_group', 'tfa_required_'.$id);
		}
		if (is_multisite()) {
			register_setting('tfa_user_roles_group', 'tfa__super_admin');
			register_setting('tfa_user_roles_required_group', 'tfa_required__super_admin');
		}
		register_setting('tfa_user_roles_required_group', 'tfa_requireafter');
		register_setting('authorizer_tfa_default_hmac_group', 'tfa_default_hmac');
		register_setting('authorizer_tfa_default_refresh_token', 'tfa_default_refreshtoken');
		register_setting('authorizer_tfa_default_access_token', 'tfa_default_accesstoken');
        $optargs = array(
            'type' => 'string',
            'default' => 'second-factor-service',
        );
		register_setting('authorizer_tfa_default_clientid', 'tfa_default_clientid', $optargs);
		register_setting('authorizer_tfa_default_contractid', 'tfa_default_contractid');
		$optargs = array(
            'type' => 'string',
            'default' => 'https://api.authorizer.de/secondFactor',
        );
		register_setting('authorizer_tfa_default_api_url', 'tfa_default_apiurl', $optargs);
		$optargs = array(
            'type' => 'string',
            'default' => 'https://api.authorizer.de/auth/realms/Authorizer',
        );
		register_setting('authorizer_tfa_default_oauth_url', 'tfa_default_oauthurl', $optargs);
		register_setting('tfa_xmlrpc_status_group', 'tfa_xmlrpc_on');
	}

	public function tfaListEnableRadios($user_id, $long_label = false)
    {
		if(!$user_id)
			return;
			
		$setting = get_user_meta($user_id, 'tfa_enable_tfa', true);
		$setting = !$setting ? false : $setting;
		
		$tfa = $this->getTFA();

		if ($tfa->isRequiredForUser($user_id)) {
			$requireafter = absint($this->get_option('tfa_requireafter'));

			echo '<p class="tfa_required_warning" style="font-weight:bold; font-style:italic;">'.sprintf(__('N.B. This site is configured to forbid you to log in if you disable two-factor authentication after your account is %d days old', 'authorizer-secondfactor'), $requireafter).'</p>';
		}

		$tfa_enabled_label = ($long_label) ? __('Enable two-factor authentication', 'authorizer-secondfactor') : __('Enabled', 'authorizer-secondfactor');
		$tfa_disabled_label = ($long_label) ? __('Disable two-factor authentication', 'authorizer-secondfactor') : __('Disabled', 'authorizer-secondfactor');

		print '<input type="radio" class="tfa_enable_radio" id="tfa_enable_tfa_true" name="tfa_enable_tfa" value="true" '.($setting == true ? 'checked="checked"' :'').'> <label class="tfa_enable_radio_label" for="tfa_enable_tfa_true">'.apply_filters('authorizertfa_radiolabel_enabled', $tfa_enabled_label, $long_label).'</label> <br>';

		print '<input type="radio" class="tfa_enable_radio" id="tfa_enable_tfa_false" name="tfa_enable_tfa" value="false" '.($setting == false ? 'checked="checked"' :'').'> <label class="tfa_enable_radio_label" for="tfa_enable_tfa_false">'.apply_filters('authorizertfa_radiolabel_disabled', $tfa_disabled_label, $long_label).'</label> <br>';
	}

	public function get_option($key)
    {
		if (!is_multisite()) {
		    return get_option($key);
        }
		switch_to_blog(1);
		$v = get_option($key);
		restore_current_blog();

		return $v;
	}

	public function update_option($key, $val)
    {
		if (!is_multisite()) {
		    return update_option($key, $val);
        }
		switch_to_blog(1);
		$v = update_option($key, $val);
		restore_current_blog();

		return $v;
	}

	public function tfaListUserTFACaps()
	{
		global $wp_users;
		$wp_users = get_users( array( 'fields' => array( 'ID', 'user_login', 'user_email' ) ) );

        $authorizerAccounts = $this->getTFA()->getAccounts();
        $accountList = array();
        foreach ($authorizerAccounts['data'] as $account) {
            $accountList[$account['id']] = $account;
        }

        print '<table style="width:100%; margin-bottom: -47px;">';
		print '<tr>
            <th style="width:15%; text-align: left; padding-right: 20px;">'.__('Username', 'authorizer-secondfactor').'</th>
            <th style="width:15%; text-align: left; padding-right: 35px;" class="nobr">'.__('TFA active', 'authorizer-secondfactor').'</th>
            <th style="width:40%; text-align: left;">'.__('mailTAN', 'authorizer-secondfactor').'<sup>*</sup></th>
            <th style="width:30%; text-align: left;">'.__('smsTAN', 'authorizer-secondfactor').'<sup>* **</sup></th>
        </tr>';

		foreach($wp_users as $user) {
		    $account = $accountList[$user->user_login];
			$exists = !empty($account);
			$tfaActivated = !empty($account['attributes']['challengeTypes']['mailTan']['enabled'])
                            || !empty($account['attributes']['challengeTypes']['smsTan']['enabled']);
            if (!$exists || !$tfaActivated) {
                update_user_meta($user->ID, 'tfa_enable_tfa', 0);
            }
            $setting = get_user_meta($user->ID, 'tfa_enable_tfa', true);

            print '<tr>';
			print '<td style="padding-right: 20px;">'.esc_html($user->user_login).'</td>';
			print '<td><input '
                .'onclick="switchEnableTfaFields(this, \''.esc_html($user->ID).'\');" '
                .'type="checkbox" '
                .'id="tfa_enable_tfa_box_'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][enable_tfa]" '
                .'value="1" '
                .($setting ? 'checked="checked"' :'').' />';
			print '</td>';

            $smsenabled = !empty($account['attributes']['challengeTypes']['smsTan']['enabled']);
            $mailenabled = !empty($account['attributes']['challengeTypes']['mailTan']['enabled']);

            print '<td style="white-space: nowrap; padding-right: 20px;">';
            print '<input '
                .($setting ? '' : 'disabled ')
                .'onclick="var e=jQuery(\'#tfa_user_mail_field'.esc_html($user->ID).'\'); e.attr(\'placeholder\', this.checked ? \'\' : \''.esc_html(__('Email address', 'authorizer-secondfactor')).'\'); if (this.checked) e.focus();" '
                .'type="checkbox" '
                .'id="tfa_enable_mailtan_'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][enable_mailtan]" '
                .'value="1" '
                .($mailenabled ? 'checked="checked"' :'').'/>'."\n";
            print '<input '
                .(!$setting ? '' : 'disabled ')
                .'type="hidden" '
                .'id="disabled_tfa_enable_mailtan_'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][enable_mailtan]" '
                .'value="'.($mailenabled ? '1' :'').'"/>'."\n";

            print '<input class="authInput" '
                .($setting ? '' : 'disabled ')
                .'type="search" '
                .'size="25" '
                .'placeholder="'.esc_html(__('Email address', 'authorizer-secondfactor')).'" '
                .'id="tfa_user_mail_field'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][mail]" '
                .'value="'.($exists ? esc_html($account['attributes']['challengeTypes']['mailTan']['email']) : '').'">';
            print '<input '
                .(!$setting ? '' : 'disabled ')
                .'type="hidden" '
                .'id="disabled_tfa_user_mail_field'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][mail]" '
                .'value="'.($exists ? esc_html($account['attributes']['challengeTypes']['mailTan']['email']) : '').'">';
            print '</td>'."\n";

            print '<td style="white-space: nowrap;">';
            print '<input '
                .($setting ? '' : 'disabled ')
                .'onclick="var e=jQuery(\'#tfa_user_phone_field'.esc_html($user->ID).'\'); e.attr(\'placeholder\', this.checked ? \'\' : \''.esc_html(__('Mobile phone number', 'authorizer-secondfactor')).'\'); if (this.checked) e.focus();" '
                .'type="checkbox" '
                .'id="tfa_enable_smstan_'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][enable_smstan]" '
                .'value="1" '
                .($smsenabled ? 'checked="checked"' : '').'/>'."\n";
            print '<input '
                .(!$setting ? '' : 'disabled ')
                .'type="hidden" '
                .'id="disabled_tfa_enable_smstan_'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][enable_smstan]" '
                .'value="'.($smsenabled ? '1' :'').'"/>'."\n";

            print '<input class="authInput" '
                .($setting ? '' : 'disabled ')
                .'type="search" '
                .'placeholder="'.esc_html(__('Mobile phone number', 'authorizer-secondfactor')).'" '
                .'id="tfa_user_phone_field'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][phone]" '
                .'value="'.($exists ? esc_html($account['attributes']['challengeTypes']['smsTan']['phoneNumber']) : '').'">';
            print '<input '
                .(!$setting ? '' : 'disabled ')
                .'type="hidden" '
                .'id="disabled_tfa_user_phone_field'.esc_html($user->ID).'" '
                .'name="tfa_user['.esc_html($user->ID).'][phone]" '
                .'value="'.($exists ? esc_html($account['attributes']['challengeTypes']['smsTan']['phoneNumber']) : '').'">';
            print '</td>'."\n";
			print '</tr>';
		}

		print '<tr><td></td><td></td><td colspan="2">';
		print '<hr>';
        print '<div style="margin-top:5px; white-space:nowrap; font-size:12px">'
            .__('Accounts available', 'authorizer-secondfactor').': '.esc_html(!empty($authorizerAccounts['meta']) ? $authorizerAccounts['meta']['accountsAvailable'] : '').', '
            .__('SMS available', 'authorizer-secondfactor').': '.esc_html(!empty($authorizerAccounts['meta']) ? $authorizerAccounts['meta']['smsAvailable'] : '').', '
            .__('transactions available', 'authorizer-secondfactor').': '.esc_html(!empty($authorizerAccounts['meta']) ? __($authorizerAccounts['meta']['transactionsAvailable'], 'authorizer-secondfactor') : '')
            .'</div>';
        print '</td></tr>';
		print '</table>';

        print '<script type="text/javascript">
            function switchEnableTfaFields(e, userId) {
                var checkMailTan = jQuery("#tfa_enable_mailtan_" + userId);
                var checkSmsTan = jQuery("#tfa_enable_smstan_" + userId);
                var inputMailTan = jQuery("#tfa_user_mail_field" + userId);
                var inputSmsTan = jQuery("#tfa_user_phone_field" + userId);

                var disCheckMailTan = jQuery("#disabled_tfa_enable_mailtan_" + userId);
                var disCheckSmsTan = jQuery("#disabled_tfa_enable_smstan_" + userId);
                var disInputMailTan = jQuery("#disabled_tfa_user_mail_field" + userId);
                var disInputSmsTan = jQuery("#disabled_tfa_user_phone_field" + userId);

                if (!e.checked) {
                    disInputMailTan[0].value = inputMailTan[0].value;
                    disInputSmsTan[0].value = inputSmsTan[0].value;
                    disCheckMailTan[0].value = checkMailTan[0].checked ? 1 : 0;
                    disCheckSmsTan[0].value = checkSmsTan[0].checked ? 1 : 0;                    
                }

                disCheckMailTan.attr("disabled", e.checked);
                disCheckSmsTan.attr("disabled", e.checked);
                disInputMailTan.attr("disabled", e.checked);
                disInputSmsTan.attr("disabled", e.checked);                
                
                checkMailTan.attr("disabled", !e.checked);
                checkSmsTan.attr("disabled", !e.checked);
                inputMailTan.attr("disabled", !e.checked);
                inputSmsTan.attr("disabled", !e.checked);                
            }
		</script>';
	}

	public function tfaListUserRolesCheckboxes()
	{
		if (is_multisite()) {
			// Not a real WP role; needs separate handling
			$id = '_super_admin';
			$name = __('Multisite Super Admin', 'authorizer-secondfactor');
			$setting = $this->get_option('tfa_'.$id);
			$setting = $setting === false || $setting ? 1 : 0;
			
			print '<input type="checkbox" id="tfa_'.$id.'" name="tfa_'.$id.'" value="1" '.($setting ? 'checked="checked"' :'').'> <label for="tfa_'.$id.'">'.esc_html($name)."</label><br>\n";
		}

		global $wp_roles;
		if (!isset($wp_roles)) {
		    $wp_roles = new WP_Roles();
        }
		
		foreach($wp_roles->role_names as $id => $name) {
			$setting = $this->get_option('tfa_'.$id);
			$setting = $setting === false || $setting ? 1 : 0;
			
			print '<input type="checkbox" id="tfa_'.$id.'" name="tfa_'.$id.'" value="1" '.($setting ? 'checked="checked"' :'').'> <label for="tfa_'.$id.'">'.esc_html($name)."</label><br>\n";
		}
		
	}

	public function tfaListDefaultRefreshToken()
	{
		$tfa = $this->getTFA();
		$setting = $this->get_option('tfa_default_refreshtoken');
		$setting = $setting === false || !$setting ? $tfa->default_refreshtoken : $setting;

		print '<textarea rows="10" cols="60" id="tfa_default_refreshtoken_field" name="tfa_default_refreshtoken">'.$setting.'</textarea>'."\n";	
	}

	public function tfaListDefaultContractID()
	{
		$tfa = $this->getTFA();
		$setting = $this->get_option('tfa_default_contractid');
		$setting = $setting === false || !$setting ? $tfa->default_contractid : $setting;
		
		 print '<input type="text" id="tfa_default_contractid_field" name="tfa_default_contractid" value="'.$setting.'"><br>'."\n";
	}

	public function tfaListDefaultHMACRadios()
	{
		$tfa = $this->getTFA();
		$setting = $this->get_option('tfa_default_hmac');
		$setting = $setting === false || !$setting ? $tfa->default_hmac : $setting;
		
		$types = array('totp' => __('TOTP (time based - most common algorithm; used by Google Authenticator)', 'authorizer-secondfactor'), 'hotp' => __('HOTP (event based)', 'authorizer-secondfactor'));
		
		foreach($types as $id => $name)
			print '<input type="radio" id="tfa_default_hmac_'.esc_attr($id).'" name="tfa_default_hmac" value="'.$id.'" '.($setting == $id ? 'checked="checked"' :'').'> '.'<label for="tfa_default_hmac_'.esc_attr($id).'">'."$name</label><br>\n";
	}

	public function tfaListXMLRPCStatusRadios()
	{
		$tfa = $this->getTFA();
		$setting = $this->get_option('tfa_xmlrpc_on');
		$setting = $setting === false || !$setting ? 0 : 1;
		
		$types = array(
			'0' => __('Do not require 2FA over XMLRPC (best option if you must use XMLRPC and your client does not support 2FA)', 'authorizer-secondfactor'),
			'1' => __('Do require 2FA over XMLRPC (best option if you do not use XMLRPC or are unsure)', 'authorizer-secondfactor')
		);
		
		foreach($types as $id => $name)
			print '<input type="radio" name="tfa_xmlrpc_on" id="tfa_xmlrpc_on_'.$id.'" value="'.$id.'" '.($setting == $id ? 'checked="checked"' :'').'> <label for="tfa_xmlrpc_on_'.$id.'">'.$name."</label><br>\n";
	}

	public function tfaShowAdminSettingsPage()
	{
		$tfa = $this->getTFA();
		require_once(AUTHORIZER_TFA_PLUGIN_DIR.'/includes/admin_settings.php');
	}

	/*
	public function tfaShowServerSettingsPage()
	{
		$tfa = $this->getTFA();
		require_once(AUTHORIZER_TFA_PLUGIN_DIR.'/includes/server_settings.php');
	}
	*/

	public function tfaShowUserSettingsPage()
	{
		$tfa = $this->getTFA();
		//include AUTHORIZER_TFA_PLUGIN_DIR.'/includes/user_settings.php';
	}

	public function admin_menu() 
	{
		$tfa = $this->getTFA();
		
		global $current_user;
		if(!$tfa->isActivatedForUser($current_user->ID)) return;
		//add_menu_page(__('Authorizer SecondFactor', 'authorizer-secondfactor'), __('SecondFactor Auth', 'authorizer-secondfactor'), 'read', 'two-factor-auth-user', array($this, 'tfaShowUserSettingsPage'), AUTHORIZER_TFA_PLUGIN_URL.'/img/tfa_admin_icon_16x16.png', 72);
	}

	public function wpdocs_selectively_enqueue_admin_script()
    {
        global $pagenow;

        if ($pagenow != 'options-general.php') {
            return;
        }
        wp_register_style('tfa-admin-page-style',plugin_dir_url( __FILE__ ) . '/includes/tfa-admin-page-style.css');
        wp_enqueue_style('tfa-admin-page-style');
    }

	public function menu_entry_for_admin()
    {
		if (is_multisite() && !is_super_admin()) {
		    return;
        }

		add_action( 'admin_init', array($this, 'tfaRegisterTwoFactorAuthSettings' ));
		add_options_page(
			__('Authorizer SecondFactor', 'authorizer-secondfactor'),
			__('Authorizer SecondFactor', 'authorizer-secondfactor'),
			'manage_options',
			'two-factor-auth',
			array($this, 'tfaShowAdminSettingsPage')
		);
		// add_submenu_page('two-factor-auth', __('Server Settings', 'authorizer-secondfactor'), __('Server Settings', 'authorizer-secondfactor'), 'manage_options', 'two-factor-server', array($this, 'tfaShowServerSettingsPage'));
	}

	public function addPluginSettingsLink($links)
	{
		if (!is_network_admin()) {
			$link = '<a href="options-general.php?page=two-factor-auth">'.__('Plugin settings', 'authorizer-secondfactor').'</a>';
			array_unshift($links, $link);
		}

		// %TODO Currently no user settings
		// $link2 = '<a href="admin.php?page=two-factor-auth-user">'.__('User settings', 'authorizer-secondfactor').'</a>';
		// array_unshift($links, $link2);

		return $links;
	}

	public function footer()
    {
		$ajax_url = admin_url('admin-ajax.php');
		// It's possible that FORCE_ADMIN_SSL will make that SSL, whilst the user is on the front-end having logged in over non-SSL - and as a result, their login cookies won't get sent, and they're not registered as logged in.
		if (!is_admin() && substr(strtolower($ajax_url), 0, 6) == 'https:' && !is_ssl()) {
			$also_try = 'http:'.substr($ajax_url, 6);
		}
	}

	public function add_footer($admin)
    {
		static $added_footer;
		if (empty($added_footer)) {
			$added_footer = true;
			add_action( $admin ? 'admin_footer' : 'wp_footer' , array($this, 'footer'));
		}
	}

	public function advanced_settings_box($submit_button_callback = false)
    {
		$tfa = $this->getTFA();
		global $current_user;
	
		?>
		<h2><?php _e('Advanced settings', 'authorizer-secondfactor'); ?></h2>

		<?php
	}

	/**
	 * Called not only upon the WP action login_enqueue_scripts, but potentially upon the action 'init' and various others from other plugins too. It can handle being called multiple times.
	 */
	public function login_enqueue_scripts()
    {
		if (isset($_GET['action']) && 'logout ' != $_GET['action'] && 'login' != $_GET['action']) {
		    return;
        }
		static $already_done = false;
		if ($already_done) {
		    return;
        }
		
		// Prevent cacheing when in debug mode
		$script_ver = (defined('WP_DEBUG') && WP_DEBUG) ? time() : $this->version;

		wp_enqueue_script('tfa-ajax-request', AUTHORIZER_TFA_PLUGIN_URL.'/includes/tfa.js', array('jquery'), $script_ver);
		
		$localize = array(
			'ajaxurl' => admin_url('admin-ajax.php'),
			'click_to_enter_otp' => __("Click to enter One Time Password", 'authorizer-secondfactor'),
			'enter_username_first' => __('You have to enter a username first.', 'authorizer-secondfactor'),
			'otp' => __("Authorizer Security Code", 'authorizer-secondfactor'),
			'otp_login_help' => __('(Check your SecondFactor client (e.g. mail or SMS client) to get this password)', 'authorizer-secondfactor'),
			'nonce' => wp_create_nonce("authorizer_tfa_loginform_nonce"),
            'loginHeadlineSecondFactor' => __('Please choose your desired OTP method', 'authorizer-secondfactor'),
            'loginSms' => __('SMS', 'authorizer-secondfactor'),
            'loginEmail' => __('Email', 'authorizer-secondfactor'),
            'loginCard' => __('Card', 'authorizer-secondfactor'),
            'noSecondFactorMethodAvailable' => __('Unfortunately no second factor method is available.', 'authorizer-secondfactor')
		);
		
		// Spinner exists since WC 3.8. Use the proper functions to avoid SSL warnings.
		if (file_exists(ABSPATH.'wp-admin/images/spinner-2x.gif')) {
			$localize['spinnerimg'] = admin_url('images/spinner-2x.gif');
		} elseif (file_exists(ABSPATH.WPINC.'/images/spinner-2x.gif')) {
			$localize['spinnerimg'] = includes_url('images/spinner-2x.gif');
		}
		
		wp_localize_script('tfa-ajax-request', 'authorizer_tfasettings', $localize);
		
		$already_done = true;
	}

	public function settings_intro_notices()
    {
		?>
		<p class="authorizer_tfa_personal_settings_notice authorizer_tfa_intro_notice">
			<?php echo __('These are your personal settings.', 'authorizer-secondfactor').' '.__('Nothing you change here will have any effect on other users.', 'authorizer-secondfactor'); ?>
		</p>
		<p class="authorizer_tfa_verify_tfa_notice authorizer_tfa_intro_notice"><strong>
			<?php _e('If you activate two-factor authentication, please make sure that you have it properly configured.', 'authorizer-secondfactor'); ?></strong> <?php if (current_user_can('manage_options')) { ?><?php } ?>
		</p>
		<?php
	}

	/**
	 * Run upon the WP plugins_loaded action
	 */
	public function plugins_loaded()
    {
		load_plugin_textdomain(
			'authorizer-secondfactor',
			false,
			dirname(plugin_basename(__FILE__)).'/languages/'
		);
	}

	/**
	 * Make sure that self::$frontend is the instance of TFA_Frontend, and return it
	 *
	 * @return TFA_Frontend
	 */
	public function load_frontend()
    {
		if (!class_exists('TFA_Frontend')) require_once(AUTHORIZER_TFA_PLUGIN_DIR.'/includes/tfa_frontend.php');
		if (empty($this->frontend)) $this->frontend = new TFA_Frontend($this);
		return $this->frontend;
	}

	public function shortcode_when_not_logged_in()
    {
		return '';
	}

	// Affiliate-WP login form
	public function affwp_login_fields_before()
    {
		$this->before_login_form_generic();
	}
	
	public function affwp_process_login_form()
    {
		if (!function_exists('affiliate_wp')) return;
		$affiliate_wp = affiliate_wp();
		$login = $affiliate_wp->login;
		
		$tfa = $this->getTFA();
		$params = array(
			'log' => sanitize_user($_POST['affwp_user_login']),
			'caller'=> $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['REQUEST_URI'],
			'two_factor_code' => sanitize_text_field($_POST['two_factor_code'])
		);
		$code_ok = $tfa->authUserFromLogin($params);
		
		$code_ok = apply_filters('authorizertfa_affwp_process_login_form_auth_result', $code_ok, $params);
		
		if (is_wp_error($code_ok)) {
			$login->add_error($code_ok->get_error_code, $code_ok->get_error_message());
		} elseif (!$code_ok) {
			$login->add_error('authentication_failed', __('Error:', 'authorizer-secondfactor').' '.__('The one-time password (TFA code) you entered was incorrect.', 'authorizer-secondfactor'));
		}
	}
	
	// Shared by some 3rd-party login forms
	// For historical reasons there are references to WooCommerce in this code - left for the sake of not fixing what was not broken
	private function before_login_form_generic()
    {
		static $already_included = false;
		if ($already_included) return;
		$already_included = true;
	
		$script_ver = (defined('WP_DEBUG') && WP_DEBUG) ? time() : $this->version;
		wp_enqueue_script( 'tfa-wc-ajax-request', AUTHORIZER_TFA_PLUGIN_URL.'/includes/wooextend.js', array('jquery'), $script_ver);

		$localize = array(
			'ajaxurl' => admin_url('admin-ajax.php'),
			'click_to_enter_otp' => __("Enter One Time Password (if you have one)", 'authorizer-secondfactor'),
			'enter_username_first' => __('You have to enter a username first.', 'authorizer-secondfactor'),
			'otp' => __("One Time Password", 'authorizer-secondfactor'),
			'nonce' => wp_create_nonce("authorizer_tfa_loginform_nonce"),
			'otp_login_help' => __('(check your OTP app to get this password)', 'authorizer-secondfactor'),
		);
		// Spinner exists since WC 3.8. Use the proper functions to avoid SSL warnings.
		if (file_exists(ABSPATH.'wp-admin/images/spinner-2x.gif')) {
			$localize['spinnerimg'] = admin_url('images/spinner-2x.gif');
		} elseif (file_exists(ABSPATH.WPINC.'/images/spinner-2x.gif')) {
			$localize['spinnerimg'] = includes_url('images/spinner-2x.gif');
		}

		wp_localize_script( 'tfa-wc-ajax-request', 'authorizertfa_wc_settings', $localize);
	}
	
	// WooCommerce login form
	public function woocommerce_before_customer_login_form()
    {
		$this->before_login_form_generic();
	}
	
	// Catch TML login widgets (other TML login forms already trigger)
	public function tml_display($whatever)
    {
		$this->login_enqueue_scripts();
		return $whatever;
	}
}

$authorizer_two_factor_authentication = new Authorizer_Two_Factor_Auth();
