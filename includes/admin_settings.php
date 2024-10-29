<?php
define('AUTHORIZER_TFA_PLUGIN_URL', plugins_url('', __FILE__));

if (!defined('ABSPATH')) {
    die('Access denied.');
}
if (!is_admin() || !current_user_can('manage_options')) {
    exit;
}

global $wp_roles;
global $authorizer_two_factor_authentication;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if ($_POST['form_method'] == "autoconfig") {

        // Sanitize posted auto user
		$autouser = sanitize_email($_POST['auto_user']);
		$autopass = trim($_POST['auto_pass']);

        $result = $authorizer_two_factor_authentication->getTFA()->autoconfigTFAPlugin($autouser, $autopass);
        $autoconfigError = ($result !== true ? __("Unauthorized. Have you already activated your Authorizer customer account?", 'authorizer-secondfactor') : '');

	} else {

        // Sanitize posted user list
        $datalist = $_POST['tfa_user'];
        $sanitizedDatalist = array();
        if (is_array($datalist)) {
            foreach ($datalist as $key => $user) {
                $sanitizedKey = sanitize_key($key);
                $sanitizedEmail = $user['mail'] ? sanitize_email($user['mail']) : '';
                if (!empty($user['phone'])) {
                    $user['phone'] = str_replace(' ', '', $user['phone']);
                    $user['phone'] = str_replace('-', '', $user['phone']);
                    $user['phone'] = str_replace('/', '', $user['phone']);
                    $user['phone'] = preg_replace('/[a-zA-Z]/', '', $user['phone']);
                    $user['phone'] = preg_replace('/^0([1-9])/', '0049$1', $user['phone']);
                    $user['phone'] = preg_replace('/^\+/', '00', $user['phone']);
                    $sanitizedPhone = ctype_digit($user['phone']) ? $user['phone'] : '';
                } else {
                    $sanitizedPhone = '';
                }
                $sanitizedEnableTfa = !!$user['enable_tfa'];
                $sanitizedMailFlag = !!$user['enable_mailtan'];
                $sanitizedSmsFlag = !!$user['enable_smstan'];

                $sanitizedDatalist[$sanitizedKey] = array(
                    'enable_tfa' => $sanitizedEnableTfa,
                    'enable_mailtan' => $sanitizedMailFlag,
                    'mail' => $sanitizedEmail,
                    'enable_smstan' => $sanitizedSmsFlag,
                    'phone' => $sanitizedPhone
                );
            }
        }

        // create/update/delete users
        $wp_users = get_users( array( 'fields' => array( 'ID', 'user_login', 'user_email' ) ) );
        foreach($wp_users as $user) {
            $authorizerAccount = $this->getTFA()->getAccountData($user->user_login);
            $existsOnAuthorizer = isset($authorizerAccount['data']['id'])
                && ($authorizerAccount['data']['id'] == $user->user_login);

			$enmail = !empty($sanitizedDatalist[$user->ID]['mail']) && $sanitizedDatalist[$user->ID]['enable_mailtan'];
			$ensms = !empty($sanitizedDatalist[$user->ID]['phone']) && $sanitizedDatalist[$user->ID]['enable_smstan'];
			// check if we should create or modify or delete authorizer account
			if (!$existsOnAuthorizer
                //&& $sanitizedDatalist[$user->ID]['enable_tfa'] == 1
                && (!empty($sanitizedDatalist[$user->ID]['mail']) || !empty($sanitizedDatalist[$user->ID]['phone']))) {
			    $authorizer_two_factor_authentication->getTFA()->createTFAAccount(
				        $user->user_login, $sanitizedDatalist[$user->ID]['mail'],
                        $sanitizedDatalist[$user->ID]['phone'], $enmail, $ensms);
			} elseif ($existsOnAuthorizer
                && (!empty($sanitizedDatalist[$user->ID]['mail']) || !empty($sanitizedDatalist[$user->ID]['phone']))) {
				$authorizer_two_factor_authentication->getTFA()->modifyTFAAccount(
				        $user->user_login, $sanitizedDatalist[$user->ID]['mail'],
                        $sanitizedDatalist[$user->ID]['phone'], $enmail, $ensms);
			} elseif ($existsOnAuthorizer
                && empty($sanitizedDatalist[$user->ID]['mail'])
                && empty($sanitizedDatalist[$user->ID]['phone'])) {
                $authorizer_two_factor_authentication->getTFA()->deleteTFAAccount($user->user_login);
			}

            update_user_meta($user->ID, 'tfa_enable_tfa', +($sanitizedDatalist[$user->ID]['enable_tfa'] && ($enmail || $ensms)));
		}
	}
}
?>

   <div class="wrap">
    <h1>Authorizer SecondFactor</h1>

	<?php if (defined('TWO_FACTOR_DISABLE') && TWO_FACTOR_DISABLE) { ?>
	<div class="error">
		<h3><?php _e('Authorizer SecondFactor currently disabled', 'authorizer-secondfactor');?></h3>
		<p>
			<?php _e('Authorizer SecondFactor is currently disabled via the TWO_FACTOR_DISABLE constant (which is mostly likely to be defined in your wp-config.php)', 'authorizer-secondfactor'); ?>
		</p>
	</div>
	<?php } ?>

	<div style="max-width:800px;">

<?php
    if (is_multisite() && is_super_admin()) {
        print '<p class="info-multisite">';
        _e('These two-factor settings apply to your entire WordPress network. They are not localised to one particular site.', 'authorizer-secondfactor');
        print '</p>';
    }

	if (!$authorizer_two_factor_authentication->getTFA()->PluginIsConfigured()) {
		echo '<form method="post" action="options-general.php?page=two-factor-auth" style="margin-top: 40px">';
		echo '<h2>';
		_e('Plugin Auto-Configuration', 'authorizer-secondfactor');
		echo '</h2>';
		print '<div>'.__('Enter your Authorizer username and password to automatically configure the plugin.', 'authorizer-secondfactor').'</div>';
        print '<div>'.__('For more information see', 'authorizer-secondfactor').' <a href="https://'.__('www.authorizer.de/en/wordpress', 'authorizer-secondfactor').'" target="_blank" rel="noopener noreferrer">'.__('www.authorizer.de/en/wordpress', 'authorizer-secondfactor').'</a></div>';
		echo '<p>';
		print '<table style="width:50%">';
		print '<tr><td style="width:20%; text-align: left;">';
		echo '<label for="tfa_auto_user" style="white-space: nowrap">';
		echo __('Authorizer-ID', 'authorizer-secondfactor');
		echo '&nbsp;&nbsp;</label>';
		print '</td><td style="width:80%; text-align: left;">';
		echo '<input type="text" id="tfa_auto_user" name="auto_user" /><br>';
		print '</td></tr><tr><td style="width:20%; text-align: left;">';
		echo '<label for="tfa_auto_pass">';
		echo __('Password', 'authorizer-secondfactor');
		echo '</label>';
		print '</td><td style="width:80%; text-align: left;">';
		echo '<input type="password" id="tfa_auto_pass" name="auto_pass" />';
		print '</td></tr></table>';
		echo '</p>';
		wp_nonce_field('tfa_button_clicked');
		echo '<input type="hidden" value="true" name="tfa_button" />';
		echo '<input type="hidden" value="autoconfig" name="form_method" />';
		if ($autoconfigError) {
		    print '<div style="color: #af040f">'.esc_html($autoconfigError).'</div>';
        }
		submit_button(__('Configure Plugin Settings', 'authorizer-secondfactor'), 'primary', 'plugin-autoconfig' );
		echo '</form>';
		echo '<hr>';

	 } else {

        if (!empty($_POST['create-authorizer'])) {
            echo '<div class="updated notice is-dismissible">'."<p><strong>".__('Settings saved.', 'authorizer-secondfactor')."</strong></p></div>";
        }
        echo '<hr>';
		echo '<form method="post" action="options-general.php?page=two-factor-auth" style="margin-top: 40px">';
		echo '<h2>'; 
		_e('Users', 'authorizer-secondfactor');
		echo '</h2>';
		_e('List of available users and their TFA settings on Authorizer SecondFactor', 'authorizer-secondfactor');
		echo ': <p>';
		$authorizer_two_factor_authentication->tfaListUserTFACaps();
		echo '</p>';
		wp_nonce_field('tfa_button_clicked');
		echo '<input type="hidden" value="true" name="tfa_button" />';
		submit_button(__('Submit', 'authorizer-secondfactor'), 'primary', 'create-authorizer' );
		echo '</form>';
        print '<div style="margin-top:50px; font-size:12px"><sup>*</sup>'.__('Data is stored in the Authorizer Cloud and synced between your WordPress instances.', 'authorizer-secondfactor').'</div>';
        print '<div style="font-size:12px"><sup>**</sup>'.__('Mobile phone number in international format starting with 00.', 'authorizer-secondfactor').'</div>';
		echo '<hr style="margin-bottom:-20px;">';
	};
?>

<div id="tfa-advanced" style="margin-top: 40px">
    <a class="tfa-show" href="#tfa-advanced"><?php _e('Advanced Settings', 'authorizer-secondfactor'); ?></a>
    <a class="tfa-hide" href="#"><?php _e('Hide Advanced Settings', 'authorizer-secondfactor'); ?></a>

	<div class="tfa-content" style="margin-top: 0px">

	<?php
	if ($authorizer_two_factor_authentication->getTFA()->PluginIsConfigured()) {
		echo '<form method="post" action="options-general.php?page=two-factor-auth" style="margin-top: 40px">';
		echo '<h2>';
		_e('Redo Plugin Auto-Configuration', 'authorizer-secondfactor');
		echo '</h2>';
		_e('If your configuration does not work, enter your Authorizer Username and Password to automatically configure the plugin again.', 'authorizer-secondfactor');
		echo '<p>';
		print '<table style="width:50%">';
		print '<tr><td style="width:20%; text-align: left;">';
		echo '<label for="tfa_auto_user" style="white-space: nowrap">';
		echo __('Authorizer-ID', 'authorizer-secondfactor');
		echo '&nbsp;&nbsp;</label>';
		print '</td><td style="width:80%; text-align: left;">';
		echo '<input type="text" id="tfa_auto_user" name="auto_user" /><br>';
		print '</td></tr><tr><td style="width:20%; text-align: left;">';
		echo '<label for="tfa_auto_pass">';
		echo __('Password', 'authorizer-secondfactor');
		echo '</label>';
		print '</td><td style="width:80%; text-align: left;">';
		echo '<input type="password" id="tfa_auto_pass" name="auto_pass" />';
		print '</td></tr></table>';
		echo '</p>';
		wp_nonce_field('tfa_button_clicked');
		echo '<input type="hidden" value="true" name="tfa_button" />';
		echo '<input type="hidden" value="autoconfig" name="form_method" />';
		submit_button(__('Configure Plugin Settings', 'authorizer-secondfactor'), 'primary', 'plugin-autoconfig');
		echo '</form>';
		echo '<hr>';
	 };
	?>

		<form method="post" action="options.php" style="margin-top: 40px">
		<?php
			settings_fields('tfa_xmlrpc_status_group');
		?>
			<h2><?php _e('XMLRPC requests', 'authorizer-secondfactor'); ?></h2>
			<?php 

			echo '<p>';
			echo __("XMLRPC is a feature within WordPress allowing other computers to talk to your WordPress install. For example, it could be used by an app on your tablet that allows you to blog directly from the app (instead of needing the WordPress dashboard).", 'authorizer-secondfactor');

			echo '<p></p>';

			echo __("Unfortunately, XMLRPC also provides a way for attackers to perform actions on your WordPress site, using only a password (i.e. without a two-factor password). More unfortunately, authors of legitimate programmes using XMLRPC have not yet added two-factor support to their code.", 'authorizer-secondfactor');

			echo '<p></p>';

			echo __(" i.e. XMLRPC requests coming in to WordPress (whether from a legitimate app, or from an attacker) can only be verified using the password - not with a two-factor code. As a result, there not be an ideal option to pick below. You may have to choose between the convenience of using your apps, or the security of two factor authentication.", 'authorizer-secondfactor');

			echo '</p>';
			?>
			<p>
			<?php
				$authorizer_two_factor_authentication->tfaListXMLRPCStatusRadios();
			?></p>
			<?php submit_button(__('Submit', 'authorizer-secondfactor')); ?>
		</form>

	<hr>
	<form method="post" action="options.php" style="margin-top: 20px">
	<?php
		settings_fields('authorizer_tfa_default_refresh_token');
	?>
		<h2><?php _e('Refresh Token', 'authorizer-secondfactor'); ?></h2>
		<?php _e('You will get the Refresh Token from the Authorizer Customer Panel.', 'authorizer-secondfactor'); ?>
		<p>
		<?php
			$authorizer_two_factor_authentication->tfaListDefaultRefreshToken();
		?></p>
		<?php submit_button(__('Submit', 'authorizer-secondfactor')); ?>
	</form>

	<hr>
	<form method="post" action="options.php" style="margin-top: 20px">
	<?php
		settings_fields('authorizer_tfa_default_contractid');
	?>
		<h2><?php _e('ContractID', 'authorizer-secondfactor'); ?></h2>
		<?php _e('You will get your Contract ID from the Authorizer Customer Panel.', 'authorizer-secondfactor'); ?>
		<p>
		<?php
			$authorizer_two_factor_authentication->tfaListDefaultContractID();
		?></p>
		<?php submit_button(__('Submit', 'authorizer-secondfactor')); ?>
	</form>
    </div>
    <p style="margin-top: 40px;">
        <a class="tfa-hide" href="#"><?php _e('Hide Advanced Settings', 'authorizer-secondfactor'); ?></a>
    </p>
	</div>
</div>
</div>
