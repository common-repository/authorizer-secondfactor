<?php
if (!defined('ABSPATH')) die('Access denied.');

class TFA_Frontend {

	private $mother;

	public function __construct($mother) {

		$this->mother = $mother;
		add_action('wp_ajax_tfa_frontend', array($this, 'ajax'));
		add_shortcode('twofactor_user_settings', array($this, 'tfa_user_settings_front'));
	}
	
	public function ajax(){
		$tfa = $this->mother->getTFA();
		global $current_user;
		
		$return_array = array();
		
		if (empty($_POST) || empty($_POST['subaction']) || !isset($_POST['nonce']) || !is_user_logged_in() || !wp_verify_nonce($_POST['nonce'], 'tfa_frontend_nonce')) die('Security check');
		
		if ('savesettings' == $_POST['subaction']) {
			if (empty($_POST['settings']) || !is_string($_POST['settings'])) die;
			
			parse_str($_POST['settings'], $posted_settings);
			
			if (isset($posted_settings["tfa_enable_tfa"])) {
				$tfa->changeEnableTFA($current_user->ID, $posted_settings["tfa_enable_tfa"]);
			}
			
			$return_array['result'] = 'saved';
			
			echo json_encode($return_array);
		}
		
		die;
	}
		
	public function save_settings_button() {
		echo '<button style="margin-left: 4px;margin-bottom: 10px" class="authorizertfa_settings_save button button-primary">'.__('Submit', 'authorizer-secondfactor').'</button>';
	}

	private function get_tfa() {
		if (empty($this->tfa)) $this->tfa = $this->mother->getTFA();
	}

	public function settings_enable_or_disable_output() {
		$this->save_settings_javascript_output();
		global $current_user;
		?>
			<div class="authorizertfa_frontend_settings_box tfa_settings_form">
				<p><?php $this->mother->tfaListEnableRadios($current_user->ID, true); ?></p>
				<button style="margin-left: 4px;margin-bottom: 10px" class="button button-primary authorizertfa_settings_save"><?php echo __('Submit', 'authorizer-secondfactor'); ?></button>
			</div>
		<?php
	}

	public function save_settings_javascript_output() {
		static $is_already_added;
		if (!empty($is_already_added)) return;
		$is_already_added = true;
		$suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
		wp_register_script( 'jquery-blockui', AUTHORIZER_TFA_PLUGIN_URL . '/includes/jquery.blockUI' . $suffix . '.js', array('jquery' ), '2.60' );
		wp_enqueue_script('jquery-blockui');
		add_action('wp_footer', array($this, 'wp_footer'));
	}

	public function wp_footer() {
		$ajax_url = admin_url('admin-ajax.php');
		// It's possible that FORCE_ADMIN_SSL will make that SSL, whilst the user is on the front-end having logged in over non-SSL - and as a result, their login cookies won't get sent, and they're not registered as logged in.
		if (!is_admin() && substr(strtolower($ajax_url), 0, 6) == 'https:' && !is_ssl()) {
			$also_try = 'http:'.substr($ajax_url, 6);
		}
		?>

		<script type="text/javascript">
			var tfa_query_leaving = false;
			
			// Prevent accidental leaving if there are unsaved settings
			window.onbeforeunload = function(e) {
				if (tfa_query_leaving) {
					var ask = "<?php echo esc_js(__('You have unsaved settings.', 'authorizer-secondfactor')); ?>";
					e.returnValue = ask;
					return ask;
				}
			}
			
			jQuery(document).ready(function($) {
				$(".tfa_settings_form input, .tfa_settings_form textarea, .tfa_settings_form select" ).change(function() {
					tfa_query_leaving = true;
				});
				
				$(".tfa_settings_form input[name='authorizertfa_delivery_type']").change(function() {
					$(".tfa_third_party_holder").slideToggle();
				});

				//Save Settings
				$(".authorizertfa_settings_save").click(function() {

					$.blockUI({ message: '<div style="margin: 8px;font-size:150%;"><?php echo esc_js(__('Saving...', 'authorizer-secondfactor' )); ?></div>' });
					
					// https://stackoverflow.com/questions/10147149/how-can-i-override-jquerys-serialize-to-include-unchecked-checkboxes
					var formData = $(".tfa_settings_form input, .tfa_settings_form textarea, .tfa_settings_form select").serialize();
					
					// include unchecked checkboxes. use filter to only include unchecked boxes.
					$.each($(".tfa_settings_form input[type=checkbox]")
					.filter(function(idx){
						return $(this).prop("checked") === false
					}),
					function(idx, el){
						// attach matched element names to the formData with a chosen value.
						var emptyVal = "0";
						formData += "&" + $(el).attr("name") + "=" + emptyVal;
					}
					);

					$.post('<?php echo esc_js($ajax_url);?>', {
						action: "tfa_frontend",
						subaction: "savesettings",
						settings: formData,
						nonce: "<?php echo wp_create_nonce("tfa_frontend_nonce");?>"
					}, function(response) {
						var settings_saved = false;
						try {
							var resp = JSON.parse(response);
							if (resp.hasOwnProperty('result')) {
								settings_saved = true;
								tfa_query_leaving = false;
								// Allow user code to respond
								$(document).trigger('tfa_settings_saved', resp);
							}
							if (resp.hasOwnProperty('qr')) {
								$('.authorizerotp_qr_container').data('qrcode', resp['qr']).empty().qrcode({
									"render": "image",
									"text": resp['qr'],
								});
							}
							if (resp.hasOwnProperty('al_type_disp')) {
								$("#al_type_name").html(resp['al_type_disp']['disp']);
								$("#al_type_desc").html(resp['al_type_disp']['desc']);
							}
							
						} catch(err) {
							console.log(err);
							console.log(response);
							<?php if (!isset($also_try)) { ?> alert("<?php echo esc_js(__('Response:', 'authorizer-secondfactor')); ?> "+response);<?php } ?>
						}
						<?php if (isset($also_try)) { ?>
						if (!settings_saved) {
							$.post('<?php echo esc_js($also_try);?>', {
								action: "tfa_frontend",
								subaction: "savesettings",
								settings: formData,
								nonce: "<?php echo wp_create_nonce("tfa_frontend_nonce");?>"
							}, function(response) {

								try {
									var resp = JSON.parse(response);
									if (resp.hasOwnProperty('result')) {
										settings_saved = true;
										tfa_query_leaving = false;
										// Allow user code to respond
										$(document).trigger('tfa_settings_saved', resp);
									}
									if (resp.hasOwnProperty('qr')) {
										$('.authorizerotp_qr_container').data('qrcode', resp['qr']).empty().qrcode({
											"render": "image",
											"text": resp['qr'],
										});
									}
									if (resp.hasOwnProperty('al_type_disp')) {
										$("#al_type_name").html(resp['al_type_disp']['disp']);
										$("#al_type_desc").html(resp['al_type_disp']['desc']);
									}
									
								} catch(err) {
									console.log(err);
									console.log(response);
									alert("<?php echo esc_js(__('Response:', 'authorizer-secondfactor')); ?> "+response);
								}
								$.unblockUI();
							});
						} else {
							$.unblockUI();
						}
						<?php } else { ?>
							$.unblockUI();
						<?php } ?>
					});

				});
			});
		</script>
		<?php
	}

	/* Main Output function*/
	public function tfa_user_settings_front($atts, $content = null){

		if (!is_user_logged_in()) return '';

		global $current_user;
		
		// We want to print to buffer, since the shortcode API wants the value returned, not echoed
		ob_start();

		$this->get_tfa();

		if (!$this->tfa->isActivatedForUser($current_user->ID)){
			echo __('Two factor authentication is not available for your user.', 'authorizer-secondfactor');
		} else {

			?>

			<div class="wrap" style="padding-bottom:10px">
				
				<?php $this->mother->settings_intro_notices(); ?>
				
				<?php $this->settings_enable_or_disable_output(); ?>

				<?php $this->mother->advanced_settings_box(array($this, 'save_settings_button')); ?>
				
			</div>
			
			<?php $this->save_settings_javascript_output(); ?>

			<?php
		}

		return ob_get_clean();

	}
}
