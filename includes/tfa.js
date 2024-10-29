jQuery(document).ready(function($) {
	
	// Return value: whether to submit the form or not
	// Form types: 1 = anything else, 2 = TML shortcode or widget, WP Members, or Ultimate Membership Pro
	// The form parameter is only used for form_type == 2, which is essentially a later bolt-on extra (which explains why there are apparently other form types handled below still covered under 1)
	function runGenerateOTPCall(form_type, form, tfastep) {

		if (2 == form_type) {
			var username = $(form).find('[name="log"]').val();
		} else {
			var username = $('#user_login').val() || $('[name="log"]').val();
		}

		if (2 == tfastep) {
			if (2 == form_type) {
				var tfa_selection = $(form).find('[name="two_factor_provider"]:checked').val();
			} else {
				var tfa_selection = $('[name="two_factor_provider"]:checked').val();
			}
		} else {
			var tfa_selection = "";
		}
		
		if (!username.length) return false;
		
		var $submit_button = (null === form) ? $('#wp-submit') : $(form).find('input[name="wp-submit"]');
		if ($submit_button.length < 1) {
			$submit_button = $(form).find('input[type="submit"]').first();
		}
					   
		// If this is a "lost password" form, then exit
		if ($('#user_login').parents('#lostpasswordform, #resetpasswordform').length) return false;

		if (authorizer_tfasettings.hasOwnProperty('spinnerimg')) {
			var styling = 'float:right; margin:6px 12px; width: 20px; height: 20px;';
			if ($('#theme-my-login #wp-submit').length >0) {
				styling = 'margin-left: 4px; position: relative; top: 4px; width: 20px; height: 20px; border:0px; box-shadow:none;';
			}	
			$submit_button.after('<img class="authorizerotp_spinner" src="'+authorizer_tfasettings.spinnerimg+'" style="'+styling+'">');
		}

		$.ajax({
			url: authorizer_tfasettings.ajaxurl,
			type: 'POST',
			data: {
				action: 'authorizertfa-init-otp',
				user: username,
				tfastep: tfastep,
				selection: tfa_selection,
				pwd: (2 == form_type) ? $(form).find('[name="pwd"]').val() : $('#user_pass').val() || $('[name="pwd"]').val()
			},
			dataType: 'text',
			success: function(resp) {
				try {
					var json_begins = resp.search('{"jsonstarter":"justhere"');
					if (json_begins > -1) {
						if (json_begins > 0) {
							console.log("Expected JSON marker found at position: "+json_begins);
							resp = resp.substring(json_begins);
						}
					} else {
							console.log("Expected JSON marker not found");
							console.log(resp);
					}
					response = JSON.parse(resp);
					if (response.hasOwnProperty('php_output')) {
						console.log("PHP output was returned (follows)");
						console.log(response.php_output);
					}
					if (response.hasOwnProperty('extra_output')) {
						console.log("Extra output was returned (follows)");
						console.log(response.extra_output);
					}
					if (true === response.status) {
						// Don't bother to remove the spinner if the form is being submitted.
						$('.authorizerotp_spinner').remove();
						//console.log("Authorizer TFA: User has OTP enabled: showing OTP field (form_type="+form_type+")");
						if (2 === response.tfastep) {
							tfaShowOTPField(form_type, form);
						} else {
							tfaShowOTPSelection(form_type, form, response.selection);
						}
						
					} else {
						//console.log("Authorizer TFA: User does not have OTP enabled: submitting form (form_type="+form_type+")");
						if (2 == form_type) {
							// Form some reason, .submit() stopped working with TML 7.x
							//$(form).submit();
							$(form).find('input[type="submit"], button[type="submit"]').first().click();
						} else {
							$('#wp-submit').parents('form:first').submit();
						}
					}
				} catch(err) {
					$('#login').html(resp);
					console.log("Authorizer TFA: Error when processing response");
					console.log(err);
					console.log(resp);
				}
			},
			error: function(jq_xhr, text_status, error_thrown) {
				console.log("Authorizer TFA: AJAX error: "+error_thrown+": "+text_status);
				console.log(jq_xhr);
				if (jq_xhr.hasOwnProperty('responseText')) { console.log(jq_xhr.responseText);}
			}
		});
		return true;
	}
	

	function tfaShowOTPSelection(form_type, form, selection) {
		var $submit_button;

		// selection = ["SMS", "Card", "EMail"];
		
		if (null === form) {
			$submit_button = $('#wp-submit');
		} else {
			// name="Submit" is WP-Members. 'submit' is Theme My Login starting from 7.x
			$submit_button = $(form).find('input[name="wp-submit"], input[name="Submit"], input[name="submit"]');
			// This hasn't been needed for anything yet (Jul 2018), but is a decent back-stop that would have prevented some breakage in the past that needed manual attention:
			if (0 == $submit_button.length) {
				$submit_button = $(form).find('input[type="submit"]:first');
			}
		}
		
		// Hide all elements in a browser safe way
		$submit_button.parents('form:first').find('p, .impu-form-line-fr, .tml-field-wrap').each(function(i) {
			$(this).css('visibility','hidden').css('position', 'absolute');
		});
		
		// WP-Members
		$submit_button.parents('#wpmem_login').find('fieldset').css('visibility','hidden').css('position', 'absolute');
		
		// Test
		// $submit_button.prop('disabled', true);
		
		// Add new field and controls
		var html = '';
		html += '<div id="div-select">';
		html += '<p>' + authorizer_tfasettings.loginHeadlineSecondFactor + ':</p>';
		html += '<br>';
		html += '<script type="application/javascript">if (jQuery(\'.user-pass-wrap\').length) { jQuery(\'.user-pass-wrap\').hide(); }</script>';
		html += '<table style="border: 1px solid #e5e5e5; border-radius: 5px; width: 100%; height: 140px;"><tr>';
		html += '<td align="center" valign="bottom" width="100%" style="vertical-align: bottom;">';
		if (selection.indexOf("SMS") > -1) {
			html += '<div style="display: inline-block; margin: 20px; vertical-align: bottom;">';
			html += '<label for="markSMS" onclick="jQuery(\'#tfa_login_btn\').attr(\'disabled\', false);">'
				+ '<img src="wp-content/plugins/authorizer-secondfactor/img/sms.png" alt="SMS" width="40"></br>'
				+ authorizer_tfasettings.loginSms + '</br><input type="radio" name="two_factor_provider" id="markSMS" value="SMS" style="margin-top:5px;"/></label>';
			html += '</div>';
		}
		if (selection.indexOf("EMail") > -1) {
			html += '<div style="display: inline-block; margin: 20px; vertical-align: bottom;">';
			html += '<label for="markEmail" onclick="jQuery(\'#tfa_login_btn\').attr(\'disabled\', false);">'
				+ '<img src="wp-content/plugins/authorizer-secondfactor/img/email.png" alt="Email" width="40"></br>'
				+ authorizer_tfasettings.loginEmail + '</br><input type="radio" name="two_factor_provider" id="markEmail" value="EMail" style="margin-top:5px;"/></label>';
			html += '</div>';
		}
		if (selection.indexOf("Card") > -1) {
			html += '<div style="display: inline-block; margin: 20px; vertical-align: bottom;">';
			html += '<label for="markCard" onclick="jQuery(\'#tfa_login_btn\').attr(\'disabled\', false);">'
				+ '<img src="wp-content/plugins/authorizer-secondfactor/img/card.png" alt="Card" width="40"></br>'
				+ authorizer_tfasettings.loginCard + '</br><input type="radio" name="two_factor_provider" id="markCard" value="Card" style="margin-top:5px;"/></label>';
			html += '</div>';
		}
		if (selection.length == 0) {
			html += authorizer_tfasettings.noSecondFactorMethodAvailable;
		}
		html += '</td>';
		html += '</tr></table>';
		html += '</br>';
		html += '</div>';
		if (selection.length == 0) {
			html += '<p class="submit" style="float: left;">' +
				'<input id="tfa_login_back_btn" onclick="window.location.href = \'/wp-login.php\';" class="button button-primary button-large" style="width:68px;" value="Zurück">' +
				'</p>';
		} else {
			html += '<p class="submit">' +
				'<input id="tfa_login_btn" class="button button-primary button-large" type="submit" value="' + $submit_button.val() + '" disabled>' +
				'</p>';
		}
		$submit_button.parents('form:first').prepend(html);
		$('#authorizer_two_factor_provider').focus();

		$('#wp-submit').parents('form[name!="resetpassform"]:first').not('.tml-login form[name="loginform"], .tml-login form[name="login"]').on('submit', tfa_cb);
	}

	// Parameters: see runGenerateOTPCall
	function tfaShowOTPField(form_type, form) {
		
		var $submit_button;
		//var $prov_label;
		//var $prov_select;
		var $div_select;
		
		if (null === form) {
			$submit_button = $('#wp-submit');
			$div_select = $('#div-select');
			//$prov_label = $('#authorizer_two_factor_provider_label');
			//$prov_select = $('#authorizer_two_factor_provider');
		} else {
			//$prov_label = $(form).find('label[for="authorizer_two_factor_provider"]:first');
			//$prov_select = $(form).find('select[id="authorizer_two_factor_provider"]:first');
			// name="Submit" is WP-Members. 'submit' is Theme My Login starting from 7.x
			$div_select = $(form).find('select[id="div-select"]:first');

			$submit_button = $(form).find('input[name="wp-submit"], input[name="Submit"], input[name="submit"]');
			// This hasn't been needed for anything yet (Jul 2018), but is a decent back-stop that would have prevented some breakage in the past that needed manual attention:
			if (0 == $submit_button.length) {
				$submit_button = $(form).find('input[type="submit"]:first');
			}
		}

		$div_select.css('display','none');
		//$prov_label.css('visibility','hidden').css('position', 'absolute');
		//$prov_select.css('visibility','hidden').css('position', 'absolute');

		// Hide all elements in a browser safe way
		$submit_button.parents('form:first').find('p, .impu-form-line-fr, .tml-field-wrap').each(function(i) {
			$(this).css('visibility','hidden').css('position', 'absolute');
		});
		
		// WP-Members
		$submit_button.parents('#wpmem_login').find('fieldset').css('visibility','hidden').css('position', 'absolute');
		
		// Test
		// $submit_button.prop('disabled', true);
		
		// Add new field and controls
		var html = '';
		html += '<label for="authorizer_two_factor_auth">' + authorizer_tfasettings.otp + '<br><input type="text" name="two_factor_code" id="authorizer_two_factor_auth" autocomplete="off"></label>';
		// html += '<p class="forgetmenot" style="font-size:small; max-width: 60%">' + authorizer_tfasettings.otp_login_help + '</p>';
		html += '<p class="submit"><input id="tfa_login_btn" class="button button-primary button-large" type="submit" value="' + $submit_button.val() + '"></p>';
		
		$submit_button.parents('form:first').prepend(html);
		$('#authorizer_two_factor_auth').focus();
		
	}

	var tfa_cb_1 = function(e) {
		//console.log("Authorizer TFA: form submit request");

		var form_type = 1;
		var form = null;

		// .tml-login works for both TML 6.x and 7.x.
		if ($(e.target).parents('.tml-login').length > 0 || $(e.target).closest('#wpmem_login').find('form').length > 0 || 'ihc_login_form' == $(e.target).attr('id')) {
			$(e.target).off();
			form_type = 2;
			form = e.target;
		} else {
			$('#wp-submit').parents('form:first').off();
		}

		var res = runGenerateOTPCall(form_type, form, 1);

		if (!res) return true;

		e.preventDefault();
		return false;
	};

	var tfa_cb = function(e) {
		//console.log("Authorizer TFA: form submit request");

		var form_type = 1;
		var form = null;

		// .tml-login works for both TML 6.x and 7.x.
		if ($(e.target).parents('.tml-login').length > 0 || $(e.target).closest('#wpmem_login').find('form').length > 0 || 'ihc_login_form' == $(e.target).attr('id')) {
			$(e.target).off();
			form_type = 2;
			form = e.target;
		} else {
			$('#wp-submit').parents('form:first').off();
		}

		var res = runGenerateOTPCall(form_type, form, 2);

		if (!res) return true;

		e.preventDefault();
		return false;
	};
	
	// Aug 2017: TML now uses #wp-submit on a reset form; hence the exclusion
	$('#wp-submit').parents('form[name!="resetpassform"]:first').not('.tml-login form[name="loginform"], .tml-login form[name="login"]').on('submit', tfa_cb_1);
	
	// Theme My Login 6.x - .tml-login form[name="loginform"]
	// Theme My Login 7.x - .tml-login form[name="login"] (Jul 2018)
	// WP Members - Mar 2018
	// Ultimate Membership Pro - April 2018
	$('#ihc_login_form').unbind('submit');
	$('.tml-login form[name="loginform"], .tml-login form[name="login"], #wpmem_login form, form#ihc_login_form').on('submit', tfa_cb_1);
	
});
