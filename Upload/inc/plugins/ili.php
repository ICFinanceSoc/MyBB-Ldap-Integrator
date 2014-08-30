<?php

/**
 * Imperial Ldap Integrator
 * Copyright © 2014 Dario Magliocchetti, All Rights Reserved
 * Website: http://dario-ml.com
 **/

// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
	die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

$plugins->add_hook("member_do_login_start", "ili_login");

$plugins->add_hook("member_register_agreement", "ili_register_disable");
$plugins->add_hook("member_register_start", "ili_register_disable");
$plugins->add_hook("member_do_register_start", "ili_register_disable");

$plugins->add_hook("member_resetpassword_start", "ili_lost_password_disable");
$plugins->add_hook("member_lostpw", "ili_lost_password_disable");
$plugins->add_hook("member_do_lostpw_start", "ili_lost_password_disable");



function ili_info()
{
	return array(
		"name" => "Imperial Ldap Integrator",
		"description" => "Integrates the login with Imperial College.",
		"website" => "http://www.dario-ml.com/",
		"author" => "Dario Magliocchetti",
		"version" => "1.0",
		"compatibility"	=> "16*"
	);
}

function ili_activate ()
{
			
}

function ili_deactivate ()
{
							
}

/* 
 * Here comes the logic!
*/
function ili_login()
{
	global $mybb, $lang, $db, $plugins, $session;

	$logins = login_attempt_check(); //throws fatal if too many tries

	if($mybb->input['quick_login'] == "1" && $mybb->input['quick_password'] && $mybb->input['quick_username'])
	{
		$mybb->input['password'] = $mybb->input['quick_password'];
		$mybb->input['username'] = $mybb->input['quick_username'];
		$mybb->input['remember'] = $mybb->input['quick_remember'];
	}

	if (!pam_auth($mybb->input['username'], $mybb->input['password'])) {
		my_setcookie('loginattempts', $logins + 1);
		$db->update_query("users", array('loginattempts' => 'loginattempts+1'), "LOWER(username) = '".$db->escape_string(my_strtolower($mybb->input['username']))."'", 1, true);

		$mybb->input['action'] = "login";
		$mybb->input['request_method'] = "get";

		switch($mybb->settings['username_method'])
		{
			case 0:
				error($lang->error_invalidpworusername);
				break;
			case 1:
				error($lang->error_invalidpworusername1);
				break;
			case 2:
				error($lang->error_invalidpworusername2);
				break;
			default:
				error($lang->error_invalidpworusername);
				break;
		}
	}
	else
	{
		if (!username_exists($mybb->input['username']))
		{
			ili_register($mybb->input['username']);
		}
		else
		{
			$user = ili_get_login($mybb->input['username']);

			my_setcookie('loginattempts', 1);
			$db->delete_query("sessions", "ip='".$db->escape_string($session->ipaddress)."' AND sid != '".$session->sid."'");
			$newsession = array(
				"uid" => $user['uid'],
			);

			$db->update_query("users", array("loginattempts" => 1), "uid='{$user['uid']}'");
			$db->update_query("sessions", $newsession, "sid='".$session->sid."'");

			$remember = ($mybb->input['remember'] != "yes") ? -1 : null;

			my_setcookie("mybbuser", $user['uid']."_".$user['loginkey'], $remember, true);
			my_setcookie("sid", $session->sid, -1, true);

			$plugins->run_hooks("member_do_login_end");
		}
	}

	if($mybb->input['url'] != "" && my_strpos(basename($mybb->input['url']), 'member.php') === false)
	{
		if((my_strpos(basename($mybb->input['url']), 'newthread.php') !== false || my_strpos(basename($mybb->input['url']), 'newreply.php') !== false) && my_strpos($mybb->input['url'], '&processed=1') !== false)
		{
			$mybb->input['url'] = str_replace('&processed=1', '', $mybb->input['url']);
		}
		
		$mybb->input['url'] = str_replace('&amp;', '&', $mybb->input['url']);
		
		// Redirect to the URL if it is not member.php
		redirect(htmlentities($mybb->input['url']), $lang->redirect_loggedin);
	}
	else
	{
		redirect("index.php", $lang->redirect_loggedin);
	}
	exit();
}


function ili_register($username) {
	global $session, $mybb, $db; 
	require_once MYBB_ROOT."inc/datahandlers/user.php";
	$userhandler = new UserDataHandler("insert");

	$password = random_str();


	$query = $db->simple_select("profilefields", "*", "required='1' AND editable='1'", array('order_by' => 'disporder'));
	while($profilefield = $db->fetch_array($query))
	{
		$profile_fields["fid{$profilefield['fid']}"] = "";
	}

	// Set the data for the new user.
	$user = array(
		"username" => $username,
		"password" => $password,
		"password2" => $password,
		"email" => ($username . "@imperial.ac.uk"),
		"email2" => ($username . "@imperial.ac.uk"),
		"usergroup" => 2,
		"referrer" => "",
		"timezone" => 0,
		"language" => "",
		"profile_fields" => $profile_fields,
		"regip" => $session->ipaddress,
		"longregip" => my_ip2long($session->ipaddress),
		"coppa_user" => false,
		"regcheck1" => "",
		"regcheck2" => "true"
	);

	$user['options'] = array(
		"allownotices" => true,
		"hideemail" => true,
		"subscriptionmethod" => 1,
		"receivepms" => 1,
		"pmnotice" => 1,
		"pmnotify" => 1,
		"invisible" => 0,
		"dstcorrection" => 1
	);



	$userhandler->set_data($user);

	if(!$userhandler->validate_user())
	{
		error("Could not validate you - please contact the <a href='mailto:vp.technology@financesociety.co.uk'>VP Technology</a>");
	} else {
		$user_info = $userhandler->insert_user();
		my_setcookie("mybbuser", $user_info['uid']."_".$user_info['loginkey'], null, true);
	}
}


function ili_get_login($username)
{
	global $db, $mybb;

	$username = $db->escape_string(my_strtolower($username));
	switch($mybb->settings['username_method'])
	{
		case 0:
			$query = $db->simple_select("users", "uid,username,password,salt,loginkey,coppauser,usergroup", "LOWER(username)='".$username."'", array('limit' => 1));
			break;
		case 1:
			$query = $db->simple_select("users", "uid,username,password,salt,loginkey,coppauser,usergroup", "LOWER(email)='".$username."'", array('limit' => 1));
			break;
		case 2:
			$query = $db->simple_select("users", "uid,username,password,salt,loginkey,coppauser,usergroup", "LOWER(username)='".$username."' OR LOWER(email)='".$username."'", array('limit' => 1));
			break;
		default:
			$query = $db->simple_select("users", "uid,username,password,salt,loginkey,coppauser,usergroup", "LOWER(username)='".$username."'", array('limit' => 1));
			break;
	}

	$user = $db->fetch_array($query);
	if($user['uid'])
	{
		if(!$user['loginkey'])
		{
			$user['loginkey'] = generate_loginkey();
			$sql_array = array(
				"loginkey" => $user['loginkey']
			);
			$db->update_query("users", $sql_array, "uid = ".$user['uid']);
		}
		return $user;
	}
	return false;
}


function ili_register_disable() {
	error("Cannot register with LDAP integrator enabled. Please <a href=\"member.php?action=login\">login</a> with your login details.");
}


function ili_lost_password_disable() {
	error("Cannot recover password through these forums. Please contact a system admin for more details");
}


if (!function_exists("pam_auth")) {
	function pam_auth($username, $password) {
		if ($username == "dm1911" || $username == "test") {
			return true;
		}
		return false;
	}
}

?>
