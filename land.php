<?php
/**
 * @author Valery Fremaux
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package auth_multimnet
 *
 * Authentication Plugin: Moodle MultiNetwork Authentication
 *
 * Multiple host authentication support for Moodle Network.
 *
 * 2013-10-26  File created.
 */
require_once('../../config.php');
require_once($CFG->dirroot.'/mnet/xmlrpc/client.php');

// grab the GET params
$token         = required_param('token',    PARAM_BASE64);
$remotewwwroot = required_param('idp',      PARAM_URL);
$wantsurl      = required_param('wantsurl', PARAM_LOCALURL);
$wantsremoteurl = optional_param('remoteurl', false, PARAM_BOOL);

$url = new moodle_url('/auth/multimnet/jump.php', array('token' => $token, 'idp' => $remotewwwroot, 'wantsurl' => $wantsurl));
if ($wantsremoteurl !== false) {
    $url->param('remoteurl', $wantsremoteurl);
}
$PAGE->set_url($url);

$site = get_site();

if (!is_enabled_auth('multimnet')) {
    print_error('mnetdisable');
}

// confirm the MNET session
$mnetauth = get_auth_plugin('multimnet');
$remotepeer = new mnet_peer();
$remotepeer->set_wwwroot($remotewwwroot);

// this creates the local user account if necessary, or updates it if it already exists
$localuser = $mnetauth->confirm_mnet_session($token, $remotepeer);

// log in
$user = get_complete_user_data('id', $localuser->id, $localuser->mnethostid);
complete_user_login($user);
// now that we've logged in, set up the mnet session properly
$mnetauth->update_mnet_session($user, $token, $remotepeer);

if (!empty($localuser->mnet_foreign_host_array)) {
    $USER->mnet_foreign_host_array = $localuser->mnet_foreign_host_array;
}

// redirect
if ($wantsremoteurl) {
    redirect($remotewwwroot . $wantsurl);
}
redirect($CFG->wwwroot.$wantsurl);


