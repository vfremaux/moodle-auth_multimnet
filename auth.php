<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @package auth_multimnet
 * @category auth
 * @author Valery Fremaux (valery.fremaux@gmail.com)
 * @copyright 2011 onwards Valery Fremaux
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Authentication Plugin: Moodle Network Authentication Modified for multi mnet
 *
 * Multiple host authentication support for Moodle Network.
 *
 * this variant checks for a remote account identity in one of the known 
 * mnet hosts, requires remote login and come back to the local landing page
 * with proper $USER setup and shifted.
 * 
 * If no user is known in the local base, with neither a local nor remote
 * possible identity, the plugin calls an abstract hook to process an heuristic
 * additional method to try to guess a possible origin node.
 * 
 * This authentication class might be overloaded for specific use of the heuristic
 * capability.
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/mnet/lib.php');
require_once($CFG->dirroot.'/mnet/xmlrpc/client.php');
require_once($CFG->dirroot.'/auth/multimnet/lib.php');
require_once($CFG->dirroot.'/auth/multimnet/rpclib.php');

/**
 * Moodle Network authentication plugin.
 */
class auth_plugin_multimnet extends auth_plugin_base{

    /**
     * Constructor.
     */
    public function __contruct() {
        $this->authtype = 'multimnet';
        $this->config = get_config('auth/multimnet');
        $this->mnet = get_mnet_environment();
    }

    /**
     * This function is normally used to determine if the username and password
     * are correct for local logins. Always returns false, as local users do not
     * need to login over mnet xmlrpc.
     *
     * We need this to process the heuristic on username. In case we are using central register, 
     * we need get a primary identity host for this username
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $CFG, $SESSION, $DB;

        $identities = $DB->get_records('user', array('username' => $username, 'deleted' => 0));

        if (empty($identities)) {

            if (debugging()) debug_trace("Fetch remote identity location");
            // if we have no identities at all. We cannot do anything else than rely on other plugins
            // fallbackdomain should not be set on the fallback host, as local accounts from the fallback
            // will be authenticated as they are : local 
            if (!empty($this->config->enable_central_register)) {
                if (!empty($this->config->fallback_domain)){ // this denotes we are on the fallback domain
                    $knownmnethostforusername = $this->get_primary_location($username);
                } else {
                    // query locally
                    $knownmnethostforusername = $DB->get_field('auth_multimnet_user', 'mnethostid', array('username' => $username));
                }
            } else {
                if (debugging()) debug_trace("No register");
                return false;
            }
        } else {
                
            if (count($identities) > 1) {
                // we have several accounts, such as a manual account and a MNET account
                // this is rather indeterministic situation, but we can chooose local identity prepends
                if (debugging()) debug_trace("Unresolved identity choice. Let local override");
                return false;
            }

            // at this stage, account is local and has local mnethostid, or is mnet and may have foreign mnethostid
            // we anyway only process if the account is mnet.
            $identity = array_pop($identities); // should be only one
            if ($identity->auth != 'multimnet') {
                // pass thru to let other plugins manage
                if (debugging()) debug_trace("Non matched auth type. Let other");
                return false;
            }
        }

        if (empty($knownmnethostforusername)) {
            $knownmnethostforusername = $DB->get_field('user', 'mnethostid', array('username' => $username));
        }
        
        // if we failed we try to guess it from his username
        if (empty($knownmnethostforusername)) {
            $knownmnethostforusername = $this->guess_origin_for_username($username);
        }

        // if the username is known but not from here, try bouncing its sign on and 
        // come back through a remote mnet jumping
        // debug_trace("Redirecting login to base host ID : $knownmnethostforusername ");
        if ($knownmnethostforusername && $knownmnethostforusername != $CFG->mnet_localhost_id) {
            $remotemnet = $DB->get_record('mnet_host', array('id' => $knownmnethostforusername));

            $PEER = new mnet_peer;
            $PEER->set_wwwroot($remotemnet->wwwroot);

            if ($publickey = $PEER->get_public_key()) {
                $sso = new StdClass();
                $sso->username = $username;
                $sso->password = $password;
                $sso->from = $CFG->wwwroot;
                if (isset($SESSION->wantsurl)) {
                    $remotewantsurl = urlencode(str_replace($CFG->wwwroot, '', $SESSION->wantsurl));
                    $sso->wantsurl = $remotemnet->wwwroot.'/auth/multimnet/jump.php?wwwroot='.urlencode($CFG->wwwroot).'&wantsurl='.$remotewantsurl;
                } else {
                    $sso->wantsurl = $remotemnet->wwwroot.'/auth/multimnet/jump.php?wwwroot='.urlencode($CFG->wwwroot);
                }
                $ssoticket = json_encode($sso);
                if (openssl_seal($ssoticket, $sealedssoticket, $env, array($publickey))){
                    $url = $remotemnet->wwwroot.'/login/index.php?ssoticket='.urlencode(base64_encode($sealedssoticket)).'&amp;enveloppe='.urlencode(base64_encode($env[0]));
                    redirect($url);
                }
            }
        }

        // if everything failed, we let the next authentication plugin play
        return false; // error("Remote MNET users cannot login locally.");
    }
    
    /**
     * override your own heuristic here
     *
     * default way is finding a 'domain identifier' part in the user name
     * (mail address scheme) and constructing an associated wwwroot
     * using pattern replacement.
     *
     * A fallback host can be defined in auth plugin config for trying
     * any unmatched usernames
     * 
     * @param string $username a value where from guessing things
     * @return a domain name (without protocol prefix) or a mnet_host id
     */
    function guess_origin_for_username($username) {
        global $DB;
        
        // protects from unconfigured auth plugins
        if (is_null($this->config)) {
            $this->config = get_config('auth/multimnet');
        }
        
        if (preg_match("/{$this->config->login_pattern}/", $username, $matches)) {
            $domain = $matches[1];

            $fulldomain = str_replace('<%%HOSTNAME%%>', $domain, $this->config->host_guess_pattern);
            $looseaccessoption = '';
            if (empty($this->config->loose_access)) {
                $looseaccessoption = ' AND visible = 1 ';
            }
            if ($foundmnet = $DB->get_record_select('mnet_host', " wwwroot LIKE 'http://{$fulldomain}' $looseaccessoption ")) {
                return $foundmnet->id;
            }

            if (!empty($this->config->fallback_domain)) {
                return $this->config->fallback_domain;
            }
        }
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        //TODO: it should be able to redirect, right?
        return false;
    }

    /**
     * Returns the URL for changing the user's pw, or false if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        global $CFG, $DB;

         $query = "
            SELECT
                h.id,
                h.name as hostname,
                h.wwwroot,
                h2idp.publish as idppublish,
                h2idp.subscribe as idpsubscribe,
                idp.name as idpname,
                h2sp.publish as sppublish,
                h2sp.subscribe as spsubscribe,
                sp.name as spname
            FROM
                {mnet_host} h
            LEFT JOIN
                {mnet_host2service} h2idp
            ON
               (h.id = h2idp.hostid AND
               (h2idp.publish = 1 OR
                h2idp.subscribe = 1))
            INNER JOIN
                {mnet_service} idp
            ON
               (h2idp.serviceid = idp.id AND
                idp.name = 'sso_idp')
            LEFT JOIN
                {mnet_host2service} h2sp
            ON
               (h.id = h2sp.hostid AND
               (h2sp.publish = 1 OR
                h2sp.subscribe = 1))
            INNER JOIN
                {mnet_service} sp
            ON
               (h2sp.serviceid = sp.id AND
                sp.name = 'sso_sp')
            WHERE
               ((h2idp.publish = 1 AND h2sp.subscribe = 1) OR
               (h2sp.publish = 1 AND h2idp.subscribe = 1)) AND
                h.id != ?
            ORDER BY
                h.name ASC";

        $id_providers       = array();
        $service_providers  = array();
        if ($resultset = $DB->get_records_sql($query, array($CFG->mnet_localhost_id))) {
            foreach ($resultset as $hostservice) {
                if (!empty($hostservice->idppublish) && !empty($hostservice->spsubscribe)) {
                    $service_providers[] = array('id' => $hostservice->id, 'name' => $hostservice->hostname, 'wwwroot' => $hostservice->wwwroot);
                }
                if (!empty($hostservice->idpsubscribe) && !empty($hostservice->sppublish)) {
                    $id_providers[] = array('id' => $hostservice->id, 'name' => $hostservice->hostname, 'wwwroot' => $hostservice->wwwroot);
                }
            }
        }

        include $CFG->dirroot.'/auth/multimnet/config.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     *
     * @param object $config Configuration object
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset ($config->rpc_negotiation_timeout)) {
            $config->rpc_negotiation_timeout = '30';
        }
        /*
        if (!isset ($config->auto_add_remote_users)) {
            $config->auto_add_remote_users = '0';
        } See MDL-21327   for why this is commented out
        set_config('auto_add_remote_users',   $config->auto_add_remote_users,   'auth_mnet');
        */
        
        if (!isset($config->host_guess_pattern)) {
            $config->host_guess_pattern = '<%%HOSTNAME%%>';
        }
        
        if (!isset($config->login_pattern)) {
            $config->login_pattern = '.*@([^\.]+)';
        }

        if (!isset($config->fallback_domain)) {
            $config->fallback_domain = 0;
        }

        if (!isset($config->loose_access)) {
            $config->loose_access = 0;
        }

        if (!isset($config->enable_central_register)) {
            $config->enable_central_register = 0;
        }

        if (!isset($config->mnetsiteadmins)) {
            $config->mnetsiteadmins = 0;
        }

        // save settings
        set_config('rpc_negotiation_timeout', $config->rpc_negotiation_timeout, 'auth_multimnet');
        set_config('host_guess_pattern', $config->host_guess_pattern, 'auth/multimnet');
        set_config('login_pattern', $config->login_pattern, 'auth/multimnet');
        set_config('fallback_domain', $config->fallback_domain, 'auth/multimnet');
        set_config('loose_access', $config->loose_access, 'auth/multimnet');
        set_config('enable_central_register', $config->enable_central_register, 'auth/multimnet');
        set_config('mnetsiteadmins', $config->mnetsiteadmins);

        return true;
    }

    /**
     * Cron function will be called automatically by cron.php every 5 minutes
     *
     * @return void
     */
    function cron() {
        global $DB;

        // run the keepalive client
        multimnet_keepalive_client();

        // admin/cron.php should have run srand for us
        $random100 = rand(0,100);
        if ($random100 < 10) {     // Approximately 10% of the time.
            // nuke olden sessions
            $longtime = time() - (1 * 3600 * 24);
            $DB->delete_records_select('mnet_session', "expires < ?", array($longtime));
        }
    }

    /**
     * Cleanup any remote mnet_sessions, kill the local mnet_session data
     *
     * This is called by require_logout in moodlelib
     *
     * @return   void
     */
    function prelogout_hook() {
        global $CFG, $USER;

        if (!is_enabled_auth('multimnet')) {
            return;
        }

        // If the user is local to this Moodle:
        if ($USER->mnethostid == $this->mnet->id) {
            multimnet_kill_children($USER->username, sha1($_SERVER['HTTP_USER_AGENT']));

        // Else the user has hit 'logout' at a Service Provider Moodle:
        } else {
            $this->kill_parent($USER->username, sha1($_SERVER['HTTP_USER_AGENT']));
        }
    }

    /**
     * The SP uses this function to kill the session on the parent IdP
     *
     * @param   string  $username       Username for session to kill
     * @param   string  $useragent      SHA1 hash of user agent to look for
     * @return  string                  A plaintext report of what has happened
     */
    function kill_parent($username, $useragent) {
        global $CFG, $USER, $DB;

        require_once $CFG->dirroot.'/mnet/xmlrpc/client.php';
        $sql = "
            select
                *
            from
                {mnet_session} s
            where
                s.username   = ? AND
                s.useragent  = ? AND
                s.mnethostid = ?";

        $mnetsessions = $DB->get_records_sql($sql, array($username, $useragent, $USER->mnethostid));

        $ignore = $DB->delete_records('mnet_session',
                                 array('username' => $username,
                                 'useragent' => $useragent,
                                 'mnethostid' => $USER->mnethostid));

        if (false != $mnetsessions) {
            $mnet_peer = new mnet_peer();
            $mnet_peer->set_id($USER->mnethostid);

            $mnet_request = new mnet_xmlrpc_client();
            $mnet_request->set_method('auth/multimnet/rpclib.php/multimnet_kill_children');

            // set $token and $useragent parameters
            $mnet_request->add_param($username);
            $mnet_request->add_param($useragent);
            if ($mnet_request->send($mnet_peer) === false) {
                debugging(join("\n", $mnet_request->error));
                return false;
            }
        }

        return true;
    }

    /**
     * To delete a host, we must delete all current sessions that users from
     * that host are currently engaged in.
     *
     * @param   string  $sessionidarray   An array of session hashes
     * @return  bool                      True on success
     */
    function end_local_sessions(&$sessionArray) {
        global $CFG;
        
        if (is_array($sessionArray)) {
            while($session = array_pop($sessionArray)) {
                session_kill($session->session_id);
            }
            return true;
        }
        return false;
    }

    /**
     * Checks the MNET access control table to see if the username/mnethost
     * is permitted to login to this moodle.
     *
     * @param string $username   The username
     * @param int    $mnethostid The id of the remote mnethost
     * @return bool              Whether the user can login from the remote host
     */
    function can_login_remotely($username, $mnethostid) {
        global $DB;

        $accessctrl = 'allow';
        $aclrecord = $DB->get_record('mnet_sso_access_control', array('username' => $username, 'mnet_host_id' => $mnethostid));
        if (!empty($aclrecord)) {
            $accessctrl = $aclrecord->accessctrl;
        }
        return $accessctrl == 'allow';
    }

    /**
    * basically receives the sealed credential, unseal it using its
    * own MNET host keypair, and finds username/password pair in it.
    *
    */
    function loginpage_hook() { 
        global $MNET;
        global $SESSION;
        global $PAGE;
        global $CFG;
        global $DB;    
        global $frm; // we must catch the login/index.php $user credential holder.

        // get rid of MNET potentialIDPs as not needed any more if multimnet is enabled
        // we use a CSS rule to hide.
        if(multimnet_get_enabled()){        
            $PAGE->requires->css('/auth/multimnet/condstyles.css');
        }

        if (debugging()) debug_trace("Redirected login from non primary node");

        $sealedssoticket = base64_decode(optional_param('ssoticket', null, PARAM_RAW));
        $enveloppe = base64_decode(optional_param('enveloppe', null, PARAM_RAW));

        if (!$sealedssoticket){
            if (debugging()) debug_trace("No ticket");
            return false; // do nothing other login methods
        }
        
        $privatekey = $this->mnet->get_private_key();
        
        // We unseal credential
        $res = openssl_open($sealedssoticket, $ssoticket, $enveloppe, $privatekey);
                
        $sso = json_decode($ssoticket);

        $potentialuser = $DB->get_record('user', array('username' => $sso->username));
        
        // Trap potential CAS plugin installed and resolve CAS or NOCAS routing
        get_enabled_auth_plugins(true); // fix the list of enabled auths
        if (empty($CFG->auth)) {
            $authsenabled = array();
        } else {
            $authsenabled = explode(',', $CFG->auth);
        }
        if (in_array('cas', $authsenabled)){
            if ($potentialuser->auth == 'cas'){
                $casmode = 'authCAS=CAS';
                $_GET['authCAS'] = 'CAS'; // maybe we can add params...
            } else {
                $casmode = 'authCAS=NOCAS';
                $_GET['authCAS'] = 'NOCAS';
            }
        } else {
            $casmode = '';
        }
        
        // If we have user_mnet_host access control installed, check access control
        // we are actually checking credential AT THE PRIMARY site of the user. 
        // access keys should be consistant in his local profile.
        if (is_file($CFG->dirroot.'/blocks/user_mnet_hosts/xlib.php')){
            require_once($CFG->dirroot.'/blocks/user_mnet_hosts/xlib.php');
            $access = user_mnet_hosts_read_access($potentialuser, $sso->from);
            
            if (!$access){
                redirect($sso->from.'/auth/multimnet/host_authorization.php?primary='.urlencode($CFG->wwwroot));
            }
        }        
        
        if (!empty($sso) && !empty($sso->username)){
            $frm = new StdClass();
            $frm->username = $sso->username;
            $frm->password = $sso->password;
            $SESSION->wantsurl = $sso->wantsurl;
        }
        
    }

    /**
     * Post authentication hook.
     * This method is called from authenticate_user_login() for all enabled auth plugins.
     * Here we need ensure all authenticated users are properly registered in central multimnet register
     * If the local account is mnet, we need update the lastseenhost and last move for the user
     *
     * @param object $user user object, later used for $USER
     * @param string $username (with system magic quotes)
     * @param string $password plain text password (with system magic quotes)
     */
    function user_authenticated_hook(&$user, $username, $password) {
        global $CFG;
        
        $registerenabled = @$this->config->enable_central_register;
        
        if ($registerenabled){
            // register only if primary account is loging in
            // do nothing if fails.
            // never try to register primary admin
            if ($user->auth != 'multimnet' && $user->auth != 'mnet' && $username != 'admin'){
                $this->set_primary_location($user);
            }
            
            // the following should occur in landing pages so tracking user moves
            if ($user->auth == 'mnet' || $user->auth == 'multimnet'){
                // this will also update lastmovetime 
                $this->update_primary_location($username, 'lastseenmnethost', $CFG->wwwroot);
            }
        }
    }

    /**
    *
    *
    */
    function logoutpage_hook() {
        global $USER, $CFG, $redirect, $DB;

        /*
        // do not redirect people on their origin node
        if (!empty($USER->mnethostid) and $USER->mnethostid != $CFG->mnet_localhost_id) {
            $host = $DB->get_record('mnet_host', array('id' => $USER->mnethostid));
            $redirect = $host->wwwroot.'/';
        }
        */

        $redirect = $CFG->wwwroot.'/';
    }

    /**
     * Trims a log line from mnet peer to limit each part to a length which can be stored in our DB
     *
     * @param object $logline The log information to be trimmed
     * @return object The passed logline object trimmed to not exceed storable limits
     */
    function trim_logline ($logline) {
        $limits = array('ip' => 15, 'coursename' => 40, 'module' => 20, 'action' => 40,
                        'url' => 255);
        foreach ($limits as $property => $limit) {
            if (isset($logline->$property)) {
                $logline->$property = substr($logline->$property, 0, $limit);
            }
        }

        return $logline;
    }

    /**
    * Gets origin information about the user based on unique username in the system
    *
    */
    function get_primary_location($username) {
        global $DB;

        if (empty($this->config->fallback_domain)) return null;

        $mnet_host = $DB->get_record('mnet_host', array('id' => $this->config->fallback_domain));

        $PEER = new mnet_peer();
        $PEER->set_wwwroot($mnet_host->wwwroot);

        debug_trace("Getting user register at {$mnet_host->wwwroot}");

        $rpc_client = new mnet_xmlrpc_client();
        $rpc_client->set_method('auth/multimnet/rpclib.php/multimnet_get_primary_location');
        $rpc_client->add_param($username, 'string');

        if (!$rpc_client->send($PEER)) {
            if (debugging()) {
                echo '<pre>';
                var_dump($rpc_client);
                echo '</pre>';
            }
            return false;
        } else {
            $response = json_decode($rpc_client->response);

            if (isset($response->user)) {
                if ($mnethost = $DB->get_record('mnet_host', array('wwwroot' => $response->user->wwwroot, 'deleted' => 0))) {
                    return $mnethost->id;
                }
            } else {
                // If no location, will return false or a textual non numeric error message.
                if(debugging()){
                    echo $response->error;
                }
            }
        }
        return false;
    }

    /**
     * TOT : Write this call to check a remote user in the register matching this user.
     */
     function is_remotely_registered($user) {
        // Call a check mnet service at register to seek for a matching user.
    }

    /**
    * Registers a user information in the central register
    *
    *
    */
    function set_primary_location($user) {
        global $CFG, $DB;

        debug_trace("Setting user $user->username in remote register ");

        $location['remoteuserid'] = $user->id;
        $location['wwwroot'] = $CFG->wwwroot;
        $location['username'] = $user->username;
        $location['firstname'] = $user->firstname;
        $location['lastname'] = $user->lastname;
        $location['idnumber'] = $user->idnumber;

        if ($this->register_is_remote()) {

            $remotemnet = $DB->get_record('mnet_host', array('id' => $this->config->fallback_domain));

            $PEER = new mnet_peer();
            $PEER->set_wwwroot($remotemnet->wwwroot);

            $rpc_client = new mnet_xmlrpc_client();
            $rpc_client->set_method('auth/multimnet/rpclib.php/multimnet_register_primary_location');
            $rpc_client->add_param($location, 'struct');

            if (!$rpc_client->send($PEER)) {
                /*
                if (debugging()) {
                    echo '<pre>';
                    var_dump($rpc_client);
                    echo '</pre>';
                }
                */
            } else {
                $response = json_decode($rpc_client->response);
                if (debugging() && !empty($response->error)){
                    echo $response->error;
                }
            }
        } else {
            // do it locally
            $locationobj = (object)$location;
            unset($locationobj->wwwroot);
            $locationobj->mnethostid = $CFG->mnet_localhost_id;
            $locationobj->lastseenmnethost = $locationobj->mnethostid;
            $locationobj->lastmovetime = time();
            if (!$user = $DB->get_record('auth_multimnet_user', array('username' => $user->username))){
                $DB->insert_record('auth_multimnet_user', $locationobj);
            } else {
                $locationobj->id = $user->id;
                $DB->update_record('auth_multimnet_user', $locationobj);
            }
        }
    }

    function update_primary_location($username, $param, $value) {
        global $CFG, $DB;

        if (!in_array($param, array('idnumber', 'lastseenmnethost', 'firstname', 'lastname', 'lastmovetime', 'deleted', 'mnethostid', 'wwwroot', 'remoteuserid'))) {
            return;
        }

        // We are not the master register.
        if (!empty($this->config->fallback_domain)) {

            $remotemnet = $DB->get_record('mnet_host', array('id' => $this->config->fallback_domain));

            $PEER = new mnet_peer;
            $PEER->set_wwwroot($remotemnet->wwwroot);

            $rpc_client = new mnet_xmlrpc_client();
            $rpc_client->set_method('auth/multimnet/rpclib.php/multimnet_update_primary_location');
            $rpc_client->add_param($username, 'string');
            $rpc_client->add_param($param, 'string');
            $rpc_client->add_param($value, 'string');

            if (!$rpc_client->send($PEER)) {
                if (debugging()) {
                    /*
                    echo '<pre>';
                    var_dump($rpc_client);
                    echo '</pre>';
                    */
                }
            } else {
                $response = json_decode($rpc_client->response);
                if ($response->status == RPC_SUCCESS){
                    return true;
                }
            }
            return false;
        } else {
            // do it locally
            $DB->set_field('auth_multimnet_user', $param, $value, array('username' => $username));
        }
    }

    function search_location($pattern) {
        global $DB;

        if ($this->config->multimnet_fallback_domain) {
            $remotemnet = $DB->get_record('mnet_host', array('id' => $this->config->multimnet_fallback_domain)); 

            $PEER = new mnet_peer;
            $PEER->set_wwwroot($remotemnet->wwwroot);

            $rpc_client = new mnet_xmlrpc_client();
            $rpc_client->set_method('auth/multimnet/rpclib.php/multimnet_search_location');
            $rpc_client->add_param($pattern, 'string');
    
            if (!$rpc_client->send($PEER)) {
                if (debugging()) {
                    /*
                    echo '<pre>';
                    var_dump($rpc_client);
                    echo '</pre>';
                    */
                }
            } else {
                $response = json_decode($rpc_client->response);
                if ($response->status == RPC_SUCCESS){
                    return $response->matches;
                }
            }
        }
    }

    /**
     * Checks if the register is remote.
     * @return boolean
     */
    function register_is_remote() {
        global $CFG;

        return !empty($this->config->fallback_domain) && ($this->config->fallback_domain != $CFG->mnet_localhost_id);
    }

    /**
     * Starts an RPC jump session and returns the jump redirect URL.
     *
     * @param int $mnethostid id of the mnet host to jump to
     * @param string $wantsurl url to redirect to after the jump (usually on remote system)
     * @param boolean $wantsurlbackhere defaults to false, means that the remote system should bounce us back here
     *                                  rather than somewhere inside *its* wwwroot
     */
    function start_jump_session($mnethostid, $wantsurl, $wantsurlbackhere=false) {
        global $CFG, $USER, $DB;

        require_once $CFG->dirroot . '/mnet/xmlrpc/client.php';

// CHANGE FROM MNET : allows multijump and admin hands on.
/*
        if (session_is_loggedinas()) {
            print_error('notpermittedtojumpas', 'mnet');
        }
*/

        // Check remote login permissions.
        if (!has_capability('moodle/site:mnetlogintoremote', context_system::instance())
//                or is_mnet_remote_user($USER)
// /CHANGE
                or isguestuser()
                or !isloggedin()) {
            print_error('notpermittedtojump', 'mnet');
        }

        // check for SSO publish permission first
        if ($this->has_service($mnethostid, 'sso_sp') == false) {
            print_error('hostnotconfiguredforsso', 'mnet');
        }

        // set RPC timeout to 30 seconds if not configured
        if (empty($this->config->rpc_negotiation_timeout)) {
            $this->config->rpc_negotiation_timeout = 30;
            set_config('rpc_negotiation_timeout', '30', 'auth_multimnet');
        }

        // get the host info
        $mnet_peer = new mnet_peer();
        $mnet_peer->set_id($mnethostid);

        // set up the session
        $mnet_session = $DB->get_record('mnet_session',
                                   array('userid' => $USER->id, 
                                            'mnethostid' => $mnethostid,
                                            'useragent' => sha1($_SERVER['HTTP_USER_AGENT'])));
        if ($mnet_session == false) {
            $mnet_session = new stdClass();
            $mnet_session->mnethostid = $mnethostid;
            $mnet_session->userid = $USER->id;
            $mnet_session->username = $USER->username;
            $mnet_session->useragent = sha1($_SERVER['HTTP_USER_AGENT']);
            $mnet_session->token = $this->generate_token();
            $mnet_session->confirm_timeout = time() + $this->config->rpc_negotiation_timeout;
            $mnet_session->expires = time() + (integer)ini_get('session.gc_maxlifetime');
            $mnet_session->session_id = session_id();
            $mnet_session->id = $DB->insert_record('mnet_session', $mnet_session);
        } else {
            $mnet_session->useragent = sha1($_SERVER['HTTP_USER_AGENT']);
            $mnet_session->token = $this->generate_token();
            $mnet_session->confirm_timeout = time() + $this->config->rpc_negotiation_timeout;
            $mnet_session->expires = time() + (integer)ini_get('session.gc_maxlifetime');
            $mnet_session->session_id = session_id();
            $DB->update_record('mnet_session', $mnet_session);
        }

        // construct the redirection URL
        //$transport = mnet_get_protocol($mnet_peer->transport);
        $wantsurl = urlencode($wantsurl);
        if ($mnet_peer->application->name == 'moodle') {
            $ssolandurl = '/auth/multimnet/land.php';
        } else {
            $ssolandurl = $mnet_peer->application->sso_land_url;
        }
        $url = "{$mnet_peer->wwwroot}{$ssolandurl}?token={$mnet_session->token}&idp={$this->mnet->wwwroot}&wantsurl={$wantsurl}";
        if ($wantsurlbackhere) {
            $url .= '&remoteurl=1';
        }

        return $url;
    }

    /**
     * This function confirms the remote (ID provider) host's mnet session
     * by communicating the token and UA over the XMLRPC transport layer, and
     * returns the local user record on success.
     *
     *   @param string    $token           The random session token.
     *   @param mnet_peer $remotepeer   The ID provider mnet_peer object.
     *   @return array The local user record.
     */
    function confirm_mnet_session($token, $remotepeer) {
        global $CFG, $DB, $SITE;

        require_once $CFG->dirroot . '/mnet/xmlrpc/client.php';
        require_once $CFG->libdir . '/gdlib.php';

        // verify the remote host is configured locally before attempting RPC call
        if (! $remotehost = $DB->get_record('mnet_host', array('wwwroot' => $remotepeer->wwwroot, 'deleted' => 0))) {
            print_error('notpermittedtoland', 'mnet');
        }

        // set up the RPC request
        $mnetrequest = new mnet_xmlrpc_client();
        $mnetrequest->set_method('auth/multimnet/rpclib.php/multimnet_user_authorise');

        // set $token and $useragent parameters
        $mnetrequest->add_param($token);
        $mnetrequest->add_param(sha1($_SERVER['HTTP_USER_AGENT']));

        // Thunderbirds are go! Do RPC call and store response
        if ($mnetrequest->send($remotepeer) === true) {
            $remoteuser = (object) $mnetrequest->response;
        } else {
            // print_object($mnetrequest);
            foreach ($mnetrequest->error as $errormessage) {
                list($code, $message) = array_map('trim', explode(':', $errormessage, 2));
                if($code == 702) {
                    print_error('mnet_session_prohibited', 'mnet', $remotepeer->wwwroot, format_string($SITE->fullname));
                    exit;
                }
                $message .= "ERROR $code:<br/>$errormessage<br/>";
            }
            print_error("rpcerror", '', '', $message);
        }
        unset($mnetrequest);

        if (empty($remoteuser) or empty($remoteuser->username)) {
            print_error('unknownerror', 'mnet');
            exit;
        }

        if (user_not_fully_set_up($remoteuser)) {
            print_error('notenoughidpinfo', 'mnet');
            exit;
        }

        // CHANGE FROM MNET : Invert mnet fields filtering default rule
        if (!empty($CFG->enablemnetimportfilter)) {
            $remoteuser = mnet_strip_user($remoteuser, mnet_fields_to_import($remotepeer));
        }
        // /CHANGE

        $remoteuser->auth = 'multimnet';
        $remoteuser->wwwroot = $remotepeer->wwwroot;

        // the user may roam from Moodle 1.x where lang has _utf8 suffix
        // also, make sure that the lang is actually installed, otherwise set site default
        if (isset($remoteuser->lang)) {
            $remoteuser->lang = clean_param(str_replace('_utf8', '', $remoteuser->lang), PARAM_LANG);
        }

        if (empty($remoteuser->lang)) {
            if (!empty($CFG->lang)) {
                $remoteuser->lang = $CFG->lang;
            } else {
                $remoteuser->lang = 'en';
            }
        }
        $firsttime = false;

        // EXPERIMENTAL CHANGE
        // If the remote user has a sufficiant heuristic identical profile matching a local account, 
        // let the local account play rather than creating a mnet account.
        // In that case, no propagation of profile attributes are done.
        if ($localuser = $this->guess_local_user_match($remoteuser)) {
            $localuser->lastaccess = time();
            $DB->update_record('user', $localuser);
            return $localuser;
        }
        // CHANGE

        // get the local record for the remote user
        $localuser = $DB->get_record('user', array('username' => $remoteuser->username, 'mnethostid' => $remotehost->id));

        // add the remote user to the database if necessary, and if allowed
        // TODO: refactor into a separate function
        if (empty($localuser) || ! $localuser->id) {
            /*
            if (empty($this->config->auto_add_remote_users)) {
                print_error('nolocaluser', 'mnet');
            } See MDL-21327   for why this is commented out
            */
            $remoteuser->mnethostid = $remotehost->id;
            $remoteuser->firstaccess = time(); // First time user in this server, grab it here
            $remoteuser->confirmed = 1;

            $remoteuser->id = $DB->insert_record('user', $remoteuser);
            $firsttime = true;
            $localuser = $remoteuser;
        }

        // check sso access control list for permission first
        if (!$this->can_login_remotely($localuser->username, $remotehost->id)) {
            print_error('sso_mnet_login_refused', 'mnet', '', array('user' => $localuser->username, 'host' => $remotehost->name));
        }

        $fs = get_file_storage();

        // update the local user record with remote user data
        foreach ((array) $remoteuser as $key => $val) {
            if ($key == '_mnet_userpicture_timemodified' and empty($CFG->disableuserimages) and isset($remoteuser->picture)) {
                // update the user picture if there is a newer verion at the identity provider
                $usercontext = context_user::instance($localuser->id, MUST_EXIST);
                if ($usericonfile = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f1.png')) {
                    $localtimemodified = $usericonfile->get_timemodified();
                } else if ($usericonfile = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f1.jpg')) {
                    $localtimemodified = $usericonfile->get_timemodified();
                } else {
                    $localtimemodified = 0;
                }

                if (!empty($val) and $localtimemodified < $val) {
                    mnet_debug('refetching the user picture from the identity provider host');
                    $fetchrequest = new mnet_xmlrpc_client();
                    $fetchrequest->set_method('auth/multimnet/rcplib.php/multimnet_fetch_user_image');
                    $fetchrequest->add_param($localuser->username);
                    if ($fetchrequest->send($remotepeer) === true) {
                        if (strlen($fetchrequest->response['f1']) > 0) {
                            $imagefilename = $CFG->tempdir . '/mnet-usericon-' . $localuser->id;
                            $imagecontents = base64_decode($fetchrequest->response['f1']);
                            file_put_contents($imagefilename, $imagecontents);
                            if ($newrev = process_new_icon($usercontext, 'user', 'icon', 0, $imagefilename)) {
                                $localuser->picture = $newrev;
                            }
                            unlink($imagefilename);
                        }
                        // note that since Moodle 2.0 we ignore $fetchrequest->response['f2']
                        // the mimetype information provided is ignored and the type of the file is detected
                        // by process_new_icon()
                    }
                }
            }

            if ($key == 'myhosts') {
                $localuser->mnet_foreign_host_array = array();
                foreach($val as $rhost) {
                    $name  = clean_param($rhost['name'], PARAM_ALPHANUM);
                    $url   = clean_param($rhost['url'], PARAM_URL);
                    $count = clean_param($rhost['count'], PARAM_INT);
                    $url_is_local = stristr($url , $CFG->wwwroot);
                    if (!empty($name) && !empty($count) && empty($url_is_local)) {
                        $localuser->mnet_foreign_host_array[] = array('name'  => $name,
                                                                      'url'   => $url,
                                                                      'count' => $count);
                    }
                }
            }

            // CHANGE FROM MNET : capture profile fields, check if corresponding entry is defined and update data
            if (preg_match('/^profile_field_(.*)/', $key, $matches)){
                $fieldname = $matches[1];
                if ($field = $DB->get_record('user_info_field', array('shortname' => $fieldname))){
                    $datum = new StdClass;
                    $datum->fieldid = $field->id;
                    $datum->userid = $localuser->id;
                    $datum->data = $val;
                    if ($oldrecord = $DB->get_record('user_info_data', array('fieldid' => $field->id, 'userid' => $localuser->id))){
                        $datum->id = $oldrecord->id;
                        $DB->update_record('user_info_data', $datum);
                    } else {
                        $DB->insert_record('user_info_data', $datum);
                    }
                }
            }

            // /CHANGE

            $localuser->{$key} = $val;
        }

        $localuser->mnethostid = $remotepeer->id;
        if (empty($localuser->firstaccess)) { // Now firstaccess, grab it here.
            $localuser->firstaccess = time();
        }

        $DB->update_record('user', $localuser);

        if (!$firsttime) {
            // Repeat customer! let the IDP know about enrolments.
            // we have for this user.
            // set up the RPC request
            $mnetrequest = new mnet_xmlrpc_client();
            $mnetrequest->set_method('auth/multimnet/rcplib.php/multimnet_update_enrolments');

            /** Pass username and an assoc array of "my courses"
             * with info so that the IDP can maintain mnetservice_enrol_enrolments
             */
            $mnetrequest->add_param($remoteuser->username);
            $fields = 'id, category, sortorder, fullname, shortname, idnumber, summary, startdate, visible';
            $courses = enrol_get_users_courses($localuser->id, false, $fields, 'visible DESC,sortorder ASC');
            if (is_array($courses) && !empty($courses)) {
                // Second request to do the JOINs that we'd have done
                // inside enrol_get_users_courses() if we had been allowed
                $sql = "SELECT c.id,
                               cc.name AS cat_name, cc.description AS cat_description
                          FROM {course} c
                          JOIN {course_categories} cc ON c.category = cc.id
                         WHERE c.id IN (" . join(',',array_keys($courses)) . ')';
                $extra = $DB->get_records_sql($sql);

                $keys = array_keys($courses);
                $studentroles = get_archetype_roles('student');
                if (!empty($studentroles)) {
                    $defaultrole = reset($studentroles);
                    //$defaultrole = get_default_course_role($ccache[$shortname]); //TODO: rewrite this completely, there is no default course role any more!!!
                    foreach ($keys as $id) {
                        if ($courses[$id]->visible == 0) {
                            unset($courses[$id]);
                            continue;
                        }
                        $courses[$id]->cat_id          = $courses[$id]->category;
                        $courses[$id]->defaultroleid   = $defaultrole->id;
                        unset($courses[$id]->category);
                        unset($courses[$id]->visible);

                        $courses[$id]->cat_name        = $extra[$id]->cat_name;
                        $courses[$id]->cat_description = $extra[$id]->cat_description;
                        $courses[$id]->defaultrolename = $defaultrole->name;
                        // coerce to array
                        $courses[$id] = (array)$courses[$id];
                    }
                } else {
                    throw new moodle_exception('unknownrole', 'error', '', 'student');
                }
            } else {
                // if the array is empty, send it anyway
                // we may be clearing out stale entries
                $courses = array();
            }
            $mnetrequest->add_param($courses);

            // Call 0800-RPC Now! -- we don't care too much if it fails
            // as it's just informational.
            if ($mnetrequest->send($remotepeer) === false) {
                // error_log(print_r($mnetrequest->error,1));
            }
        }

        return $localuser;
    }

    /**
     * Use some heuristics to determine if there is no local account superseeding a mnet
     * remote access
     */
    function guess_local_user_match($remoteuser) {
        global $DB;

        // Identity on some profile identfying fields are weighted. A match scroe of 5
        // should allow considering the account is identical 
        $weights = array('firstname' => 1,
                         'lastname' => 2,
                         'username' => 2,
                         'idnumber' => 4,
                         'email' => 5);

        $userscores = array();
        foreach ($weights as $key => $weight) {
            $usermatch = $DB->get_records_select('user', " {$key} = ? AND deleted = 0 ", array($remoteuser->$key));
            foreach($usermatch as $potentialuser) {
                $userscores[$potentialuser->id] += $weight;
                if ($userscores[$potentialuser->id] >= 5) {
                    // Retain user in cache if reaching matching score.
                    $guessedusers[$potentialuser->id] = $potentialuser;
                }
            }
        }
        
        // speed up if no match
        if (empty($guessedusers)) return null;

        // Ensure we get matches in order.
        asort($userscores);

        $maxscore = 0;
        $maxuid = 0;
        foreach ($guessedusers as $uid => $user) {
            // This will catch the first matching user from the highest score
            if ($maxscore < $userscore[$uid]) {
                $maxscore = $userscore[$uid];
                $maxuid = $uid;
                continue;
            }
            // Here we can track a potential conflict in matching more than one.
            if (($maxscore == $userscore[$uid]) && $maxuid) {
                // Todo: Chack what to do really. 
                // First approach is that this should NOT occur in a sane user base.
                print_error(get_string('localcollision', 'auth_multimnet'));
            }
        }
    }

    /**
     * creates (or updates) the mnet session once
     * {@see confirm_mnet_session} and {@see complete_user_login} have both been called
     *
     * @param stdclass  $user the local user (must exist already
     * @param string    $token the jump/land token
     * @param mnet_peer $remotepeer the mnet_peer object of this users's idp
     */
    public function update_mnet_session($user, $token, $remotepeer) {
        global $DB;

        $session_gc_maxlifetime = 1440;
        if (isset($user->session_gc_maxlifetime)) {
            $session_gc_maxlifetime = $user->session_gc_maxlifetime;
        }
        if (!$mnet_session = $DB->get_record('mnet_session',
                                   array('userid' => $user->id, 
                                            'mnethostid' => $remotepeer->id,
                                            'useragent' => sha1($_SERVER['HTTP_USER_AGENT'])))) {
            $mnet_session = new stdClass();
            $mnet_session->mnethostid = $remotepeer->id;
            $mnet_session->userid = $user->id;
            $mnet_session->username = $user->username;
            $mnet_session->useragent = sha1($_SERVER['HTTP_USER_AGENT']);
            $mnet_session->token = $token; // Needed to support simultaneous sessions
                                           // and preserving DB rec uniqueness
            $mnet_session->confirm_timeout = time();
            $mnet_session->expires = time() + (integer)$session_gc_maxlifetime;
            $mnet_session->session_id = session_id();
            $mnet_session->id = $DB->insert_record('mnet_session', $mnet_session);
        } else {
            $mnet_session->expires = time() + (integer)$session_gc_maxlifetime;
            $DB->update_record('mnet_session', $mnet_session);
        }
    }

    /**
     * Generate a random string for use as an RPC session token.
     */
    protected function generate_token() {
        return sha1(str_shuffle('' . mt_rand() . time()));
    }

    /**
     * Determines if an MNET host is providing the nominated service.
     *
     * @param int    $mnethostid   The id of the remote host
     * @param string $servicename  The name of the service
     * @return bool                Whether the service is available on the remote host
     */
    protected function has_service($mnethostid, $servicename) {
        global $CFG, $DB;

        $sql = "
            SELECT
                svc.id as serviceid,
                svc.name,
                svc.description,
                svc.offer,
                svc.apiversion,
                h2s.id as h2s_id
            FROM
                {mnet_host} h,
                {mnet_service} svc,
                {mnet_host2service} h2s
            WHERE
                h.deleted = '0' AND
                h.id = h2s.hostid AND
                h2s.hostid = ? AND
                h2s.serviceid = svc.id AND
                svc.name = ? AND
                h2s.subscribe = '1'";

        return $DB->get_records_sql($sql, array($mnethostid, $servicename));
    }
}
