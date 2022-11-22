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

defined('MOODLE_INTERNAL') || die;

require_once $CFG->dirroot.'/auth/multimnet/lib.php';

if (!defined('RPC_SUCCESS')) {
    define('RPC_TEST', 100);
    define('RPC_SUCCESS', 200);
    define('RPC_FAILURE', 500);
    define('RPC_FAILURE_USER', 501);
    define('RPC_FAILURE_CONFIG', 502);
    define('RPC_FAILURE_DATA', 503); 
    define('RPC_FAILURE_CAPABILITY', 510);
    define('MNET_FAILURE', 511);
    define('RPC_FAILURE_RECORD', 520);
    define('RPC_FAILURE_RUN', 521);
}

function multimnet_get_primary_location($username, $json_response = true) {
    global $DB, $CFG;

    // Creating response
    $response = new stdclass;
    $response->status = RPC_SUCCESS;

    debug_trace(" querying for user register for $username at {$CFG->wwwroot} in {$CFG->dbname}");

    try{
        if ($user = $DB->get_record('auth_multimnet_user', array('username' => $username, 'deleted' => 0))){
            $user->wwwroot = $DB->get_field('mnet_host', 'wwwroot', array('id' => $user->mnethostid));
            $response->user = $user;
        } else {
            $response->status = RPC_FAILURE_USER;
            $response->errors[] = 'No such user in central register';
            $response->error = 'No such user in central register';
        }

        debug_trace(serialize($response));
    } catch(Exception $e) {
        debug_trace($e);
    }

    if ($json_response) {
        return json_encode($response);
    } else {
        return $response;
    }
}

function multimnet_search_location($pattern, $json_response = true) {
    global $DB, $CFG;

    // Creating response
    $response = new stdclass;
    $response->status = RPC_SUCCESS;
    
    if (strstr($pattern, ':') !== false){
        list($lastnamepattern, $firstnamepattern) = explode(':', $pattern);
        $lastnamepattern = "%{$lastnamepattern}%";
        $firstnamepattern = "%{$firstnamepattern}%";
    } else {
        $lastnamepattern = "%{$pattern}%";
        $firstnamepattern = '%';
    }
    
    try{
        $select = " lastname LIKE '$lastnamepattern' AND firstname LIKE '$firstnamepattern' AND deleted = 0 ";
        debug_trace($select);
        if ($users = $DB->get_records_select('auth_multimnet_user', $select, array())){
            $response->matches = $users;
            foreach($response->matches as $uid => $location){
                $response->matches[$uid]->wwwroot = $DB->get_field('mnet_host', 'wwwroot', array('id' => $location->lastseenmnethost));                
            }
        } else {
            $response->status = RPC_FAILURE_USER;
            $response->errors[] = 'Not matching query';
            $response->error = 'Not matching query';
        }        
    } catch(Exception $e) {
        debug_trace($e);
    }

    if ($json_response){
        return json_encode($response);
    } else {
        return $response;
    }    
}

function multimnet_update_primary_location($username, $param, $value, $json_response = true){
    global $DB;

    // Creating response
    $response = new stdclass;
    $response->status = RPC_SUCCESS;
    
    if (!in_array($param, array('mnethostid', 'remoteuserid', 'idnumber', 'lastseenmnethost', 'lastsessionstart', 'deleted'))){
        $response->status = RPC_FAILURE_DATA;
        $response->errors[] = 'Wrong parameter for update';
        $response->error = 'Wrong parameter for update';

        if ($json_response){
            return json_encode($response);
        } else {
            return $response;
        }
    }
    
    if ($user = $DB->get_record('auth_multimnet_user', array('username' => $username))){
        
        // changing mnet host for user or lastseenmnethosts is always performed on a wwwroot basis 
        if ($param == 'mnethostid' || $param == 'lastseenmnethost'){
            if ($remotehost = $DB->get_record('mnet_host', array('wwwroot' => $value))){            
                $value = $remotehost->id;
            } else {
                $response->status = RPC_FAILURE_DATA;
                $response->errors[] = 'Unknown host at register side';
                $response->error = 'Unknown host at register side';
        
                if ($json_response){
                    return json_encode($response);
                } else {
                    return $response;
                }
            }
        }

        if ($param == 'lastseenmnethost'){
            $user->lastmovetime = time();
        }

        $user->$param = $value;
        $DB->update_record('auth_multimnet_user', $user);
    } else {
        $response->status = RPC_FAILURE_USER;
        $response->errors[] = 'No such user in central register';
        $response->error = get_string('errornotregistered', 'auth_multimnet');
    }

    if ($json_response){
        return json_encode($response);
    } else {
        return $response;
    }    
}

/**
* this function is called by any host to register a local primary account.
* Users register a primary account at several occasions, such as user
* creation (and user local), or at user login time
*
*/
function multimnet_register_primary_location($location, $json_response = true){
    global $DB;

    // Creating response
    $response = new stdclass;
    $response->status = RPC_SUCCESS;
    
    $location = (object)$location;

    // debug_trace(serialize($location));
    
    if ($user = $DB->get_record('auth_multimnet_user', array('username' => $location->username))){
        
        if ($user->idnumber != $location->idnumber){
            $response->status = RPC_FAILURE_USER;
            $response->errors[] = 'Identity collision on IDNumber';
            $response->error = 'Identity collision on IDNumber';

            if ($json_response){
                return json_encode($response);
            } else {
                return $response;
            }
        }
        
        $locationmnethost = $DB->get_record('mnet_host', array('wwwroot' => $location->wwwroot));
        if ($locationmnethost->id != $user->mnethostid){
            $response->status = RPC_FAILURE_USER;
            $response->errors[] = 'Identity collision on Mnet Host';
            $response->error = 'Identity collision on Mnet Host';

            if ($json_response){
                return json_encode($response);
            } else {
                return $response;
            }
        }

        if ($user->remoteuserid != $location->remoteuserid){
            $response->status = RPC_FAILURE_USER;
            $response->errors[] = 'Identity collision on Remote User ID';
            $response->error = 'Identity collision on Remote User ID';

            if ($json_response){
                return json_encode($response);
            } else {
                return $response;
            }
        }

        // update those fields anyway for better information integrity        
        $DB->set_field('auth_multimnet_user', 'firstname', $location->firstname, array('username' => $location->username));
        $DB->set_field('auth_multimnet_user', 'lastname', $location->lastname, array('username' => $location->username));

        $response->message = 'User is known in register';
        
    } else {
        $locationmnethost = $DB->get_record('mnet_host', array('wwwroot' => $location->wwwroot));
        $location->mnethostid = $locationmnethost->id;
        unset($location->wwwroot);
        $location->lastseenmnethost = $location->mnethostid; // user just triggered us so we know where it is
        $location->lastsessionstart = time(); // user just triggered us so we know where it is
        $location->lastmovetime = time(); // user just triggered us so we know where it is
        $location->deleted = 0;

        $DB->insert_record('auth_multimnet_user', $location);
        $response->message = 'User added to register';
    }

    if ($json_response){
        return json_encode($response);
    } else {
        return $response;
    }    
}

/**
 * Return user data for the provided token, compare with user_agent string.
 * This relocalizes in multimnet the auth_mnet::user_authorise RPC function.
 *
 * @param  string $token    The unique ID provided by remotehost.
 * @param  string $UA       User Agent string.
 * @return array  $userdata Array of user info for remote host
 */
function multimnet_user_authorise($token, $useragent) {
    global $CFG, $SITE, $DB;

    debug_trace("Request for authorisation ");
    if (!$auth = multimnet_get_enabled()){
        debug_trace("Multimnet is disabled");
        return;
    }
    
    $remoteclient = get_mnet_remote_client();
    require_once $CFG->dirroot . '/mnet/xmlrpc/serverlib.php';

    $mnet_session = $DB->get_record('mnet_session', array('token' => $token, 'useragent' => $useragent));
    if (empty($mnet_session)) {
        throw new mnet_server_exception(1, 'authfail_nosessionexists');
    }

    // check session confirm timeout
    if ($mnet_session->confirm_timeout < time()) {
        throw new mnet_server_exception(2, 'authfail_sessiontimedout');
    }

    // session okay, try getting the user
    if (!$user = $DB->get_record('user', array('id' => $mnet_session->userid))) {
        throw new mnet_server_exception(3, 'authfail_usermismatch');
    }

    $userdata = mnet_strip_user((array)$user, mnet_fields_to_send($remoteclient));

    // extra special ones
    $userdata['auth']                    = 'multimnet';
    $userdata['wwwroot']                 = $auth->mnet->wwwroot;
    $userdata['session.gc_maxlifetime']  = ini_get('session.gc_maxlifetime');

    if (array_key_exists('picture', $userdata) && !empty($user->picture)) {
        $fs = get_file_storage();
        $usercontext = context_user::instance($user->id, MUST_EXIST);
        if ($usericonfile = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f1.png')) {
            $userdata['_mnet_userpicture_timemodified'] = $usericonfile->get_timemodified();
            $userdata['_mnet_userpicture_mimetype'] = $usericonfile->get_mimetype();
        } else if ($usericonfile = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f1.jpg')) {
            $userdata['_mnet_userpicture_timemodified'] = $usericonfile->get_timemodified();
            $userdata['_mnet_userpicture_mimetype'] = $usericonfile->get_mimetype();
        }
    }

    // CHANGE FROM MNET : Get user's custom fields and aggregate them to the user profile
    $sql = "
        SELECT
            f.shortname,
            d.data
        FROM
            {user_info_field} f,
            {user_info_data} d
        WHERE
            d.userid = ? AND
            f.id = d.fieldid
    ";
    if ($profilefields = $DB->get_records_sql_menu($sql, array($mnet_session->userid))){
        foreach($profilefields as $fieldname => $fielddata){
            $userdata["profile_field_{$fieldname}"] = $fielddata;
        }
    }        
    // /CHANGE

    $userdata['myhosts'] = array();
    if ($courses = enrol_get_users_courses($user->id, false)) {
        $userdata['myhosts'][] = array('name'=> $SITE->shortname, 'url' => $CFG->wwwroot, 'count' => count($courses));
    }

    $sql = "SELECT h.name AS hostname, h.wwwroot, h.id AS hostid,
                   COUNT(c.id) AS count
              FROM {mnetservice_enrol_courses} c
              JOIN {mnetservice_enrol_enrolments} e ON (e.hostid = c.hostid AND e.remotecourseid = c.remoteid)
              JOIN {mnet_host} h ON h.id = c.hostid
             WHERE e.userid = ? AND c.hostid = ?
          GROUP BY h.name, h.wwwroot, h.id";

    if ($courses = $DB->get_records_sql($sql, array($user->id, $remoteclient->id))) {
        foreach($courses as $course) {
            $userdata['myhosts'][] = array('name'=> $course->hostname, 'url' => $CFG->wwwroot.'/auth/multimnet/jump.php?hostid='.$course->hostid, 'count' => $course->count);
        }
    }

    return $userdata;
}

/**
 * When the IdP requests that child sessions are terminated,
 * this function will be called on each of the child hosts. The machine that
 * calls the function (over xmlrpc) provides us with the mnethostid we need.
 *
 * @param   string  $username       Username for session to kill
 * @param   string  $useragent      SHA1 hash of user agent to look for
 * @return  bool                    True on success
 */
function multimnet_kill_child($username, $useragent) {
    global $CFG, $DB;

    $remoteclient = get_mnet_remote_client();
    $session = $DB->get_record('mnet_session', array('username' => $username, 'mnethostid' => $remoteclient->id, 'useragent' => $useragent));
    $DB->delete_records('mnet_session', array('username' => $username, 'mnethostid' => $remoteclient->id, 'useragent' => $useragent));
    if (false != $session) {
        session_kill($session->session_id);
        return true;
    }
    return false;
}

/**
 * The IdP uses this function to kill child sessions on other hosts
 *
 * @param   string  $username       Username for session to kill
 * @param   string  $useragent      SHA1 hash of user agent to look for
 * @return  string                  A plaintext report of what has happened
 */
function multimnet_kill_children($username, $useragent) {
    global $CFG, $USER, $DB;
    
    $remoteclient = null;
    if (defined('MNET_SERVER')) {
        $remoteclient = get_mnet_remote_client();
    }
    require_once $CFG->dirroot.'/mnet/xmlrpc/client.php';

    $userid = $DB->get_field('user', 'id', array('mnethostid' => $CFG->mnet_localhost_id, 'username' => $username));

    $returnstring = '';

    $mnetsessions = $DB->get_records('mnet_session', array('userid' => $userid, 'useragent' => $useragent));

    if (false == $mnetsessions) {
        $returnstring .= "Could find no remote sessions\n";
        $mnetsessions = array();
    }

    foreach($mnetsessions as $mnetsession) {
        // If this script is being executed by a remote peer, that means the user has clicked
        // logout on that peer, and the session on that peer can be deleted natively.
        // Skip over it.
        if (isset($remoteclient->id) && ($mnetsession->mnethostid == $remoteclient->id)) {
            continue;
        }
        $returnstring .=  "Deleting session\n";

        $mnet_peer = new mnet_peer();
        $mnet_peer->set_id($mnetsession->mnethostid);

        $mnet_request = new mnet_xmlrpc_client();
        $mnet_request->set_method('auth/multimnet/rpclib.php/multimnet_kill_child');

        // set $token and $useragent parameters
        $mnet_request->add_param($username);
        $mnet_request->add_param($useragent);
        if ($mnet_request->send($mnet_peer) === false) {
            debugging("Server side error has occured on host $mnetsession->mnethostid: " .
                      join("\n", $mnet_request->error));
        }
    }

    $ignore = $DB->delete_records('mnet_session',
                             array('useragent' => $useragent, 'userid' => $userid));

    if (isset($remoteclient) && isset($remoteclient->id)) {
        session_kill_user($userid);
    }
    return $returnstring;
}

/**
 * Returns the user's profile image info
 *
 * If the user exists and has a profile picture, the returned array will contain keys:
 *  f1          - the content of the default 100x100px image
 *  f1_mimetype - the mimetype of the f1 file
 *  f2          - the content of the 35x35px variant of the image
 *  f2_mimetype - the mimetype of the f2 file
 *
 * The mimetype information was added in Moodle 2.0. In Moodle 1.x, images are always jpegs.
 *
 * @see process_new_icon()
 * @uses mnet_remote_client callable via MNet XML-RPC
 * @param int $userid The id of the user
 * @return false|array false if user not found, empty array if no picture exists, array with data otherwise
 */
function multimnet_fetch_user_image($username) {
    global $CFG, $DB;

    if ($user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id))) {
        $fs = get_file_storage();
        $usercontext = context_user::instance($user->id, MUST_EXIST);
        $return = array();
        if ($f1 = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f1.png')) {
            $return['f1'] = base64_encode($f1->get_content());
            $return['f1_mimetype'] = $f1->get_mimetype();
        } else if ($f1 = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f1.jpg')) {
            $return['f1'] = base64_encode($f1->get_content());
            $return['f1_mimetype'] = $f1->get_mimetype();
        }
        if ($f2 = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f2.png')) {
            $return['f2'] = base64_encode($f2->get_content());
            $return['f2_mimetype'] = $f2->get_mimetype();
        } else if ($f2 = $fs->get_file($usercontext->id, 'user', 'icon', 0, '/', 'f2.jpg')) {
            $return['f2'] = base64_encode($f2->get_content());
            $return['f2_mimetype'] = $f2->get_mimetype();
        }
        return $return;
    }
    return false;
}

/**
 * Returns the theme information and logo url as strings.
 *
 * @return string     The theme info
 */
function multimnet_fetch_theme_info() {
    global $CFG;

    $themename = "$CFG->theme";
    $logourl   = "$CFG->wwwroot/theme/$CFG->theme/images/logo.jpg";

    $return['themename'] = $themename;
    $return['logourl'] = $logourl;
    return $return;
}

/**
 * Invoke this function _on_ the IDP to update it with enrolment info local to
 * the SP right after calling user_authorise()
 *
 * Normally called by the SP after calling user_authorise()
 *
 * @param string $username The username
 * @param array $courses  Assoc array of courses following the structure of mnetservice_enrol_courses
 * @return bool
 */
function multimnet_update_enrolments($username, $courses) {
    global $CFG, $DB;
    
    $remoteclient = get_mnet_remote_client();

    if (empty($username) || !is_array($courses)) {
        return false;
    }
    // make sure it is a user we have an in active session
    // with that host...
    $mnetsessions = $DB->get_records('mnet_session', array('username' => $username, 'mnethostid' => $remoteclient->id), '', 'id, userid');
    $userid = null;
    foreach ($mnetsessions as $mnetsession) {
        if (is_null($userid)) {
            $userid = $mnetsession->userid;
            continue;
        }
        if ($userid != $mnetsession->userid) {
            throw new mnet_server_exception(3, 'authfail_usermismatch');
        }
    }

    if (empty($courses)) { // no courses? clear out quickly
        $DB->delete_records('mnetservice_enrol_enrolments', array('hostid' => $remoteclient->id, 'userid' => $userid));
        return true;
    }

    // IMPORTANT: Ask for remoteid as the first element in the query, so
    // that the array that comes back is indexed on the same field as the
    // array that we have received from the remote client
    $sql = "SELECT c.remoteid, c.id, c.categoryid AS cat_id, c.categoryname AS cat_name, c.sortorder,
                   c.fullname, c.shortname, c.idnumber, c.summary, c.summaryformat, c.startdate,
                   e.id AS enrolmentid
              FROM {mnetservice_enrol_courses} c
         LEFT JOIN {mnetservice_enrol_enrolments} e ON (e.hostid = c.hostid AND e.remotecourseid = c.remoteid)
             WHERE e.userid = ? AND c.hostid = ?";

    $currentcourses = $DB->get_records_sql($sql, array($userid, $remoteclient->id));

    $local_courseid_array = array();
    foreach($courses as $ix => $course) {

        $course['remoteid'] = $course['id'];
        $course['hostid']   =  (int)$remoteclient->id;
        $userisregd         = false;

        // if we do not have the the information about the remote course, it is not available
        // to us for remote enrolment - skip
        if (array_key_exists($course['remoteid'], $currentcourses)) {
            // Pointer to current course:
            $currentcourse =& $currentcourses[$course['remoteid']];
            // We have a record - is it up-to-date?
            $course['id'] = $currentcourse->id;

            $saveflag = false;

            foreach($course as $key => $value) {
                if ($currentcourse->$key != $value) {
                    $saveflag = true;
                    $currentcourse->$key = $value;
                }
            }

            if ($saveflag) {
                $DB->update_record('mnetervice_enrol_courses', $currentcourse);
            }

            if (isset($currentcourse->enrolmentid) && is_numeric($currentcourse->enrolmentid)) {
                $userisregd = true;
            }
        } else {
            unset ($courses[$ix]);
            continue;
        }

        // By this point, we should always have a $dataObj->id
        $local_courseid_array[] = $course['id'];

        // Do we have a record for this assignment?
        if ($userisregd) {
            // Yes - we know about this one already
            // We don't want to do updates because the new data is probably
            // 'less complete' than the data we have.
        } else {
            // No - create a record
            $assignObj = new stdClass();
            $assignObj->userid    = $userid;
            $assignObj->hostid    = (int)$remoteclient->id;
            $assignObj->remotecourseid = $course['remoteid'];
            $assignObj->rolename  = $course['defaultrolename'];
            $assignObj->id = $DB->insert_record('mnetservice_enrol_enrolments', $assignObj);
        }
    }

    // Clean up courses that the user is no longer enrolled in.
    if (!empty($local_courseid_array)) {
        $local_courseid_string = implode(', ', $local_courseid_array);
        $whereclause = " userid = ? AND hostid = ? AND remotecourseid NOT IN ($local_courseid_string)";
        $DB->delete_records_select('mnetservice_enrol_enrolments', $whereclause, array($userid, $remoteclient->id));
    }
}

/**
* pull all user custom info and send it back to caller.
* @TODO : possibly not usefull at all. We keep it in case of...
*/
function multimnet_pull_user_info($username){

    if ($localuser = $DB->get_record('user', array('username' => $username))){

        $sql = "
            SELECT
                uf.shortname,
                ud.data
            FROM
                [user_info_field} uf,
                [user_info_data} ud
            WHERE
                ud.userid = ? AND
                ud.fieldid = uf.id
        ";

        if($userdata = $DB->get_records_sql_menu($sql, array($localuser->id))){
            return $userdata;
        }    
    }
    return false;
}

/**
 * Receives an array of usernames from a remote machine and prods their
 * sessions to keep them alive
 *
 * @param   array   $array      An array of usernames
 * @return  string              "All ok" or an error message
 */
function multimnet_keepalive_server($array) {
    global $CFG, $DB;

    $remoteclient = get_mnet_remote_client();

    // We don't want to output anything to the client machine
    $start = ob_start();

    // We'll get session records in batches of 30
    $superArray = array_chunk($array, 30);

    $returnString = '';

    foreach($superArray as $subArray) {
        $subArray = array_values($subArray);
        $instring = "('".implode("', '",$subArray)."')";
        $query = "select id, session_id, username from {mnet_session} where username in $instring";
        $results = $DB->get_records_sql($query);

        if ($results == false) {
            // We seem to have a username that breaks our query:
            // TODO: Handle this error appropriately
            $returnString .= "We failed to refresh the session for the following usernames: \n".implode("\n", $subArray)."\n\n";
        } else {
            foreach($results as $emigrant) {
                session_touch($emigrant->session_id);
            }
        }
    }

    $end = ob_end_clean();

    if (empty($returnString)) return array('code' => 0, 'message' => 'All ok', 'last log id' => $remoteclient->last_log_id);
    return array('code' => 1, 'message' => $returnString, 'last log id' => $remoteclient->last_log_id);
}

/**
 * Poll the IdP server to let it know that a user it has authenticated is still
 * online
 *
 * @return  void
 */
function multimnet_keepalive_client() {
    global $CFG, $DB;
    $cutoff = time() - 300; // TODO - find out what the remote server's session
                            // cutoff is, and preempt that

    $sql = "
        select
            id,
            username,
            mnethostid
        from
            {user}
        where
            lastaccess > ? AND
            mnethostid != ?
        order by
            mnethostid";

    $immigrants = $DB->get_records_sql($sql, array($cutoff, $CFG->mnet_localhost_id));

    if ($immigrants == false) {
        return true;
    }

    $usersArray = array();
    foreach($immigrants as $immigrant) {
        $usersArray[$immigrant->mnethostid][] = $immigrant->username;
    }

    require_once $CFG->dirroot . '/mnet/xmlrpc/client.php';
    foreach($usersArray as $mnethostid => $users) {
        $mnet_peer = new mnet_peer();
        $mnet_peer->set_id($mnethostid);

        $mnet_request = new mnet_xmlrpc_client();
        $mnet_request->set_method('auth/multimnet/auth.php/keepalive_server');

        // set $token and $useragent parameters
        $mnet_request->add_param($users);

        if ($mnet_request->send($mnet_peer) === true) {
            if (!isset($mnet_request->response['code'])) {
                debugging("Server side error has occured on host $mnethostid");
                continue;
            } elseif ($mnet_request->response['code'] > 0) {
                debugging($mnet_request->response['message']);
            }

            if (!isset($mnet_request->response['last log id'])) {
                debugging("Server side error has occured on host $mnethostid\nNo log ID was received.");
                continue;
            }
        } else {
            debugging("Server side error has occured on host $mnethostid: " .
                      join("\n", $mnet_request->error));
            break;
        }
        $mnethostlogssql = "
        SELECT
            mhostlogs.remoteid, mhostlogs.time, mhostlogs.userid, mhostlogs.ip,
            mhostlogs.course, mhostlogs.module, mhostlogs.cmid, mhostlogs.action,
            mhostlogs.url, mhostlogs.info, mhostlogs.username, c.fullname as coursename,
            c.modinfo
        FROM
            (
                SELECT
                    l.id as remoteid, l.time, l.userid, l.ip, l.course, l.module, l.cmid,
                    l.action, l.url, l.info, u.username
                FROM
                    {user} u
                    INNER JOIN {log} l on l.userid = u.id
                WHERE
                    u.mnethostid = ?
                    AND l.id > ?
                ORDER BY remoteid ASC
                LIMIT 500
            ) mhostlogs
            INNER JOIN {course} c on c.id = mhostlogs.course
        ORDER by mhostlogs.remoteid ASC";

        $mnethostlogs = $DB->get_records_sql($mnethostlogssql, array($mnethostid, $mnet_request->response['last log id']));

        if ($mnethostlogs == false) {
            continue;
        }

        $processedlogs = array();

        foreach($mnethostlogs as $hostlog) {
            // Extract the name of the relevant module instance from the
            // course modinfo if possible.
            if (!empty($hostlog->modinfo) && !empty($hostlog->cmid)) {
                $modinfo = unserialize($hostlog->modinfo);
                unset($hostlog->modinfo);
                $modulearray = array();
                foreach($modinfo as $module) {
                    $modulearray[$module->cm] = $module->name;
                }
                $hostlog->resource_name = $modulearray[$hostlog->cmid];
            } else {
                $hostlog->resource_name = '';
            }

            $processedlogs[] = array (
                                'remoteid'      => $hostlog->remoteid,
                                'time'          => $hostlog->time,
                                'userid'        => $hostlog->userid,
                                'ip'            => $hostlog->ip,
                                'course'        => $hostlog->course,
                                'coursename'    => $hostlog->coursename,
                                'module'        => $hostlog->module,
                                'cmid'          => $hostlog->cmid,
                                'action'        => $hostlog->action,
                                'url'           => $hostlog->url,
                                'info'          => $hostlog->info,
                                'resource_name' => $hostlog->resource_name,
                                'username'      => $hostlog->username
                             );
        }

        unset($hostlog);

        $mnet_request = new mnet_xmlrpc_client();
        $mnet_request->set_method('auth/multimnet/auth.php/multimnet_refresh_log');

        // set $token and $useragent parameters
        $mnet_request->add_param($processedlogs);

        if ($mnet_request->send($mnet_peer) === true) {
            if ($mnet_request->response['code'] > 0) {
                debugging($mnet_request->response['message']);
            }
        } else {
            debugging("Server side error has occured on host $mnet_peer->ip: " .join("\n", $mnet_request->error));
        }
    }
}

/**
 * Receives an array of log entries from an SP and adds them to the mnet_log
 * table
 *
 * @param   array   $array      An array of usernames
 * @return  string              "All ok" or an error message
 */
function multimnet_refresh_log($array) {
    global $CFG, $DB;

    $remoteclient = get_mnet_remote_client();

    // We don't want to output anything to the client machine
    $start = ob_start();

    $returnString = '';
    $transaction = $DB->start_delegated_transaction();
    $useridarray = array();

    foreach($array as $logEntry) {
        $logEntryObj = (object)$logEntry;
        $logEntryObj->hostid = $remoteclient->id;

        if (isset($useridarray[$logEntryObj->username])) {
            $logEntryObj->userid = $useridarray[$logEntryObj->username];
        } else {
            $logEntryObj->userid = $DB->get_field('user', 'id', array('username'=>$logEntryObj->username, 'mnethostid'=>(int)$logEntryObj->hostid));
            if ($logEntryObj->userid == false) {
                $logEntryObj->userid = 0;
            }
            $useridarray[$logEntryObj->username] = $logEntryObj->userid;
        }

        unset($logEntryObj->username);

        $logEntryObj = $this->trim_logline($logEntryObj);
        $insertok = $DB->insert_record('mnet_log', $logEntryObj, false);

        if ($insertok) {
            $remoteclient->last_log_id = $logEntryObj->remoteid;
        } else {
            $returnString .= 'Record with id '.$logEntryObj->remoteid." failed to insert.\n";
        }
    }
    $remoteclient->commit();
    $transaction->allow_commit();

    $end = ob_end_clean();

    if (empty($returnString)) return array('code' => 0, 'message' => 'All ok');
    return array('code' => 1, 'message' => $returnString);
}

