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
 * Authentication Plugin: Moodle MultiNetwork Authentication
 *
 * Multiple host authentication support for Moodle Network.
 */

require_once('../../config.php');

// grab the GET params - wantsurl could be anything - take it
// with PARAM_RAW
$hostid = optional_param('hostid', '0', PARAM_INT);

// CHANGE FROM MNET : Multijump rerouting
$wwwroot = optional_param('wwwroot', '', PARAM_RAW);
$wwwroot = optional_param('hostwwwroot', $wwwroot, PARAM_RAW); // ensures compatibility with standard versions
$wantsurl = optional_param('wantsurl', '', PARAM_RAW);

// check a bouncing user so we must route its jump through its origin server
// Fix : Only when multimnet is on, otherwise jump normally from where you are
if (preg_match('/\bmultimnet\b/', $CFG->auth) && ($USER->mnethostid != $CFG->mnet_localhost_id)) {
    $originhost = $DB->get_record('mnet_host', array('id' => $USER->mnethostid));
    if (!empty($hostid)){
        $destinationhost = $DB->get_record('mnet_host', array('id' => $hostid));
    } else {
        $destinationhost->wwwroot = $wwwroot;
    }
    $bounceurl = $originhost->wwwroot.'/auth/multimnet/jump.php?wwwroot='.$destinationhost->wwwroot.'&amp;wantsurl='.urlencode($wantsurl);
    redirect($bounceurl);
}

if (empty($hostid) && empty($wwwroot)) {
    print_error('errornohosttobounceby', 'auth_multimnet');
}
if (empty($hostid)) {
    $host = $DB->get_record('mnet_host', array('wwwroot' => $wwwroot));
    if (empty($host)) {
        print_error('erroremptyhostid', 'auth_multimnet');
    }
    $hostid = $host->id;
}
// /CHANGE


// start the mnet session and redirect browser to remote URL
$mnetauth = get_auth_plugin('multimnet');
$url = $mnetauth->start_jump_session($hostid, $wantsurl);

if (empty($url)) {
    print_error('DEBUG: Jump session was not started correctly or blank URL returned.'); // TODO: errors
}
redirect($url);


