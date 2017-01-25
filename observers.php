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

defined('MOODLE_INTERNAL') || die();

/**
 * @package auth_multimnet
 * @category auth
 * @author Valery Fremaux (valery.fremaux@gmail.com)
 * @copyright 2011 onwards Valery Fremaux
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
require_once ($CFG->dirroot.'/auth/multimnet/auth.php');

class auth_multimnet_event_observer {

    /**
     * Record primary location of the user in central register. 
     * this needs the central register features being enabled in the
     * local node.
     */
    public static function on_user_created($e) {
        global $DB;

        if (!$auth = multimnet_get_enabled()) {
            return;
        }

        $user = $DB->get_record($e->objecttable, array('id' => $e->objectid));

        if (!empty($auth->config->enable_central_register)) {
            if ($user->auth != 'multimnet' && $user->auth != 'mnet') {
                $auth->set_primary_location($user);
            }
        }
    }

    /**
     * Update some interesting data in the central register
     */
    public static function on_user_updated($e) {
        global $DB;

        $user = $DB->get_record($e->objecttable, array('id' => $e->objectid));

        if (!$auth = multimnet_get_enabled()) {
            return;
        }

        // All participants to a multimnet centrally registered network should enable register.
        if (!empty($auth->config->enable_central_register)) {
            // Only local accounts should care about there register registration.
            if ($user->auth != 'multimnet' && $user->auth != 'mnet') {
                if (!$auth->is_remotely_registered($user->id)) {
                    $auth->set_primary_location($user);
                } else {
                    $auth->update_primary_location($user->username, 'idnumber', $user->idnumber);
                    $auth->update_primary_location($user->username, 'firstname', $user->firstname);
                    $auth->update_primary_location($user->username, 'lastname', $user->lastname);
                }
            }
        }
    }

    /**
     * We will not completely delete a user from register, but just mark it as deleted
     * the same way could a user be marked revived by simply disable the deleted flag
     */
    public static function on_user_deleted($e) {

        $olduser = $e->get_record_snapshot($e->objecttable, $e->objectid);

        if (!$auth = multimnet_get_enabled()) {
            return;
        }

        if (!empty($auth->config->enable_central_register)) {
            // user never should be mnet if deleted as GUI forbids this
            if ($olduser->auth != 'multimnet' && $olduser->auth != 'mnet') {
               $auth->update_primary_location($olduser->username, 'deleted', 1);
            }
        }
    }
}
