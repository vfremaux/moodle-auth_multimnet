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

/**
 * This file contains the mnet services for the user_mnet_host plugin
 *
 * @since 2.0
 * @package auth_multimnet
 * @category auth
 * @copyright 2012 Valery Fremaux
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$publishes = array(
    'multimnet' => array(
        'servicename' => 'multimnet',
        'description' => get_string('multimnet_service_name', 'auth_multimnet'),
        'apiversion' => 1,
        'classname'  => '',
        'filename'   => 'rpclib.php',
        'methods'    => array(
            'multimnet_get_primary_location',
            'multimnet_search_location',
            'multimnet_update_primary_location',
            'multimnet_register_primary_location',
            'multimnet_user_authorise',
            'multimnet_kill_child',
            'multimnet_kill_children',
            'multimnet_fetch_user_image',
            'multimnet_fetch_theme_info',
            'multimnet_update_enrolments',
            'multimnet_pull_user_info',
            'multimnet_keepalive_client',
            'multimnet_keepalive_server',
            'multimnet_refresh_log',
        ),
    ),
);

$subscribes = array(
    'multimnet' => array(
        'multimnet_get_primary_location' => 'auth/multimnet/rpclib.php/multimnet_get_primary_location',
        'multimnet_search_location' => 'auth/multimnet/rpclib.php/multimnet_search_location',
        'multimnet_update_primary_location' => 'auth/multimnet/rpclib.php/multimnet_update_primary_location',
        'multimnet_register_primary_location' => 'auth/multimnet/rpclib.php/multimnet_register_primary_location',
        'multimnet_user_authorise' => 'auth/multimnet/rpclib.php/multimnet_user_authorise',
        'multimnet_kill_child' => 'auth/multimnet/rpclib.php/multimnet_kill_child',
        'multimnet_kill_children' => 'auth/multimnet/rpclib.php/multimnet_kill_children',
        'multimnet_fetch_user_image' => 'auth/multimnet/rpclib.php/multimnet_fetch_user_image',
        'multimnet_fetch_theme_info' => 'auth/multimnet/rpclib.php/multimnet_fetch_theme_info',
        'multimnet_update_enrolments' => 'auth/multimnet/rpclib.php/multimnet_update_enrolments',
        'multimnet_pull_user_info' => 'auth/multimnet/rpclib.php/multimnet_pull_user_info',
        'multimnet_keepalive_client' => 'auth/multimnet/rpclib.php/multimnet_keepalive_client',
        'multimnet_keepalive_server' => 'auth/multimnet/rpclib.php/multimnet_keepalive_server',
        'multimnet_refresh_log' => 'auth/multimnet/rpclib.php/multimnet_refresh_log'
    ),
);
