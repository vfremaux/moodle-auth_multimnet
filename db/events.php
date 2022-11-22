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
 * @package auth_multimnet
 * @category event
 * @author Valery Fremaux (valery.fremaux@gmail.com)
 * @copyright 2011 onwards Valery Fremaux
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/* List of handlers */
$observers = array (
    array(
        'eventname'   => '\core\event\user_created',
        'callback'    => 'auth_multimnet_event_observer::on_user_created',
        'includefile' => '/auth/multimnet/observers.php',
        'internal'    => true,
        'priority'    => 9999,
    ),
    array(
        'eventname'   => '\core\event\user_updated',
        'callback'    => 'auth_multimnet_event_observer::on_user_updated',
        'includefile' => '/auth/multimnet/observers.php',
        'internal'    => true,
        'priority'    => 9999,
    ),
    array(
        'eventname'   => '\core\event\user_deleted',
        'callback'    => 'auth_multimnet_event_observer::on_user_deleted',
        'includefile' => '/auth/multimnet/observers.php',
        'internal'    => true,
        'priority'    => 9999,
    ),
);