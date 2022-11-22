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
 */

require('../../config.php');

$context = context_system::instance();

$primaryhost = required_param('primary', PARAM_URL);

$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/auth/multimnet/host_authorization.php', array('primary' => $primaryhost)));
$PAGE->set_heading(get_string('hostaccesscontrol', 'auth_multimnet'));
$PAGE->set_title(get_string('hostaccesscontrol', 'auth_multimnet'));

echo $OUTPUT->header();

echo $OUTPUT->box(get_string('errorhostaccess', 'auth_multimnet', $primaryhost.'/login/index.php'));

echo $OUTPUT->footer();