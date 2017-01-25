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

/**
 * Authentication Plugin: Moodle Network Authentication Modified for multi mnet
 *
 * Multiple host authentication support for Moodle Network.
 *
 * This library will provide with internal function wrapper to high level multimnet primitives
 * such as invoking remote multimnet Mnet services, or event wrappers.
 *
 */

/**
 * checks if the multimnet plugin is part of enabled plugins
 * and returns an instance
 */
function multimnet_get_enabled(){
    $authsequence = get_enabled_auth_plugins(true); // auths, in sequence
    if (in_array('multimnet', $authsequence)) {
        return get_auth_plugin('multimnet');
    }
    return false;
}