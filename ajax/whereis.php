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

require('../../../config.php');
require_once($CFG->dirroot.'/auth/multimnet/lib.php');

// Security.
require_login();

/**
* This wrapper searches in central register last recent location of a user.
*
*/

$query = required_param('query', PARAM_TEXT);

if (!$auth = multimnet_get_enabled()) {
    echo get_string('notenabled', 'auth_multimnet');
}

if ($results = (array)$auth->search_location($query)) {
    // echo "Searching for $query ";
    // print_object($results);
    if (count($results) > 1) {
        echo get_string('toomanyresults', 'auth_multimnet');
    } else {
        $location = array_pop($results);
        if ($location->lastmovetime > time() - MINSECS * 10) {
            $locallocation = $DB->get_record('mnet_host', array('wwwroot' => $location->wwwroot));
            if ($locallocation) {
                $a->fullname = fullname($location);
                $a->jumplink = "<a href=\"javascript:jump('{$CFG->wwwroot}','{$locallocation->id}')\">{$locallocation->name}</a>";
                echo get_string('johnishere', 'auth_multimnet', $a);
            } else {
                echo get_string('johnisherenoreach', 'auth_multimnet', $location->wwwroot);
            }
        } else {
            echo get_string('nothingfound', 'auth_multimnet', $query);
        }
    }
} else {
    echo get_string('nothingfound', 'auth_multimnet', $query);
}
