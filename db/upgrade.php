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

function xmldb_auth_multimnet_upgrade($oldversion = 0) {
/// This function does anything necessary to upgrade 
/// older versions to match current functionality 

    global $CFG, $DB;

    $dbman = $DB->get_manager();

    $result = true;

    if ($oldversion < 2013102203) {
        $table = new xmldb_table('auth_multimnet_user');
        if (!$dbman->table_exists($table)){
            $table->add_field('id', XMLDB_TYPE_INTEGER, 11, XMLDB_UNSIGNED, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
            $table->add_field('mnethostid', XMLDB_TYPE_INTEGER, 9, XMLDB_UNSIGNED, XMLDB_NOTNULL, null, 0);
            $table->add_field('remoteuserid', XMLDB_TYPE_INTEGER, 11, XMLDB_UNSIGNED, XMLDB_NOTNULL, null, 0);
            $table->add_field('idnumber', XMLDB_TYPE_CHAR, 64, null, null, null, null);
            $table->add_field('username', XMLDB_TYPE_CHAR, 64, null, null, null, null);
            $table->add_field('firstname', XMLDB_TYPE_CHAR, 64, null, null, null, null);
            $table->add_field('lastname', XMLDB_TYPE_CHAR, 64, null, null, null, null);
            $table->add_field('lastseenmnethost', XMLDB_TYPE_INTEGER, 11, XMLDB_UNSIGNED, XMLDB_NOTNULL, null, 0);
            $table->add_field('lastsessionstart', XMLDB_TYPE_INTEGER, 11, XMLDB_UNSIGNED, XMLDB_NOTNULL, null, 0);
            $table->add_field('lastmovetime', XMLDB_TYPE_INTEGER, 11, XMLDB_UNSIGNED, XMLDB_NOTNULL, null, 0);
            $table->add_field('deleted', XMLDB_TYPE_INTEGER, 1, XMLDB_UNSIGNED, XMLDB_NOTNULL, null, 0);

            $table->add_key('primary', XMLDB_KEY_PRIMARY, array('id'));

            $dbman->create_table($table);

            // savepoint reached
            upgrade_plugin_savepoint(true, 2013102203, 'auth', 'multimnet');
        }
    }
    
    return $result;
}