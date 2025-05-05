Auth multimnet enhances mnet behaviour for big Moodle arrays intensively using
mnet.

##### Goodies :

Patch for allowing mnet users to be site admins : 

In admin/roles/lib.php

class admins_potential_selector extends user_selector_base {
    /**
     * @param string $name control name
     * @param array $options should have two elements with keys groupid and courseid.
     */
    public function __construct($name = null, $options = array()) {
        global $CFG;
        if (is_null($name)) {
            $name = 'addselect';
        }
        $options['multiselect'] = false;
        $options['exclude'] = explode(',', $CFG->siteadmins);
        parent::__construct($name, $options);
    }

    public function find_users($search) {
        global $CFG, $DB;
        list($wherecondition, $params) = $this->search_sql($search, '');

        $fields      = 'SELECT ' . $this->required_fields_sql('');
        $countfields = 'SELECT COUNT(1)';

		// PATCH : Keep more liberal mnet siteadmins 
        $sql = " FROM {user}
                WHERE $wherecondition ";
                
        $strictmnet = " AND mnethostid = :localmnet ";
        if (empty($CFG->mnetsiteadmins)) $sql .= $strictmnet;
		// /PATCH

##### Goodies : 

Better reaction of the logout : in standard code, auth stack is played the same order at login and logout.
This leads to some inconsistant behaviours regarding logout priorities and redirect choices.

f.e : If the stack requires (Manual auth over) Multimnet => Mnet => CAS, the most logical
should be logouting as CAS => Mnet => Multimnet

In login/logout.php §56

// PATCH : Stack should be played reverse from login 
$authsequence = array_reverse($authsequence);
// /PATCH
foreach($authsequence as $authname) {
    $authplugin = get_auth_plugin($authname);
    $authplugin->logoutpage_hook();
}

##### Testgrid

Simple login :

Admin login on register site : PASSED
Admin login on non register site (local) : PASSED
User unregistered register site : Try login non register site : PASSED 
User unregistered non register site : Try login non primary non register site : PASSED 
User unregistered non register site : Try login register site : PASSED
User unregistered register site : Login and register : PASSED
User enregistered non register site : Login and register : PASSED

Simple Logout : logout from same site after successfull login

All connectable users : Logout and stay on same site : PASSED

Roaming path :

Regiter site Admin roaming (unconstrainted)
 