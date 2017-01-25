<?php

$string['pluginname'] = '"Multinode" Moodle Network extension';
$string['auth_multimnettitle'] = '"Multinode" Moodle Network extension';
$string['auth_multimnetdescription'] = 'This authentication uses Mnet and Mnet auth to route users to their adeqsuate entry point when they need open a session in a multinode Moodle. The auth can guess about the user\'s legacy origin and ask the origin door to authenticate before browsing back to the current node.';
$string['loginpattern'] = 'Login applicable pattern for extracting origin detection heuristic.';
$string['looseaccess'] = 'Loose access policy';
$string['configlooseaccess'] = 'If not loose access, mnet_hosts need to be enabled as VMoodle known hosts in the same MNET subnetwork for authenticaztion to be evaluated';
$string['configloginpattern'] = 'This pattern is a REGEX pattern applied to the login given by the user, in order to extract mnethost origin identity of the user. e.g. : .*@(.*) captures a host part of a mail address.';
$string['hostguesspattern'] = 'MNET Origin Host Pattern';
$string['confighostguesspattern'] = 'This template expression allows to recontruct the origin full MNET host name as origin node of the user';
$string['fallbackdomain'] = 'Default origin server';
$string['configfallbackdomain'] = 'If any of the heuristics fails, we can try to route the login to a default node. In case central register is enabled, this setting designates the central register location. Central register host must leave this setting undefined.';
$string['errornohosttobounceby'] = 'No host id definition to jump to';
$string['erroremptyhostid'] = 'You cannot reach this host from this jump base';
$string['enablecentralregister'] = 'Enable central register';
$string['configenablecentralregister'] = 'If enabled, a central register is held with all user origin references. If multimnet is enabled on all hosts, user login will track information in the central register for sessions, that can be queried by other nodes, and 
multimnet host will guess origin of incoming user from this register, even if no reference of the user is known in the current node';
$string['multimnet_service_name'] = 'Multimnet services';
$string['multimnet_service_description'] = 'Enhance mnet for global mnet assemblies';
$string['multimnet_name'] = 'Multimnet services';
$string['multimnet_description'] = 'Enhance mnet for global mnet assemblies';
$string['mnetsiteadmins'] = 'Allow mnet users to be site admins';
$string['configmnetsiteadmins'] = 'If enabled remote MNET users can be choosen as site administrators. A patch is required for this feature to be effective. Read Readme file for more information.';
$string['errornotregistered'] = 'User is not yet known in central register';
$string['hostaccesscontrol'] = 'Host access control';
$string['errorhostaccess'] = 'You are not allowed to enter this instance. You should use your <a href="{$a}">primary front door</a> to enter, then browse to the instance you want to use.';
$string['rpc_negotiation_timeout'] = 'RPC negotiation timeout';
$string['auth_multimnet_rpc_negotiation_timeout'] = 'The timeout in seconds for authentication over the XMLRPC transport.';
$string['johnishere'] = '{$a->fullname} was at {$a->jumplink} 10 minutes ago so far';
$string['johnisherenoreach'] = '{$a->fullname} is at {$a->jumplink} (you cannot roam there)';
$string['nothingfound'] = 'No results for "{$a}"';
$string['toomanyresults'] = 'Your search finds too many entries. You should be more precise. You can use lastnamepattern:firstnamepattern to discriminate more accurately.';
$string['errornotenabled'] = 'Auth multimnet is not enabled';
$string['localcollision'] = 'There are more than one local account that seems matching your identity in the landing Moodle. This may denote an issue with your acocunt registrations and should be reported to administrators for investigation.';



