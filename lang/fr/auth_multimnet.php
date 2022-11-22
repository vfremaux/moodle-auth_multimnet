<?php

$string['pluginname'] = 'Authentification en réseau MNET total';
$string['auth_multimnettitle'] = 'Réseau Moodle "total"';
$string['auth_multimnetdescription'] = 'Cette authentification permet de router automatiquement des utilisateurs vers leur porte d\'entrée d\'origine dans un réseau MNET fonctionnant en mode multinoeuds. Le site d\'origine est détecté à partir des données d\'identification de compte, et le noeud d\'origine de l\'utilisateur est déterminé. Le plugin délègue la création de la session active au portail d\'origine de l\'utlisateur (si autorisé) et ramène l\'utilisateur sur la page d\'accueil du noeud courant.';
$string['loginpattern'] = 'Motif pour déterminer l\'heuristique d\'identification d\'origine';
$string['looseaccess'] = 'Prise en compte des hôtes non visibles';
$string['configloginpattern'] = 'Ce motif est appliqué sur l\'identifiant pour extraire une portion \"interessante\" qui permette de reconstituer le nom d\'hôte d\'origine de l\'utilisateur. Il s\'agit d\'un motif REGEXP qui doit comporter un et un seul motif de sous-capture parenthésé. Ex : .*@(.*) capture le nom d\'hôte d\'une adresse mél.';
$string['hostguesspattern'] = 'Motif pour déterminer le noeud MNET d\'origine';
$string['confighostguesspattern'] = 'Cette expression permet, par remplacement, de trouver un nom d\'hôte MNET reconnaissable à partir de l\'heuristique appliquée au login donné par l\'utilisateur';
$string['configlooseaccess'] = 'Si la prise en compte des hôtes non visibles est activée, les utilisateurs peuvent se connecter à partir de noeuds origines cachés du réseau. Si elle est inactive, les hôtes non visibles sont exclus du réseau.';
$string['fallbackdomain'] = 'Domaine origine par défaut';
$string['configfallbackdomain'] = 'Si on ne peut deviner par l\'heuristique l\'hôte d\'origine dans le Réseau Moodle, une dernière chance est de tenter une authentification locale sur le domaine par défaut. Ce domaine est celui où le registre central est activé.';
$string['errornohosttobounceby'] = 'Définition de l\'hôte de destination manquante';
$string['erroremptyhostid'] = 'Vous ne pouvez rejoindre la destination désirée à partir de ce site';
$string['multimnet_service_name'] = 'Réseau Multimnet';
$string['multimnet_service_description'] = 'Augmente les services mnet pour des constellations de Moodle';
$string['multimnet_name'] = 'Réseau Multimnet';
$string['multimnet_description'] = 'Augmente les services mnet pour des constellations de Moodle';
$string['mnetsiteadmins'] = 'Utilisateurs mnet administrateurs de site';
$string['configmnetsiteadmins'] = 'Si activé, les utilisateurs distants mnet peuvent être administrateur de site. Un patch est requis pour cette fonctionnalité. Lire le fichier Readme.';
$string['errornotregistered'] = 'Utilisateur inconnu dans le registre central';
$string['enablecentralregister'] = 'Activer le registre central';
$string['configenablecentralregister'] = 'Si actif, un registre central est activé mémorisant l\'hôte primaire d\'origine de l\'utilisateur. Si multimnet est actif sur tous les hôtes, les informations de session des utilisateurs seront tracées dans le registre central qui peuvent être requêtées , et 
la couche multimnet utilisera ce registre pour déterminer le site d\'origine de l\'utilisateur se présentant à l\'entrée même si aucune référence de cet utilisateur n\'existe dans la plate-forme courante. Une seule des plates-formes du réseau doit avoir ce registre activé.';
$string['hostaccesscontrol'] = 'Contrôle des autorisations';
$string['errorhostaccess'] = 'Vous n\'êtes pas autorisé à utiliser ce point d\'entrée. Veuillez vous connecter sur votre <a href="{$a}">porte d\'accès primaire</a> et naviguer vers la plate-forme que vous souhaitez atteindre.';
$string['rpc_negotiation_timeout'] = 'Délai de négociation RPC';
$string['auth_multimnet_rpc_negotiation_timeout'] = 'Le délai de négociation dans la couche transport XMLRPC.';
$string['johnishere'] = '{$a->fullname} était sur {$a->jumplink} au moins il y a 10 minutes';
$string['johnisherenoreach'] = '{$a->fullname} est sur {$a->jumplink} (vous ne pouvez pas y aller)';
$string['nothingfound'] = 'Aucun résultat trouvé pour "{$a}"';
$string['toomanyresults'] = 'Votre recherche a trop de résultats. Vous devriez être plus précis. Vous pouvez utiliser le motif motifnom:motifprenom pour mieux discriminer.';
$string['errornotenabled'] = 'L\'authentification Multimnet n\'est pas active';
$string['localcollision'] = 'Il semble que plusieurs comptes locaux correspondent à votre profil. Ceci est une situation probablement anormale et doit être rapportée à un administrateur pour examen.';
