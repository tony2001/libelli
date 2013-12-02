<?php

$txt = file_get_contents($_SERVER['argv'][1]); 
preg_match_all('/priv:(.*)pub:(.*)ASN1/ms', $txt, $match);

$delete = array(":", "\n", " ");

for ($i = 1; $i < 3; $i++) {
	$match[$i][0] = trim($match[$i][0]);
	$match[$i][0] = str_replace($delete, "", $match[$i][0]);
}

$private = $match[1][0];
$public = $match[2][0];
$name = basename($_SERVER['argv'][1], ".txt");

echo '{"', $name , '", "', $private, '", "',  $public, '"},', "\n";

?>
