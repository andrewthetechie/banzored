<?PHP
	$dbhost="localhost";
	$dbname="banzored";
	$dbuser="banzored";
	$dbpass="password";

	$safe_ips=['173.174.158.6'];

$user_ip = getUserIP();

echo $user_ip; // Output IP address [Ex: 177.87.193.134]
try {
    $conn = new PDO("mysql:host=$dbhost;dbname=$dbname", $dbuser, $dbpass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	$stmt = $conn->prepare('SELECT INET_NTOA(ip),count FROM trapped WHERE ip = INET_ATON(:ip)');
	$stmt->execute(array('ip' => $user_ip));

	$result = $stmt->fetchAll();

	if(count($result))
	{
		$result = $result[0];
		if($result['count'] > 3)
		{
			//ban them

			if(!in_array($user_ip,$safe_ips))
			{
				//ban then

				$banArray = array(':ip' => $user_ip,':count'=> (int)$result['count']+1);
				$ban = $conn->prepare('update trapped set count=:count, last_hit_date=NOW(),ban_date=NOW() where ip=INET_ATON(:ip)');
				$ban->execute($banArray);
				$ufwCommand = "sudo /usr/sbin/ufw insert 1 deny from $user_ip";

				exec($ufwCommand);	
				
			}
		}
		else
		{
			$updateArray = array(':ip' => $user_ip,':count'=> (int)$result['count']+1);
			$update = $conn->prepare('update trapped set count=:count, last_hit_date=NOW() where ip=INET_ATON(:ip)');
			$update->execute($updateArray);	
		}
	} 
	else
	{
		$insert = $conn->prepare('INSERT INTO trapped VALUES(NULL,INET_ATON(:ip),:count,NOW(),NULL)');
  		$insert->execute(array(
   			 ':ip' => $user_ip,
			':count' => 1
  		));

	}

} catch(PDOException $e) {
    echo 'ERROR: ' . $e->getMessage();
}

$query = "select * from trapped where ip='$user_ip'";
$dbh = null;
function getUserIP()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];

    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    return $ip;
}




?>
