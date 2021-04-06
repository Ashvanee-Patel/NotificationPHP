<?php
	include "config.php";
	//an array to display response
	$response = array();
	if(isset($_POST['email']) && isset($_POST['password']) && isset($_POST['token'])){
		$email = $_POST['email'];
		$password = $_POST['password'];
		$token = $_POST['token'];
		$fetchuser = $conn->prepare("SELECT password FROM fcm WHERE email=?");
		$fetchuser->bind_param("s",$email);
		$fetchuser->execute();
		$fetchuser->store_result();
		$fetchuser->bind_result($db_password);
		$fetchuser->close();
		if ($db_password != null){
			if(password_verify($password, $db_password)){
				$updtuser = $conn->prepare("UPDATE fcm SET token=? WHERE email=?");
				$updtuser->bind_param("ss",$token, $email);
				if($updtuser->execute()){
					$response['error'] = false;
					$response['message'] = "Login Successful";
				} else {
					$response['error'] = true;
					$response['message'] = "Login Failed";
				}
			} else {
				$response['error'] = true;
				$response['message'] = "Invalid password";
			}
		} else {
			$password_encrypted = password_hash($password, PASSWORD_DEFAULT);
			$saveuser = $conn->prepare("INSERT INTO fcm(email, password, token) VALUES (?,?,?)");
			$saveuser->bind_param("sss",$email, $password_encrypted, $token);
			if($saveuser->execute()){
				$response['error'] = false;
				$response['message'] = "Registered Successfully";
			} else {
				$response['error'] = true;
				$response['message'] = "Registration failed";
			}
		}
	} else {
		$response['error'] = true;
		$response['message'] = "Insufficient parameters";
	}
	echo json_encode($response);
?>