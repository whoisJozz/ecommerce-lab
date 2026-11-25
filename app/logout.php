<?php
require_once __DIR__ . '/session_helper.php';
startSecureSession();
session_unset();
session_destroy();
jwt_clear_cookie();
header("Location: index.php");
exit;
