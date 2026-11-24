<?php
require __DIR__ . '/session_helper.php';
startSecureSession();
session_unset();
session_destroy();
header("Location: index.php");
exit;
