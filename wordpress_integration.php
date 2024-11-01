<?php
/*
Plugin Name: WWPass Authentication
Plugin URI: http://www.wwpass.com
Description: WWPass Two-factor Authentication plugin for WordPress
Author: WWPass Corporation
Version: 3.1.2
Author URI: http://www.wwpass.com
*/
/**
 * wordpress_integration.php
 *
 * WWPass Two-factor Authentication plugin for WordPress
 *
 * @copyright (c) WWPass Corporation, 2011-2019
 * @author Vladimir Korshunov <v.korshunov@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function wwpass_check() {
    # check curl in php
    if ( ! extension_loaded('curl')) {
        if ( ! function_exists('dl'))
            return false;
        
        $prefix = (PHP_SHLIB_SUFFIX === 'dll') ? 'php_' : '';
        try {
            return dl($prefix . 'curl.' . PHP_SHLIB_SUFFIX);
        } catch (Exception $e) {
            # dl
            return false;
        }
    } else
        return true;
}

function wwpass_install() {
    global $wpdb;
    $wpdb->show_errors();
    $wpdb->query('CREATE TABLE IF NOT EXISTS `' . $wpdb->prefix . 'wwpass` (
            `user_id` bigint(20) unsigned NOT NULL,
            `wwpass_puid` varchar(64) NOT NULL DEFAULT "",
            KEY `user_id` (`user_id`),
            KEY `wwpass_puid` (`wwpass_puid`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;');
    
    # if get_option not set, create
}

function wwpass_uninstall() {
    global $wpdb;
    $wpdb->show_errors();
    $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wwpass;');
}

function wwpass_update_check() {
    if (get_option('WWPASS_PASSKEY', false) === false &&
        get_option('WWPASS_QRCODE', false) === false ) {
        
        # update to version 3.0
        add_option('WWPASS_QRCODE', 'enabled', ' ', 'no');
        add_option('WWPASS_PASSKEY', '', ' ', 'no');
        add_option('WWPASS_VERSION', '3.1', ' ', 'no');
    }
}
add_action( 'plugins_loaded', 'wwpass_update_check' );


register_activation_hook(__FILE__ , 'wwpass_install');
register_uninstall_hook(__FILE__ , 'wwpass_uninstall');


/* fix for not defined magic constants */

try {
    include('include/wwpass.php');
} catch (Exception $e) {}

if ( ! class_exists('WWPASSConnection')) {
    try {
        include(plugin_dir_path(__FILE__) . 'include/wwpass.php');
    } catch (Exception $e) {}
}

define('WWPASS_PATH_CA', plugin_dir_path(__FILE__) . 'include/wwpass.ca');

/* end of fix */

function get_query_argument($name, $default = NULL, $query = NULL) {
    $query = $query ? $query : $_SERVER['QUERY_STRING'];
    foreach (explode('&', $query) as $param) {
        list($key, $value) = explode('=', $param);
        if ($key == $name)
            return $value;
    }
    
    return $default;
}

function get_arguments() {
    $code = get_query_argument('status');
    
    if ( ! $code )
        return NULL;
    
    $ticket = get_query_argument('ticket');
    $reason = get_query_argument('reason');
    $echo = get_query_argument('echo');
    
    return array($code, $reason, $ticket, $echo);
}


function wwpass_connection() {
    return new WWPASSConnection(
            get_option('WWPASS_PATH_KEY'),
            get_option('WWPASS_PATH_CRT'),
            WWPASS_PATH_CA
        );
}

function wwpass_cw_ticket() {
    return get_option('WWPASS_SPNAME') . (get_option('WWPASS_ASKPASS', false) ? ':p' : '');
}

function wwpass_ccw_ticket($conn = false, $ttl = 120) {
    if ( ! $conn)
        $conn = wwpass_connection();
    return $conn->getTicket($ttl, (get_option('WWPASS_ASKPASS', false) ? ':p' : ''));
}

function wwpass_qrcode_url() {
    return '//wauth.wwpass.com/assets/wwpass.qrcode.min.js';
}

function my_action_ajax_callback(){
    $ttl = 1200;
    $result = array('ticket' => wwpass_ccw_ticket(false, $ttl), 'ttl' => $ttl);
    header( "Content-Type: application/json" );
    echo json_encode($result);
    exit();
}

add_action( 'wp_ajax_nopriv_get-ticket', 'my_action_ajax_callback' );
add_action( 'wp_ajax_get-ticket', 'my_action_ajax_callback' );
add_action( 'login_init', 'wwpass_endpoint');

function wwpass_endpoint() {
    if (array_key_exists('status', $_GET) && $_GET['status']) {
        list($status, $reason, $ticket, $echo) = get_arguments();
        
        $type = substr(base64_decode($echo), 0, 1);
        $redirect_to = trim(substr(base64_decode($echo), 1));
        
        if ($type == '1') {
            $url = wp_login_url();
            if ( ! $redirect_to) {
                $redirect_to = admin_url();
            }
            
        } else {
            $url = $redirect_to;
        }

    ?><!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WWPass Endpoint</title>
    </head>
    <body>
        <p>Redirecting…</p>
        
        <form id="submitform" action="<?php echo $url; ?>" method="POST">
            <input type="hidden" name="wwpass_status" value="<?php echo $status; ?>">
            <input type="hidden" name="wwpass_response" value="<?php echo ($status === '200' ? $ticket : urldecode($reason)); ?>">
            <?php
                if ($type == '0') {
                    ?>
                        <input type="hidden" name="action" value="bind">
                    <?php
                } else {
                    ?>
                        <input type="hidden" name="redirect_to" value="<?php echo $redirect_to; ?>">
                    <?php
                }
            ?>
        </form>
        <script>
            document.addEventListener('DOMContentLoaded', function () {
                document.getElementById('submitform').submit();
            }, false);
        </script>
    </body>
    </html>

    <?php
    exit;
    }
}


add_action('login_head', 'wwpass_wp_login_head');
add_action('login_form', 'wwpass_wp_login_form');

add_action('authenticate', 'wwpass_wp_auth');

function wwpass_wp_login_head() {
    if (get_option('WWPASS_SPNAME', false)) {
        ?>
        <?php
        if (get_option('WWPASS_PASSKEY', false)) {
            ?><script type="text/javascript" src="//cdn.wwpass.com/packages/latest/wwpass.js"></script><?php
        }
        if (get_option('WWPASS_QRCODE', false)) {
            ?><script type="text/javascript" src="<?php echo wwpass_qrcode_url();?>"></script><?php
        }
        if (get_option('WWPASS_QRCODE', false) or get_option('WWPASS_PASSKEY', false)) {
            $echo = '1' . ( $_REQUEST['redirect_to'] ? $_REQUEST['redirect_to'] : admin_url() );
        ?>
        <script type="text/javascript" charset="utf-8">

        function wwpassCallback(status, response) {
            console.log(arguments);
            if (status != 603 && status != 601) {
                var form_status = document.createElement('input');
                form_status.type = 'hidden';
                form_status.name = 'wwpass_status';
                form_status.value = status;
                
                var form_response = document.createElement('input');
                form_response.type = 'hidden';
                form_response.name = 'wwpass_response';
                form_response.value = response;
                
                var f = document.getElementById('loginform');
                f.appendChild(form_status);
                f.appendChild(form_response);
                f.submit();
            }
        }
        
        function OnAuth() {
            wwpass_auth('<?php echo wwpass_cw_ticket();?>', wwpassCallback);
        }
        
        </script>
        
        <script>
            var ajax_object = {'ajaxurl': '<?php echo admin_url( 'admin-ajax.php' ) ;?>'};
            wwpassQRCodeAuth({
                'ticketURL': ajax_object.ajaxurl + '?action=get-ticket&rnd_wordpress=' + new Date().getTime(),
                'callback': wwpassCallback,
                'render': 'qrcode',
                'callbackURL': '<?php echo wp_login_url(); ?>',
                'echo': '<?php echo base64_encode($echo); ?>'
            });
        </script>
        
        <?php }
    } // if
}

function wwpass_wp_login_form()
{
    if (get_option('WWPASS_SPNAME', false) && wwpass_check()) {
        if (get_option('WWPASS_QRCODE', false)) {
        if (wp_is_mobile()) { ?>
        <p style="margin-bottom: 10px;text-align: center;">Tap the QR code below to log in with <strong>WWPass PassKey App</strong></p>
        <?php
        } else {
        ?>
        <p style="margin-bottom: 10px;text-align: center;">Scan the QR code below to log in with <strong>WWPass PassKey App</strong></p>
        <?php } ?>
        <div id="qrcode"></div>
        
        <style type="text/css">
            #qrcode {
                border: 1px solid black;
                border-radius: 2px;
                padding: 7px;
                margin-bottom: 10px;
                display: inline-block;
                background-color: white;
                width: 256px;
                height: 256px;
            }
        </style>
        <?php
        }
        
        if ( ! wp_is_mobile()) {
            if (get_option('WWPASS_PASSKEY', false)) {
                ?>
                    <p style="text-align: center; margin-bottom: 16px;">
                        <button type="button" class="button button-large" style="width:100%; " onClick="javascript:OnAuth();">Log In with <strong>WWPass PassKey</strong></button>
                    </p>
                    <?php
            }
        }
    }
}

function wwpass_wp_auth($user)
{
    global $error;
    
    if ( array_key_exists('wwpass_response', $_POST) && $_POST['wwpass_response'] )
    {
        $redirect_to = array_key_exists('redirect_to', $_REQUEST) ? $_REQUEST['redirect_to'] : null;
        $status = array_key_exists('wwpass_status', $_REQUEST) ? $_REQUEST['wwpass_status'] : null;
        $response = array_key_exists('wwpass_response', $_REQUEST) ? $_REQUEST['wwpass_response'] : null;
                
        if ($status == 200) {
            try {
                $SPFE = new WWPASSConnection(
                    get_option('WWPASS_PATH_KEY'),
                    get_option('WWPASS_PATH_CRT'),
                    WWPASS_PATH_CA
                    );
                
                $puid = $SPFE->getPUID($response, '', false); # @fix
                global $wpdb;
                $wpdb->show_errors();
                
                $user_id = $wpdb->get_var(
                    $wpdb->prepare('SELECT `user_id` FROM `' . $wpdb->prefix . 'wwpass` WHERE `wwpass_puid` = %s LIMIT 1;', $puid)
                    );
               
                if ($user_id)
                    return new WP_User($user_id);
                else
                    $error .= 'Your PassKey is not attached to any WordPress account. ';
            } catch (Exception $e) {
                $error .= 'Authentication error. Please, try again. ';
                $error .= $e->getMessage();
            }
        } else {
            $error .= $response;
        }
        
        $user = new WP_Error();
        
        return $user;
    }
}

add_action('admin_menu', 'wwpass_admin_actions');

function wwpass_admin_actions() {
    add_options_page("WWPass Plugin Settings", "WWPass", 10, __FILE__ . 'admin', "wwpass_admin");
    if (get_option('WWPASS_SPNAME', false) && wwpass_check()) {
        add_menu_page("WWPass Authentication", "WWPass", 0, __FILE__ . 'user', "wwpass_user");
    }
}

function wwpass_certificate_check($crt) {
    $data = openssl_x509_parse(file_get_contents($crt));
    $validFrom = date('Y-m-d H:i:s', $data['validFrom_time_t']);
    $validTo = date('Y-m-d H:i:s', $data['validTo_time_t']);

    $delta = round(($data['validTo_time_t'] - time())/60/60/24);
    if ($delta > 1)
        $hdelta = 'Certificate expires in ' . $delta . ' days';
    elseif ($delta == 1)
        $hdelta = 'Certificate expires in ' . $delta . ' day';
    elseif ($delta == 0)
        if ($data['validTo_time_t'] - time() > 0)
            $hdelta = 'Expires today';
        else
            $hdelta = 'Expired';
    else
        $hdelta = 'Expired';
    
    return array($validFrom, $validTo, $delta, $hdelta);
}

function wwpass_connection_settings($key, $crt) {
    $errors = null;
    $spName = null;
    $cert_info = null;
    
    if (! file_exists($crt)) {
        $errors .= '<p>File does not exist: ' . $crt . '</p>';
    }
    // 'Cannot open file: <file>'
    if (is_null($errors)) {
        $cert_info = wwpass_certificate_check($crt);
        list(,$validTo, $delta, $hdelta) = $cert_info;
        if ($delta <= 0) {
            $errors .= '<p>Certificate has expired</p>';
        }
    }
    
    if (! file_exists($key)) {
        $errors .= '<p>File does not exist: ' . $key . '</p>';
    }
    // 'Cannot open file: <file>'
    if (is_null($errors)) {
        try {
            $SPFE = new WWPASSConnection(
                $key,
                $crt,
                WWPASS_PATH_CA
            );
            
            $spName = $SPFE->getName();
        } catch (Exception $e) {
            
            $errors .= '<p>Cannot connect to WWPass</p>';
        }
    }
    
    return array($spName, $cert_info, $errors);
}

function wwpass_admin() {
    if ( ! wwpass_check()) {
        ?>
        <div class="wrap">
            <h2>WWPass Plugin Settings</h2>
            <div id="message" class="error">
                <p>PHP cURL is not installed.</p>
            </div>
            
            <p><a href="http://php.net/manual/en/book.curl.php">PHP cURL</a> is not installed. Install PHP cURL and restart your web server.</p>
        </div>
        <?php
        return 0;
    }
    
    if (array_key_exists('wwp_qrcode', $_POST) ){
        $p_qrcode = 'enabled';
    } else {
        $p_qrcode = get_option('WWPASS_QRCODE', false);
    }
    
    if (array_key_exists('wwp_passkey', $_POST) ){
        $wwp_settings['WWPASS_PASSKEY'] = 'enabled';
        $p_passkey = 'enabled';
    } else {
        $p_passkey = get_option('WWPASS_PASSKEY', false);
    }
    
    if (array_key_exists('wwp_key', $_POST) && $_POST['wwp_key'] &&
        array_key_exists('wwp_crt', $_POST) && $_POST['wwp_crt']) {
        $wwp_settings['WWPASS_PATH_KEY'] = $_POST['wwp_key'];
        $wwp_settings['WWPASS_PATH_CRT'] = $_POST['wwp_crt'];
        
        $fi = 0;
        global $error;
        
        if (@$h_key = fopen($wwp_settings['WWPASS_PATH_KEY'], 'r'))
        {
            $fi++;
            fclose($h_key);
        } else {
            $error .= "<p>Cannot open file: " . $wwp_settings['WWPASS_PATH_KEY'] ." </p>";
        }

        if (@$h_crt = fopen($wwp_settings['WWPASS_PATH_CRT'], 'r'))
        {
            $fi++;
            fclose($h_crt);
        } else {
            $error .= "<p>Cannot open file: " . $wwp_settings['WWPASS_PATH_CRT'] ." </p>";
        }
        
        if ( ! $error ) {
            try {
                $SPFE = new WWPASSConnection(
                    $wwp_settings['WWPASS_PATH_KEY'],
                    $wwp_settings['WWPASS_PATH_CRT'],
                    WWPASS_PATH_CA
                );
                $wwp_settings['WWPASS_SPNAME'] = $SPFE->getName();
            } catch (Exception $e) {
                $error .= '<p>Cannot connect to WWPass: '.$e->getMessage().'</p>';
            }
            
            $wwp_settings['WWPASS_ASKPASS'] = array_key_exists('wwp_askpass', $_POST) && $_POST['wwp_askpass'] ? ':p' : '';
            $wwp_settings['WWPASS_QRCODE'] = array_key_exists('wwp_qrcode', $_POST) && $_POST['wwp_qrcode'] ? 'enabled' : '';
            $wwp_settings['WWPASS_PASSKEY'] = array_key_exists('wwp_passkey', $_POST) && $_POST['wwp_passkey'] ? 'enabled' : '';

            if (array_key_exists('WWPASS_SPNAME', $wwp_settings)) {
                foreach ($wwp_settings as $option_name => $value)
                {
                    if ( get_option($option_name, false) !== false) {
                        update_option( $option_name, $value );
                    } else {
                        $deprecated = ' ';
                        $autoload = 'no';
                        add_option( $option_name, $value, $deprecated, $autoload );
                    }
                }
                
                $message = "Settings were saved";
            }
        }
        
    }

    if (array_key_exists('wwp_spfe', $_POST) && $_POST['wwp_spfe']) {
        $p_spfe = $_POST['wwp_spfe'];
    } else
        $p_spfe = get_option('WWPASS_SPFE', 'spfe.wwpass.com');

    if (array_key_exists('wwp_key', $_POST) && $_POST['wwp_key']) {
        $p_key = $_POST['wwp_key'];
    } else
        $p_key = get_option('WWPASS_PATH_KEY', '');

    if (array_key_exists('wwp_crt', $_POST) && $_POST['wwp_crt']) {
        $p_crt = $_POST['wwp_crt'];
    } else
        $p_crt = get_option('WWPASS_PATH_CRT', '');
    
    if (array_key_exists('wwp_qrcode', $_POST) ){
        $p_qrcode = 'enabled';
    } else {
        $p_qrcode = get_option('WWPASS_QRCODE', false);
    }
    
    if (array_key_exists('wwp_passkey', $_POST) ){
        $p_passkey = 'enabled';
    } else {
        $p_passkey = get_option('WWPASS_PASSKEY', false);
    }
    
    $p_ask = isset($wwp_settings['WWPASS_ASKPASS']) ? $wwp_settings['WWPASS_ASKPASS'] : get_option('WWPASS_ASKPASS', '');
    
    $sp_name = get_option('WWPASS_SPNAME', 'Unknown');
    
?>
    <div class="wrap">
    <h2>WWPass Two-factor Authentication Settings</h2>
<?php
    if (@$message) {
    ?>
    <div class="updated">
        <p><strong><?php echo $message;?></strong></p>
    </div>
    <?php
    }

    if (@$error) {
    ?>
    <div id="m-error" class="error">
        <p><strong>Settings were not saved</strong></p>
        <p><?php echo $error;?></p>
    </div>
    <?php
    }
    
    if ( ! get_option('WWPASS_SPNAME', false)) { ?>
        <div class="updated">
            <p>Please register your website at <a href="https://developers.wwpass.com">WWPass Developers</a> to receive your ".crt" and ".key" files.</p>
        </div>
        <?php 
    } else {
        list($_spName, $_certInfo, $_errors) = wwpass_connection_settings(
            get_option('WWPASS_PATH_KEY'), 
            get_option('WWPASS_PATH_CRT')
        );
        
        if ($_errors) {
            ?>
            <div id="m-error" class="error">
                <p><strong>Plugin status</strong></p>
                <?php echo $_errors; ?>
            </div>
            
            
            <?php
        } else {
            if ( ! @$error) {
            ?>
            <div class="updated">
                <p><strong>Plugin status</strong></p>
                <p><b>Service Provider Name:</b> <?php echo urldecode($_spName); ?></p>
                <p><b>Certificate Info:</b> <?php echo $_certInfo[3] . ' (valid until '. $_certInfo[1] .' UTC)'; ?></p>
            </div>
            <?php
            }
        }
    }
    ?>
    
    <form method="post">
        <h3>Certificate Settings</h3>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><label for="wwp_crt">Certificate file path (.crt):</label></th>
                <td>
                    <input name="wwp_crt" type="text" id="wwp_crt" value="<?php echo $p_crt;?>" class="regular-text" />
                </td>
            </tr>
            
            <tr valign="top">
                <th scope="row"><label for="wwp_key">Key file path (.key):</label></th>
                <td>
                    <input name="wwp_key" type="text" id="wwp_key" value="<?php echo $p_key;?>" class="regular-text" />
                </td>
            </tr>
        </table>
        
        <h3>Authentication Settings</h3>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"></th>
                <td>
                    <input name="wwp_askpass" type="checkbox" value="1" id="wwp_askpass" <?php echo $p_ask ? 'checked="checked"': '';?> />&nbsp;<label for="wwp_askpass">Enable PIN Code (2nd factor)</label>
                    <p class="description">Prompt for PIN Code during authentication</p>
                </td>
            </tr>
            
            <tr valign="top">
                <th scope="row"></th>
                <td>
                    <input name="wwp_qrcode" type="checkbox" value="1" id="wwp_qrcode" <?php echo $p_qrcode ? 'checked="checked"': '';?> />&nbsp;<label for="wwp_qrcode">Enable PassKey App</label>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"></th>
                <td>
                    <input name="wwp_passkey" type="checkbox" value="1" id="wwp_passkey" <?php echo $p_passkey ? 'checked="checked"': '';?> />&nbsp;<label for="wwp_passkey">Enable Passkey</label>
                </td>
            </tr>
        </table>
        <p class="submit"><input type="submit" name="submit" id="submit" class="button-primary" value="Save Settings" /></p>
    </form>
</div>

<style type="text/css">
    
    .h3-point {
        cursor: pointer;
        font-weight: bold;
        color: rgb(33, 117, 155);
        border-bottom: 1px dashed rgb(33, 117, 155);
    }
    
    .form-table th {
        width: 250px;
    }
    
    input.regular-text, #adduser .form-field input {
        width: 35em;
    }
</style>

<?php
}

function wwpass_user() {
    $user = wp_get_current_user();
    global $wpdb;
    if (array_key_exists('action', $_POST) && $_POST['action']) {
        $action = $_POST['action'];
        
        $status = array_key_exists('wwpass_status', $_REQUEST) ? $_REQUEST['wwpass_status'] : null;
        $response = array_key_exists('wwpass_response', $_REQUEST) ? $_REQUEST['wwpass_response'] : null;
        
        if ($action == 'unbind') {
            // unbind
            // global $wpdb;
            $wpdb->show_errors();
            $wpdb->query(
                $wpdb->prepare('DELETE FROM `' . $wpdb->prefix . 'wwpass` WHERE `user_id` = %s;', $user->ID)
                );
            ?>
            <div id="message" class="updated">
                <p><strong>Your PassKey has been detached from your account.</strong></p>
            </div>
            <?php
            
            $user->wwpass_puid = '';
        } elseif ($action == 'bind' && $status == 200 && $response) {
            // bind
                $SPFE = new WWPASSConnection(
                    get_option('WWPASS_PATH_KEY', ''),
                    get_option('WWPASS_PATH_CRT', ''),
                    WWPASS_PATH_CA
                    );
                
                try {
                    $puid = $SPFE->getPUID($response, '', FALSE);
                    
                    $wpdb->show_errors();
                    $result = $wpdb->get_var(
                        $wpdb->prepare('SELECT `user_id` FROM `' . $wpdb->prefix . 'wwpass` WHERE `wwpass_puid` = %s LIMIT 1;', $puid)
                        );
                    
                    if ( ! $result)
                    {
                        $wpdb->query(
                            $wpdb->prepare('INSERT INTO `' . $wpdb->prefix . 'wwpass` VALUES (%s, %s);', $user->ID, $puid)
                            );
                        $message = '<p>Your PassKey has been successfully bound to your account.</p>';
                    } elseif ($result == $user->ID) {
                        $message = '<p>Your PassKey is already bound to your account.</p>';
                    } else {
                        $error .= '<p>Your PassKey is already bound to another account on this web site.</p>';
                    }
                } catch (Exception $e) {
                    $error .= $e->getMessage();
                }
        } else {
            $error .= $response;
        }
    }
    $puid = $wpdb->get_var($wpdb->prepare('SELECT wwpass_puid FROM `'. $wpdb->prefix .'wwpass` WHERE user_id = %s LIMIT 1;', $user->ID)) or false;
?>

<div class="wrap">
    <h2>WWPass Authentication</h2>
    
    <?php if ( @$message ) { ?>
    <div id="message" class="updated">
        <p><strong><?php echo $message;?></strong></p>
    </div>
    <?php } elseif ( @$error ) { ?>
        <div class="error">
            <p><strong>A Error Has Occured</strong></p>
            <p><?php echo $error; ?></p>
        </div>
    <?php }
    
    if (wp_is_mobile()) {
    ?>
    <p>Tap the QR code below to bind your PassKey App to your WordPress account. <?php echo ( get_option('WWPASS_ASKPASS', false) ? 'Your will need to provide your Access Code.' : '' ) ;?></p>
    <?php
    } else {
    ?>
    <p>Scan the QR code below with your PassKey App to bind it to your WordPress account. <?php echo ( get_option('WWPASS_ASKPASS', false) ? 'Your will need to provide your Access Code.' : '' ) ;?></p>
    <?php
    }
    
    if (get_option('WWPASS_QRCODE', false) or get_option('WWPASS_PASSKEY', false)) {
        ?>
        <form method="POST" id="bindform" name="bindform">
                <input type="hidden" name="action" value="bind">
        <?php
        if (get_option('WWPASS_QRCODE', false)) {
        ?>
            <div id="qrcode"></div>
        <?php
        }
        
        if ( ! wp_is_mobile()) {
            if (get_option('WWPASS_PASSKEY', false)) {
        
        ?>
        
        <p>Connect your PassKey and click the Bind button to bind your PassKey to your WordPress account. <?php echo ( get_option('WWPASS_ASKPASS', false) ? 'Your will need to provide your Access Code.' : '' ) ;?></p>
        <p><input type="submit" name="btn-bind" value="Bind" class="button-primary" onClick="javascript:OnBind();return false;"></p>
        
        <?php
            }
        }
        ?>
    
    </form>
    
    <?
    }
    
    if ((bool) $puid) { ?>
        <p>Press the Clear bindings button to stop using your PassKey with your WordPress account.</p>
        
        <form method="POST" id="unbindform" name="unbindform">
            <input type="hidden" name="action" value="unbind">
            <p><input type="submit" name="btn-unbind" value="Clear bindings" class="button-primary"></p>
        </form>
    <?php } else { ?>
        <p>No PassKey is currently bound to your WordPress account.</p>
    <?php } ?>

</div>
    <style type="text/css">
        #qrcode {
            border: 1px solid black;
            border-radius: 2px;
            padding: 7px;
            margin-bottom: 10px;
            display: inline-block;
            background-color: white;
        }
    </style>
    <?php
    if (get_option('WWPASS_PASSKEY', false)) {
        ?><script type="text/javascript" src="//cdn.wwpass.com/packages/latest/wwpass.js"></script><?php
    }
    if (get_option('WWPASS_QRCODE', false)) {
        ?><script type="text/javascript" src="<?php echo wwpass_qrcode_url();?>"></script>
        <script type="text/javascript">
            var ajax_object = {'ajaxurl': '<?php echo admin_url( 'admin-ajax.php' ) ;?>'};
        </script>
        
        <?php
    }
    if (get_option('WWPASS_QRCODE', false) or get_option('WWPASS_PASSKEY', false)) {
    ?>
    
    <script type="text/javascript" charset="utf-8">
    
    function wwpassCallback(status, response, echo) {
        if (status != 603) {
            var form_status = document.createElement('input');
            form_status.type = 'hidden';
            form_status.name = 'wwpass_status';
            form_status.value = status;
            
            var form_response = document.createElement('input');
            form_response.type = 'hidden';
            form_response.name = 'wwpass_response';
            form_response.value = response;
            
            var f = document.getElementById('bindform');
            f.appendChild(form_status);
            f.appendChild(form_response);
            f.submit();
        }
    }
    
    function OnBind() {
        wwpass_auth('<?php echo wwpass_cw_ticket();?>', wwpassCallback);
    }
    
    </script>
    <?php
    }
    
    $echo = '0' . $_SERVER["REQUEST_URI"];
    
    if (get_option('WWPASS_QRCODE', false)) { ?>
        <script>
            wwpassQRCodeAuth({
                'ticketURL': ajax_object.ajaxurl + '?action=get-ticket&rnd_wordpress=' + new Date().getTime(),
                'callback': wwpassCallback,
                'render': 'qrcode',
                'callbackURL': '<?php echo wp_login_url(); ?>',
                'echo': '<?php echo base64_encode($echo); ?>'
            });
        </script>
        <?php
    }
}
