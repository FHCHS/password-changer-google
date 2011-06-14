<?php
// $Id$
/**
*
* @file
* Classes to support the Google password changer module.
*
* Classes to support the Google password changer module to
* implements the hooks define by the password changer API.
* 
*/

/**
 Password Changer Google Exception class
 *
 *Password changer Google exception class extends the Exception class.
 *
 */
class passwordChangerGoogleExeption extends Exception {}


/**
* Represents a Google token.
*
* Represents a Google token, retrieve or generated Google token.
* 
*/
class googleToken {
 
 /**
 * The Google token object.
 *
 * @var $token
 * 
 */ 
 private static $token;
 
 /**
 * The Google when token was generated.
 *
 * @var $generationTime
 * 
 */
 public $generationTime;
 
 /**
 * The Google token value.
 *
 * @var $tokenValue
 * 
 */
 public $tokenValue;
 
 /**
 * The Google token domain.
 *
 * @var $tokenDomain
 * 
 */
 public $tokenDomain;
 
 
 /**
 * Constructs initialize the Google token object.
 *
 * @param string $role_id
 *  User type that it will define the Domain that it will use for
 *  Google authentication.
 *  
 */
 
 private function __construct($role_id) {
  
   //Set URL for constructor
   $url = $this->getGoogleLoginUrl();
   
   //Create header
   $header = $this->getGoogleLoginHeader();
   
   //Get credentials
   $credentials = $this->getGoogleLoginCredentials($role_id);
  
   //Generate token
   $this->generateGoogleToken($url, $header, $credentials, $role_id);
   
 }
 
 /**
 *
 * Return Google log-in credentials depending on the user type
 * pass in the parameter.
 *
 * @param string $role_id user type.
 *
 * @throws Exception passwordChangerGoogleExeption.
 * 
 * @return array with credentials.
 *  Email=>'email value',
 *  password=>'password value',
 *  accountType=>'account type value',
 *  service=>'apps'
 *  
 */ 
 private function getGoogleLoginCredentials($role_id) {
  
  //Get credentials from settings
  $settings = variable_get('password_changer_google_domains', array());
  
  //Check that settings is set
  if (empty($settings)) {
   
   //Log error to watchdog
   watchdog('[password_changer_google_inc][getGoogleLoginCredentials]', 'There are no domains save on the Google module settings.' , WATCHDOG_ERROR);
   
   //Throw a google password changer exeption
   throw new passwordChangerGoogleExeption('There are no domains save on the Google module settings.');
  }
  //Initialize credentials
  $credentials = array();
  
  //Check if role is set on the settings
  foreach ($settings AS $index => $rid_record) {
    foreach ($rid_record AS $rid => $values) {
      if ($rid == $role_id) {
       //Set role Domain
       $this->tokenDomain = $settings[$index][$rid]['domain'];
       //Return Credentials to user
       return $settings[$index][$rid];
      }
    }  
  }

  
   //Log error to watchdon
   watchdog('[password_changer_google_inc][getGoogleLoginCredentials]', 'There is no credentials define for that user type.' , WATCHDOG_ERROR);
    
   //Throw error to if user type is not define 
   throw new passwordChangerGoogleExeption('There is no credentials define for that user type.');   
 
 }
 
 /**
 * Static function that will return an googleToken object.
 *
 * @param string $role_id
 *  User type that it will define the Domain that it will use for
 *  Google authentication.
 *  
 * @return googleToken object. 
 *  
 */ 
 public static function getGoogleToken($role_id) {

   //Check if object exist if does not exist generate
   //new object
   if (!self::$token) {
    //Generate new object
    self::$token = new googleToken($role_id);
 
    
   }
      
    //Return object
    return self::$token;
  
  }
  
  /**
  * Return Google client log-in URL.
  * 
  * @return string 
  *  
  */  
  private function getGoogleLoginUrl() {
   //Return Google URL to get token to manage user
   return 'https://www.google.com/accounts/ClientLogin';
   
  }
  
  /**
  * Return Google log-in header.
  * 
  * @return string 
  *  
  */  
  private function getGoogleLoginHeader() {
   //Return Google log-in headers
   return array('Content-type: multipart/form-data');;
   
  }
  
  /**
  * Return get the domain related to the role in the settingsS.
  * 
  * @return string 
  *  
  */  
  private function getRoleDomain($role_id) {
   
   //Get Google credentials for the role and return the domain
   $domain = $this->getGoogleLoginCredentials($role_id);
   
   //Check if domain is set return the domain
   if (!isset($domain['domain'])) {
    
     watchdog('[password_changer_google_inc][getRoleDomain]', 'There is no domain set for role id ' . $role_id, WATCHDOG_ERROR);
     
     throw new passwordChangerGoogleExeption('There is no domain set for role id ' . $role_id);
      
   }
   
   //Return credentials 
   return $domain['domain'];
   
  }
  
  /**
  *
  * Save token in Drupal a persistent variable.
  *  
  */ 
   private function saveTokenInDrupal($role_id) {
    
    //Get variable
    $tokens = variable_get('password_changer_google_tokens', array());
    
    //Save role  
    $tokens[$role_id] = array('token_value' => $this->tokenValue,
                              'generation_time' => $this->generationTime);
    
     //Save password changer token
     variable_set('password_changer_google_tokens', $tokens);
   
  }
  
  /**
  *
  * Get save values from Drupal persistent variable password_changer_google_tokens
  *
  * @throws Exception passwordChangerGoogleExeption there is no token information
  *  store in the variable.
  *  
  */ 
  
  private function getSavedValues($role_id) {
   
   //Get the variable get
   $result = $this->getRoleToken($role_id);
 
   //Set token value and generation time 
   $this->tokenValue = $result['token_value'];
   $this->generationTime = $result['generation_time'];
   
   //Return save values for the role
   return $result;
   
  }
  
  /**
  *
  * Check if token is expired.
  *
  * @throws Exception passwordChangerGoogleExeption there is no token information
  *  store in the variable.
  *
  * @return boolean TRUE if token has expired FALSE if token is not expired.
  * 
  */ 
  private function tokenIsExpirired($role_id) {
 
    //Get the variable get
    $result = $this->getRoleToken($role_id);
        
    //If the password_changer_google_tokens is empty
    //Return true
    if (empty($result) || $result == FALSE) {
      
      return TRUE;
    }
    else {
     //Get generation time elapse
     $elapse_time = time() - $result['generation_time'];
     
     // 86400 seconds in 24 hours
     if ($elapse_time  > 86400) {
      //Token has expired return TRUE.
      return TRUE;
     }
      //Token has not expired
      return FALSE;
    }  
 }
 
 /**
 *
 * Get token if exist for the role.
 *
 * @throws Exception passwordChangerGoogleExeption there is no token information
 *  store in the variable.
 *
 * @return array
 *   'tokenValue' => the token value for the role
 *   'generationTime' => the time the toke was generated
 * 
 */ 
 
 private function getRoleToken($role_id) {
   
   //Get token
   $tokens = variable_get('password_changer_google_tokens', array());
   
   //If array is not empty
   if (empty($tokens)) {
    
    //Log error to watchdog
    watchdog('[password_changer_google_inc][getRoleToken]', 'There is no tokens save for the saved.' , WATCHDOG_INFO);
    
    return FALSE;
   }
   
   //If array is not empty
   if (!isset($tokens[$role_id])) {
    
    //Log error to watchdon
    watchdog('[password_changer_google_inc][getRoleToken]', 'Token is no save for the role id ' . $role_id . '.' , WATCHDOG_ERROR);
    
    //Throw Error
    return FALSE;
   }
  
   //Return token for role
   return $tokens[$role_id];
  
 }
 
 /**
 *
 * Check if token is expired.
 *
 * @throws Exception passwordChangerGoogleExeption there is no token information
 *  store in the variable.
 *
 * @return boolean TRUE if token has expired FALSE if token is not expired.
 * 
 */ 
 private function generateGoogleToken($url, $header, $credentials, $role_id) {
  
 
   try {
    
     if ($this->tokenIsExpirired($role_id)) {
      
      //Set post variable to generate token
      //Set cURL options
      $send = array( 'Email' => $credentials['email'],
                    'Passwd' => $credentials['password'],
                    'accountType' => $credentials['account_type'],
      
                    'service' => $credentials['service']);
   
      
      //Set options
      $options = array(CURLOPT_POST => TRUE,
                       CURLOPT_HTTPHEADER => $header,
                       CURLOPT_RETURNTRANSFER => TRUE,
                       CURLOPT_POSTFIELDS => $send,
                       CURLOPT_SSL_VERIFYPEER => FALSE);
   
      //Make curl call 
      $result = password_changer_api_simple_curl_call($url, $options);
     
      //Get Authenticated token from 
      $pattern = '/Auth=(.+)/';
      
      if (preg_match($pattern , $result, $auth)) {
       
        //Extract the token from the string response
        preg_match($pattern , $result, $auth);
        
        //Remove the 'Auth=' from the token token
        $this->tokenValue = str_replace('Auth=', "", $auth[0]);
        
        //Set date the token was generated
        $this->generationTime = time();
         
        //Save token in Drupal
        $this->saveTokenInDrupal($role_id);
        
       }//No token return a Google error
       else {
        //Save error in watchdog
        watchdog('[password_changer_google_inc][generateGoogleToken]', $result, WATCHDOG_ERROR);
        //Throw password changer
        throw new passwordChangerGoogleExeption($result);
       }
       
     }
     else {
      //Get the save values in Drupal
      $this->getSavedValues($role_id);
     }
     
   }
   catch(Exception $e) {
     
     watchdog('[password_changer_google_inc][generateGoogleToken]',$e->getMessage());
     
     throw new passwordChangerGoogleExeption('Exeption occurd while generating Google Token.');
    
   }
 }
 
} 

/**
* Represents a Google user.
*
* Represents a Google user, change password for user.
* 
*/
class googleUser {
 
  /**
  * The Google token object.
  *
  * @var $token
  * 
  */ 
  private $token; 
  
  /**
  * Create a drupal Object
  *
  * @var $drupalUser
  * 
  */  
  private $drupalUser;
  
  /**
  * Constructor to create google user, runs when an object is
  * created
  *  
  */  
  function __construct($user_name) {
   
    try {
       //Get user id
       $uid = db_query("SELECT uid FROM {users} WHERE name = :user_name",
                       array(':user_name' => $user_name))->fetchField();
       
       //Create drupal user
       //@todo check errors
       $this->drupalUser = user_load($uid);
       
       //Get role id
       $role_id = $this->getUserRegisterRole();
     
       //Get user role
       $this->token = googleToken::getGoogleToken($role_id);
       
      }
      catch( passwordChangerApiExeption $e ) {
       
        watchdog('[password_changer_google_inc][__construct]', $e->getMessage(), WATCHDOG_ERROR);
       
        throw new passwordChangerGoogleExeption($e->getMessage());
       
      }
      
  }
  
  
  /**
  *
  * Get Google API user API URL.
  *
  * @throws Exception passwordChangerGoogleExeption if there is not a URL define
  * for the role.
  * 
  */ 
  private function getUserRegisterRole() {
    
     //Get settings
     $settings = variable_get('password_changer_google_domains', array());
     
     //Check if settings is empty throw and error
     if (empty($settings)) {
      
        watchdog('[password_changer_google_inc][getUserRegisterRole]', 'Their is no settings set for the Google password changer.', WATCHDOG_ERROR);
       
       throw new passwordChangerGoogleExeption('Their is no settings set for the Google password changer.');
       
     }
 
    //Check if one user role maches a role in the settings
    foreach ($settings AS $index => $setting_rid) {
      //Get role id
      foreach ($setting_rid AS $rid => $values) {
        //Check role 
        foreach ($this->drupalUser->roles AS $user_rid => $role_name) {
         //Get role id
          if ($rid == $user_rid) {
           
            return $user_rid;
            
          }
        }  
      }
    }
     watchdog('[password_changer_google_inc][getUserRegisterRole]', 'Sorry user role does not match register roles in
                                             the Google configuration settings.', WATCHDOG_ERROR);
    
    //If it reach here it did not find a role register that match the users roles
    throw new passwordChangerGoogleExeption('Sorry user role does not match register roles in
                                             the Google configuration settings.');
  }
  
  /**
  *
  * Get Google API user API URL.
  *
  * @throws Exception passwordChangerGoogleExeption if there is not a URL define
  * for the role.
  * 
  */ 
  private function getGoogleApiUrl() {
    
    try {
    
     //Get credentials for the role
     $role_id = $this->getUserRegisterRole();
     
    }
    catch( passwordChangerApiExeption $e ) {
      
       watchdog('[password_changer_google_inc][getGoogleApiUrl]', $e->getMessage(), WATCHDOG_ERROR);
      
       throw new passwordChangerGoogleExeption($e->getMessage());
      
     }
  
 
    try {
     
      //Get role domain
      $domain = $this->token->tokenDomain;
      
      //Remove protocol from domain
      $domain = preg_replace ( '(|^http(s)?://)', '', $domain);
      
      //Return URL
      return 'https://apps-apis.google.com/a/feeds/' . $domain . '/user/2.0/' . $this->drupalUser->name;
     
    }
    catch (passwordChangerGoogleExeption $e) {
     
      watchdog('[password_changer_google_inc][getGoogleApiUrl]', 'There is not a domain define for the role ' .
               $this->drupalUser->roles[$role_id] . '.', WATCHDOG_ERROR);
     
      //Error there is no domain define for this user type.
      throw new passwordChangerGoogleExeption('There is not a domain define for the role ' .
                                              $this->drupalUser->roles[$role_id]);
    }
    
  }
  
  /**
  *
  * Get header to send with user call.
  *
  * @throws Exception passwordChangerGoogleExeption if there is not a Google token.
  * 
  */ 
  private function generateHeader() {
   
   //Check if token is set
   if (strlen($this->token->tokenValue) > 0) {
   //Generate error
   $header[] = 'Content-type: application/atom+xml';
   $header[] = 'Authorization: GoogleLogin auth='. $this->token->tokenValue ;
   //Return headere
   return $header;
   }
   //Log error
   watchdog('[password_changer_google_inc][generateHeader]', 'There is not a Google token set.', WATCHDOG_ERROR);
   
   //Error there is not a token set
   throw new passwordChangerGoogleExeption('There is not a Google token set.');
  }
  
  /**
  *
  * Check if user exist is Google.
  *
  *
  * @return boolean
  *  If title is set in the XML sent from Google user exist return FALSE
  *  else return FALSE.
  *  
  */ 
  public function checkUserExist() {
   
   try {
     //Get user resgister module
     $role_id = $this->getUserRegisterRole();
   }
   catch( passwordChangerApiExeption $e ) {
      
       watchdog('[password_changer_google_inc][checkUserExist]', $e->getMessage(), WATCHDOG_ERROR);
      
       throw new passwordChangerGoogleExeption($e->getMessage());
      
   }
   
   //Create URL that will be use to user information
   $url =  $this->getGoogleApiUrl();
     
   //Create header to send Google
   $header = $this->generateHeader();
     
   //Set options
   $options = array(CURLOPT_HTTPGET => TRUE,
                    CURLOPT_HTTPHEADER => $header,
                    CURLOPT_RETURNTRANSFER => TRUE,
                    CURLOPT_SSL_VERIFYPEER => FALSE);
   
   //Make curl call 
   $user = password_changer_api_simple_curl_call($url, $options);
   
   //Get the XML generated by Google
   $user = new SimpleXMLElement($user);
   
   //If user is set $user->title is set
   if (isset($user->title)) {
    
    if ($user->title ==  $this->drupalUser->name) {
     
     return TRUE;
    
    }//Else user was not found in Google return FALSE
    else {
     //Return FALSE there is no user
     return FALSE;
    
    }
   }
   
   //Return FALSE user
   return FALSE;
  
  }
  
  /**
  *
  * Change Google user password.
  *
  * @param array $credentials
  *  'user_name' user name to change password
  *  'password' change password
  *  
  * @return object status and status message.
  *
  * @todo handle captcha error  it could either redirect users
  *       https://www.google.com/a/yourdomain.com/UnlockCaptcha
  *       or display catcha for user to display for more
  *       info http://code.google.com/googleapps/faq.html
  *
  */
  public function changeUserPassword($credentials, $attempt = 0) {
  
    try {
      //Get user register role id 
      $role_id = $this->getUserRegisterRole();
    }
    catch( passwordChangerApiExeption $e ) {
      
      watchdog('[password_changer_google_inc][changeUserPassword]', $e->getMessage(), WATCHDOG_ERROR);
    
      throw new passwordChangerGoogleExeption($e->getMessage());
      
    }
    
    //Generate XML file to send to Google to change password 
    //Get file path
    $module_path = db_query_range('SELECT `filename` FROM {system} WHERE `name` = :name ', 0, 1,
                     array(':name' => 'password_changer_google'))->fetchField();
 
    //Get path length
    $lenght = strlen($module_path) - strlen('password_changer_google.module');
    
    //Google XML to change password
    $change_password_xml = file( DRUPAL_ROOT . '/' . substr($module_path, 0, $lenght) . 'password_changer_google.xml');
  
    //Create a string out of the file
    $change_password_xml = implode( "", $change_password_xml);
    
    
    //Replace user_name and password on the XML with current values
    foreach ($credentials AS $replacement_name => $replacement_value) {
      //Check if password is the value 
      if ($replacement_name == 'password') {
        $replacement_value = sha1($replacement_value);
      }
      //Replace value
      $change_password_xml = str_replace('user_' . $replacement_name,  $replacement_value, $change_password_xml );
    }
       
    //Get API URL to manage users
    $url = $this->getGoogleApiUrl();
    
    //Get header for request
    $header = $this->generateHeader();
   
    //Create a temporary file
    $xml = tmpfile();
    fwrite($xml, $change_password_xml);
    fseek($xml, 0);
    
    //echo $url;
    //Set request options
    //Set URL
    $options = array(CURLOPT_URL => $url,
                     CURLOPT_PUT => TRUE,
                     CURLOPT_HTTPHEADER => $header,
                     CURLOPT_RETURNTRANSFER => TRUE,
                     CURLOPT_SSL_VERIFYPEER => FALSE,
                     CURLOPT_HEADER => 1,
                     CURLOPT_INFILE => $xml,
                     CURLOPT_INFILESIZE => strlen($change_password_xml));
    //Set information
    $information = '';
    
    $result = password_changer_api_simple_curl_call($url, $options, $information);
    /*echo '<pre>';
    print_r($header);
    print_r($information);
    echo '</pre>';
    exit();
    */  
    //Check if password has been changed
    if ($information['http_code'] == 200) {
     
     //Return the status
     return password_changer_api_status(array('status' => 'status',
                                              'message' => 'Password has been changed in your Google account.'));
    
    } //Malform password
    elseif ($information['http_code'] == 400) {
     
     //Return the status
      return password_changer_api_status(array('status' => 'error',
                                               'message' => 'Unable to change password, your password might smaller than six character.')); 
    
    }//Server is overloaded try to change it again
    elseif ($information['http_code'] == 503) {
     
     //Increase number of attemps to change the passwords
     $attempt++;
     
     //A little wait time
     if($attempt < 4) {
      
       //Wait for the number of seconds before trying to change again.    
       sleep($attempt * 5);
      
      //Call this function again and try to change the password 
      $this->changeUserPassword($credentials, $attempt); 
       
     }
     else {
     
      //Return error status on the message
      return password_changer_api_status(array('status' => 'error',
                                               'message' => 'Unable to change password due to server overload.'));
      
     }  
    }
    else {
     
     //If set the generation time to expired
      
      //Return error password was not change
      return password_changer_api_status(array('status' => 'error',
                                               'message' => 'Unable to change password try to again.'));
    }
  } 
}