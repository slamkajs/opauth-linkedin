<?php
/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.LinkedInStrategy
 * @license      MIT License
 */

/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 * 
 * @package			Opauth.LinkedIn
 */
class LinkedInStrategy extends OpauthStrategy{
	
	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('api_key', 'secret_key');
	
	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array();
	
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'method' => 'POST', 		// The HTTP method being used. e.g. POST, GET, HEAD etc 
		'oauth_callback' => '{complete_url_to_strategy}oauth_callback',
		
		// For LinkedIn
		'request_token_url' => 'https://api.linkedin.com/uas/oauth/requestToken',
		'authorize_url' => 'https://www.linkedin.com/uas/oauth/authenticate', // or 'https://www.linkedin.com/uas/oauth/authorize'
		'access_token_url' => 'https://api.linkedin.com/uas/oauth/accessToken',
		
		'get_profile_url' => 'http://api.linkedin.com/v1/people/~',
		'profile_fields' => array('id', 'first-name', 'last-name', 'formatted-name', 'headline', 'picture-urls::(original)', 'summary', 'location', 'public-profile-url', 'site-standard-profile-request', 'email-address', 'educations', 'volunteer', 'certifications', 'skills', 'three-current-positions', 'three-past-positions'),

		// From tmhOAuth
		'user_token'					=> '',
		'user_secret'					=> '',
		'use_ssl'						=> true,
		'debug'							=> false,
		'force_nonce'					=> false,
		'nonce'							=> false, // used for checking signatures. leave as false for auto
		'force_timestamp'				=> false,
		'timestamp'						=> false, // used for checking signatures. leave as false for auto
		'oauth_version'					=> '1.0',
		'curl_connecttimeout'			=> 30,
		'curl_timeout'					=> 10,
		'curl_ssl_verifypeer'			=> false,
		'curl_followlocation'			=> false, // whether to follow redirects or not
		'curl_proxy'					=> false, // really you don't want to use this if you are using streaming
		'curl_proxyuserpwd'				=> false, // format username:password for proxy, if required
		'is_streaming'					=> false,
		'streaming_eol'					=> "\r\n",
		'streaming_metrics_interval'	=> 60,
		'as_header'				  		=> true,
	);
	
	public function __construct($strategy, $env){
		parent::__construct($strategy, $env);
		
		$this->strategy['consumer_key'] = $this->strategy['api_key'];
		$this->strategy['consumer_secret'] = $this->strategy['secret_key'];
		
		require dirname(__FILE__).'/Vendor/tmhOAuth/tmhOAuth.php';
		$this->tmhOAuth = new tmhOAuth($this->strategy);
	}
	
	/**
	 * Auth request
	 */
	public function request(){
		$params = array(
			'oauth_callback' => $this->strategy['oauth_callback'],
			'scope' => $this->strategy['scope'],
		);
		
		$results =  $this->_request('POST', $this->strategy['request_token_url'], $params);

		if ($results !== false && !empty($results['oauth_token']) && !empty($results['oauth_token_secret'])){
			session_start();
			$_SESSION['_opauth_linkedin'] = $results;

			$this->_authorize($results['oauth_token']);
		}
	}

	/**
	 * Receives oauth_verifier, requests for access_token and redirect to callback
	 */
	public function oauth_callback(){
		if(session_id() == '') session_start();
		$session = $_SESSION['_opauth_linkedin'];
		unset($_SESSION['_opauth_linkedin']);

		if ($_REQUEST['oauth_token'] == $session['oauth_token']){
			$this->tmhOAuth->config['user_token'] = $session['oauth_token'];
			$this->tmhOAuth->config['user_secret'] = $session['oauth_token_secret'];
			
			$params = array(
				'oauth_verifier' => $_REQUEST['oauth_verifier']
			);
	
			$results =  $this->_request('POST', $this->strategy['access_token_url'], $params);
			
			if ($results !== false && !empty($results['oauth_token']) && !empty($results['oauth_token_secret'])){
				$profile = $this->_getProfile($results['oauth_token'], $results['oauth_token_secret']);

				if(isset($profile['picture-urls'])) $profile['picture-url'] = $profile['picture-urls']['picture-url'];
		
				if (!empty($profile['id'])){
					$this->auth = array(
						'uid' => $profile['id'],
						'info' => array(),
						'credentials' => array(
							'token' => $results['oauth_token'],
							'secret' => $results['oauth_token_secret']
						),
						'raw' => $profile
					);

					if(isset($this->auth['raw']['educations']) && $this->auth['raw']['educations']['@attributes']['total'] == 1) $this->auth['raw']['educations']['education'] = array($this->auth['raw']['educations']['education']);
					if(isset($this->auth['raw']['three-current-positions']) && $this->auth['raw']['three-current-positions']['@attributes']['total'] == 1) $this->auth['raw']['three-current-positions']['position'] = array($this->auth['raw']['three-current-positions']['position']);
					if(isset($this->auth['raw']['three-past-positions']) && $this->auth['raw']['three-past-positions']['@attributes']['total'] == 1) $this->auth['raw']['three-past-positions']['position'] = array($this->auth['raw']['three-past-positions']['position']);
					if(isset($this->auth['raw']['volunteer']) && $this->auth['raw']['volunteer']['volunteer-experiences']['@attributes']['total'] == 1) $this->auth['raw']['volunteer']['volunteer-experiences']['volunteer-experience'] = array($this->auth['raw']['volunteer']['volunteer-experiences']['volunteer-experience']);

					$profile['education'] = array();
					$profile['volunteer'] = array();
					$profile['work'] = array();

					if(isset($this->auth['raw']['educations']) && !empty($this->auth['raw']['educations'])) {
						foreach ($this->auth['raw']['educations']['education'] as $edu => $cnt) {
							$edu = $this->auth['raw']['educations']['education'][$edu];
							array_push($profile['education'], array(
								'institution' => (isset($edu['school-name']) && !empty($edu['school-name']) ? $edu['school-name'] : 'Unknown Institution'),
								'field_of_study' => (isset($edu['field-of-study']) && !empty($edu['field-of-study']) ? $edu['field-of-study'] : null),
								'start_date' => (isset($edu['start-date']) && !empty($edu['start-date']) ? date('Y-m-d H:i:s', strtotime((isset($edu['start-date']['month']) ? $edu['start-date']['month'] : '01') . '/01/' . $edu['start-date']['year'])) : null),
								'end_date' => (isset($edu['end-date']) && !empty($edu['end-date']) ? date('Y-m-d H:i:s', strtotime((isset($edu['end-date']['month']) ? $edu['end-date']['month'] : '01') . '/01/' . $edu['end-date']['year'])) : null),
								'currentlyAttendingFlag' => (!isset($edu['end-date']) || isset($edu['end-date']) && date('Y') <= date('Y', $edu['end-date']['year']) ? 1 : 0)));
						}
					}

					if(isset($this->auth['raw']['three-current-positions']) && !empty($this->auth['raw']['three-current-positions'])) {
						foreach ($this->auth['raw']['three-current-positions']['position'] as $job => $cnt) {
							$job = $this->auth['raw']['three-current-positions']['position'][$job];
							array_push($profile['work'], array(
								'employer' => (isset($job['company']) && !empty($job['company']) ? $job['company']['name'] : 'Unknown Employer'),
								'position' => (isset($job['title']) && !empty($job['title']) ? $job['title'] : null),
								'start_date' => (isset($job['start-date']) && !empty($job['start-date']) ? date('Y-m-d H:i:s', strtotime((isset($job['start-date']['month']) ? $job['start-date']['month'] : '01') . '/01/' . $job['start-date']['year'])) : null),
								'end_date' => (isset($job['end-date']) && !empty($job['end-date']) ? date('Y-m-d H:i:s', strtotime((isset($job['end-date']['month']) ? $job['end-date']['month'] : '01') . '/01/' . $job['end-date']['year'])) : null),
								'currentlyWorkingFlag' => (isset($job['is-current']) && !empty($job['is-current']) ? ($job['is-current'] == 'true' ? 1 : 0) : 0)));
						}
					}

					if(isset($this->auth['raw']['three-past-positions']) && !empty($this->auth['raw']['three-past-positions'])) {
						foreach ($this->auth['raw']['three-past-positions']['position'] as $job => $cnt) {
							$job = $this->auth['raw']['three-past-positions']['position'][$job];
							array_push($profile['work'], array(
								'employer' => (isset($job['company']) && !empty($job['company']) ? $job['company']['name'] : 'Unknown Employer'),
								'position' => (isset($job['title']) && !empty($job['title']) ? $job['title'] : null),
								'start_date' => (isset($job['start-date']) && !empty($job['start-date']) ? date('Y-m-d H:i:s', strtotime((isset($job['start-date']['month']) ? $job['start-date']['month'] : '01') . '/01/' . $job['start-date']['year'])) : null),
								'end_date' => (isset($job['end-date']) && !empty($job['end-date']) ? date('Y-m-d H:i:s', strtotime((isset($job['end-date']['month']) ? $job['end-date']['month'] : '01') . '/01/' . $job['end-date']['year'])) : null),
								'currentlyWorkingFlag' => 0));
						}
					}

					if(isset($this->auth['raw']['volunteer']['volunteer-experiences']) && !empty($this->auth['raw']['volunteer']['volunteer-experiences'])) {
						foreach ($this->auth['raw']['volunteer']['volunteer-experiences']['volunteer-experience'] as $vol => $cnt) {
							$vol = $this->auth['raw']['volunteer']['volunteer-experiences']['volunteer-experience'][$vol];
							array_push($profile['volunteer'], array(
								'volunteer_location' => (isset($vol['organization']) && !empty($vol['organization']) ? $vol['organization']['name'] : 'Unknown Organization'),
								'job_description' => (isset($vol['role']) && !empty($vol['role']) ? $vol['role'] : null)));
						}
					}


					$profile['username'] = (!empty($profile['email-address']) ? explode('@',$profile['email-address']): '');
                	$profile['username'] = (is_array($profile['username']) ? $profile['username'][0] : '');
                	
					$this->mapProfile($profile, 'formatted-name', 'info.name');
					$this->mapProfile($profile, 'first-name', 'info.first_name');
					$this->mapProfile($profile, 'last-name', 'info.last_name');
					$this->mapProfile($profile, 'email-address', 'info.email');
					$this->mapProfile($profile, 'headline', 'info.headline');
					$this->mapProfile($profile, 'summary', 'info.description');
					$this->mapProfile($profile, 'location.name', 'info.location');
					$this->mapProfile($profile, 'picture-url', 'info.image');
					$this->mapProfile($profile, 'public-profile-url', 'info.urls.linkedin');
					$this->mapProfile($profile, 'site-standard-profile-request.url', 'info.urls.linkedin_authenticated');
					$this->mapProfile($profile, 'username', 'info.username');
					$this->mapProfile($profile, 'education', 'info.education');
					$this->mapProfile($profile, 'volunteer', 'info.volunteer');
					$this->mapProfile($profile, 'work', 'info.work');
					
					$this->callback();
				}
			}
			else{
				$error = array(
					'code' => 'oauth_token_expected',
					'message' => 'OAuth token and secret expected.',
					'raw' => $results
				);

				$this->errorCallback($error);
			}
		}
		else{
			$error = array(
				'code' => 'access_denied',
				'message' => 'User denied access.',
				'raw' => $_GET
			);

			$this->errorCallback($error);
		}
		
				
	}

	private function _authorize($oauth_token){
		$params = array(
			'oauth_token' => $oauth_token
		);

		$this->clientGet($this->strategy['authorize_url'], $params);
	}
	
	private function _getProfile($user_token, $user_token_secret){
		$this->tmhOAuth->config['user_token'] = $user_token;
		$this->tmhOAuth->config['user_secret'] = $user_token_secret;

		$url = $this->strategy['get_profile_url'];
		if (!empty($this->strategy['profile_fields'])){
			if (is_array($this->strategy['profile_fields']))
				$url = $url.':('.implode(',',$this->strategy['profile_fields']).')';
			else
				$url = $url.':('.$this->strategy['profile_fields'].')';
		}
		
		$response = $this->_request('GET', $url, array(), true, false, 'xml');
		
		return $this->recursiveGetObjectVars($response);
	}
	


	/**
	 * Wrapper of tmhOAuth's request() with Opauth's error handling.
	 * 
	 * request():
	 * Make an HTTP request using this library. This method doesn't return anything.
	 * Instead the response should be inspected directly.
	 *
	 * @param string $method the HTTP method being used. e.g. POST, GET, HEAD etc
	 * @param string $url the request URL without query string parameters
	 * @param array $params the request parameters as an array of key=value pairs
	 * @param string $useauth whether to use authentication when making the request. Default true.
	 * @param string $multipart whether this request contains multipart data. Default false
	 * @param string $hander Set to 'json' or 'xml' to parse JSON or XML-based output.
	 */	
	private function _request($method, $url, $params = array(), $useauth = true, $multipart = false, $handler = null){
		$code = $this->tmhOAuth->request($method, $url, $params, $useauth, $multipart);
		
		if (is_null($handler)){
			if (strpos($url, '.json') !== false) $handler = 'json';
			elseif (strpos($url, '.xml') !== false) $handler = 'xml';
		}

		if ($code == 200){
			if ($handler == 'json')
				$response = json_decode($this->tmhOAuth->response['response']);
			elseif ($handler == 'xml')
				$response = simplexml_load_string($this->tmhOAuth->response['response']);
			else
				$response = $this->tmhOAuth->extract_params($this->tmhOAuth->response['response']);
			
			return $response;		
		}
		else {
			$error = array(
				'code' => $code,
				'raw' => $this->tmhOAuth->response['response']
			);

			$this->errorCallback($error);
			
			return false;
		}
	}
	
}
