<?php

namespace Aacotroneo\Saml2;

use OneLogin_Saml2_Auth;
use OneLogin_Saml2_Response;
use OneLogin_Saml2_Error;
use OneLogin_Saml2_Utils;
use Aacotroneo\Saml2\Events\Saml2LogoutEvent;
use Illuminate\Http\Request;

Use DB;
use Log;
use Psr\Log\InvalidArgumentException;

class Saml2Auth
{

    /**
     * @var \OneLogin_Saml2_Auth
     */
    protected $auth;

    protected $samlAssertion;

    function __construct(OneLogin_Saml2_Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * @return bool if a valid user was fetched from the saml assertion this request.
     */
    function isAuthenticated()
    {
        $auth = $this->auth;

        return $auth->isAuthenticated();
    }

    /**
     * The user info from the assertion
     * @return Saml2User
     */
    function getSaml2User()
    {
        return new Saml2User($this->auth);
    }

    /**
     * Initiate a saml2 login flow. It will redirect! Before calling this, check if user is
     * authenticated (here in saml2). That would be true when the assertion was received this request.
     */
    function login($returnTo = null)
    {
        $auth = $this->auth;

        $auth->login($returnTo);
    }


    function wayfLogin($idPLoginUrl, $returnTo = null)
    {
        $auth = $this->auth;
        $settings = $this->auth->getSettings();
        $settings->setIdPSingleSignOnServiceUrl($idPLoginUrl);
        $this->auth->setSettings($settings);

        $auth->login($returnTo);
    }

    /**
     * Initiate a saml2 logout flow. It will close session on all other SSO services. You should close
     * local session if applicable.
     */
    function logout($entity_id = null, $returnTo = null, $nameId = null, $sessionIndex = null)
    {
        $auth = $this->auth;
        $settings = $this->auth->getSettings();
        // add settings taken from database for certain IDP 
        $settings->setIdpEntityId($entity_id);
        $idpData = DB::select("select * from school_sso where entity_id = '$entity_id'");
        $idp = $idpData[0];

        $settings->setIdPSingleSignOutServiceUrl($idp->ssout_url);
        $x509cert = empty($idp->public_key_encryption) ? $idp->public_key_signing : $idp->public_key_encryption;
        $settings->setIdPCert($x509cert);
        $auth->logout($returnTo, [], $nameId, $sessionIndex);
    }

    /**
     * Process a Saml response (assertion consumer service)
     * When errors are encountered, it returns an array with proper description
     */
    function acs()
    {

        /** @var $auth OneLogin_Saml2_Auth */
        $auth = $this->auth;


        $settings = $this->auth->getSettings();

        $idpData = null;
        $response = new OneLogin_Saml2_Response($settings, $_POST['SAMLResponse']);
        $issuers = $response->getIssuers();
        if (env('ALLOW_SAML_LOG')) {
            Log::info('--------------------------------- SAML LOG ---------------------------' . PHP_EOL);
            Log::info('$issuers saml2Auth->acs()', $issuers);
        }
        $idps = implode(',', $issuers);
        $idp = DB::select("select * from school_sso where entity_id in ('$idps')");

        $idpData = $idp[0];
        if(!$idpData) {
            Log::error('Idp Data Missing in DB', ['idps' => $idps]);
            return array('error' => 'Unknown issuer [WAYF].');
        }

        $settings->setIdPSingleSignOnServiceUrl($idpData->sso_url);
        $public_key = empty($idpData->public_key_encryption) ? $idpData->public_key_signing : $idpData->public_key_encryption ;

        $settings->setIdPCert($public_key);
        $settings->setIdpEntityId($idpData->entity_id);
        $this->auth->setSettings($settings);

        $auth->processResponse();

        $errors = $auth->getErrors();

        if (!empty($errors)) {
            return $errors;
        }

        if (!$auth->isAuthenticated()) {
            return array('error' => 'Could not authenticate');
        }

        return null;

    }

    /**
     * Process a Saml response (assertion consumer service)
     * returns an array with errors if it can not logout
     */
    function sls($retrieveParametersFromServer = false)
    {
        $auth = $this->auth;

        // destroy the local session by firing the Logout event
        $keep_local_session = false;
        $session_callback = function () {
            event(new Saml2LogoutEvent());
        };

        $auth->processSLO($keep_local_session, null, $retrieveParametersFromServer, $session_callback);

        $errors = $auth->getErrors();

        return $errors;
    }

    /**
     * Show metadata about the local sp. Use this to configure your saml2 IDP
     * @return mixed xml string representing metadata
     * @throws \InvalidArgumentException if metadata is not correctly set
     */
    function getMetadata()
    {
        $auth = $this->auth;
        $settings = $auth->getSettings();
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);

        if (empty($errors)) {

            return $metadata;
        } else {

            throw new InvalidArgumentException(
                'Invalid SP metadata: ' . implode(', ', $errors),
                OneLogin_Saml2_Error::METADATA_SP_INVALID
            );
        }
    }


}
