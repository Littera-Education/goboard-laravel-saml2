<?php

namespace Aacotroneo\Saml2;

use OneLogin_Saml2_Auth;
use Log;

/**
 * A simple class that represents the user that 'came' inside the saml2 assertion
 * Class Saml2User
 * @package Aacotroneo\Saml2
 */
class Saml2User
{

    protected $auth;

    function __construct(OneLogin_Saml2_Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * @return string User Id retrieved from assertion processed this request
     */
    function getUserId()
    {
        $auth = $this->auth;
        $trimmedIssuer = null;
        $issuers = $auth->getIssuers();
        foreach ($issuers as $issuer) {
            $trimmedIssuer = strtolower(trim($issuer));
            break;
        }
        $email = $this->getEmail();
        if(!$trimmedIssuer || !$email) {
            throw new \Exception('Can not build user id.');
        }

        return hash('sha1', $trimmedIssuer . strtolower($email), false);
    }

    /**
     * @return array attributes retrieved from assertion processed this request
     */
    function getAttributes()
    {
        $auth = $this->auth;

        return $auth->getAttributes();
    }

    /**
     * @return string the saml assertion processed this request
     */
    function getRawSamlAssertion()
    {
        return app('request')->input('SAMLResponse'); //just this request
    }

    function getIntendedUrl()
    {
        $relayState = app('request')->input('RelayState'); //just this request

        $url = app('Illuminate\Contracts\Routing\UrlGenerator');

        if ($relayState && $url->full() != $relayState) {

            return $relayState;
        }
    }

    function getSessionIndex()
    {
        return $this->auth->getSessionIndex();
    }

    function getNameId()
    {
        return $this->auth->getNameId();
    }

    function getEmail()
    {
        $attributes = $this->getAttributes();
        if (env('ALLOW_SAML_LOG')) {
            Log::info('user_attributes saml2User->getEmail()', $attributes);
            Log::info('------------------------- SAML LOG END --------------------------------' . PHP_EOL);
        }
        foreach($attributes as $k => $v) {
            if($k == 'urn:oid:0.9.2342.19200300.100.1.3') {
                if($v && count($v) > 0) {
                    return $v[0];
                }
                break;
            }
        }

        return null;
    }

    function getFirstName()
    {
        $attributes = $this->getAttributes();
        foreach($attributes as $k => $v) {
            if($k == 'urn:oid:2.5.4.42') {
                if($v && count($v) > 0) {
                    return $v[0];
                }
                break;
            }
        }

        return null;
    }

    function getLastName()
    {
        $attributes = $this->getAttributes();
        foreach($attributes as $k => $v) {
            if($k == 'urn:oid:2.5.4.4') {
                if($v && count($v) > 0) {
                    return $v[0];
                }
                break;
            }
        }

        return null;
    }

}
