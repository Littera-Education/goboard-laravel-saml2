<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use App\Services\Auth\Auth;
use Illuminate\Support\Facades\Log;


class Saml2Controller extends Controller
{

    protected $saml2Auth;
    protected $tmsAuth;

    /**
     * @param Saml2Auth $saml2Auth injected.
     */
    function __construct(Saml2Auth $saml2Auth, Auth $tmsAuth)
    {
        $this->saml2Auth = $saml2Auth;
        $this->tmsAuth = $tmsAuth;
    }


    /**
     * Generate local sp metadata
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {

        $metadata = $this->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'saml2.loginRequestReceived' event if a valid user is Found
     */
    public function acs()
    {
        $errors = $this->saml2Auth->acs();

        if (!empty($errors)) {
            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }
        $saml_user = $this->saml2Auth->getSaml2User();

        event(new Saml2LoginEvent($saml_user));

        $redirectUrl = $saml_user->getIntendedUrl();

        $profile = [
            'id' => $saml_user->getUserId(),
            'firstName' => $saml_user->getFirstName(),
            'lastName' => $saml_user->getLastName(),
            'email' => $saml_user->getEmail()
        ];

        $user = $this->tmsAuth->viaSchoolProfile($profile);
        $userToken = $this->tmsAuth->getToken($user);
		$userToken->setIsSSO(true);
        $userTokenStr = $userToken->encode();
		$userFBTokenStr = $this->tmsAuth->createFirebaseToken($user);

        if ($redirectUrl !== null) {
            return redirect($redirectUrl . '/' . $userTokenStr . '/' . $userFBTokenStr);
        } else {
            return redirect(config('saml2_settings.loginRoute') . '/' . $userTokenStr . '/' . $userFBTokenStr);
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'saml2.logoutRequestReceived' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     */
    public function sls()
    {
       /* $error = $this->saml2Auth->sls(config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($error)) {
            throw new \Exception("Could not log out");
        }
*/
        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     */
    public function logout(Request $request)
    {
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
        $nameId = $request->query('nameId');
        $this->saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
        //does not return
    }


    /**
     * This initiates a login request
     */
    public function login()
    {
        $this->saml2Auth->login(config('saml2_settings.loginRoute'));
    }



    public function wayfLogin(Request $request)
    {
        $idpLoginUrl = $request->query('entityID');
        $return = $request->input('return');
        Log::info('return', ['r' => $return]);
        if(!$return) {
          $return = 'false';
        }
        $this->saml2Auth->wayfLogin($idpLoginUrl, config('saml2_settings.loginRoute') . '/' . $return);
    }
}
