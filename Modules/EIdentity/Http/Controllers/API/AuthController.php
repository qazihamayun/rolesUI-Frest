<?php


namespace Modules\EIdentity\Http\Controllers\API;


use App\Http\Controllers\Controller;
use Modules\EIdentity\Http\Requests\Auth\LoginRequest;
use Modules\EIdentity\Entities\Employees;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    /**
     * Handle an incoming api authentication request.
     *
     * @param LoginRequest $request
     * @return JsonResponse
     */
    public function login(LoginRequest $request): JsonResponse
    {


        // TODO implement rate limiter
        $credentials = $request->only('cnic', 'password');
        $token = Auth::guard('eidentity_api')->attempt($credentials);

        if (!$token) {
            return response()->json([
                'response' => false,
                'errors' => [__('auth.failed')]
            ], 401);
        }
        $user = Auth::guard('eidentity_api')->user();
        return $this->generateToken($user, $token);
    }

    /**
     * Generate login token for user.
     *
     * @param User $user
     * @return JsonResponse
     */
    private function generateToken(Employees $user, $token = null): JsonResponse
    {
        // Revoke previously generated tokens
        $user->tokens()->delete();
        $user->access_token = $token;
        $user->user_id = $user->id;
        return response()->json([
            'response' => true,
            'data' => $user,
        ]);
    }


    /**
     * Logout user.
     *
     * @return JsonResponse
     */


    public function logout()
    {
        Auth::guard('vms_api')->logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::guard('eidentity_api')->user(),
            'authorisation' => [
                'token' => Auth::guard('eidentity_api')->refresh(),
                'type' => 'bearer',
            ]
        ]);
    }
}
